package dev.rubcut.zapret.core.desync

import dev.rubcut.zapret.core.proto.ClientHelloInfo
import dev.rubcut.zapret.core.proto.Http
import dev.rubcut.zapret.core.proto.Tls
import dev.rubcut.zapret.core.split.Segmenter
import dev.rubcut.zapret.data.DesyncMode
import dev.rubcut.zapret.data.SplitPos
import dev.rubcut.zapret.data.Strategy

/** Контекст потока, для которого принимается решение о десинхронизации. */
class FlowContext(
    val dstPort: Int,
    val knownHost: String?,
    val v6: Boolean
)

/**
 * Результат работы движка: последовательность независимых записей в upstream-сокет.
 * Каждая запись при включённом TCP_NODELAY уходит отдельным TCP-сегментом.
 */
class DesyncPlan(
    val writes: List<ByteArray>,
    val applied: Boolean,
    val technique: String,
    val host: String?,
    /**
     * Запись-подстава, отправляемая перед основными.
     *
     * Отдельно от [writes], потому что у неё другой смысл и другое время жизни:
     * сервер её не считает рукопожатием, а DPI на ней спотыкается. Её нельзя
     * смешивать с фрагментами настоящего ClientHello — иначе потеряется и
     * подстава, и разбиение.
     */
    val poison: ByteArray? = null,
    /** Пауза между подставой и настоящими данными, мс. */
    val poisonDelayMs: Int = 0
) {
    val segmentCount: Int get() = writes.size

    /** Подставу не считаем фрагментом: она идёт отдельной записью до [writes]. */
    val totalWrites: Int get() = writes.size + (if (poison != null) 1 else 0)

    companion object {
        fun passthrough(payload: ByteArray, technique: String, host: String? = null) =
            DesyncPlan(listOf(payload), false, technique, host)
    }
}

/**
 * Движок десинхронизации DPI.
 *
 * Оригинальный zapret правит уже готовые пакеты в NFQUEUE/WinDivert. На Android без root
 * исходящие пакеты формирует ядро, поэтому мы управляем не заголовками, а границами
 * TCP-сегментов: сами решаем, какими порциями и с какими паузами байты уходят в сокет.
 * Для DPI, разбирающего только первые сегменты потока (так устроено большинство систем
 * фильтрации по SNI), эффект эквивалентен --dpi-desync=split / multisplit / tlsrec.
 */
class DesyncEngine {

    fun plan(payload: ByteArray, ctx: FlowContext, s: Strategy): DesyncPlan {
        if (payload.isEmpty()) return DesyncPlan.passthrough(payload, "empty")

        val isTls = Tls.isRecordType(payload, 0, payload.size)
        val isHttp = Http.looksLikeRequest(payload, 0, payload.size)
        val hello: ClientHelloInfo? = if (isTls) Tls.parseClientHello(payload, 0, payload.size) else null
        val httpHostRange = if (isHttp) Http.hostValueRange(payload, 0, payload.size) else null
        val host = hello?.sni
            ?: ctx.knownHost
            ?: httpHostRange?.let { String(payload, it.first, it.second - it.first, Charsets.ISO_8859_1) }

        // Смена регистра в имени хоста. Делается ДО разбиения: фильтр должен
        // не найти домен в том потоке, который до него дойдёт, а не в том,
        // который мы разрежем уже после.
        var data = payload
        var mixed = false
        if (s.sniCaseMix) {
            val rewritten = when {
                hello != null -> Tls.mixFirstLabel(data, hello.sniStart, hello.sniEnd, hello.sni)
                httpHostRange != null -> Http.mixFirstHostLabel(
                    data, httpHostRange.first, httpHostRange.second
                )
                else -> null
            }
            if (rewritten != null) {
                data = rewritten
                mixed = true
            }
        }

        // Отравление разбора DPI: сперва уходит целая посторонняя запись,
        // настоящие данные — следом. Приём самостоятельный, поэтому переживает
        // и ветки, где разбить нечего.
        val poison = if (s.poisonEnabled && isTls && hello != null) {
            Tls.poisonHello(s.poisonSni.ifBlank { DEFAULT_POISON_SNI })
        } else null

        // Смена регистра — самостоятельный приём, а не часть разбиения, поэтому
        // работает и при выключенном десинхронизме. Дальше любая ветка, где
        // разбить нечего, обязана отдать изменённые байты целиком, иначе приём
        // молча потеряется.
        // Разделитель в конце: lead всегда либо пуст, либо уже готов к склейке с
        // названием техники — иначе надписи в журнале слипаются.
        val lead = when {
            poison != null && mixed -> "отравление DPI + смена регистра + "
            poison != null -> "отравление DPI + "
            mixed -> "смена регистра + "
            else -> ""
        }
        fun giveUp(reason: String) =
            if (lead.isNotEmpty()) DesyncPlan(listOf(data), true, lead.trim(), host, poison, s.poisonDelayMs)
            else DesyncPlan.passthrough(payload, reason, host)

        if (s.desync == DesyncMode.NONE) return giveUp("off")

        // 1) Переупаковка TLS-записей — аналог --dpi-desync-tlsrec=N
        val wantsTlsRec = s.desync == DesyncMode.TLSREC || s.desync == DesyncMode.MULTISPLIT_TLSREC
        val parts = if (s.tlsrecParts >= 2) s.tlsrecParts else 2
        if (isTls && wantsTlsRec) {
            // Точка реза берётся из настроек, если она попадает внутрь записи.
            //
            // Победивший на реальном фильтре вариант — `--tlsrec=0+wm
            // --split=0+wm`: запись режется в середине домена второго уровня, и
            // там же рвётся поток. Раньше запись делилась пополам, то есть граница
            // уезжала совсем в другое место и приём не срабатывал.
            val cutAt = collectPositions(s, data, hello, null)
                .firstOrNull { it in (Tls.RECORD_HEADER + 1) until data.size }
            val repacked = cutAt?.let { Tls.repackRecordAt(data, 0, data.size, it) }
                ?: Tls.repackRecords(data, 0, data.size, parts)
            if (repacked != null) {
                // Границы записей И точки разбиения из настроек — вместе.
                //
                // Раньше здесь брались только границы переупакованных записей, и
                // ветка возвращалась раньше общего кода: половина названия
                // MULTISPLIT_TLSREC не работала, точки из splitPositions
                // игнорировались.
                //
                // SNI разбирается заново: после переупаковки он сдвинут на
                // длину добавленной записи, старые смещения больше не годятся.
                val hello2 = Tls.parseClientHello(repacked, 0, repacked.size)
                val bounds = Tls.recordBoundaries(repacked, 0, repacked.size)
                val positions = (bounds + collectPositions(s, repacked, hello2, null))
                    .filter { it in 1 until repacked.size }
                    .distinct()
                    .sorted()
                val writes = splitAt(repacked, positions)
                if (writes.size >= 2) {
                    return DesyncPlan(
                        writes, true, "${lead}tlsrec x$parts + разбиение → ${writes.size} записей", host,
                        poison, s.poisonDelayMs
                    )
                }
            }
        }

        // 2) hostfakesplit для plaintext HTTP — режем значение заголовка Host.
        // Разбиваем уже изменённые данные (со сменой регистра), иначе приём
        // молча терялся бы на HTTP-правилах с sniCaseMix.
        if (s.desync == DesyncMode.HOSTFAKESPLIT && isHttp && httpHostRange != null) {
            val vs = httpHostRange.first
            val ve = httpHostRange.second
            val positions = linkedSetOf(1, vs, vs + (ve - vs) / 2, ve)
            val writes = splitAt(data, positions.filter { it in 1 until data.size }.sorted())
            if (writes.size >= 2) {
                return DesyncPlan(
                    writes, true, "${lead}hostfakesplit Host=${host ?: "?"}", host,
                    poison, s.poisonDelayMs
                )
            }
        }

        // 3) split / multisplit
        if (!isTls && !isHttp && !s.anyProtocol) return giveUp("не TLS/HTTP, пропуск")

        val raw = collectPositions(s, data, hello, httpHostRange)
        val positions = raw.filter { it in 1 until data.size }.distinct().sorted()
        if (positions.isEmpty()) return giveUp("нет точки разбиения")

        // Ключевой момент: разбиение должно идти ПОДРЯД с точками, а не только
        // в середину. Иначе первая точка (FIRST = 1) отсекает один байт и весь
        // ClientHello уходит вторым сегментом целиком — DPI его склеивает и
        // десинхронизации не происходит вовсе.
        val ordered = orderedPositions(s, positions, hello)

        val single = s.desync == DesyncMode.SPLIT || s.desync == DesyncMode.TLSREC
        val chosen = if (single) listOf(ordered.maxOrNull() ?: return giveUp("разбиение не удалось")) else ordered
        val writes = splitAt(data, chosen)
        if (writes.size < 2) return giveUp("разбиение не удалось")

        val label = buildString {
            // Разделитель обязателен, иначе надпись склеивается: «смена регистра в имени
            // хостаmultisplit».
            append(lead)
            append(if (single) "split" else "multisplit")
            append(" [").append(chosen.joinToString(",")).append("] → ")
            append(writes.size).append(" сегм.")
            if (host != null) append(" sni=").append(host)
        }
        return DesyncPlan(writes, true, label, host, poison, s.poisonDelayMs)
    }

    private fun collectPositions(
        s: Strategy,
        payload: ByteArray,
        hello: ClientHelloInfo?,
        httpHostRange: Pair<Int, Int>?
    ): List<Int> {
        val out = ArrayList<Int>()
        for (pos in s.splitPositions) {
            when (pos) {
                SplitPos.FIRST -> out += 1
                // MIDSNI — это midsld из zapret: середина ДОМЕНА ВТОРОГО УРОВНЯ,
                // а не середина всей строки SNI. Разница критична для YouTube,
                // где видео идёт с CDN-хостов rr*.googlevideo.com.
                SplitPos.MIDSNI -> when {
                    hello != null -> out += hello.midsldOffset
                    httpHostRange != null -> out += Tls.midsldOffset(
                        httpHostRange.first, httpHostRange.second,
                        String(payload, httpHostRange.first, httpHostRange.second - httpHostRange.first, Charsets.ISO_8859_1)
                    )
                    else -> out += payload.size / 2
                }
                SplitPos.SNIEND -> when {
                    hello != null -> out += hello.sniEnd
                    httpHostRange != null -> out += httpHostRange.second
                    else -> out += payload.size / 2
                }
                SplitPos.MIDDLE -> out += payload.size / 2
                SplitPos.CUSTOM -> out += s.splitCustomPos
            }
        }
        return out
    }

    /**
     * Порядок точек разбиения.
     *
     * `split` берёт ОДНУ точку, и выбирать её надо осмысленно: точка возле начала
     * ClientHello отрезает пустой префикс, после чего весь hello уходит вторым
     * сегментом целиком. Поэтому для `split` берётся самая глубокая точка —
     * та, что стоит внутри имени хоста, — независимо от порядка в списке.
     *
     * Дубликаты (например `FIRST` и `custom=1`) схлопываются в одну точку.
     */
    private fun orderedPositions(s: Strategy, positions: List<Int>, hello: ClientHelloInfo?): List<Int> {
        val seen = LinkedHashSet<Int>()
        for (pos in s.splitPositions) {
            when (pos) {
                SplitPos.FIRST -> seen += 1
                SplitPos.MIDSNI -> if (hello != null) seen += hello.midsldOffset else seen += -1
                SplitPos.SNIEND -> if (hello != null) seen += hello.sniEnd else seen += -1
                SplitPos.MIDDLE -> seen += -2
                SplitPos.CUSTOM -> seen += s.splitCustomPos
            }
        }
        // Позиции, которые не удалось разрешить (SNI не найден), заменяем на
        // середину — иначе профиль без разбора SNI не делал бы ничего.
        val fallback = seen.map { if (it < 0) positions.last() else it }
        return fallback.distinct()
    }

    private fun splitAt(payload: ByteArray, positions: List<Int>): List<ByteArray> =
        Segmenter.split(payload, positions)

    companion object {
        /**
         * Домен в подставной записи.
         *
         * Он должен выглядеть обычным и не быть в списках блокировки: DPI
         * разбирает его первым и на нём спотыкается, а до заблокированного
         * домена в потоке уже не доходит.
         */
        const val DEFAULT_POISON_SNI = "www.google.com"
    }
}
