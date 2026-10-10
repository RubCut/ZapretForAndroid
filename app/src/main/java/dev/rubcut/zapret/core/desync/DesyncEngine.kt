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
    val poisonDelayMs: Int = 0,
    /**
     * Первый фрагмент уходит с байтом срочных данных — как `r1.a` в ZapretYT.
     *
     * Отдельный признак, а не флаг в [writes]: на проводе это данные фрагмента
     * плюс один байт, отправленные одним вызовом `sendto(MSG_OOB)`. Сервер,
     * читающий обычный поток, срочный байт пропускает, а разбор имени у
     * фильтра, читающего поток как есть, сбивается.
     */
    val urgentByte: Int? = null,
    /**
     * Перед данными уходит пустышка с этим TTL.
     *
     * Ноль означает «не подменять»: значение 0 нельзя отличить от молчания.
     */
    val fakeTtl: Int = 0,
    /**
     * Содержимое пустышки для [DesyncMode.FAKE].
     *
     * Это заведомо безвредное hello (чужой SNI), а не настоящий ClientHello:
     * слать туда настоящие данные бессмысленно — фильтр найдёт в них тот же
     * SNI. Отдельно от [writes], как и [poison]: настоящие данные идут следом
     * обычным способом.
     */
    val fakeDummy: ByteArray? = null,
    /**
     * Хвост [writes] уходит раньше начала (`--disoob`).
     *
     * По эталону ByeDPI (`--disoob 3`: отправка `3-30, 1-4+URG`) хвост потока
     * пишется первым обычной записью, а начало — вторым вместе со срочным
     * байтом. Сервер пересобирает по sequence, фильтр видит обратный порядок.
     */
    val tailFirst: Boolean = false,
    /**
     * Индексы фрагментов [writes], уходящих с TTL=1 (`--disorder`).
     *
     * По эталону ByeDPI фрагмент с TTL=1 умирает на первом хопе, а ядро само
     * переотправляет его после SACK от сервера — порядок на проводе ломается
     * без единого raw-сокета. Пусто — обычный TTL для всех фрагментов.
     */
    val ttl1Indices: Set<Int> = emptySet()
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
            if (lead.isNotEmpty()) DesyncPlan(listOf(data), true, lead.removeSuffix("+ ").trim(), host, poison, s.poisonDelayMs)
            else DesyncPlan.passthrough(payload, reason, host)

        if (s.desync == DesyncMode.NONE) return giveUp("off")

        // 0) Приёмы на параметрах сокета — до всего остального: они не режут
        // поток, а меняют то, как отдельный сегмент уходит в провод.
        //
        // OOB: к последнему фрагменту добавляется байт срочных данных, который
        // на проводе есть, а в обычном потоке получателя — нет.
        //
        // FAKE: перед данными уходит пустышка с малым TTL. Она умирает на
        // первом хопе, до сервера не доходит, но инлайновый фильтр её видит и
        // разбирает — до настоящего ClientHello дело может не дойти.
        if (s.desync == DesyncMode.OOB) {
            // Ноль — законное значение байта, поэтому «не задано» выражается
            // отсутствием (null), а не нулём: иначе отличить их нельзя.
            val urgent = s.urgentByte ?: return giveUp("не задан OOB-байт")
            val positions = collectPositions(s, data, hello, httpHostRange)
                .filter { it in 1 until data.size }
                .distinct()
                .sorted()
            val writes = splitAt(data, positions)
            if (writes.size >= 2) {
                return DesyncPlan(
                    writes, true, "${lead}oob → ${writes.size} записей", host,
                    poison, s.poisonDelayMs, urgentByte = urgent and 0xFF
                )
            }
            return giveUp("нет точки разбиения для OOB")
        }
        // DISORDER/DISOOB — те же точки разбиения, что у OOB, но другая
        // механика отправки (см. DesyncPlan.tailFirst/ttl1Indices и ByeDPI
        // desync.c: TTL=1 для гибнущей копии + обратный порядок для disoob).
        if (s.desync == DesyncMode.DISORDER) {
            val positions = collectPositions(s, data, hello, httpHostRange)
                .filter { it in 1 until data.size }
                .distinct()
                .sorted()
            val writes = splitAt(data, positions)
            if (writes.size >= 2) {
                return DesyncPlan(
                    writes, true, "${lead}disorder → ${writes.size} записей", host,
                    poison, s.poisonDelayMs, ttl1Indices = setOf(0)
                )
            }
            return giveUp("нет точки разбиения для disorder")
        }
        if (s.desync == DesyncMode.DISOOB) {
            val urgent = s.urgentByte ?: return giveUp("не задан OOB-байт")
            val positions = collectPositions(s, data, hello, httpHostRange)
                .filter { it in 1 until data.size }
                .distinct()
                .sorted()
            val writes = splitAt(data, positions)
            if (writes.size >= 2) {
                return DesyncPlan(
                    writes, true, "${lead}disoob → ${writes.size} записей", host,
                    poison, s.poisonDelayMs, urgentByte = urgent and 0xFF,
                    tailFirst = true
                )
            }
            return giveUp("нет точки разбиения для disoob")
        }
        if (s.desync == DesyncMode.FAKE) {
            if (s.fakeTtl <= 0) return giveUp("не задан TTL пустышки")
            if (!isTls || hello == null) return giveUp("fake только для TLS")
            // Пустышка — заведомо безвредное hello с чужим SNI: её разбор
            // фильтром сбивает поиск имени, а до сервера она не доходит из-за
            // малого TTL. Настоящие данные идут следом.
            //
            // Как у эталона (AbstractC0195z0.a): подстава — полноценный
            // ClientHello с ALPN и браузерным набором расширений, а не
            // обрезанный poison-шаблон. poisonHello минимален (4 шифра, без
            // ALPN) и палится отпечатком; buildFakeClientHello ближе к
            // настоящему hello и к тому, что шлёт ZapretYT.
            val dummy = Tls.buildFakeClientHello(s.poisonSni.ifBlank { DEFAULT_POISON_SNI })
            return DesyncPlan(
                listOf(data), true, "${lead}fake ttl=${s.fakeTtl}", host,
                poison, s.poisonDelayMs, fakeTtl = s.fakeTtl, fakeDummy = dummy
            )
        }

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
            // Как у эталона AbstractC0148g.a: рез вставляется в исходный буфер
            // со сдвигом тела (repackRecordInPlace), а не пересобирается.
            // repackRecordAt даёт тот же байтовый образ для одиночного реза,
            // но InPlace доказан тестом побайтового совпадения с ZapretYT.
            val repacked = cutAt?.let { Tls.repackRecordInPlace(data, 0, data.size, it - Tls.RECORD_HEADER) }
                ?: Tls.repackRecords(data, 0, data.size, parts)
            if (repacked != null) {
                // Позиции считаются на ИСХОДНЫХ данных и отображаются вперёд
                // через известный рез.
                //
                // Переразбор SNI после переупаковки здесь не годится: имя после
                // реза лежит на границе записей, а парсер несколько записей не
                // склеивает — вернёт усечённое имя (на практике было «googl????»),
                // из него вычислятся чужая точка и лишний сегмент.
                //
                // Один рез в точке cut вставляет ровно один заголовок: всё
                // правее точки сдвинуто на RECORD_HEADER. Граница, созданная
                // резом, уже рвёт поток в этом месте, поэтому точка, прилипшая
                // к ней на длину заголовка, — артефакт сдвига, а не воля
                // настроек, и вычитается: иначе вместо образа победителя
                // (ровно 2 сегмента) получается 3 с одиноким заголовком.
                val origSplit = collectPositions(s, data, hello, null)
                val split = if (cutAt != null) {
                    origSplit.map { p -> if (p >= cutAt) p + Tls.RECORD_HEADER else p }
                        .filterNot { p -> p > cutAt && p - cutAt <= Tls.RECORD_HEADER }
                } else {
                    // Деление пополам: точек в теле не было, пересчёт идёт по
                    // новым записям как раньше.
                    val hello2 = Tls.parseClientHello(repacked, 0, repacked.size)
                    collectPositions(s, repacked, hello2, null)
                }
                // Границы записей И точки разбиения из настроек — вместе.
                val bounds = Tls.recordBoundaries(repacked, 0, repacked.size)
                val positions = (bounds + split)
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
