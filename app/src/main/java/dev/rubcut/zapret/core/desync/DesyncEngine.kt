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
    val host: String?
) {
    val segmentCount: Int get() = writes.size

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
                hello != null -> Tls.mixCaseInSld(data, hello.sniStart, hello.sniEnd, hello.sni)
                httpHostRange != null -> Http.mixCaseInHost(
                    data, httpHostRange.first, httpHostRange.second
                )
                else -> null
            }
            if (rewritten != null) {
                data = rewritten
                mixed = true
            }
        }

        // Смена регистра — самостоятельный приём, а не часть разбиения, поэтому
        // работает и при выключенном десинхронизме. Дальше любая ветка, где
        // разбить нечего, обязана отдать изменённые байты целиком, иначе приём
        // молча потеряется.
        fun giveUp(reason: String) =
            if (mixed) DesyncPlan(listOf(data), true, "смена регистра в имени хоста", host)
            else DesyncPlan.passthrough(payload, reason, host)

        if (s.desync == DesyncMode.NONE) return giveUp("off")

        // 1) Переупаковка TLS-записей — аналог --dpi-desync-tlsrec=N
        val wantsTlsRec = s.desync == DesyncMode.TLSREC || s.desync == DesyncMode.MULTISPLIT_TLSREC
        val parts = if (s.tlsrecParts >= 2) s.tlsrecParts else 2
        if (isTls && wantsTlsRec) {
            val repacked = Tls.repackRecords(data, 0, data.size, parts)
            if (repacked != null) {
                val bounds = Tls.recordBoundaries(repacked, 0, repacked.size)
                val writes = splitAt(repacked, bounds.filter { it in 1 until repacked.size })
                if (writes.size >= 2) {
                    return DesyncPlan(writes, true, "tlsrec x$parts → ${writes.size} записей", host)
                }
            }
        }

        // 2) hostfakesplit для plaintext HTTP — режем значение заголовка Host
        if (s.desync == DesyncMode.HOSTFAKESPLIT && isHttp && httpHostRange != null) {
            val vs = httpHostRange.first
            val ve = httpHostRange.second
            val positions = linkedSetOf(1, vs, vs + (ve - vs) / 2, ve)
            val writes = splitAt(payload, positions.filter { it in 1 until payload.size }.sorted())
            if (writes.size >= 2) {
                return DesyncPlan(writes, true, "hostfakesplit Host=${host ?: "?"}", host)
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
        val chosen = if (single) listOf(ordered.last()) else ordered
        val writes = splitAt(data, chosen)
        if (writes.size < 2) return giveUp("разбиение не удалось")

        val label = buildString {
            if (mixed) append("смена регистра + ")
            append(if (single) "split" else "multisplit")
            append(" [").append(chosen.joinToString(",")).append("] → ")
            append(writes.size).append(" сегм.")
            if (host != null) append(" sni=").append(host)
        }
        return DesyncPlan(writes, true, label, host)
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
     * сегментом целиком. Поэтому для `split` берётся последняя точка — та, что
     * стоит внутри имени хоста.
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
}
