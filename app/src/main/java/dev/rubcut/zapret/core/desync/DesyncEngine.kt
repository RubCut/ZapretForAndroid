package dev.rubcut.zapret.core.desync

import dev.rubcut.zapret.core.proto.ClientHelloInfo
import dev.rubcut.zapret.core.proto.Http
import dev.rubcut.zapret.core.proto.Tls
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

        if (s.desync == DesyncMode.NONE) return DesyncPlan.passthrough(payload, "off", host)

        // 1) Переупаковка TLS-записей — аналог --dpi-desync-tlsrec=N
        val wantsTlsRec = s.desync == DesyncMode.TLSREC || s.desync == DesyncMode.MULTISPLIT_TLSREC
        val parts = if (s.tlsrecParts >= 2) s.tlsrecParts else 2
        if (isTls && wantsTlsRec) {
            val repacked = Tls.repackRecords(payload, 0, payload.size, parts)
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
        if (!isTls && !isHttp && !s.anyProtocol) {
            return DesyncPlan.passthrough(payload, "не TLS/HTTP, пропуск", host)
        }

        val raw = collectPositions(s, payload, hello, httpHostRange)
        val positions = raw.filter { it in 1 until payload.size }.distinct().sorted()
        if (positions.isEmpty()) return DesyncPlan.passthrough(payload, "нет точки разбиения", host)

        val single = s.desync == DesyncMode.SPLIT || s.desync == DesyncMode.TLSREC
        val chosen = if (single) listOf(positions.first()) else positions
        val writes = splitAt(payload, chosen)
        if (writes.size < 2) return DesyncPlan.passthrough(payload, "разбиение не удалось", host)

        val label = buildString {
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
                SplitPos.MIDSNI -> when {
                    hello != null -> out += hello.sniStart + (hello.sniEnd - hello.sniStart) / 2
                    httpHostRange != null -> out += httpHostRange.first + (httpHostRange.second - httpHostRange.first) / 2
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

    private fun splitAt(payload: ByteArray, positions: List<Int>): List<ByteArray> {
        val writes = ArrayList<ByteArray>()
        var prev = 0
        for (p in positions.sorted()) {
            if (p <= prev || p >= payload.size) continue
            writes += payload.copyOfRange(prev, p)
            prev = p
        }
        if (prev < payload.size) writes += payload.copyOfRange(prev, payload.size)
        return writes
    }
}
