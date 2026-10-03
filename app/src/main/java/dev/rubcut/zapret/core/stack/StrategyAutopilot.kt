package dev.rubcut.zapret.core.stack

import dev.rubcut.zapret.core.LogManager
import dev.rubcut.zapret.core.LogTag
import dev.rubcut.zapret.core.net.PacketBuilder
import dev.rubcut.zapret.core.net.TcpFlag
import dev.rubcut.zapret.core.net.parseIp
import dev.rubcut.zapret.core.net.parseTcp
import dev.rubcut.zapret.data.DesyncMode
import dev.rubcut.zapret.data.SplitPos
import dev.rubcut.zapret.data.Strategy
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeoutOrNull
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random

/** Результат подбора: человекочитаемое имя, сама стратегия и счёт проверок. */
data class TuneResult(val name: String, val strategy: Strategy, val ok: Int, val total: Int)

/**
 * Автоподбор стратегии обхода.
 *
 * Стратегий много, и «правильная» зависит от конкретного DPI на пути. Подбор
 * работает честно: через собственный TCP-стек прогоняется НАСТОЯЩИЙ TLS
 * ClientHello с SNI проверяемого хоста, к первым байтам применяются
 * кандидаты-стратегии, а успехом считается приход ServerHello (0x16) от
 * сервера. Всё происходит внутри туннеля, поэтому проверяется ровно тот путь,
 * по которому потом пойдёт трафик приложений.
 *
 * Пассивный кандидат идёт первым: если DPI не блокирует без обработки, лучше
 * не обрабатывать вовсе — это быстрее и надёжнее.
 */
class StrategyAutopilot(private val stack: TcpStack) {

    private val portCounter = AtomicInteger(45000)

    companion object {
        val CANDIDATES: List<Pair<String, Strategy>> = listOf(
            "без обработки (прозрачно)" to Strategy(desync = DesyncMode.NONE),
            "multisplit · середина SNI" to Strategy(desync = DesyncMode.MULTISPLIT, splitPositions = listOf(SplitPos.MIDSNI)),
            "multisplit · первый байт" to Strategy(desync = DesyncMode.MULTISPLIT, splitPositions = listOf(SplitPos.FIRST)),
            "multisplit · середина SNI + tlsrec" to Strategy(
                desync = DesyncMode.MULTISPLIT_TLSREC,
                splitPositions = listOf(SplitPos.MIDSNI),
                tlsrecParts = 2
            ),
            "split · середина SNI" to Strategy(desync = DesyncMode.SPLIT, splitPositions = listOf(SplitPos.MIDSNI)),
            "tlsrec · две части" to Strategy(desync = DesyncMode.TLSREC, tlsrecParts = 2),
            "multisplit · конец SNI" to Strategy(desync = DesyncMode.MULTISPLIT, splitPositions = listOf(SplitPos.SNIEND)),
            "multisplit · середина SNI + задержка 40 мс" to Strategy(
                desync = DesyncMode.MULTISPLIT,
                splitPositions = listOf(SplitPos.MIDSNI),
                splitDelayMs = 40
            )
        )
    }

    /**
     * Перебирает кандидатов на [hosts] и возвращает лучшего. null — не подошёл
     * никто (например, хосты вообще недоступны).
     */
    suspend fun tune(
        hosts: List<String>,
        perHostTimeoutMs: Long = 6000,
        lookup: suspend (String) -> InetAddress?
    ): TuneResult? {
        var best: TuneResult? = null
        for ((name, strategy) in CANDIDATES) {
            var ok = 0
            for (host in hosts) {
                val addr = withTimeoutOrNull(5000) { lookup(host) } ?: continue
                if (probe(addr, 443, host, strategy, perHostTimeoutMs)) ok++
            }
            LogManager.i(LogTag.DPI, "Автоподбор: $name → $ok/${hosts.size}")
            if (ok == hosts.size && hosts.isNotEmpty()) return TuneResult(name, strategy, ok, hosts.size)
            if (ok > 0 && (best == null || ok > best.ok)) best = TuneResult(name, strategy, ok, hosts.size)
        }
        return best
    }

    /** Одна проверка: полный рукопожатный цикл через стек с принудительной стратегией. */
    suspend fun probe(
        addr: InetAddress,
        port: Int,
        host: String,
        strategy: Strategy,
        timeoutMs: Long = 6000
    ): Boolean = withTimeoutOrNull(timeoutMs) {
        val clientPort = portCounter.incrementAndGet() and 0xFFFF
        val clientIsn = Random.nextInt()
        val captured = Channel<ByteArray>(Channel.UNLIMITED)
        val tap: (ByteArray) -> Unit = { p -> captured.trySend(p) }
        var result = false
        stack.packetWriter.tap = tap
        stack.forcedStrategy = strategy
        try {
            val syn = clientTcp(addr, clientPort, port, clientIsn, 0, TcpFlag.SYN, options = synOptions())
            feed(syn)

            val synAck = receive(captured, 4000) { p ->
                val ip = parseIp(p, p.size) ?: return@receive false
                val seg = parseTcp(p, ip.payloadOffset, ip.payloadLength) ?: return@receive false
                seg.isSynAck && seg.dstPort == clientPort
            } ?: return@withTimeoutOrNull false
            val saIp = parseIp(synAck, synAck.size)!!
            val sa = parseTcp(synAck, saIp.payloadOffset, saIp.payloadLength)!!
            val serverIsn = sa.seq

            feed(clientTcp(addr, clientPort, port, clientIsn + 1, serverIsn + 1, TcpFlag.ACK))
            val hello = clientHello(host)
            feed(
                clientTcp(
                    addr, clientPort, port, clientIsn + 1, serverIsn + 1,
                    TcpFlag.ACK or TcpFlag.PSH, payload = hello
                )
            )

            val down = receive(captured, timeoutMs) { p ->
                val ip = parseIp(p, p.size) ?: return@receive false
                val seg = parseTcp(p, ip.payloadOffset, ip.payloadLength) ?: return@receive false
                seg.dstPort == clientPort && !seg.isSynAck && seg.payloadLength > 0
            } ?: return@withTimeoutOrNull false

            val ip = parseIp(down, down.size)!!
            val seg = parseTcp(down, ip.payloadOffset, ip.payloadLength)!!
            val first = down[ip.payloadOffset + seg.headerLen].toInt() and 0xFF
            // 0x16 — TLS Handshake: сервер дошёл до ответа на ClientHello.
            // 0x15 (alert) и мусор означают, что обход не сработал.
            result = first == 0x16
        } finally {
            stack.forcedStrategy = null
            stack.packetWriter.tap = null
            runCatching {
                feed(
                    clientTcp(addr, clientPort, port, clientIsn + 1, 0, TcpFlag.RST)
                )
            }
        }
        result
    } ?: false

    /* ------------------------------------------------------------ */

    private suspend fun receive(ch: Channel<ByteArray>, timeoutMs: Long, pred: (ByteArray) -> Boolean): ByteArray? =
        withTimeoutOrNull(timeoutMs) {
            while (true) {
                val p = ch.receive()
                if (pred(p)) return@withTimeoutOrNull p
            }
            @Suppress("UNREACHABLE_CODE")
            null
        }

    private fun feed(packet: ByteArray) {
        val ip = parseIp(packet, packet.size) ?: return
        val seg = parseTcp(packet, ip.payloadOffset, ip.payloadLength) ?: return
        stack.onPacket(ip, seg)
    }

    private val probeSource = InetAddress.getByName("10.9.0.9")

    private fun synOptions(): ByteArray {
        val b = ByteArrayOutputStream()
        b.write(byteArrayOf(2, 4, 5, 188.toByte()))
        b.write(byteArrayOf(3, 3, 7))
        b.write(byteArrayOf(4, 2))
        b.write(1)
        return b.toByteArray()
    }

    private fun clientTcp(
        dst: InetAddress,
        srcPort: Int,
        dstPort: Int,
        seq: Int,
        ack: Int,
        flags: Int,
        options: ByteArray? = null,
        payload: ByteArray = ByteArray(0)
    ): ByteArray {
        val tcpHeaderLen = 20 + (options?.size ?: 0)
        val total = 20 + tcpHeaderLen + payload.size
        val p = ByteArrayOutputStream()
        p.write(0x45); p.write(0)
        p.write((total ushr 8) and 0xFF); p.write(total and 0xFF)
        p.write(0); p.write(0); p.write(0x40); p.write(0)
        p.write(64); p.write(6); p.write(0); p.write(0)
        p.write(probeSource.address)
        p.write(dst.address)
        p.write((srcPort ushr 8) and 0xFF); p.write(srcPort and 0xFF)
        p.write((dstPort ushr 8) and 0xFF); p.write(dstPort and 0xFF)
        p.write(seq ushr 24 and 0xFF); p.write(seq ushr 16 and 0xFF); p.write(seq ushr 8 and 0xFF); p.write(seq and 0xFF)
        p.write(ack ushr 24 and 0xFF); p.write(ack ushr 16 and 0xFF); p.write(ack ushr 8 and 0xFF); p.write(ack and 0xFF)
        p.write(((tcpHeaderLen / 4) shl 4) and 0xF0)
        p.write(flags and 0xFF)
        p.write(65535 ushr 8 and 0xFF); p.write(65535 and 0xFF)
        p.write(0); p.write(0); p.write(0); p.write(0)
        if (options != null) p.write(options)
        p.write(payload)
        val bytes = p.toByteArray()
        val segment = bytes.copyOfRange(20, bytes.size)
        val cs = checksum(probeSource, dst, 6, segment)
        bytes[36] = (cs ushr 8 and 0xFF).toByte()
        bytes[37] = (cs and 0xFF).toByte()
        return bytes
    }

    private fun checksum(src: InetAddress, dst: InetAddress, proto: Int, segment: ByteArray): Int {
        val pseudo = ByteArrayOutputStream()
        pseudo.write(src.address)
        pseudo.write(dst.address)
        pseudo.write(0)
        pseudo.write(proto)
        pseudo.write((segment.size ushr 8) and 0xFF)
        pseudo.write(segment.size and 0xFF)
        val all = pseudo.toByteArray() + segment
        var sum = 0L
        var i = 0
        while (i + 1 < all.size) {
            sum += ((all[i].toInt() and 0xFF) shl 8) or (all[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < all.size) sum += (all[i].toInt() and 0xFF) shl 8
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    /** Минимальный TLS ClientHello с SNI — ровно то, на что смотрит DPI. */
    private fun clientHello(host: String): ByteArray {
        val name = host.toByteArray(Charsets.US_ASCII)
        val ext = ByteArrayOutputStream()
        ext.write(0); ext.write(0)                                  // server_name
        val sniInner = 2 + 1 + 2 + name.size                        // list len + type + name len + name
        ext.write((sniInner ushr 8) and 0xFF); ext.write(sniInner and 0xFF)
        ext.write((sniInner - 2) ushr 8 and 0xFF); ext.write((sniInner - 2) and 0xFF)
        ext.write(0)
        ext.write((name.size ushr 8) and 0xFF); ext.write(name.size and 0xFF)
        ext.write(name)

        val body = ByteArrayOutputStream()
        body.write(3); body.write(3)                                // TLS 1.2
        body.write(ByteArray(32) { 7 })                             // random
        body.write(0)                                               // session id
        body.write(0); body.write(2); body.write(0x13); body.write(0x01)   // cipher suites
        body.write(1); body.write(0)                                // compression
        body.write((ext.size() ushr 8) and 0xFF); body.write(ext.size() and 0xFF)
        body.write(ext.toByteArray())
        val bodyBytes = body.toByteArray()
        val hs = ByteArrayOutputStream()
        hs.write(1)                                                 // client_hello
        hs.write((bodyBytes.size ushr 16) and 0xFF)
        hs.write((bodyBytes.size ushr 8) and 0xFF)
        hs.write(bodyBytes.size and 0xFF)
        hs.write(bodyBytes)
        val hsBytes = hs.toByteArray()

        val rec = ByteArrayOutputStream()
        rec.write(0x16); rec.write(3); rec.write(1)
        rec.write((hsBytes.size ushr 8) and 0xFF); rec.write(hsBytes.size and 0xFF)
        rec.write(hsBytes)
        return rec.toByteArray()
    }
}
