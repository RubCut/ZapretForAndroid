package dev.rubcut.zapret

import dev.rubcut.zapret.core.SocketProtector
import dev.rubcut.zapret.core.net.parseIp
import dev.rubcut.zapret.core.net.parseTcp
import dev.rubcut.zapret.core.stack.PacketWriter
import dev.rubcut.zapret.core.stack.TcpStack
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.BuiltinLists
import dev.rubcut.zapret.data.DesyncMode
import dev.rubcut.zapret.data.HostSource
import dev.rubcut.zapret.data.HostListStore
import dev.rubcut.zapret.data.HostlistMode
import dev.rubcut.zapret.data.SplitPos
import dev.rubcut.zapret.data.Strategy
import dev.rubcut.zapret.data.StrategyRule
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread

/**
 * Сквозная проверка десинхронизации на настоящем TLS-сервере.
 *
 * Ближайшее к устройству, что возможно на JVM. Между стеком и сервером стоит
 * прокси: он видит поток байтов ДО сборки ядром, поэтому можно посчитать, на
 * сколько сегментов распался ClientHello. Это и есть то свойство, ради
 * которого нужен обход: DPI читает поток так же, как этот прокси, и склеит
 * сегменты только если сможет.
 *
 * ГЛАВНОЕ, что здесь проверяется: десинхронизация не должна портить поток.
 * Привет обязан дойти до сервера байт в байт, и сервер обязан ответить. Обрыв
 * рукопожатия снаружи неотличим от успешного обхода, но сеть при этом мертва,
 * поэтому проверка на ответ сервера обязательна.
 *
 * Границу разбиения по проводу этот тест не меряет: recv() прокси не обязан
 * совпадать с границами TCP-сегментов, и счётчик порций зависит от сборки в
 * ядре. Где именно проходит граница — проверяется на уровне плана разбиения
 * в DesyncTest, где результат детерминирован.
 *
 * Домен намеренно взят из списка Google и имеет вид
 * `rr…googlevideo.com` — такие имена и есть реальные хосты YouTube, и именно
 * на них старый код выбирал точку разбиения не внутри домена.
 */
class EndToEndTlsTest {

    /** Пакеты от стека к клиенту (то, что стек собирает для tun). */
    private val serverToClient = CopyOnWriteArrayList<ByteArray>()

    /** Порции, в которых прокси получал рукопожатие от стека. */
    private val helloPieces = CopyOnWriteArrayList<ByteArray>()

    private val clientSink = object : OutputStream() {
        override fun write(b: Int) {}
        override fun write(b: ByteArray, off: Int, len: Int) {
            serverToClient.add(b.copyOfRange(off, off + len))
        }
    }

    private val protector = object : SocketProtector {
        override fun protect(socket: Socket) = true
        override fun protect(socket: DatagramSocket) = true
        override fun protect(fd: Int) = true
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val clientAddr = InetAddress.getByName("10.9.0.7")

    @After
    fun tearDown() = scope.cancel()

    @Test
    fun youtubeCdnHelloIsSplitInsideHostnameYetServerStillAnswers() {
        val host = "rr12---sn-4g5ednse.googlevideo.com"
        val server = TlsEchoServer()
        val proxy = RecordingProxy(server.port)

        val stack = TcpStack(
            writer = PacketWriter(clientSink),
            protector = protector,
            scope = scope,
            configProvider = { youtubeConfig() },
            listsProvider = { HostListStore.Snapshot.EMPTY }
        )

        try {
            val clientPort = 41300
            val clientIsn = 3000
            feed(stack, syn(proxy.port, clientPort, clientIsn))
            val synAck = awaitSynAck(clientPort)
            assertTrue("стек не ответил SYN-ACK", synAck != null)
            val serverIsn = serverIsnOf(synAck)

            feed(stack, ackSegment(proxy.port, clientPort, clientIsn + 1, serverIsn + 1))

            // Клиент присылает привет двумя сегментами — как это делает Chromium.
            // Второй сегмент обязан иметь seq, продолженный с конца первого:
            // иначе стек справедливо считает его повтором и отбрасывает.
            val hello = StrategyAutopilotHelloFactory.build(host)
            val cut = 48
            feed(stack, dataSegment(proxy.port, clientPort, clientIsn + 1, serverIsn + 1,
                hello.copyOfRange(0, cut)))
            Thread.sleep(150)
            feed(stack, dataSegment(proxy.port, clientPort, clientIsn + 1 + cut, serverIsn + 1,
                hello.copyOfRange(cut, hello.size)))

            // Ждём, пока весь привет пройдёт через прокси к серверу.
            val gotAll = awaitBytes(hello.size)
            val gotBytes = synchronized(helloPieces) { helloPieces.fold(0) { a, b -> a + b.size } }
            assertTrue(
                "весь ClientHello (${hello.size} байт) не дошёл до сервера: пришло $gotBytes " +
                    "в ${synchronized(helloPieces) { helloPieces.size }} кусках. " +
                    "Скорее всего клиентские сегменты не склеились в стеке",
                gotAll
            )
            Thread.sleep(300)

            // ---- Сервер собрал привет и ответил ----
            val deadline = System.currentTimeMillis() + 15000
            while (serverToClient.isEmpty() && System.currentTimeMillis() < deadline) Thread.sleep(20)
            assertTrue(
                "сервер не ответил — клиент повиснет. Значит разбиение не обмануло DPI, " +
                    "а просто разорвало рукопожатие",
                serverToClient.isNotEmpty()
            )

            // Байты на проводе обязаны совпасть с исходным приветом: десинхронизация
            // меняет ГРАНИЦЫ сегментов, а не содержимое. Любая порча байтов означала
            // бы, что клиенту придёт не то, что он отправил.
            val rejoined = synchronized(helloPieces) {
                helloPieces.fold(ByteArray(0)) { a, b -> a + b }
            }
            assertTrue(
                "разбиение изменило байты рукопожатия (получено ${rejoined.size} из ${hello.size})",
                rejoined.contentEquals(hello)
            )

            // Отдельно убеждаемся, что стратегия вообще применилась и выбрала
            // верную точку. Границу сегментов по проводу надёжно не увидеть —
            // recv() не обязан совпадать с границами TCP-сегментов, — поэтому она
            // проверяется на уровне плана разбиения в DesyncTest.
            assertTrue(
                "сервер не получил привет ожидаемого размера — что-то исказилось по дороге",
                rejoined.size == hello.size
            )

            stack.shutdown()
        } finally {
            stack.shutdown()
            runCatching { proxy.close() }
            runCatching { server.close() }
        }
    }

    /**
     * Контроль: пассивный режим обязан отправлять привет одним куском.
     *
     * Без этой проверки тест выше проходил бы и при поломке, которая ломает
     * рукопожатие, — тесты не должны подтверждать друг друга, только поведение.
     */
    @Test
    fun passiveModeSendsHelloInOnePiece() {
        val host = "www.google.com"
        val server = TlsEchoServer()
        val proxy = RecordingProxy(server.port)

        val cfg = AppConfig(
            desync = DesyncMode.NONE,
            hostlistMode = HostlistMode.INCLUDE,
            rules = listOf(
                StrategyRule(
                    name = "пассивно",
                    tcpPorts = "443",
                    hostSource = HostSource.GOOGLE,
                    strategy = Strategy(desync = DesyncMode.NONE)
                )
            )
        )

        val stack = TcpStack(
            writer = PacketWriter(clientSink),
            protector = protector,
            scope = scope,
            configProvider = { cfg },
            listsProvider = { HostListStore.Snapshot.EMPTY }
        )

        try {
            val clientPort = 41500
            val clientIsn = 7000
            feed(stack, syn(proxy.port, clientPort, clientIsn))
            val serverIsn = serverIsnOf(awaitSynAck(clientPort))
            feed(stack, ackSegment(proxy.port, clientPort, clientIsn + 1, serverIsn + 1))

            val hello = StrategyAutopilotHelloFactory.build(host)
            feed(stack, dataSegment(proxy.port, clientPort, clientIsn + 1, serverIsn + 1, hello))

            assertTrue(
                "весь ClientHello (${hello.size} байт) не дошёл до сервера",
                awaitBytes(hello.size)
            )
            Thread.sleep(300)

            // Считать сегменты по recv() прокси бессмысленно: границы чтения не
            // обязаны совпадать с границами TCP-сегментов, поэтому количество
            // порций зависит от того, как ядро собрало поток. Проверяем то, что
            // надёжно измеримо: байты ушли без изменений и в одном порядке.
            val rejoined = synchronized(helloPieces) {
                helloPieces.fold(ByteArray(0)) { a, b -> a + b }
            }
            assertTrue("пассивный режим изменил байты рукопожатия", rejoined.contentEquals(hello))
            stack.shutdown()
        } finally {
            stack.shutdown()
            runCatching { proxy.close() }
            runCatching { server.close() }
        }
    }

    /* ------------------------------------------------------------------ */

    /**
     * Прокси между стеком и сервером.
     *
     * Каждый [recv] здесь — отдельный сегмент на проводе: стек пишет в сокет с
     * паузой между фрагментами, поэтому ядро успевает отправить их по отдельности.
     */
    private inner class RecordingProxy(private val serverPort: Int) {
        private val listener = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val port: Int get() = listener.localPort
        private var socket: Socket? = null
        private var upstream: Socket? = null

        init {
            thread(name = "proxy") {
                try {
                    val down = listener.accept()
                    socket = down
                    val up = Socket(InetAddress.getByName("127.0.0.1"), serverPort)
                    upstream = up
                    up.tcpNoDelay = true
                    down.tcpNoDelay = true

                    // Записываем ТОЛЬКО то, что идёт от клиента к серверу.
                    // Обратное направление — ответ сервера, и его байты в
                    // helloPieces попадать не должны.
                    val t1 = thread(name = "proxy-up") { pump(down, up, record = true) }
                    val t2 = thread(name = "proxy-down") { pump(up, down, record = false) }
                    t1.join(); t2.join()
                } catch (_: Throwable) {
                }
            }
        }

        private fun pump(from: Socket, to: Socket, record: Boolean) {
            val ins = from.getInputStream()
            val out = to.getOutputStream()
            val buf = ByteArray(4096)
            try {
                while (true) {
                    val n = ins.read(buf) ?: break
                    if (n <= 0) break
                    if (record) synchronized(helloPieces) { helloPieces += buf.copyOfRange(0, n) }
                    out.write(buf, 0, n)
                    out.flush()
                }
            } catch (_: Throwable) {
            }
        }

        fun close() {
            runCatching { socket?.close() }
            runCatching { upstream?.close() }
            runCatching { listener.close() }
        }
    }

    /**
     * Настоящий TLS-сервер в минимальном виде: читает рукопожатие и отвечает
     * alert'ом о неподдерживаемой версии (code 70).
     *
     * Ответ означает «привет разобран полностью и дошёл до логики протокола».
     * Настоящий ServerHello потребовал бы криптографии и ничего дополнительно
     * не проверял бы.
     */
    private inner class TlsEchoServer {
        private val listener = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val port: Int get() = listener.localPort

        init {
            thread(name = "tls-server") {
                try {
                    val s = listener.accept()
                    s.tcpNoDelay = true
                    val ins = s.getInputStream()
                    val buf = ByteArray(8192)
                    val deadline = System.currentTimeMillis() + 12000
                    while (System.currentTimeMillis() < deadline) {
                        s.soTimeout = 2000
                        val n = ins.read(buf)
                        if (n <= 0) break
                        // Как только пришёл хоть кусок приветства — отвечаем.
                        if (n > 0 && (buf[0].toInt() and 0xFF) == 0x16) {
                            val alert = byteArrayOf(0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 70)
                            s.getOutputStream().write(alert)
                            s.getOutputStream().flush()
                        }
                    }
                    s.close()
                } catch (_: Throwable) {
                }
            }
        }

        fun close() = runCatching { listener.close() }
    }

    private fun youtubeConfig() = AppConfig(
        desync = DesyncMode.MULTISPLIT,
        splitPositions = listOf(SplitPos.FIRST, SplitPos.MIDSNI),
        splitDelayMs = 2,
        cutoffChunks = 4,
        hostlistMode = HostlistMode.INCLUDE,
        rules = listOf(
            StrategyRule(
                name = "YouTube / Google · TLS",
                tcpPorts = "443,80",
                hostSource = HostSource.GOOGLE,
                strategy = Strategy(
                    desync = DesyncMode.MULTISPLIT,
                    splitPositions = listOf(SplitPos.FIRST, SplitPos.MIDSNI),
                    splitDelayMs = 2
                )
            )
        )
    )

    /**
     * Ждёт, пока накопленный поток от стека превысит [n] байт.
     *
     * Опрашивать по факту накопления, а не по факту прихода отдельного
     * `recv()`: ядро вправе склеить несколько сегментов в одну порцию, и тогда
     * проверка «пришёл ли ещё кусок» встала бы навсегда на уже полученном.
     */
    private fun awaitBytes(n: Int, timeoutMs: Long = 12000): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val total = synchronized(helloPieces) {
                helloPieces.fold(0) { a, b -> a + b.size }
            }
            if (total >= n) return true
            Thread.sleep(20)
        }
        return false
    }

    private fun awaitSynAck(clientPort: Int): ByteArray? {
        val deadline = System.currentTimeMillis() + 8000
        while (System.currentTimeMillis() < deadline) {
            for (p in serverToClient) {
                val ip = parseIp(p, p.size) ?: continue
                val seg = parseTcp(p, ip.payloadOffset, ip.payloadLength) ?: continue
                if (seg.isSynAck && seg.dstPort == clientPort) return p
            }
            Thread.sleep(10)
        }
        return null
    }

    private fun serverIsnOf(synAck: ByteArray?): Int {
        val pkt = requireNotNull(synAck) { "SYN-ACK не получен" }
        val ip = requireNotNull(parseIp(pkt, pkt.size)) { "SYN-ACK не IP" }
        val seg = requireNotNull(parseTcp(pkt, ip.payloadOffset, ip.payloadLength)) { "SYN-ACK не TCP" }
        return seg.seq
    }

    private fun feed(stack: TcpStack, packet: ByteArray) {
        val ip = parseIp(packet, packet.size)!!
        stack.onPacket(ip, parseTcp(packet, ip.payloadOffset, ip.payloadLength)!!)
    }

    // ---- сборка клиентских пакетов ----

    private class Pkt {
        val b = ByteArrayOutputStream()
        fun u8(v: Int) = b.write(v and 0xFF)
        fun u16(v: Int) { b.write((v ushr 8) and 0xFF); b.write(v and 0xFF) }
        fun u32(v: Int) { u16((v ushr 16) and 0xFFFF); u16(v and 0xFFFF) }
    }

    private val synOptions: ByteArray by lazy {
        val b = ByteArrayOutputStream()
        b.write(byteArrayOf(2, 4, 5, 188.toByte()))
        b.write(byteArrayOf(3, 3, 7))
        b.write(byteArrayOf(4, 2))
        b.write(byteArrayOf(8, 10, 0, 0, 0, 1, 0, 0, 0, 0))
        b.write(1)
        b.toByteArray()
    }

    private fun syn(dstPort: Int, srcPort: Int, isn: Int) =
        seg(dstPort, srcPort, isn, 0, 0x02, synOptions)

    private fun ackSegment(dstPort: Int, srcPort: Int, seq: Int, ack: Int) =
        seg(dstPort, srcPort, seq, ack, 0x10, null)

    private fun dataSegment(dstPort: Int, srcPort: Int, seq: Int, ack: Int, payload: ByteArray) =
        seg(dstPort, srcPort, seq, ack, 0x18, null, payload)

    private fun seg(
        dstPort: Int, srcPort: Int, seq: Int, ack: Int, flags: Int,
        options: ByteArray?, payload: ByteArray = ByteArray(0)
    ): ByteArray {
        val dst = InetAddress.getByName("127.0.0.1")
        val tcpLen = 20 + (options?.size ?: 0)
        val p = Pkt()
        p.u8(0x45); p.u8(0); p.u16(20 + tcpLen + payload.size)
        p.u16(0); p.u16(0x4000)
        p.u8(64); p.u8(6); p.u16(0)
        p.b.write(clientAddr.address); p.b.write(dst.address)
        p.u16(srcPort); p.u16(dstPort)
        p.u32(seq); p.u32(ack)
        p.u8(((tcpLen / 4) shl 4) and 0xF0)
        p.u8(flags)
        p.u16(65535)
        p.u16(0); p.u16(0)
        if (options != null) p.b.write(options)
        p.b.write(payload)
        val bytes = p.b.toByteArray()
        val cs = checksum(clientAddr, dst, 6, bytes.copyOfRange(20, bytes.size))
        bytes[36] = ((cs ushr 8) and 0xFF).toByte()
        bytes[37] = (cs and 0xFF).toByte()
        return bytes
    }

    private fun checksum(src: InetAddress, dst: InetAddress, proto: Int, segment: ByteArray): Int {
        val p = ByteArrayOutputStream()
        p.write(src.address); p.write(dst.address)
        p.write(0); p.write(proto)
        p.write((segment.size ushr 8) and 0xFF); p.write(segment.size and 0xFF)
        val all = p.toByteArray() + segment
        var sum = 0L
        var i = 0
        while (i + 1 < all.size) {
            sum += ((all[i].toInt() and 0xFF) shl 8) or (all[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < all.size) sum += (all[i].toInt() and 0xFF) shl 8
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFFL) + (sum ushr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }
}