package dev.rubcut.zapret

import dev.rubcut.zapret.core.SocketProtector
import dev.rubcut.zapret.core.net.parseIp
import dev.rubcut.zapret.core.net.parseTcp
import dev.rubcut.zapret.core.stack.PacketWriter
import dev.rubcut.zapret.core.stack.TcpStack
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.HostListStore
import dev.rubcut.zapret.data.HostSource
import dev.rubcut.zapret.data.HostlistMode
import dev.rubcut.zapret.data.DesyncMode
import dev.rubcut.zapret.data.SplitPos
import dev.rubcut.zapret.data.Strategy
import dev.rubcut.zapret.data.StrategyRule
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.After
import org.junit.Assert.assertNotNull
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
 * Сборка рукопожатия: что происходит, когда клиент прислал неполный ClientHello.
 *
 * Отдельный класс, потому что проверяет граничный случай, который легко
 * упустить: клиент отправил часть рукопожатия и замолчал. Соединение в этом
 * случае обязано закрыться само, а не висеть до общей проверки простоя (минуты)
 * — иначе приложение выглядит «зависшим намертво».
 */
class HandshakeAssemblyTimeoutTest {

    private val toClient = CopyOnWriteArrayList<ByteArray>()
    private val sink = object : OutputStream() {
        override fun write(b: Int) {}
        override fun write(b: ByteArray, off: Int, len: Int) {
            toClient.add(b.copyOfRange(off, off + len))
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

    /**
     * Клиент прислал половину ClientHello и перестал присылать.
     *
     * Ожидание: соединение закрывается за разумное время, а не висит.
     * Проверяем, что стек перестал считать соединение активным.
     */
    @Test
    fun truncatedHandshakeDoesNotHangForever() {
        val upstream = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        // Сервер держит соединение открытым и ничего не отвечает.
        thread(name = "silent-server") {
            runCatching {
                val s = upstream.accept()
                Thread.sleep(20000)
                s.close()
            }
        }

        val cfg = AppConfig(
            desync = DesyncMode.MULTISPLIT,
            splitPositions = listOf(SplitPos.FIRST, SplitPos.MIDSNI),
            cutoffChunks = 8,
            hostlistMode = HostlistMode.INCLUDE,
            rules = listOf(
                StrategyRule(
                    name = "YouTube",
                    tcpPorts = "443",
                    hostSource = HostSource.GOOGLE,
                    strategy = Strategy(
                        desync = DesyncMode.MULTISPLIT,
                        splitPositions = listOf(SplitPos.FIRST, SplitPos.MIDSNI)
                    )
                )
            )
        )
        val stack = TcpStack(
            writer = PacketWriter(sink),
            protector = protector,
            scope = scope,
            configProvider = { cfg },
            listsProvider = { HostListStore.Snapshot.EMPTY }
        )

        try {
            val clientPort = 41700
            val clientIsn = 9000
            feed(stack, syn(upstream.localPort, clientPort, clientIsn))
            val serverIsn = serverIsnOf(awaitSynAck(clientPort))
            feed(stack, ackSegment(upstream.localPort, clientPort, clientIsn + 1, serverIsn + 1))

            // Ровно половина настоящего приветствия — TLS-запись обрывается.
            val hello = StrategyAutopilotHelloFactory.build("rr12---sn-4g5ednse.googlevideo.com")
            feed(stack, dataSegment(upstream.localPort, clientPort, clientIsn + 1, serverIsn + 1,
                hello.copyOfRange(0, hello.size / 2)))

            // Дальше клиент не присылает ничего. Соединение должно закрыться.
            val deadline = System.currentTimeMillis() + 20000
            while (stack.activeCount > 0 && System.currentTimeMillis() < deadline) Thread.sleep(100)

            assertTrue(
                "соединение с неполным рукопожатием должно закрыться само, " +
                    "иначе приложение выглядит зависшим; прошло ${20 - (deadline - System.currentTimeMillis()) / 1000} с",
                stack.activeCount == 0
            )
            stack.shutdown()
        } finally {
            stack.shutdown()
            runCatching { upstream.close() }
        }
    }

    /**
     * Контроль: полное рукопожатие в тех же условиях соединение НЕ закрывает.
     *
     * Без этой проверки тест выше проходил бы и при поломке, где стек закрывает
     * вообще всё, — тесты должны подтверждать поведение, а не друг друга.
     */
    @Test
    fun completeHandshakeKeepsConnectionAlive() {
        val upstream = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        thread(name = "silent-server-2") {
            runCatching {
                val s = upstream.accept()
                val buf = ByteArray(8192)
                s.soTimeout = 6000
                runCatching { while (s.getInputStream().read(buf) > 0) { } }
                Thread.sleep(3000)
                s.close()
            }
        }

        val cfg = AppConfig(
            desync = DesyncMode.NONE,
            hostlistMode = HostlistMode.INCLUDE
        )
        val stack = TcpStack(
            writer = PacketWriter(sink),
            protector = protector,
            scope = scope,
            configProvider = { cfg },
            listsProvider = { HostListStore.Snapshot.EMPTY }
        )

        try {
            val clientPort = 41800
            val clientIsn = 11000
            feed(stack, syn(upstream.localPort, clientPort, clientIsn))
            val serverIsn = serverIsnOf(awaitSynAck(clientPort))
            feed(stack, ackSegment(upstream.localPort, clientPort, clientIsn + 1, serverIsn + 1))

            val hello = StrategyAutopilotHelloFactory.build("www.youtube.com")
            feed(stack, dataSegment(upstream.localPort, clientPort, clientIsn + 1, serverIsn + 1, hello))

            Thread.sleep(2500)
            assertTrue(
                "полное рукопожатие не должно приводить к закрытию соединения",
                stack.activeCount == 1
            )
            stack.shutdown()
        } finally {
            stack.shutdown()
            runCatching { upstream.close() }
        }
    }

    /* ------------------------------------------------------------------ */

    private fun awaitSynAck(clientPort: Int): ByteArray? {
        val deadline = System.currentTimeMillis() + 8000
        while (System.currentTimeMillis() < deadline) {
            for (p in toClient) {
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
        val ip = requireNotNull(parseIp(pkt, pkt.size))
        val seg = requireNotNull(parseTcp(pkt, ip.payloadOffset, ip.payloadLength))
        return seg.seq
    }

    private fun feed(stack: TcpStack, packet: ByteArray) {
        val ip = parseIp(packet, packet.size)!!
        stack.onPacket(ip, parseTcp(packet, ip.payloadOffset, ip.payloadLength)!!)
    }

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