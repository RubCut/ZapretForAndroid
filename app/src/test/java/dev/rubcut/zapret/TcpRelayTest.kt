package dev.rubcut.zapret

import dev.rubcut.zapret.core.SocketProtector
import dev.rubcut.zapret.core.dns.DnsMessage
import dev.rubcut.zapret.core.dns.DnsType
import dev.rubcut.zapret.core.net.Checksum
import dev.rubcut.zapret.core.net.PacketBuilder
import dev.rubcut.zapret.core.net.TcpFlag
import dev.rubcut.zapret.core.net.getU16
import dev.rubcut.zapret.core.net.parseIp
import dev.rubcut.zapret.core.net.parseTcp
import dev.rubcut.zapret.core.net.parseUdp
import dev.rubcut.zapret.core.stack.PacketWriter
import dev.rubcut.zapret.core.stack.TcpStack
import dev.rubcut.zapret.core.stack.UdpStack
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.HostListStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread

/**
 * Интеграционный тест пользовательского TCP/IP-стека.
 *
 * Прогоняет ПОЛНОЕ соединение через [TcpStack] ровно так, как это делает туннель:
 * синтетические пакеты клиента подаются на вход, а всё, что стек пишет в «tun»
 (здесь — собирающий OutputStream), проверяется по байтам, включая контрольные
 * суммы независимым эталоном. Upstream-сторона — настоящий локальный сервер,
 * поэтому тест ловит и поломку рукопожатия, и поломку релея данных в любую сторону.
 *
 * Именно этот класс должен был поймать ошибку псевдозаголовка IPv4 и потерю
 * первого UDP-пакета до того, как они доехали до устройства.
 */
class TcpRelayTest {

    private val packets = CopyOnWriteArrayList<ByteArray>()

    private val sink = object : OutputStream() {
        override fun write(b: Int) {}
        override fun write(b: ByteArray, off: Int, len: Int) {
            packets.add(b.copyOfRange(off, off + len))
        }
    }

    private val writer = PacketWriter(sink)

    private val protector = object : SocketProtector {
        override fun protect(socket: Socket): Boolean = true
        override fun protect(socket: DatagramSocket): Boolean = true
        override fun protect(fd: Int): Boolean = true
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val config = AppConfig()

    private val clientAddr = InetAddress.getByName("10.9.0.7")

    /* ------------------------------------------------------------ */
    /*  Вспомогательное                                              */
    /* ------------------------------------------------------------ */

    private fun awaitPacket(timeoutMs: Long = 8000, pred: (ByteArray) -> Boolean): ByteArray {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            for (p in packets) {
                if (pred(p)) {
                    packets.remove(p)
                    return p
                }
            }
            Thread.sleep(10)
        }
        throw AssertionError("не дождались пакета от стека за $timeoutMs мс")
    }

    /** Эталонная контрольная сумма TCP/UDP, написанная независимо от боевого кода. */
    private fun referenceChecksum(src: InetAddress, dst: InetAddress, proto: Int, segment: ByteArray): Int {
        val pseudo = ByteArrayOutputStream()
        pseudo.write(src.address)
        pseudo.write(dst.address)
        if (src.address.size == 4) {
            pseudo.write(0)
            pseudo.write(proto)
        } else {
            val l = segment.size
            pseudo.write(byteArrayOf((l ushr 24).toByte(), (l ushr 16).toByte(), (l ushr 8).toByte(), l.toByte()))
            pseudo.write(byteArrayOf(0, 0, 0, proto.toByte()))
        }
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

    /**
     * Проверка суммы пакета: однодополнительная сумма псевдозаголовка и сегмента
     * ВМЕСТЕ с заполненным полем контрольной суммы обязана давать 0xFFFF, то есть
     * ~sum == 0. Ненулевой результат означает повреждённый или неверно собранный
     * пакет.
     */
    private fun assertChecksumsValid(packet: ByteArray) {
        val ip = parseIp(packet, packet.size)!!
        val seg = packet.copyOfRange(ip.payloadOffset, ip.payloadOffset + ip.payloadLength)
        val proto = if (ip.isTcp) 6 else 17
        val verified = referenceChecksum(ip.src, ip.dst, proto, seg)
        assertEquals(
            "контрольная сумма сегмента неверна (поле=${
                getU16(packet, ip.payloadOffset + if (ip.isTcp) 16 else 6)
            })",
            0, verified
        )
    }

    private class Pkt {
        val b = ByteArrayOutputStream()
        fun u8(v: Int) = b.write(v and 0xFF)
        fun u16(v: Int) {
            b.write((v ushr 8) and 0xFF)
            b.write(v and 0xFF)
        }
        fun u32(v: Int) {
            u16((v ushr 16) and 0xFFFF)
            u16(v and 0xFFFF)
        }
        fun bytes(a: ByteArray) = b.write(a)
    }

    /** Пакет клиента IPv4+TCP с корректной контрольной суммой. */
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
        val p = Pkt()
        p.u8(0x45); p.u8(0)
        p.u16(total)
        p.u16(0); p.u16(0x4000)
        p.u8(64); p.u8(6)
        p.u16(0)
        p.bytes(clientAddr.address)
        p.bytes(dst.address)
        p.u16(srcPort); p.u16(dstPort)
        p.u32(seq); p.u32(ack)
        p.u8(((tcpHeaderLen / 4) shl 4) and 0xF0)
        p.u8(flags and 0xFF)
        p.u16(65535)
        p.u16(0); p.u16(0)
        if (options != null) p.bytes(options)
        p.bytes(payload)
        val bytes = p.b.toByteArray()
        val cs = referenceChecksum(clientAddr, dst, 6, bytes.copyOfRange(20, bytes.size))
        bytes[36] = (cs ushr 8 and 0xFF).toByte()
        bytes[37] = (cs and 0xFF).toByte()
        return bytes
    }

    private fun clientUdp(dst: InetAddress, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val p = Pkt()
        p.u8(0x45); p.u8(0)
        p.u16(20 + udpLen)
        p.u16(0); p.u16(0x4000)
        p.u8(64); p.u8(17)
        p.u16(0)
        p.bytes(clientAddr.address)
        p.bytes(dst.address)
        p.u16(srcPort); p.u16(dstPort)
        p.u16(udpLen)
        p.u16(0)
        p.bytes(payload)
        val bytes = p.b.toByteArray()
        val cs = referenceChecksum(clientAddr, dst, 17, bytes.copyOfRange(20, bytes.size))
        bytes[26] = (cs ushr 8 and 0xFF).toByte()
        bytes[27] = (cs and 0xFF).toByte()
        return bytes
    }

    private val synOptions: ByteArray by lazy {
        val b = ByteArrayOutputStream()
        b.write(byteArrayOf(2, 4, 5, 188.toByte()))                          // MSS 1460
        b.write(byteArrayOf(3, 3, 7))                               // wscale 7
        b.write(byteArrayOf(4, 2))                                  // SACK permitted
        b.write(byteArrayOf(8, 10, 0, 0, 0, 1, 0, 0, 0, 0))         // timestamps
        b.write(1)                                                  // NOP → 20 байт, кратно 4
        b.toByteArray()
    }

    private fun feed(stack: TcpStack, packet: ByteArray) {
        val ip = parseIp(packet, packet.size)!!
        stack.onPacket(ip, parseTcp(packet, ip.payloadOffset, ip.payloadLength)!!)
    }

    /* ------------------------------------------------------------ */
    /*  Тесты                                                        */
    /* ------------------------------------------------------------ */

    @Test
    fun tcpPassiveRelayWorksBothWays() {
        val server = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
        val received = ByteArrayOutputStream()
        val lock = Object()
        var serverError: Throwable? = null
        val serverThread = thread(name = "test-upstream") {
            try {
                val s = server.accept()
                s.tcpNoDelay = true
                val ins = s.getInputStream()
                val buf = ByteArray(4096)
                while (true) {
                    val n = ins.read(buf)
                    if (n < 0) break
                    synchronized(lock) {
                        received.write(buf, 0, n)
                        lock.notifyAll()
                    }
                    if (received.toString("UTF-8").contains("\r\n\r\n")) break
                }
                s.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".toByteArray())
                s.getOutputStream().flush()
                Thread.sleep(1500)
                s.close()
            } catch (t: Throwable) {
                serverError = t
            }
        }

        try {
            val stack = TcpStack(
                writer = writer,
                protector = protector,
                scope = scope,
                configProvider = { config },
                listsProvider = { HostListStore.Snapshot.EMPTY }
            )

            val dst = InetAddress.getByName("127.0.0.1")
            val port = server.localPort
            val clientPort = 41000
            val clientIsn = 1000

            feed(stack, clientTcp(dst, clientPort, port, clientIsn, 0, TcpFlag.SYN, options = synOptions))

            val synAck = awaitPacket { p ->
                val ip = parseIp(p, p.size) ?: return@awaitPacket false
                val seg = parseTcp(p, ip.payloadOffset, ip.payloadLength) ?: return@awaitPacket false
                seg.isSynAck && seg.dstPort == clientPort
            }
            assertChecksumsValid(synAck)
            val saIp = parseIp(synAck, synAck.size)!!
            val sa = parseTcp(synAck, saIp.payloadOffset, saIp.payloadLength)!!
            assertEquals("SYN-ACK должен подтверждать SYN клиента", clientIsn + 1, sa.ack)
            assertEquals(dst, saIp.src)
            assertTrue("SYN-ACK обязан нести MSS", sa.mss in 536..1460)
            val serverIsn = sa.seq

            feed(stack, clientTcp(dst, clientPort, port, clientIsn + 1, serverIsn + 1, TcpFlag.ACK))
            val request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
            feed(stack, clientTcp(dst, clientPort, port, clientIsn + 1, serverIsn + 1, TcpFlag.ACK or TcpFlag.PSH, payload = request))

            synchronized(lock) {
                var waited = 0L
                while (received.size() < request.size && waited < 8000) {
                    lock.wait(50)
                    waited += 50
                }
            }
            serverError?.let { throw AssertionError("upstream-сервер упал: $it") }
            assertArrayEquals("запрос клиента дошёл до сервера искажённым", request, received.toByteArray())

            val down = ByteArrayOutputStream()
            val deadline = System.currentTimeMillis() + 8000
            while (down.size() < 5 && System.currentTimeMillis() < deadline) {
                for (p in packets.toList()) {
                    val ip = parseIp(p, p.size) ?: continue
                    val seg = parseTcp(p, ip.payloadOffset, ip.payloadLength) ?: continue
                    if (seg.dstPort == clientPort && !seg.isSynAck && seg.payloadLength > 0) {
                        assertChecksumsValid(p)
                        down.write(p, ip.payloadOffset + seg.headerLen, seg.payloadLength)
                        packets.remove(p)
                    }
                }
                Thread.sleep(10)
            }
            val body = down.toString("UTF-8")
            assertTrue("ответ сервера не дошёл до клиента (получено: «${body.take(64)}»)", body.startsWith("HTTP/1.1 200 OK"))
            assertTrue("тело ответа потеряно", body.contains("hello"))

            stack.shutdown()
        } finally {
            runCatching { server.close() }
            serverThread.join(2000)
            scope.cancel()
        }
    }

    @Test
    fun udpFirstPacketIsNotLost() {
        val udpServer = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val got = CopyOnWriteArrayList<String>()
        val t = thread(name = "test-udp") {
            try {
                val p = DatagramPacket(ByteArray(2048), 2048)
                udpServer.receive(p)
                got.add(String(p.data, 0, p.length))
                udpServer.send(DatagramPacket("pong".toByteArray(), 4, p.address, p.port))
            } catch (_: Exception) {
            }
        }

        try {
            val stack = UdpStack(
                writer = writer,
                protector = protector,
                configProvider = { config },
                listsProvider = { HostListStore.Snapshot.EMPTY }
            )
            val dst = InetAddress.getByName("127.0.0.1")
            val pkt = clientUdp(dst, 42000, udpServer.localPort, "ping".toByteArray())
            val ip = parseIp(pkt, pkt.size)!!
            stack.onPacket(ip, parseUdp(pkt, ip.payloadOffset, ip.payloadLength)!!)

            val deadline = System.currentTimeMillis() + 8000
            while (got.isEmpty() && System.currentTimeMillis() < deadline) Thread.sleep(10)
            assertEquals("первый UDP-пакет сессии потерян", listOf("ping"), got.toList())

            val reply = awaitPacket { p ->
                val i2 = parseIp(p, p.size) ?: return@awaitPacket false
                val d = parseUdp(p, i2.payloadOffset, i2.payloadLength) ?: return@awaitPacket false
                d.dstPort == 42000 && d.payloadLength == 4
            }
            assertChecksumsValid(reply)
            val i2 = parseIp(reply, reply.size)!!
            val d = parseUdp(reply, i2.payloadOffset, i2.payloadLength)!!
            assertEquals("pong", String(reply, i2.payloadOffset + 8, d.payloadLength))
            stack.shutdown()
        } finally {
            runCatching { udpServer.close() }
            t.join(2000)
            scope.cancel()
        }
    }

    @Test
    fun emittedPacketsCarryValidChecksums() {
        val src = InetAddress.getByName("198.51.100.7")
        val dst = InetAddress.getByName("203.0.113.9")
        val pkt = PacketBuilder.tcp(
            v6 = false, src = src, dst = dst, srcPort = 443, dstPort = 51000,
            seq = 77, ack = 88, flags = TcpFlag.ACK or TcpFlag.PSH, window = 65535,
            payload = "probe".toByteArray(), payloadOff = 0, payloadLen = 5
        )
        assertChecksumsValid(pkt)

        val udp = PacketBuilder.udp(
            v6 = false, src = src, dst = dst, srcPort = 53, dstPort = 51001,
            payload = byteArrayOf(1, 2, 3, 4, 5, 6, 7)
        )
        assertChecksumsValid(udp)

        val v6 = PacketBuilder.tcp(
            v6 = true,
            src = InetAddress.getByName("2001:db8::1"),
            dst = InetAddress.getByName("2001:db8::2"),
            srcPort = 443, dstPort = 51002,
            seq = 1, ack = 2, flags = TcpFlag.ACK, window = 65535
        )
        assertChecksumsValid(v6)
    }

    @Test
    fun checksumClassMatchesReference() {
        val rnd = java.util.Random(42)
        repeat(2000) {
            val n = rnd.nextInt(64)
            val b = ByteArray(n)
            rnd.nextBytes(b)
            val cs = Checksum()
            var i = 0
            while (i < n) {
                val k = minOf(1 + rnd.nextInt(7), n - i)
                cs.update(b, i, k)
                i += k
            }
            val padded = if (n % 2 == 1) b + 0 else b
            var sum = 0L
            for (j in padded.indices step 2) {
                sum += ((padded[j].toInt() and 0xFF) shl 8) or (padded[j + 1].toInt() and 0xFF)
            }
            while ((sum ushr 16) != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
            assertEquals((sum.inv() and 0xFFFF).toInt(), cs.value())
        }
    }

    @Test
    fun dnsCodecRoundTrip() {
        val q = DnsMessage.buildQuery(0x1234, "example.com", DnsType.A)
        val parsed = DnsMessage.parseQuery(q, q.size)
        assertNotNull(parsed)
        assertEquals("example.com", parsed!!.name)
        assertEquals(DnsType.A, parsed.type)

        val resp = DnsMessage.buildAddressResponse(parsed, listOf(InetAddress.getByName("93.184.216.34")), 60)
        assertEquals(0, DnsMessage.rcode(resp, resp.size))
        val addrs = DnsMessage.parseAddresses(resp, resp.size)
        assertEquals(listOf(InetAddress.getByName("93.184.216.34")), addrs)
    }
}
