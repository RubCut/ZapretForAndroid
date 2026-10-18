package dev.rubcut.zapret

import dev.rubcut.zapret.core.net.parseIp
import dev.rubcut.zapret.core.net.parseUdp
import dev.rubcut.zapret.core.stack.PacketWriter
import dev.rubcut.zapret.core.stack.UdpFakes
import dev.rubcut.zapret.core.stack.UdpStack
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.HostListStore
import dev.rubcut.zapret.data.UdpMode
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * Приманки UDP — аналог `--dpi-desync=fake` для UDP в zapret.
 *
 * Перед первым настоящим пакетом сессии уходит подставной QUIC Initial
 * с безобидным SNI: фильтр расшифровывает его, относит поток к разрешённым
 * и перестаёт трогать настоящие пакеты. Приманка отправляется с того же
 * сокета, что и поток, поэтому root не нужен.
 *
 * Проверяем три обещания: приманок ровно сколько в zapret-профиле (11 для
 * QUIC, 6 для голоса), настоящий пакет идёт строго после них, и без флага
 * `fakeUdp` стек ведёт себя как раньше.
 */
class UdpFakeTest {

    private val sink = object : OutputStream() {
        override fun write(b: Int) {}
        override fun write(b: ByteArray, off: Int, len: Int) {}
    }
    private val protector = object : dev.rubcut.zapret.core.SocketProtector {
        override fun protect(socket: Socket) = true
        override fun protect(socket: DatagramSocket) = true
        override fun protect(fd: Int) = true
    }

    private val clientAddr = InetAddress.getByName("10.9.0.7")

    /** Маркеры: по ним приманку легко отличить от настоящего пакета. */
    private val quicFake = ByteArray(64) { 0xAA.toByte() }.also { it[0] = 0xC3.toByte() }
    private val discordFake = ByteArray(48) { 0xBB.toByte() }.also { it[0] = 0xC3.toByte() }

    /** Настоящий QUIC Initial: long header (0x80) + fixed bit, форма RFC 9000. */
    private fun quicInitial(): ByteArray = ByteArray(1200) { 0x11 }.also {
        it[0] = 0xC3.toByte()
        it[1] = 0x01
    }

    /** Short header (1-RTT) — уже установленное соединение. */
    private fun shortHeader(): ByteArray = ByteArray(200) { 0x22 }.also { it[0] = 0x41 }

    @Test
    fun quicInitialIsRelayedWithDecoys() {
        // blockQuic=true — приманки обязаны его перевесить: поток, который
        // иначе бы отбросили, уходит в сеть, чтобы фильтр увидел приманку.
        val server = newServer()
        val stack = newStack(
            AppConfig(blockQuic = true, fakeUdp = true, udpMode = UdpMode.RELAY),
            quicPort = server.localPort
        )
        try {
            val real = quicInitial()
            send(stack, server.localPort, real)
            val got = receive(server, expected = 12)
            assertEquals("11 приманок и настоящий Initial", 12, got.size)
            repeat(11) { i ->
                assertArrayEquals("приманка №${i + 1} не совпала с шаблоном", quicFake, got[i])
            }
            assertArrayEquals("после приманок обязан идти настоящий пакет", real, got[11])
        } finally {
            stack.shutdown()
            server.close()
        }
    }

    @Test
    fun discordVoicePortGetsItsDecoys() {
        val (server, port) = newVoiceServer()
        val stack = newStack(AppConfig(blockQuic = true, fakeUdp = true, udpMode = UdpMode.RELAY))
        try {
            val real = ByteArray(60) { 0x33 }
            send(stack, port, real)
            val got = receive(server, expected = 7)
            assertEquals("6 приманок и настоящий пакет", 7, got.size)
            repeat(6) { i ->
                assertArrayEquals("приманка голоса №${i + 1} не совпала с шаблоном", discordFake, got[i])
            }
            assertArrayEquals("после приманок обязан идти настоящий пакет", real, got[6])
        } finally {
            stack.shutdown()
            server.close()
        }
    }

    @Test
    fun withoutFlagNothingIsSent() {
        val server = newServer()
        val stack = newStack(
            AppConfig(blockQuic = false, fakeUdp = false, udpMode = UdpMode.RELAY),
            quicPort = server.localPort
        )
        try {
            val real = quicInitial()
            send(stack, server.localPort, real)
            // Ждём на один пакет больше, чем приходит: лишние — это приманки.
            val got = receive(server, expected = 2, timeoutMs = 500)
            assertEquals("без флага должен прийти только настоящий пакет", 1, got.size)
            assertArrayEquals(real, got[0])
        } finally {
            stack.shutdown()
            server.close()
        }
    }

    @Test
    fun shortHeaderIsNotDecoyed() {
        val server = newServer()
        val stack = newStack(
            AppConfig(blockQuic = true, fakeUdp = true, udpMode = UdpMode.RELAY),
            quicPort = server.localPort
        )
        try {
            val real = shortHeader()
            send(stack, server.localPort, real)
            val got = receive(server, expected = 2, timeoutMs = 500)
            assertEquals("перед 1-RTT приманка не положена", 1, got.size)
            assertArrayEquals(real, got[0])
        } finally {
            stack.shutdown()
            server.close()
        }
    }

    @Test
    fun missingTemplateKeepsQuicBlocked() {
        // Сборка без шаблонов: приманку положить нечем, и прежняя защита
        // обязана вернуться — Initial блокируется, сессия не создаётся.
        val stack = UdpStack(
            writer = PacketWriter(sink),
            protector = protector,
            configProvider = { AppConfig(blockQuic = true, fakeUdp = true, udpMode = UdpMode.RELAY) },
            listsProvider = { HostListStore.Snapshot.EMPTY },
            udpFakes = UdpFakes(quic = null, discord = null)
        )
        try {
            val before = stack.activeCount
            send(stack, 443, quicInitial())
            Thread.sleep(80)
            assertEquals("без шаблона QUIC обязан остаться блокированным", before, stack.activeCount)
        } finally {
            stack.shutdown()
        }
    }

    private fun newStack(cfg: AppConfig, quicPort: Int = 443) = UdpStack(
        writer = PacketWriter(sink),
        protector = protector,
        configProvider = { cfg },
        listsProvider = { HostListStore.Snapshot.EMPTY },
        udpFakes = UdpFakes(quic = quicFake, discord = discordFake),
        quicPort = quicPort
    )

    private fun newServer(): DatagramSocket =
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).apply { soTimeout = 2000 }

    /**
     * Сервер на свободном голосовом порту Discord (50000-50100). Именно эти
     * порты пригодны для живого теста: они выше 1024, привязать их можно без
     * root — в отличие от 443, для которого в стеке есть отдельная огласка
     * `quicPort`.
     */
    private fun newVoiceServer(): Pair<DatagramSocket, Int> {
        val loopback = InetAddress.getByName("127.0.0.1")
        for (port in 50000..50100) {
            try {
                return DatagramSocket(port, loopback) to port
            } catch (_: Exception) {
                // занят — пробуем следующий
            }
        }
        throw IllegalStateException("нет свободного голосового порта из 50000..50100")
    }

    /**
     * Собирает до [expected] датаграмм с серверного сокета; если за
     * [timeoutMs] пришло меньше — возвращает что успело.
     */
    private fun receive(server: DatagramSocket, expected: Int, timeoutMs: Int = 1500): List<ByteArray> {
        val got = mutableListOf<ByteArray>()
        val deadline = System.currentTimeMillis() + timeoutMs
        while (got.size < expected) {
            val left = (deadline - System.currentTimeMillis()).toInt()
            if (left <= 0) break
            server.soTimeout = left
            val packet = DatagramPacket(ByteArray(4096), 4096)
            try {
                server.receive(packet)
            } catch (_: SocketTimeoutException) {
                break
            }
            got.add(packet.data.copyOf(packet.length))
        }
        return got
    }

    private fun send(stack: UdpStack, dstPort: Int, payload: ByteArray) {
        val dst = InetAddress.getByName("127.0.0.1")
        val pkt = udpPacket(dst, dstPort, payload)
        val ip = parseIp(pkt, pkt.size)!!
        stack.onPacket(ip, parseUdp(pkt, ip.payloadOffset, ip.payloadLength)!!)
    }

    private fun udpPacket(dst: InetAddress, dstPort: Int, payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val p = ByteArrayOutputStream()
        fun u8(v: Int) = p.write(v and 0xFF)
        fun u16(v: Int) { p.write((v ushr 8) and 0xFF); p.write(v and 0xFF) }
        u8(0x45); u8(0); u16(20 + udpLen)
        u16(0); u16(0x4000)
        u8(64); u8(17); u16(0)
        p.write(clientAddr.address); p.write(dst.address)
        u16(41000); u16(dstPort)
        u16(udpLen); u16(0)
        p.write(payload)
        return p.toByteArray()
    }
}
