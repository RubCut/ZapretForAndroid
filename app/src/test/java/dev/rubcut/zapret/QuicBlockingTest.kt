package dev.rubcut.zapret

import dev.rubcut.zapret.core.net.parseIp
import dev.rubcut.zapret.core.net.parseUdp
import dev.rubcut.zapret.core.stack.PacketWriter
import dev.rubcut.zapret.core.stack.UdpStack
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.HostListStore
import dev.rubcut.zapret.data.UdpMode
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Блокировка QUIC.
 *
 * Клиент, ушедший в QUIC, мимо десинхронизации: SNI там зашифрован, и
 * подделать Initial-пакет без root нельзя. Значит задача одна — не дать уйти
 * в QUIC вовсе и вернуть клиент на TCP/443, где split работает.
 *
 * Проверяем, что распознаются ВСЕ формы QUIC Initial, а не только самая
 * распространённая: обфусцированная форма идёт с обнулёнными битами и раньше
 * проходила насквозь.
 */
class QuicBlockingTest {

    private val packets = CopyOnWriteArrayList<ByteArray>()
    private val sink = object : OutputStream() {
        override fun write(b: Int) {}
        override fun write(b: ByteArray, off: Int, len: Int) {
            packets.add(b.copyOfRange(off, off + len))
        }
    }
    private val protector = object : dev.rubcut.zapret.core.SocketProtector {
        override fun protect(socket: Socket) = true
        override fun protect(socket: DatagramSocket) = true
        override fun protect(fd: Int) = true
    }

    private val clientAddr = InetAddress.getByName("10.9.0.7")

    /** Первый байт настоящего QUIC Initial (RFC 9000, без обфускации). */
    private fun quicInitial(): ByteArray {
        val b = ByteArray(1200)
        b[0] = 0xC3.toByte()      // Long header + fixed bit, type=Initial
        b[1] = 0x01               // version 1
        return b
    }

    /**
     * Обфусцированная форма, которую применяют провайдеры: reserved-биты
     * обнулены, но header form (старший бит) остался — иначе пакет перестал бы
     * быть QUIC для получателя.
     */
    private fun quicInitialObfuscated(): ByteArray {
        val b = ByteArray(1200)
        b[0] = 0x83.toByte()      // header form + type=Initial, reserved = 0
        b[1] = 0x01
        return b
    }

    /** Short header (1-RTT) — это уже установленное QUIC-соединение. */
    private fun quicShortHeader(): ByteArray {
        val b = ByteArray(200)
        b[0] = 0x41               // Short header, установлен ключ
        return b
    }

    @Test
    fun plainQuicInitialIsBlocked() {
        assertBlocked(quicInitial(), "обычный QUIC Initial обязан блокироваться")
    }

    @Test
    fun obfuscatedQuicInitialIsBlocked() {
        // Именно этот случай проскакивал: проверялся один бит 0x80 вместо маски 0xC0.
        assertBlocked(quicInitialObfuscated(), "обфусцированный QUIC Initial обязан блокироваться")
    }

    @Test
    fun shortHeaderIsNotBlocked() {
        // Short header — это уже работающее соединение; рвать его нельзя, иначе
        // оборвётся видео, которое по какой-то причине пошло по QUIC.
        val stack = newStack(AppConfig(blockQuic = true))
        try {
            val passed = send(stack, quicShortHeader())
            assertTrue("1-RTT пакеты не должны блокироваться — это разорвёт соединение", passed)
        } finally {
            stack.shutdown()
        }
    }

    @Test
    fun blockQuicOffLetsEverythingThrough() {
        val stack = newStack(AppConfig(blockQuic = false, udpMode = UdpMode.RELAY))
        try {
            val passed = send(stack, quicInitial())
            assertTrue("при выключенной блокировке QUIC пакеты должны проходить", passed)
        } finally {
            stack.shutdown()
        }
    }

    private fun assertBlocked(payload: ByteArray, message: String) {
        val stack = newStack(AppConfig(blockQuic = true))
        try {
            val passed = send(stack, payload)
            assertTrue(message, !passed)
        } finally {
            stack.shutdown()
        }
    }

    /**
     * @return true — пакет дошёл до релея (сессия создана), false — заблокирован.
     *
     * Признак один и надёжный: заблокированный пакет не создаёт UDP-сессию,
     * а пропущенный создаёт. На адрес назначения не смотрим — до нас пакет
     * дошёл из теста напрямую.
     */
    private fun send(stack: UdpStack, payload: ByteArray): Boolean {
        val dst = InetAddress.getByName("127.0.0.1")
        val pkt = udpPacket(dst, 443, payload)
        val ip = parseIp(pkt, pkt.size)!!
        val before = stack.activeCount
        stack.onPacket(ip, parseUdp(pkt, ip.payloadOffset, ip.payloadLength)!!)
        Thread.sleep(80)
        val relayed = stack.activeCount > before
        if (relayed) stack.closeAll()
        return relayed
    }

    private fun newStack(cfg: AppConfig) = UdpStack(
        writer = PacketWriter(sink),
        protector = protector,
        configProvider = { cfg },
        listsProvider = { HostListStore.Snapshot.EMPTY }
    )

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