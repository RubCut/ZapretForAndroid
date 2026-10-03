package dev.rubcut.zapret.core.stack

import dev.rubcut.zapret.core.LogManager
import dev.rubcut.zapret.core.LogTag
import dev.rubcut.zapret.core.SocketProtector
import dev.rubcut.zapret.core.TrafficStats
import dev.rubcut.zapret.core.desync.ReverseHostCache
import dev.rubcut.zapret.core.desync.StrategyResolver
import dev.rubcut.zapret.core.net.IpHeader
import dev.rubcut.zapret.core.net.PacketBuilder
import dev.rubcut.zapret.core.net.UdpDatagram
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.HostListStore
import dev.rubcut.zapret.data.UdpMode
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

data class UdpKey(
    val src: InetAddress,
    val srcPort: Int,
    val dst: InetAddress,
    val dstPort: Int
)

/**
 * Релей UDP. DNS сюда не попадает — его разбирает [dev.rubcut.zapret.core.dns.DnsHandler].
 *
 * QUIC (UDP/443) по умолчанию отбрасывается: без root подделать Initial-пакет нельзя,
 * зато браузер, не дождавшись QUIC, возвращается на TCP/443, где работает split.
 */
class UdpStack(
    private val writer: PacketWriter,
    private val protector: SocketProtector,
    private val configProvider: () -> AppConfig,
    listsProvider: () -> HostListStore.Snapshot
) {

    private val threadIndex = AtomicInteger()
    private val executor = ThreadPoolExecutor(2, 192, 30L, TimeUnit.SECONDS, SynchronousQueue()) { r ->
        Thread(r, "zapret-udp-${threadIndex.incrementAndGet()}").apply { isDaemon = true }
    }
    private val io: CoroutineDispatcher = executor.asCoroutineDispatcher()
    private val scope = CoroutineScope(SupervisorJob() + io)

    private val resolver = StrategyResolver(configProvider, listsProvider)
    private val sessions = ConcurrentHashMap<UdpKey, UdpSession>()

    val activeCount: Int get() = sessions.size

    fun onPacket(ip: IpHeader, dgram: UdpDatagram): Boolean {
        val cfg = configProvider()
        val port = dgram.dstPort

        if (cfg.blockQuic && port == 443 && dgram.payloadLength > 0) {
            val first = dgram.buffer[dgram.payloadOffset].toInt() and 0xFF
            // Long header (0xC0..0xFF с установленным старшим битом) — это QUIC Initial/Handshake.
            if (first and 0x80 != 0) {
                TrafficStats.quicBlocked()
                return true
            }
        }

        when (cfg.udpMode) {
            UdpMode.BLOCK_ALL -> {
                TrafficStats.dropped()
                return true
            }
            UdpMode.BLOCK_FILTERED -> {
                val host = ReverseHostCache.get(ip.dst)
                val decision = resolver.resolveUdp(port, host, ip.dst)
                if (!decision.strategy.isPassive) {
                    TrafficStats.dropped()
                    LogManager.d(LogTag.UDP, "UDP/$port заблокирован фильтром (${decision.reason})")
                    return true
                }
            }
            UdpMode.RELAY -> Unit
        }

        val key = UdpKey(ip.src, dgram.srcPort, ip.dst, dgram.dstPort)
        var session = sessions[key]
        if (session == null) {
            if (sessions.size >= MAX_SESSIONS) {
                evictOldest()
                if (sessions.size >= MAX_SESSIONS) return true
            }
            session = UdpSession(key, ip.v6, cfg.udpTimeoutSec.coerceIn(10, 3600))
            sessions[key] = session
            session.start()
        }
        session.touch()
        val data = dgram.buffer.copyOfRange(dgram.payloadOffset, dgram.payloadOffset + dgram.payloadLength)
        session.sendUpstream(data)
        return true
    }

    private fun evictOldest() {
        val oldest = sessions.values.minByOrNull { it.lastSeen } ?: return
        oldest.close()
        sessions.remove(oldest.key, oldest)
    }

    fun closeAll() {
        for (s in sessions.values) {
            try { s.close() } catch (_: Exception) {}
        }
        sessions.clear()
    }

    fun shutdown() {
        closeAll()
        executor.shutdownNow()
    }

    private inner class UdpSession(
        val key: UdpKey,
        private val v6: Boolean,
        private val timeoutSec: Int
    ) {
        @Volatile
        var lastSeen: Long = System.currentTimeMillis()
            private set

        private var socket: DatagramSocket? = null
        private var job: Job? = null
        @Volatile
        private var closed = false

        fun touch() { lastSeen = System.currentTimeMillis() }

        fun start() {
            job = scope.launch(io) {
                var sock: DatagramSocket? = null
                try {
                    sock = DatagramSocket(null)
                    protector.protect(sock)
                    sock.soTimeout = 0
                    sock.connect(InetSocketAddress(key.dst, key.dstPort))
                    socket = sock
                    val buf = ByteArray(64 * 1024)
                    while (scope.isActive && !closed) {
                        val packet = DatagramPacket(buf, buf.size)
                        val ok = withContext(io) {
                            try {
                                sock.receive(packet)
                                true
                            } catch (e: Exception) {
                                false
                            }
                        }
                        if (!ok) break
                        touch()
                        val reply = PacketBuilder.udp(
                            v6 = v6, src = key.dst, dst = key.src,
                            srcPort = key.dstPort, dstPort = key.srcPort,
                            payload = packet.data, payloadOff = packet.offset, payloadLen = packet.length
                        )
                        writer.write(reply)
                        TrafficStats.down(packet.length)
                    }
                } catch (e: Exception) {
                    if (!closed) LogManager.d(LogTag.UDP, "UDP ${key.dst}:${key.dstPort}: ${e.message}")
                } finally {
                    try { sock?.close() } catch (_: Exception) {}
                    close()
                }
            }
            // Сторожевой таймер простаивающих сессий.
            scope.launch(io) {
                while (scope.isActive && !closed) {
                    delay(5000)
                    if (System.currentTimeMillis() - lastSeen > timeoutSec * 1000L) {
                        close()
                        sessions.remove(key, this@UdpSession)
                        break
                    }
                }
            }
        }

        fun sendUpstream(data: ByteArray) {
            val sock = socket ?: return
            try {
                sock.send(DatagramPacket(data, data.size))
                TrafficStats.up(data.size)
            } catch (e: Exception) {
                LogManager.d(LogTag.UDP, "UDP send ${key.dst}:${key.dstPort}: ${e.message}")
                close()
            }
        }

        fun close() {
            if (closed) return
            closed = true
            try { socket?.close() } catch (_: Exception) {}
            try { job?.cancel() } catch (_: Exception) {}
        }
    }

    private companion object {
        const val MAX_SESSIONS = 256
    }
}
