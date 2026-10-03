package dev.rubcut.zapret.core.stack

import dev.rubcut.zapret.core.ConnectionLog
import dev.rubcut.zapret.core.LogManager
import dev.rubcut.zapret.core.LogTag
import dev.rubcut.zapret.core.RecentConnection
import dev.rubcut.zapret.core.SocketProtector
import dev.rubcut.zapret.core.desync.DesyncEngine
import dev.rubcut.zapret.core.desync.StrategyResolver
import dev.rubcut.zapret.core.net.IpHeader
import dev.rubcut.zapret.core.net.PacketBuilder
import dev.rubcut.zapret.core.net.TcpFlag
import dev.rubcut.zapret.core.net.TcpSegment
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.HostListStore
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.asCoroutineDispatcher
import java.io.OutputStream
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Ключ TCP-потока в направлении «приложение → сервер». */
data class TcpKey(
    val src: InetAddress,
    val srcPort: Int,
    val dst: InetAddress,
    val dstPort: Int
)

/** Потокобезопасная запись собранных пакетов в tun. */
class PacketWriter(private val out: OutputStream) {
    private val lock = Any()
    private val dropped = AtomicInteger()

    /**
     * Наблюдатель исходящих пакетов. Нужен автоподбору стратегий: он подаёт в
     * стек синтетического клиента и читает ответы стека, не трогая tun.
     */
    @Volatile
    var tap: ((ByteArray) -> Unit)? = null

    val droppedCount: Int get() = dropped.get()

    fun write(packet: ByteArray) {
        synchronized(lock) {
            try {
                out.write(packet)
            } catch (e: Exception) {
                dropped.incrementAndGet()
            }
        }
        try {
            tap?.invoke(packet)
        } catch (_: Exception) {
        }
    }
}

/**
 * Пользовательский TCP/IP-стек туннеля.
 *
 * Принимает IP-пакеты из tun, ведёт таблицу соединений и выдаёт обратно
 * корректные TCP-сегменты. Это аналог того, чем в десктопном zapret занимается
 * NFQUEUE/WinDivert, только «с другой стороны»: пакеты приложения мы терминируем
 * на себе, а в интернет выходим обычным сокетом, которым полностью управляем.
 */
class TcpStack(
    val writer: PacketWriter,
    val protector: SocketProtector,
    val scope: CoroutineScope,
    private val configProvider: () -> AppConfig,
    private val listsProvider: () -> HostListStore.Snapshot
) {

    private val threadIndex = AtomicInteger()
    private val executor = ThreadPoolExecutor(
        4, 384, 30L, TimeUnit.SECONDS, SynchronousQueue()
    ) { r ->
        Thread(r, "zapret-tcp-${threadIndex.incrementAndGet()}").apply {
            isDaemon = true
            priority = Thread.NORM_PRIORITY + 1
        }
    }

    val io: CoroutineDispatcher = executor.asCoroutineDispatcher()
    val engine = DesyncEngine()
    val resolver = StrategyResolver(configProvider, listsProvider)

    val config: AppConfig get() = configProvider()
    val lists: HostListStore.Snapshot get() = listsProvider()

    private val connections = ConcurrentHashMap<TcpKey, TcpConnection>()

    val activeCount: Int get() = connections.size

    /** Писатель пакетов — автоподбор навешивает на него наблюдателя для зонда. */
    val packetWriter: PacketWriter get() = writer

    /**
     * Стратегия, принудительно применяемая ко всем новым соединениям.
     * Используется автоподбором: на время прогона зонда правила конфигурации
     * игнорируются, чтобы проверялся именно кандидат.
     */
    @Volatile
    var forcedStrategy: dev.rubcut.zapret.data.Strategy? = null

    fun resolveFor(port: Int, host: String?, ip: InetAddress?): StrategyResolver.Decision =
        forcedStrategy?.let { StrategyResolver.Decision(it, null, "автоподбор") }
            ?: resolver.resolveTcp(port, host, ip)

    /** Сколько соединений уже продиагностировано в журнал обычным уровнем. */
    private val diagCounter = AtomicInteger()

    fun nextDiagSlot(): Int = diagCounter.incrementAndGet()

    @Volatile
    var dnsRedirect: java.net.InetAddress? = null

    fun dnsRedirectTarget(): java.net.InetAddress? = dnsRedirect

    fun onPacket(ip: IpHeader, seg: TcpSegment) {
        val key = TcpKey(ip.src, seg.srcPort, ip.dst, seg.dstPort)
        var conn = connections[key]
        if (conn == null || conn.isClosed()) {
            if (conn != null) connections.remove(key, conn)
            if (seg.isSyn && !seg.isAck) {
                if (connections.size >= config.maxConnections.coerceIn(16, 4096)) {
                    LogManager.w("TCP: достигнут предел соединений (${connections.size}), сбрасываем $key")
                    sendReset(ip, seg)
                    return
                }
                conn = TcpConnection(this, key, ip, seg)
                connections[key] = conn
                conn.start()
            } else {
                if (!seg.isRst) sendReset(ip, seg)
                return
            }
        }
        conn.onSegment(seg)
    }

    private fun sendReset(ip: IpHeader, seg: TcpSegment) {
        val hasAck = seg.isAck
        val seq = if (hasAck) seg.ack else 0
        val ackLen = seg.payloadLength + (if (seg.isSyn) 1 else 0) + (if (seg.isFin) 1 else 0)
        val ack = seg.seq + ackLen
        val flags = if (hasAck) TcpFlag.RST else TcpFlag.RST or TcpFlag.ACK
        val pkt = PacketBuilder.tcp(
            v6 = ip.v6, src = ip.dst, dst = ip.src,
            srcPort = seg.dstPort, dstPort = seg.srcPort,
            seq = seq, ack = ack, flags = flags, window = 0
        )
        writer.write(pkt)
    }

    fun remove(conn: TcpConnection) {
        connections.remove(conn.key, conn)
    }

    fun track(conn: TcpConnection, host: String?, technique: String?, applied: Boolean) {
        ConnectionLog.add(
            RecentConnection(
                host = host ?: conn.serverAddr.hostAddress ?: "?",
                address = conn.serverAddr.hostAddress ?: "?",
                port = conn.serverPort,
                technique = technique,
                applied = applied,
                v6 = conn.serverAddr.address.size == 16,
                at = System.currentTimeMillis()
            )
        )
    }

    fun closeAll() {
        val all = connections.values.toList()
        for (c in all) {
            try { c.close() } catch (_: Exception) {}
        }
        connections.clear()
    }

    fun shutdown() {
        closeAll()
        executor.shutdownNow()
    }
}
