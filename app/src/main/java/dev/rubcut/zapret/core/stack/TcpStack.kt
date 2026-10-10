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
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

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
    private val dropped = AtomicLong()

    /**
     * Наблюдатель исходящих пакетов. Нужен автоподбору стратегий: он подаёт в
     * стек синтетического клиента и читает ответы стека, не трогая tun.
     */
    @Volatile
    var tap: ((ByteArray) -> Unit)? = null

    val droppedCount: Long get() = dropped.get()

    fun write(packet: ByteArray) {
        synchronized(lock) {
            try {
                out.write(packet)
            } catch (e: Exception) {
                val n = dropped.incrementAndGet()
                // Без этого запись в tun может молча не удаляться (например,
                // пакет больше MTU → EINVAL), и пользователь видит просто
                // «интернета нет», хотя причина — на выходе из стека.
                if (n <= 3L) {
                    dev.rubcut.zapret.core.LogManager.w(
                        "Запись пакета в tun не удалась ($n/3, ${packet.size} байт): " +
                            "${e.javaClass.simpleName}: ${e.message}"
                    )
                }
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
    private val listsProvider: () -> HostListStore.Snapshot,
    /** Адреса нашего виртуального DNS: см. ZapretVpnService.VIRTUAL_DNS_ADDRESSES. */
    private val virtualDns: Set<InetAddress> = emptySet()
) {

    private val threadIndex = AtomicInteger()

    /**
     * Пул потоков для стека.
     *
     * Раньше стоял SynchronousQueue: у него нулевая ёмкость, поэтому при
     * `workerCount >= maximumPoolSize` execute() бросал RejectedExecutionException
     * МГНОВЕННО, без всякой очереди. Это ломало всё сразу, как только
     * одновременных задач становилось больше 384 — а их столько набирается
     * легко: чтение из upstream-сокета блокирующее и держит поток всё время
     * жизни соединения, плюс connect() висит до connectTimeoutMs.
     *
     * YouTube при старте открывает пачку соединений разом, и пул уходил в
     * переполнение. Дальше launch() падал, pumpTo/pumpFromUpstream не
     * запускались, pumpUp.join() ждал вечно — соединение зависало навсегда и
     * занимало слот в maxConnections. Спустя несколько таких пакетов туннель
     * переставал работать целиком.
     *
     * Теперь: небольшая ограниченная очередь вместо отказа, allowCoreThreadTimeOut —
     * чтобы пул доросал под нагрузкой и снова сжимался, и явный обработчик
     * отказа, который пишет в журнал, а не роняет соединение молча.
     *
     * Очередь маленькая не просто так: ThreadPoolExecutor наращивает число потоков
     * только когда очередь заполнена, поэтому большая ёмкость держала бы пул на
     * восьми потоках и душила бы чтения из сокетов. 128 — это компромисс: пул
     * разрастается быстро, но до отказа дело доходит лишь при тысяче соединений.
     */
    private val executor = ThreadPoolExecutor(
        8, 320, 30L, TimeUnit.SECONDS, LinkedBlockingQueue(128)
    ) { r ->
        Thread(r, "zapret-tcp-${threadIndex.incrementAndGet()}").apply {
            isDaemon = true
            priority = Thread.NORM_PRIORITY + 1
        }
    }.apply {
        allowCoreThreadTimeOut(true)
        // Отказ выполняет задачу на потоке вызывающего, а НЕ проглатывает его.
        //
        // Для корутин молчаливый отказ хуже падения: задача — это продолжение,
        // и если execute() просто вернётся, продолжение никогда не выполнится.
        // Любой await на нём (join(), awaitAll) зависнет навсегда без единой
        // записи в журнале. CallerRunsPolicy даёт противоположное поведение:
        // перегрузка превращается в честное замедление вызывающего потока,
        // ничего не теряется и ничего не зависает.
        setRejectedExecutionHandler { runnable, pool ->
            LogManager.w(
                "TCP: пул потоков переполнен (${pool.activeCount}), задача выполнится на текущем потоке"
            )
            runnable.run()
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
     * Пара «порт клиента → стратегия» для зонда автоподбора. Принудительная
     * стратегия действует ТОЛЬКО для этого соединения, настоящий трафик
     * продолжает идти по правилам конфигурации.
     */
    @Volatile
    var probeFor: Pair<Int, dev.rubcut.zapret.data.Strategy>? = null

    /** Сколько соединений успешно дошло до upstream-сокета и сколько упало. */
    val establishedTotal = AtomicLong()
    val failedTotal = AtomicLong()

    fun resolveFor(
        port: Int,
        host: String?,
        ip: InetAddress?,
        clientPort: Int
    ): StrategyResolver.Decision {
        val probe = probeFor
        if (probe != null && probe.first == clientPort) {
            return StrategyResolver.Decision(probe.second, null, "автоподбор")
        }
        return resolver.resolveTcp(port, host, ip)
    }

    /** Сколько соединений уже продиагностировано в журнал обычным уровнем. */
    private val diagCounter = AtomicInteger()

    fun nextDiagSlot(): Int = diagCounter.incrementAndGet()

    @Volatile
    var dnsRedirect: java.net.InetAddress? = null

    fun dnsRedirectTarget(): java.net.InetAddress? = dnsRedirect

    /** Адрес назначения — один из наших виртуальных DNS-серверов туннеля? */
    fun isVirtualDns(addr: java.net.InetAddress?): Boolean =
        addr != null && virtualDns.contains(addr)

    fun onPacket(ip: IpHeader, seg: TcpSegment) {
        // Виртуальные DNS-адреса — внутренняя обвязка туннеля, в сети их не
        // существует. TCP к ним приходит от системного резолвера: на порт 53
        // его надо перенаправить на наш резолвер, а любые другие порты (netd
        // пробует там DoT, 853) надо отбивать сразу — иначе каждая попытка
        // висит на connectTimeout и сеть выглядит «почти мёртвой».
        if (isVirtualDns(ip.dst) && seg.dstPort != 53) {
            if (seg.isSyn && !seg.isAck) sendReset(ip, seg)
            return
        }

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
