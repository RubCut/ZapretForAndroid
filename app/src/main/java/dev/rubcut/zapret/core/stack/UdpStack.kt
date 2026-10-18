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
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingQueue
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
 * Шаблоны-приманки для UDP — аналог `--dpi-desync-fake-quic` и
 * `--dpi-desync-fake-discord`/`fake-stun` из zapret.
 *
 * Приманка — записанный QUIC Initial с безобидным SNI. Провайдерский фильтр
 * расшифровывает его (ключи выводятся из DCID самого пакета), относит поток
 * к разрешённым и больше не мешает настоящим пакетам. Приманка уходит с того
 * же сокета, что и поток, поэтому ни root, ни подмена заголовков не нужны —
 * в отличие от TCP-приёмов ложного разбиения, где подделывать приходится
 * sequence-номера.
 *
 * Шаблоны взяты из набора zapret (bol-van, GPL-3) — как и сам приём.
 */
data class UdpFakes(
    val quic: ByteArray? = null,
    val discord: ByteArray? = null
)

/**
 * Релей UDP. DNS сюда не попадает — его разбирает [dev.rubcut.zapret.core.dns.DnsHandler].
 *
 * QUIC (UDP/443) по умолчанию отбрасывается: браузер, не дождавшись QUIC,
 * возвращается на TCP/443, где работает split. Если включены приманки
 * ([UdpFakes]), QUIC вместо блокировки пропускается: перед настоящим Initial
 * уходит подставной Initial с чужим безобидным SNI, и фильтр относит поток
 * к разрешённым.
 */
class UdpStack(
    private val writer: PacketWriter,
    private val protector: SocketProtector,
    private val configProvider: () -> AppConfig,
    listsProvider: () -> HostListStore.Snapshot,
    private val udpFakes: UdpFakes = UdpFakes(),
    /**
     * Порт QUIC (UDP). Наружу всегда 443; параметр существует ради тестов:
     * привязать локальный сокет к 443 без root нельзя, а проверить, что
     * приманка уходит перед настоящим пакетом, нужно на живом сокете.
     */
    private val quicPort: Int = 443
) {

    private val threadIndex = AtomicInteger()

    /**
     * Тот же дефект, что был в TCP-стеке: SynchronousQueue отбрасывал задачи
     * мгновенно при переполнении, а приём датаграмм блокирующий и держит поток
     * всё время жизни сессии. Голос Discord держит UDP-сессии десятками секунд,
     * поэтому пул уходил в переполнение и релей молча переставал работать.
     */
    private val executor = ThreadPoolExecutor(
        4, 128, 30L, TimeUnit.SECONDS, LinkedBlockingQueue(32)
    ) { r ->
        Thread(r, "zapret-udp-${threadIndex.incrementAndGet()}").apply { isDaemon = true }
    }.apply {
        allowCoreThreadTimeOut(true)
        // Не проглатывать: задача — это продолжение корутины, и при молчаливом
        // отказе оно просто не выполнится. См. пояснение в TcpStack.
        setRejectedExecutionHandler { runnable, pool ->
            LogManager.w("UDP: пул потоков переполнен (${pool.activeCount}), задача выполнится на текущем потоке")
            runnable.run()
        }
    }
    private val io: CoroutineDispatcher = executor.asCoroutineDispatcher()
    private val scope = CoroutineScope(SupervisorJob() + io)

    private val resolver = StrategyResolver(configProvider, listsProvider)
    private val sessions = ConcurrentHashMap<UdpKey, UdpSession>()

    val activeCount: Int get() = sessions.size

    fun onPacket(ip: IpHeader, dgram: UdpDatagram): Boolean {
        val cfg = configProvider()
        val port = dgram.dstPort

        // Старший бит payload'а — признак long header, то есть QUIC
        // Initial/Handshake. Именно один этот бит, а не маска 0xC0: провайдеры
        // обфусцируют QUIC, обнуляя reserved-бит 0x40, и такой Initial тоже
        // обязан распознаваться — иначе клиент уходит в QUIC, где мы не умеем
        // десинхронизировать SNI. Short header (1-RTT, бит 0x80 сброшен) —
        // это уже установленное соединение, его рвать нельзя.
        val quicLongHeader = port == quicPort && dgram.payloadLength > 0 &&
            (dgram.buffer[dgram.payloadOffset].toInt() and 0x80) != 0

        // С приманками QUIC не блокируем: поток уходит в сеть, приманка
        // заставляет фильтр считать его разрешённым (см. [UdpFakes]).
        val quicFakesArmed = cfg.fakeUdp && udpFakes.quic != null
        if (cfg.blockQuic && quicLongHeader && !quicFakesArmed) {
            TrafficStats.quicBlocked()
            return true
        }

        when (cfg.udpMode) {
            UdpMode.BLOCK_ALL -> {
                TrafficStats.dropped()
                return true
            }
            UdpMode.BLOCK_FILTERED -> {
                val host = ReverseHostCache.get(ip.dst)
                val decision = resolver.resolveUdp(port, host, ip.dst)
                // Для UDP значимы только десинхронизация и wssize: смена регистра
                // и отравление — приёмы TCP-уровня, из-за них релей рвать нельзя.
                val blocksUdp = decision.strategy.desync != dev.rubcut.zapret.data.DesyncMode.NONE ||
                    decision.strategy.wssizeEnabled
                if (blocksUdp) {
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

        @Volatile
        private var socket: DatagramSocket? = null
        private var job: Job? = null
        @Volatile
        private var closed = false

        /** Приманка за сессию положена ровно однажды (см. [sendFakesIfArmed]). */
        private var fakesSent = false

        /**
         * Пакеты, пришедшие до готовности сокета. Раньше первый пакет сессии
         * молча терялся (`socket ?: return`), а для DNS это единственный пакет
         * запроса: ответ не приходил никогда и запрос отваливался по таймауту.
         */
        private val pending = ArrayDeque<ByteArray>()
        // Отдельный монитор очереди: synchronized(this) внутри launch-лямбды
        // лочил бы CoroutineScope (общий для всех сессий), а в sendUpstream —
        // сессию. Флашить и добавлять шли под разными замками, ArrayDeque рвался.
        private val pendingLock = Any()

        fun touch() { lastSeen = System.currentTimeMillis() }

        fun start() {
            job = scope.launch(io) {
                var sock: DatagramSocket? = null
                try {
                    sock = DatagramSocket(null)
                    // Мягкий режим (см. TcpConnection.openUpstream): жёсткий
                    // throw здесь ронял бы весь UDP-релей и DNS на сетях, где
                    // protect() spuriously возвращает false.
                    if (!protector.protect(sock)) {
                        TrafficStats.unisolated()
                        LogManager.w("upstream UDP без изоляции: продолжаю без неё")
                    }
                    // Не нулевой: нулевой таймаут означает блокировку навсегда,
                    // а нам нужно периодически отпускать поток пула (см. ниже).
                    sock.soTimeout = UDP_RECV_TIMEOUT_MS
                    sock.connect(InetSocketAddress(key.dst, key.dstPort))
                    socket = sock
                    val queued = synchronized(pendingLock) {
                        val l = pending.toList()
                        pending.clear()
                        l
                    }
                    for (d in queued) {
                        try {
                            sendFakesIfArmed(d)
                            sock.send(DatagramPacket(d, d.size))
                            TrafficStats.up(d.size)
                        } catch (e: Exception) {
                            LogManager.d(LogTag.UDP, "UDP flush ${key.dst}:${key.dstPort}: ${e.message}")
                        }
                    }
                    // receive() ниже вызывается с soTimeout, а не блокируется
                    // навсегда. Иначе каждая сессия навсегда занимала один поток
                    // пула на все udpTimeoutSec (60 с по умолчанию), и при
                    // десятках одновременных сессий пул исчерпывал себя — релей
                    // переставал работать, о чём честно говорит журнал:
                    // «UDP: пул потоков переполнен».
                    val buf = ByteArray(64 * 1024)
                    while (scope.isActive && !closed) {
                        val packet = DatagramPacket(buf, buf.size)
                        // Блок уже идёт на stack.io: вложенный withContext(io)
                        // занимал второй поток пула на то же чтение, вдвое
                        // резал ёмкость и вёл к переполнению с CallerRuns.
                        val got = try {
                            sock.receive(packet)
                            true
                        } catch (e: java.net.SocketTimeoutException) {
                            false
                        } catch (e: Exception) {
                            LogManager.d(LogTag.UDP, "UDP receive ${key.dst}:${key.dstPort}: ${e.message}")
                            true
                        }
                        if (closed) break
                        // Не таймаут, а приход данных.
                        if (!got) {
                            // Порция работы закончена — отдаём поток пулу.
                            delay(UDP_IDLE_SLEEP_MS)
                            continue
                        }
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

        /**
         * Приманка перед первым настоящим пакетом сессии — аналог
         * `--dpi-desync=fake` для UDP. Для QUIC/443 уходит записанный Initial
         * с SNI www.google.com, для голосовых портов Discord — Initial
         * с SNI dbankcloud.ru. Повторы нужны, как в zapret: фильтру может
         * понадобиться не один пакет, чтобы отнести поток к разрешённым.
         *
         * Вызывается строго перед отправкой настоящего пакета; за сессию
         * срабатывает не более одного раза.
         */
        @Synchronized
        private fun sendFakesIfArmed(data: ByteArray) {
            if (fakesSent) return
            if (!configProvider().fakeUdp) return
            val payload: ByteArray
            val repeats: Int
            when {
                key.dstPort == quicPort -> {
                    // Приманка уместна перед QUIC Initial: short header — уже
                    // установленное соединение, туда приманка не лезет.
                    val first = data.firstOrNull()?.toInt()?.and(0xFF) ?: return
                    val quic = udpFakes.quic
                    if (first and 0x80 == 0 || quic == null) {
                        fakesSent = true
                        return
                    }
                    payload = quic
                    repeats = QUIC_FAKE_REPEATS
                }
                isVoicePort(key.dstPort) -> {
                    payload = udpFakes.discord ?: return
                    repeats = VOICE_FAKE_REPEATS
                }
                else -> {
                    fakesSent = true
                    return
                }
            }
            val sock = socket ?: return
            // Отмечаем до отправки: если серия оборвалась, повторять её на
            // каждый следующий пакет не нужно — это лишние килобайты мусора.
            fakesSent = true
            repeat(repeats) {
                try {
                    sock.send(DatagramPacket(payload, payload.size))
                } catch (e: Exception) {
                    LogManager.d(LogTag.UDP, "UDP приманка ${key.dst}:${key.dstPort}: ${e.message}")
                    return
                }
            }
            LogManager.d(
                LogTag.UDP,
                "UDP/${key.dstPort}: приманка ${payload.size} Б ×$repeats перед первым пакетом"
            )
        }

        fun sendUpstream(data: ByteArray) {
            val sock = socket
            if (sock == null) {
                synchronized(pendingLock) {
                    if (pending.size < MAX_PENDING) {
                        pending.addLast(data)
                    } else {
                        TrafficStats.dropped()
                    }
                }
                return
            }
            try {
                sendFakesIfArmed(data)
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
            // Мёртвые сессии вычищаем из карты сразу: раньше close() оставлял
            // запись до срабатывания сторожевого таймера, и activeCount врал.
            sessions.remove(key, this)
        }
    }

    private companion object {
        const val MAX_SESSIONS = 256
        const val MAX_PENDING = 8

        /** `--dpi-desync-repeats=11` и `=6` — как в рабочем zapret-профиле. */
        const val QUIC_FAKE_REPEATS = 11
        const val VOICE_FAKE_REPEATS = 6

        /** Сколько ждём очередную датаграмму, прежде чем отпустить поток пула. */
        const val UDP_RECV_TIMEOUT_MS = 2000

        /** Пауза после таймаута: coroutine suspension, а не занятый поток. */
        const val UDP_IDLE_SLEEP_MS = 200L
    }
}

/** Голосовые/STUN-порты Discord — диапазоны из zapret-профиля. */
private fun isVoicePort(port: Int): Boolean =
    port in 19294..19344 || port in 50000..50100 || port in 3478..3482
