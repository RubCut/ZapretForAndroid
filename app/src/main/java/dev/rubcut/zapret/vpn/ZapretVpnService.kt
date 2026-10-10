package dev.rubcut.zapret.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import dev.rubcut.zapret.AppGraph
import dev.rubcut.zapret.R
import dev.rubcut.zapret.core.LogManager
import dev.rubcut.zapret.core.LogTag
import dev.rubcut.zapret.core.SocketProtector
import dev.rubcut.zapret.core.TrafficStats
import dev.rubcut.zapret.core.desync.ReverseHostCache
import dev.rubcut.zapret.core.desync.withTunedPerHost
import dev.rubcut.zapret.core.dns.DnsHandler
import dev.rubcut.zapret.core.net.IpLiterals
import dev.rubcut.zapret.core.net.parseIp
import dev.rubcut.zapret.core.net.parseTcp
import dev.rubcut.zapret.core.net.parseUdp
import dev.rubcut.zapret.core.stack.PacketWriter
import dev.rubcut.zapret.core.dns.DnsResult
import dev.rubcut.zapret.core.dns.DnsType
import dev.rubcut.zapret.core.stack.StrategyAutopilot
import dev.rubcut.zapret.core.stack.TcpStack
import dev.rubcut.zapret.core.stack.UdpStack
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.AppScope
import dev.rubcut.zapret.data.DnsMode
import dev.rubcut.zapret.data.ProfileId
import dev.rubcut.zapret.ui.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.FileInputStream
import java.util.concurrent.atomic.AtomicLong
import java.io.FileOutputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket

/**
 * Сервис туннеля.
 *
 * Поднимает VpnService, читает IP-пакеты из tun, разбирает их собственным
 * TCP/IP-стеком и выходит в интернет обычными сокетами, применяя к первым байтам
 * каждого соединения стратегии zapret. Root не нужен: всё, что мы делаем, —
 * формируем пакеты для приложений и управляем границами сегментов на пути в сеть.
 */
class ZapretVpnService : VpnService() {

    companion object {
        const val ACTION_START = "dev.rubcut.zapret.action.START"
        const val ACTION_STOP = "dev.rubcut.zapret.action.STOP"
        const val ACTION_TOGGLE = "dev.rubcut.zapret.action.TOGGLE"

        const val CHANNEL_MAIN = "zapret_status"
        const val CHANNEL_EVENTS = "zapret_events"
        const val NOTIFICATION_ID = 0x5A41

        /** Отдельный ID для событийных уведомлений (остановка/ошибка). */
        const val EVENT_NOTIFICATION_ID = 0x5A42

        /**
         * Запас для сотовых сетей, когда настоящий MTU узнать не удалось
         * (LinkProperties.getMtu() есть только с API 29). У большинства
         * операторов MTU 1400–1440, и пакеты по 1500 молча теряются.
         */
        const val CELLULAR_SAFE_MTU = 1400
        const val MAX_RECONNECTS = 3

        const val VPN_ADDR_V4 = "10.211.0.1"
        const val DNS_ADDR_V4 = "10.211.0.2"
        const val VPN_ADDR_V6 = "fd61:7a6f:ee7::1"
        const val DNS_ADDR_V6 = "fd61:7a6f:ee7::2"

        /**
         * Адреса нашего виртуального DNS как [InetAddress], а не строки.
         *
         * Строковое сравнение здесь непригодно: `Inet6Address.getHostAddress()`
         * печатает адрес развёрнутым («fd61:7a6f:ee07:0:0:0:0:2»), и литерал
         * «fd61:7a6f:ee7::2» с ним никогда не совпадёт. Из-за этого на двухстёковых
         * сетях не срабатывало ни перенаправление TCP-DNS, ни защита от петли.
         */
        val VIRTUAL_DNS_ADDRESSES: Set<InetAddress> = setOfNotNull(
            IpLiterals.parse(DNS_ADDR_V4),
            IpLiterals.parse(DNS_ADDR_V6)
        )

        /** Живой экземпляр сервиса — нужен UI для проверки DNS через защищённые сокеты. */
        @Volatile
        var instance: ZapretVpnService? = null
    }

    @Volatile
    private var running = false

    private var pfd: ParcelFileDescriptor? = null
    private var input: FileInputStream? = null
    private var tcpStack: TcpStack? = null
    private var udpStack: UdpStack? = null
    private var dnsHandler: DnsHandler? = null
    private var scope: CoroutineScope? = null
    private var readerThread: Thread? = null
    private var configJob: Job? = null
    private var notifJob: Job? = null
    private var tunnelSignature: String = ""

    val protector = object : SocketProtector {
        override fun protect(socket: Socket): Boolean {
            val bound = bindToUnderlying(socket)
            val prot = try { this@ZapretVpnService.protect(socket) } catch (e: Exception) { false }
            reportIsolation(bound, prot)
            return bound || prot
        }

        override fun protect(socket: DatagramSocket): Boolean {
            val bound = bindToUnderlying(socket)
            val prot = try { this@ZapretVpnService.protect(socket) } catch (e: Exception) { false }
            reportIsolation(bound, prot)
            return bound || prot
        }

        override fun protect(fd: Int): Boolean =
            try { this@ZapretVpnService.protect(fd) } catch (e: Exception) { false }
    }

    /**
     * Привязка сокета к физической сети напрямую, в дополнение к [protect].
     *
     * Держать изоляцию только на protect() опасно: его отказ означал бы, что
     * наши же upstream-сокеты уходят в наш туннель и терминируются нами же
     * рекурсивно — трафик вставал бы намертво, снаружи это выглядит как
     * «интернета нет совсем». Сокет, привязанный к сети с
     * NET_CAPABILITY_NOT_VPN, попасть в туннель физически не может.
     */
    private fun bindToUnderlying(socket: Socket): Boolean {
        val n = underlyingNetwork ?: return false
        return try {
            n.bindSocket(socket)
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun bindToUnderlying(socket: DatagramSocket): Boolean {
        val n = underlyingNetwork ?: return false
        return try {
            n.bindSocket(socket)
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun reportIsolation(bound: Boolean, prot: Boolean) {
        isolationSummary = "привязка к физической сети=$bound, protect=$prot"
        if (isolationReported) return
        isolationReported = true
        LogManager.i(LogTag.VPN, "Изоляция upstream-сокетов: привязка к физической сети=$bound, protect=$prot")
        if (!bound && !prot) {
            LogManager.w("Upstream-сокеты НЕ изолированы от туннеля — возможен самозахват трафика")
        }
    }

    /** Физическая сеть (не VPN), к которой привязываются upstream-сокеты. */
    @Volatile
    private var underlyingNetwork: Network? = null

    private var netCallback: ConnectivityManager.NetworkCallback? = null

    @Volatile
    private var isolationReported = false

    @Volatile
    private var isolationSummary = "нет данных"

    @Volatile
    private var negotiatedMtu = 0

    private fun watchUnderlyingNetwork() {
        try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    underlyingNetwork = network
                }

                override fun onLost(network: Network) {
                    if (underlyingNetwork == network) underlyingNetwork = null
                }
            }
            cm.registerNetworkCallback(req, cb)
            netCallback = cb
        } catch (e: Exception) {
            LogManager.w("Не удалось подписаться на физическую сеть: ${e.message}")
        }
    }

    private fun unwatchUnderlyingNetwork() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        try {
            netCallback?.let { cm?.unregisterNetworkCallback(it) }
        } catch (_: Exception) {
        }
        netCallback = null
        underlyingNetwork = null
    }

    override fun onCreate() {
        super.onCreate()
        createChannels()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopEverything("по запросу пользователя")
                return START_NOT_STICKY
            }
            ACTION_TOGGLE -> {
                if (running) {
                    stopEverything("по запросу пользователя")
                } else {
                    startVpn()
                }
                return START_STICKY
            }
            else -> startVpn()
        }
        return START_STICKY
    }

    override fun onRevoke() {
        LogManager.w("Система отозвала VPN")
        // Некоторые оболочки отзывают VPN «на всякий случай» (смена сети,
        // агрессивный менеджер энергии). Раз пользователь VPN не выключал,
        // пробуем поднять туннель обратно, а не оставляем телефон без обхода.
        val cfg = AppGraph.config.current
        if (!userStopped && reconnectAttempts < MAX_RECONNECTS && cfg.profile != ProfileId.OFF) {
            reconnectAttempts++
            LogManager.i(LogTag.VPN, "Туннель отозван системой — поднимаю заново (попытка $reconnectAttempts)")
            running = false
            teardown()
            AppGraph.scope.launch {
                delay(1200L * reconnectAttempts)
                withContext(Dispatchers.Main) {
                    try {
                        if (prepare(this@ZapretVpnService) == null) {
                            scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
                            TrafficStats.reset()
                            ReverseHostCache.clear()
                            establish(AppGraph.config.current)
                        } else {
                            LogManager.w("Разрешение на VPN отозвано — автопереподключение невозможно")
                            stopEverything("отозван системой")
                        }
                    } catch (e: Exception) {
                        fail(e.message ?: "reconnect failed")
                    }
                }
            }
        } else {
            stopEverything("отозван системой")
        }
    }

    override fun onDestroy() {
        stopEverything("сервис уничтожен")
        super.onDestroy()
    }

    /* ------------------------------------------------------------ */

    /**
     * Локальные сети выводятся из-под туннеля.
     *
     * Маршрут 0.0.0.0/0 забирает ВЕСЬ трафик телефона, включая обращения к
     * локальной сети. Из-за этого с телефоном перестаёт общаться всё, что
     * рядом: ноутбук в той же Wi-Fi-сети не может открыть ни страницу на
     * телефоне, ни страницу, которую телефон сам раздаёт. Для проверки обхода
     * это особенно неудобно — компьютер нужен как пульт управления.
     *
     * Исключаются только RFC1918-сети 192.168/16 и 172.16/12 плюс
     * link-local 169.254/16. Сеть 10/8 намеренно НЕ исключается: собственные
     * адреса туннеля и виртуальных клиентов лежат именно в ней
     * ([VPN_ADDR_V4] = 10.211.0.1), и выбрасывать её из маршрутизации значило
     * бы ломать собственный стек приложения.
     */
    private fun applyLanExclusions(builder: VpnService.Builder) {
        val nets = listOf(
            "192.168.0.0" to 16,
            "172.16.0.0" to 12,
            "169.254.0.0" to 16
        )
        for ((addr, prefix) in nets) {
            runCatching { builder.addExcludedRoute(addr, prefix) }
                .onFailure { LogManager.w("Не удалось исключить локальную сеть $addr/$prefix: ${it.message}") }
        }
    }

    private suspend fun startVpn() {
        if (running) {
            updateNotification()
            return
        }
        val s = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        scope = s
        VpnController.markStarting()
        TrafficStats.reset()
        ReverseHostCache.clear()

        // Сервис запущен через startForegroundService(), поэтому startForeground()
        // обязан прозвучать до любой асинхронной работы — в том числе до первого
        // обращения к конфигурации и до establish(). establish() может вернуть
        // null (отозванное разрешение VPN, чужой активный туннель, недопустимый
        // маршрут), и раньше в этом случае процесс убивался системой с
        // ForegroundServiceDidNotStartInTimeException — вместо внятной ошибки
        // пользователь получал падение приложения.
        startForegroundSafe(null)

        s.launch {
            try {
                AppGraph.config.ensureLoaded()
            } catch (e: Exception) {
                LogManager.w("Не удалось прочитать конфигурацию", e)
            }
            val cfg = AppGraph.config.current
            LogManager.verbose = cfg.verboseLog
            if (cfg.profile == ProfileId.OFF) {
                LogManager.i(LogTag.VPN, "Профиль «Выключено» — туннель не поднимается")
                stopEverything("профиль выключен")
                return@launch
            }
            if (!cfg.ipv4 && !cfg.ipv6) {
                fail("Выключены и IPv4, и IPv6 — туннелю некуда маршрутизировать трафик")
                return@launch
            }
            try {
                withContext(Dispatchers.Main) { establish(cfg) }
            } catch (e: Exception) {
                fail(e.message ?: e.javaClass.simpleName)
            }
        }
    }

    /** Ограничение MTU, вычисленное по физической сети при подъёме туннеля. */
    @Volatile
    private var mtuCap: Int = Int.MAX_VALUE

    private var reconnectAttempts = 0

    @Volatile
    private var userStopped = false

    /**
     * Конфигурация для потоков туннеля: та же, что в репозитории, но с MTU,
     * приведённым к возможностям физической сети.
     *
     * Иначе MSS-кламп считался бы от 1500, а в tun уходили бы пакеты крупнее
     * реального MTU канала. На мобильных сетях это классическая «чёрная дыра»:
     * рукопожатие проходит, а данные не идут.
     */
    private fun tunnelConfig(): AppConfig {
        val c = AppGraph.config.current
        val cap = mtuCap
        return if (c.mtu > cap) c.copy(mtu = cap) else c
    }

    private fun establish(requested: AppConfig) {
        // Защита от любого пути, который мог бы поднять туннель «в выключенном»
        // состоянии: перезапуск, автопереподключение после отзыва и т.п.
        if (!tunnelRequired(requested)) {
            LogManager.i(LogTag.VPN, "Туннель не поднимается: профиль выключен или нет ни IPv4, ни IPv6")
            stopEverything("профиль выключен")
            return
        }
        mtuCap = computeMtuCap(requested)
        val cfg = if (requested.mtu > mtuCap) requested.copy(mtu = mtuCap) else requested
        if (cfg.mtu != requested.mtu) {
            LogManager.i(LogTag.VPN, "MTU понижен ${requested.mtu} → ${cfg.mtu} под физическую сеть")
        }
        val builder = Builder()
            .setSession(getString(R.string.app_name))
            .setConfigureIntent(
                PendingIntent.getActivity(
                    this, 0,
                    Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
            )
            .setMtu(cfg.mtu.coerceIn(576, 10000).also { negotiatedMtu = it })
            .setBlocking(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            runCatching { builder.setMetered(false) }
        }

        var hasV4 = false
        var hasV6 = false
        if (cfg.ipv4) {
            try {
                builder.addAddress(VPN_ADDR_V4, 32)
                builder.addRoute("0.0.0.0", 0)
                builder.addDnsServer(DNS_ADDR_V4)
                hasV4 = true
            } catch (e: Exception) {
                LogManager.e("Не удалось настроить IPv4 туннеля", e)
            }
        }
        if (cfg.ipv6) {
            // Объявлять маршрут ::/0 в сети без IPv6 бессмысленно и вредно:
            // приложения получают AAAA, пробуют v6 и висят по connectTimeout
            // (в логе это выглядит как «интернет есть, но всё очень медленно»).
            if (physicalHasIpv6()) {
                try {
                    builder.addAddress(VPN_ADDR_V6, 128)
                    builder.addRoute("::", 0)
                    builder.addDnsServer(DNS_ADDR_V6)
                    hasV6 = true
                } catch (e: Exception) {
                    LogManager.w("IPv6 недоступен на этом устройстве: ${e.message}")
                }
            } else {
                LogManager.i(
                    LogTag.VPN,
                    "IPv6 включён в настройках, но у физической сети нет IPv6-адреса — " +
                        "маршрут ::/0 не объявляем"
                )
            }
        }
        if (!hasV4 && !hasV6) throw IllegalStateException("не удалось назначить адрес туннелю")

        applyLanExclusions(builder)

        applyAppScope(builder, cfg)

        watchUnderlyingNetwork()
        isolationReported = false

        val fd = builder.establish() ?: throw IllegalStateException("establish() вернул null")
        pfd = fd
        input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val writer = PacketWriter(output)

        val s = scope ?: CoroutineScope(SupervisorJob() + Dispatchers.IO)

        val dns = DnsHandler(
            writer = writer,
            protector = protector,
            scope = s,
            io = Dispatchers.IO,
            configProvider = { tunnelConfig() },
            listsProvider = { AppGraph.lists.current },
            virtualServers = setOf(DNS_ADDR_V4, DNS_ADDR_V6),
            virtualAddresses = VIRTUAL_DNS_ADDRESSES
        )

        val tcp = TcpStack(
            writer = writer,
            protector = protector,
            scope = s,
            configProvider = { tunnelConfig() },
            listsProvider = { AppGraph.lists.current },
            virtualDns = VIRTUAL_DNS_ADDRESSES
        )
        tcp.dnsRedirect = pickDnsRedirect(cfg)

        val udp = UdpStack(
            writer = writer,
            protector = protector,
            configProvider = { tunnelConfig() },
            listsProvider = { AppGraph.lists.current }
        )

        dnsHandler = dns
        tcpStack = tcp
        udpStack = udp

        tunnelSignature = signature(cfg)
        running = true
        reconnectAttempts = 0
        userStopped = false
        instance = this
        VpnController.markRunning()

        startForegroundSafe(profileName(cfg.profile))
        readCount.set(0)
        handledCount.set(0)
        errorCount.set(0)
        startReader()
        startTrafficWatchdog()
        startSelfHeal()
        startConfigWatcher()
        startNotificationTicker()
        selfTest()

        LogManager.i(
            LogTag.VPN,
            "Туннель поднят: ${if (hasV4) "IPv4 " else ""}${if (hasV6) "IPv6" else ""} · MTU ${cfg.mtu} · DNS ${cfg.dnsMode} · профиль ${profileName(cfg.profile)}"
        )
    }

    /**
     * Короткая самопроверка сразу после подъёма туннеля. Её результат пишется в
     * журнал обычным (не подробным) уровнем, поэтому по одному скриншоту видно,
     * на каком именно звене рвётся цепочка: защищённый сокет, определение адреса
     * DoH-сервера или полное разрешение имён.
     */
    private fun selfTest() {
        val resolver = dnsHandler?.resolver ?: return
        scope?.launch(Dispatchers.IO) {
            delay(700)
            val cfg = AppGraph.config.current
            val host = when (cfg.dnsMode) {
                DnsMode.DOH -> cfg.dohUrl.substringAfter("://").substringBefore('/').substringBefore(':')
                DnsMode.DOT -> cfg.dotHost.substringBefore(':')
                else -> null
            }
            LogManager.i(LogTag.DNS, "Самопроверка · режим ${cfg.dnsMode}" + (if (host != null) ", сервер $host" else ""))
            LogManager.i(LogTag.DNS, "Самопроверка · защищённый UDP 1.1.1.1/8.8.8.8: ${resolver.diagProtectedUdp("www.google.com")}")
            if (host != null) {
                LogManager.i(LogTag.DNS, "Самопроверка · адрес сервера $host: ${resolver.diagBootstrap(host)}")
            }
            LogManager.i(LogTag.DNS, "Самопроверка · lookup www.google.com: ${resolver.diagLookup("www.google.com")}")

            // Живая проверка прохождения трафика: настоящий TLS-handshake через
            // наш стек с текущей стратегией. Третий хост намеренно ВНЕ списка —
            // по нему видно, не ломаем ли мы то, что трогать не должны.
            val stack = tcpStack
            if (stack != null) {
                val probeTargets = listOf("www.google.com", "www.youtube.com", "example.com")
                val autopilot = StrategyAutopilot(stack)
                for (host in probeTargets) {
                    if (!running) return@launch
                    val addr = try {
                        (resolver.lookup(host, DnsType.A) as? DnsResult.Addresses)?.list?.firstOrNull()
                    } catch (e: Exception) {
                        null
                    }
                    if (addr == null) {
                        LogManager.w("Проверка связи: $host — имя не разрешилось, соединение не проверялось")
                        continue
                    }
                    // Стратегия берётся тем же резолвером, что и для настоящего трафика. Иначе
                    // проверка врёт: правила для хоста не применялись бы, и
                    // зонд показывал бы обход там, где его нет, или наоборот.
                    val decision = try {
                        stack.resolveFor(443, host, addr, 0)
                    } catch (e: Exception) {
                        null
                    }
                    val ok = try {
                        autopilot.probe(addr, 443, host, decision?.strategy ?: cfg.toStrategy(), 9000)
                    } catch (e: Exception) {
                        LogManager.w("Проверка связи: $host — сбой зонда: ${e.message}")
                        false
                    }
                    if (ok) {
                        LogManager.i(LogTag.VPN, "Проверка связи: $host (${addr.hostAddress}) — TLS ServerHello получен, трафик проходит")
                    } else {
                        LogManager.w("Проверка связи: $host (${addr.hostAddress}) — ответа сервера НЕТ (правило: ${decision?.reason ?: "общая стратегия"})")
                    }
                }
            }
        }
    }

    /** MTU, который реально выдержит нижележащая сеть, с запасом для сотовых. */
    private fun computeMtuCap(cfg: AppConfig): Int {
        val requested = cfg.mtu.coerceIn(576, 10000)
        val physical = physicalMtu()
        val cap = when {
            physical != null -> minOf(requested, physical)
            isCellular() -> minOf(requested, CELLULAR_SAFE_MTU)
            else -> requested
        }
        return cap.coerceIn(576, 10000)
    }

    /** LinkProperties.getMtu() — API 29+; 0 означает «значение по умолчанию». */
    private fun physicalMtu(): Int? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        return try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return null
            val networks = cm.allNetworks ?: return null
            var best: Int? = null
            for (n in networks) {
                val caps = runCatching { cm.getNetworkCapabilities(n) }.getOrNull() ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
                val mtu = runCatching { cm.getLinkProperties(n)?.mtu ?: 0 }.getOrDefault(0)
                if (mtu in 576..10000 && (best == null || mtu < best!!)) best = mtu
            }
            best
        } catch (e: Throwable) {
            null
        }
    }

    private fun isCellular(): Boolean = try {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        val networks = cm.allNetworks ?: return false
        networks.any { n ->
            val caps = runCatching { cm.getNetworkCapabilities(n) }.getOrNull() ?: return@any false
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
        }
    } catch (e: Throwable) {
        false
    }

    /**
     * Есть ли у физической (не-VPN) сети реальный IPv6-адрес.
     *
     * Проверяем именно адрес в [LinkProperties], а не `NET_CAPABILITY_IPV6`:
     * у части операторов capability выставлен, а трафик всё равно не уходит
     * (IPv6-only APN без маршрута, tethering без v6).
     */
    private fun physicalHasIpv6(): Boolean = try {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        val networks = cm.allNetworks ?: return false
        networks.any { n ->
            val caps = runCatching { cm.getNetworkCapabilities(n) }.getOrNull() ?: return@any false
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@any false
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@any false
            val links = runCatching { cm.getLinkProperties(n)?.linkAddresses }.getOrNull() ?: return@any false
            links.any { it.address is java.net.Inet6Address && !it.address.isLinkLocalAddress }
        }
    } catch (e: Throwable) {
        false
    }

    private fun applyAppScope(builder: Builder, cfg: AppConfig) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return
        try {
            when (cfg.appScope) {
                AppScope.ALL ->
                    builder.addDisallowedApplication(packageName)

                AppScope.EXCLUDE -> {
                    builder.addDisallowedApplication(packageName)
                    for (p in cfg.appPackages) {
                        if (p == packageName) continue
                        runCatching { builder.addDisallowedApplication(p) }
                    }
                }

                AppScope.INCLUDE -> {
                    // Собственный пакет сюда добавлять нельзя — разрешённый и запрещённый
                    // списки не пересекаются. От зацикливания нас защищает protect().
                    for (p in cfg.appPackages) {
                        if (p == packageName) continue
                        runCatching { builder.addAllowedApplication(p) }
                    }
                }
            }
        } catch (e: Exception) {
            LogManager.w("Не удалось применить область действия: ${e.message}")
        }
    }

    private fun pickDnsRedirect(cfg: AppConfig): InetAddress? {
        val candidates = when (cfg.dnsMode) {
            DnsMode.CUSTOM -> cfg.dnsServers.lineSequence()
                .mapNotNull { IpLiterals.parseHostPort(it.trim(), 53)?.first }
                .mapNotNull { IpLiterals.parse(it) }
                .toList()
            else -> dnsHandler?.resolver?.systemDnsServers() ?: emptyList()
        }
        return candidates.firstOrNull() ?: IpLiterals.parse("1.1.1.1")
    }

    /* ------------------------------------------------------------ */
    /*  Основной цикл чтения tun                                     */
    /* ------------------------------------------------------------ */

    /** Сколько пакетов пришло из tun. Нуль при поднятом туннеле — отдельная беда. */
    private val readCount = AtomicLong()
    private val handledCount = AtomicLong()
    private val errorCount = AtomicLong()

    private fun startReader() {
        val thread = Thread({
            val stream = input ?: return@Thread
            val buf = ByteArray(32767)
            while (running) {
                val len: Int = try {
                    stream.read(buf)
                } catch (e: Exception) {
                    if (running) {
                        val n = errorCount.incrementAndGet()
                        if (n <= 3) LogManager.w("Ошибка чтения tun (${n}/3): ${e.message}")
                    }
                    -1
                }
                if (len < 0) break
                if (len == 0) continue
                val n = readCount.incrementAndGet()
                if (n == 1L) {
                    LogManager.i(LogTag.VPN, "Первый пакет из tun получен ($len байт) — маршрут в туннель есть")
                }
                try {
                    handlePacket(buf, len)
                    handledCount.incrementAndGet()
                } catch (e: Exception) {
                    val c = errorCount.incrementAndGet()
                    if (c <= 3) LogManager.w("Ошибка обработки пакета ($len байт, ${c}/3): ${e.message}", e)
                }
            }
            LogManager.w("Цикл чтения tun завершён: прочитано ${readCount.get()}, обработано ${handledCount.get()}")
        }, "zapret-tun-reader")
        thread.priority = Thread.NORM_PRIORITY + 2
        readerThread = thread
        thread.start()
    }

    /**
     * Через несколько секунд после старта туннеля отвечаем на главный вопрос:
     * доходят ли до нас пакеты вообще. Если tun молчит — проблема не в
     * стратегиях, а в маршрутизации системы (другой VPN, антивирус, прокси).
     */
    private fun startTrafficWatchdog() {
        val before = readCount.get()
        AppGraph.scope.launch {
            delay(5000)
            if (!running) return@launch
            val now = readCount.get()
            if (now - before == 0L) {
                LogManager.w(
                    "За 5 с из tun не пришло ни одного пакета: трафик не маршрутизируется в туннель. " +
                        "Причина обычно вне приложения — другой активный VPN, антивирус с собственным " +
                        "туннелем или системный прокси"
                )
            } else {
                LogManager.i(
                    LogTag.VPN,
                    "tun за 5 с: прочитано ${now - before} пакетов, обработано ${handledCount.get()}, ошибок ${errorCount.get()}"
                )
            }
        }
    }

    /**
     * Самоисцеление: если туннель поднят, пакеты в него поступают, но за
     * четверть минуты не установилось НИ ОДНОГО TCP-соединения, значит текущая
     * стратегия на этом пути не работает. Тогда автоподбор прогоняет кандидатов
     * сам и применяет победителя — без участия пользователя.
     */
    private fun startSelfHeal() {
        AppGraph.scope.launch {
            delay(25_000)
            if (!running) return@launch
            val stack = tcpStack ?: return@launch
            val read = readCount.get()
            val ok = stack.establishedTotal.get()
            val failed = stack.failedTotal.get()
            // DoH/DoT в РФ часто блокируется самим DPI: каждая попытка ждёт
            // таймаут, и для пользователя это выглядит как полный отказ сети.
            val resolver = dnsHandler?.resolver
            val cfgNow = AppGraph.config.current
            if (resolver != null && resolver.secureDnsFailures >= 3 &&
                (cfgNow.dnsMode == DnsMode.DOH || cfgNow.dnsMode == DnsMode.DOT)
            ) {
                LogManager.w(
                    "Самопроверка: ${cfgNow.dnsMode} не ответил ${resolver.secureDnsFailures} раз — " +
                        "переключаю DNS в системный режим"
                )
                runCatching { AppGraph.config.update { it.copy(dnsMode = DnsMode.SYSTEM) } }
            }
            if (read <= 0) return@launch
            if (ok > 0) {
                LogManager.i(LogTag.VPN, "Самопроверка: установлено TCP-соединений через туннель: $ok (ошибок: $failed)")
                return@launch
            }
            LogManager.w(
                "Самопроверка: за 25 с прошло $read пакетов, но ни одно TCP-соединение не установилось " +
                    "(ошибок: $failed). Запускаю автоподбор стратегии"
            )
            val hosts = autopilotHosts(tunnelConfig().profile)
            val base = AppGraph.config.current
            val perHost = try {
                // Параметр назван явно: после onProgress лямбда в конце
                // больше не привязывается к lookup.
                StrategyAutopilot(stack).tunePerHost(hosts, lookup = { host ->
                    val r = resolver?.lookup(host, DnsType.A)
                    (r as? DnsResult.Addresses)?.list?.firstOrNull()
                })
            } catch (e: Exception) {
                LogManager.w("Автоподбор завершился ошибкой: ${e.message}")
                emptyMap()
            }
            if (perHost.isEmpty()) {
                LogManager.w(
                    "Автоподбор: ни одна стратегия не получила ответа сервера — дело не в обходе, " +
                        "а в сети, DNS или самом туннеле"
                )
                return@launch
            }
            for ((host, named) in perHost) {
                LogManager.i(LogTag.DPI, "Автоподбор: $host → подошло «${named.first}» — применяю")
            }
            try {
                AppGraph.config.update { it.withTunedPerHost(perHost, base.tcpPorts) }
            } catch (e: Exception) {
                LogManager.w("Не удалось сохранить подобранную стратегию: ${e.message}")
            }
        }
    }

    /** Хосты для проверки: по профилю берём те, ради которых туннель и включён. */
    private fun autopilotHosts(profile: dev.rubcut.zapret.data.ProfileId): List<String> = when (profile) {
        dev.rubcut.zapret.data.ProfileId.YOUTUBE -> listOf("www.youtube.com", "youtubei.googleapis.com")
        dev.rubcut.zapret.data.ProfileId.DISCORD -> listOf("discord.com", "gateway.discord.gg")
        dev.rubcut.zapret.data.ProfileId.COMBINED -> listOf("www.youtube.com", "discord.com")
        dev.rubcut.zapret.data.ProfileId.MAX -> listOf("www.youtube.com", "www.google.com", "discord.com")
        else -> listOf("www.google.com")
    }

    private fun handlePacket(buf: ByteArray, len: Int) {
        val ip = parseIp(buf, len) ?: run { TrafficStats.dropped(); return }
        val tcp = tcpStack
        val udp = udpStack
        val dns = dnsHandler
        if (tcp == null || udp == null || dns == null) return

        when {
            ip.isTcp -> {
                val seg = parseTcp(buf, ip.payloadOffset, ip.payloadLength)
                if (seg == null) TrafficStats.dropped() else tcp.onPacket(ip, seg)
            }

            ip.isUdp -> {
                val dgram = parseUdp(buf, ip.payloadOffset, ip.payloadLength)
                if (dgram == null) {
                    TrafficStats.dropped()
                } else if (!dns.handle(ip, dgram)) {
                    udp.onPacket(ip, dgram)
                }
            }

            else -> TrafficStats.dropped()
        }
    }

    /* ------------------------------------------------------------ */
    /*  Горячее применение настроек                                  */
    /* ------------------------------------------------------------ */

    private fun startConfigWatcher() {
        configJob?.cancel()
        configJob = scope?.launch {
            var lastSignature = tunnelSignature
            AppGraph.config.config.collect { cfg ->
                LogManager.verbose = cfg.verboseLog
                val sig = signature(cfg)
                if (sig != lastSignature) {
                    lastSignature = sig
                    if (!tunnelRequired(cfg)) {
                        // «Выключено» должно означать именно отсутствие VPN:
                        // интерфейс освобождается, и телефон возвращается к
                        // обычной сети оператора.
                        LogManager.i(LogTag.VPN, "Профиль выключен — останавливаю туннель")
                        stopEverything("профиль выключен")
                    } else {
                        LogManager.i(LogTag.VPN, "Изменились параметры туннеля — перезапуск")
                        restart()
                    }
                } else {
                    updateNotification()
                }
            }
        }
    }

    private fun signature(cfg: AppConfig): String =
        listOf(cfg.mtu, cfg.ipv4, cfg.ipv6, cfg.appScope, cfg.appPackages.sorted().joinToString(","), cfg.profile)
            .joinToString("|")

    /** Туннель нужен только при включённом профиле и хотя бы одной семье IP. */
    private fun tunnelRequired(cfg: AppConfig): Boolean =
        cfg.profile != ProfileId.OFF && (cfg.ipv4 || cfg.ipv6)

    private fun restart() {
        running = false
        teardown()
        AppGraph.scope.launch {
            delay(200)
            val cfg = AppGraph.config.current
            withContext(Dispatchers.Main) {
                if (!tunnelRequired(cfg)) {
                    stopEverything("профиль выключен")
                    return@withContext
                }
                try {
                    scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
                    TrafficStats.reset()
                    ReverseHostCache.clear()
                    establish(cfg)
                } catch (e: Exception) {
                    fail(e.message ?: "restart failed")
                }
            }
        }
    }

    private fun startNotificationTicker() {
        notifJob?.cancel()
        notifJob = scope?.launch {
            while (isActive && running) {
                delay(3000)
                updateNotification()
            }
        }
    }

    /* ------------------------------------------------------------ */
    /*  Остановка                                                    */
    /* ------------------------------------------------------------ */

    private fun stopEverything(reason: String) {
        if (reason == "по запросу пользователя") userStopped = true
        if (!running && pfd == null && scope == null) {
            VpnController.markStopped()
            return
        }
        LogManager.i(LogTag.VPN, "Остановка туннеля: $reason")
        running = false
        teardown()
        TrafficStats.stopped()
        VpnController.markStopped()
        try {
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        } catch (_: Exception) {
        }
        // Молчаливая остановка — худший вариант: пользователь думает, что обход
        // работает, а трафик давно идёт мимо. О тихой остановке сообщаем явно.
        if (reason != "по запросу пользователя" && reason != "профиль выключен") {
            postEvent(getString(R.string.notif_event_stopped), reason)
        }
        stopSelf()
    }

    private fun fail(message: String) {
        LogManager.e("Туннель не поднят: $message")
        VpnController.markError(message)
        running = false
        teardown()
        TrafficStats.stopped()
        try {
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        } catch (_: Exception) {
        }
        postEvent(getString(R.string.notif_event_failed), message)
        stopSelf()
    }

    /**
     * Событийное уведомление (канал CHANNEL_EVENTS) — то самое, чем управляет
     * переключатель «Уведомление о работе». Само постоянное уведомление
     * foreground-сервиса отключить нельзя: Android требует его всегда.
     */
    private fun postEvent(title: String, text: String) {
        if (!AppGraph.ready) return
        if (!AppGraph.config.current.notificationEnabled) return
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                checkSelfNotificationPermission() != android.content.pm.PackageManager.PERMISSION_GRANTED
            ) {
                return
            }
            val nm = getSystemService(NotificationManager::class.java) ?: return
            val openIntent = PendingIntent.getActivity(
                this, 12, Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            nm.notify(
                EVENT_NOTIFICATION_ID,
                NotificationCompat.Builder(this, CHANNEL_EVENTS)
                    .setSmallIcon(R.drawable.ic_notification)
                    .setContentTitle(title)
                    .setContentText(text)
                    .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                    .setContentIntent(openIntent)
                    .setAutoCancel(true)
                    .setOnlyAlertOnce(true)
                    .setColor(ContextCompat.getColor(this, R.color.ic_launcher_background))
                    .build()
            )
        } catch (e: Exception) {
            LogManager.d(LogTag.VPN, "событийное уведомление: ${e.message}")
        }
    }

    private fun checkSelfNotificationPermission(): Int =
        checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS)

    /**
     * Короткая сводка состояния туннеля для отчёта «одной кнопкой»: по ней
     * видно, доходят ли пакеты до tun, устанавливаются ли соединения и
     * изолированы ли upstream-сокеты.
     */
    fun briefStats(): String {
        val stack = tcpStack
        return "прочитано из tun=${readCount.get()}, обработано=${handledCount.get()}, ошибок=${errorCount.get()}; " +
            "TCP установлено=${stack?.establishedTotal?.get() ?: 0}, упало=${stack?.failedTotal?.get() ?: 0}, " +
            "активных=${stack?.activeCount ?: 0}; udp-сессий=${udpStack?.activeCount ?: 0}; " +
            "mtu=$negotiatedMtu; в tun не записалось=${tcpStack?.packetWriter?.droppedCount ?: 0}; изоляция: $isolationSummary"
    }

    /** Живой стек туннеля — для автоподбора стратегий из UI. */
    val probeStack: TcpStack? get() = if (running) tcpStack else null

    /** Живой DNS-резолвер туннеля — автоподбору нужно разрешать имена probing-хостов. */
    val probeResolver: dev.rubcut.zapret.core.dns.DnsResolver? get() = dnsHandler?.resolver

    private fun teardown() {
        unwatchUnderlyingNetwork()
        configJob?.cancel(); configJob = null
        notifJob?.cancel(); notifJob = null
        try { readerThread?.interrupt() } catch (_: Exception) {}
        readerThread = null
        try { tcpStack?.shutdown() } catch (_: Exception) {}
        try { udpStack?.shutdown() } catch (_: Exception) {}
        try { dnsHandler?.close() } catch (_: Exception) {}
        tcpStack = null
        udpStack = null
        dnsHandler = null
        try { input?.close() } catch (_: Exception) {}
        input = null
        try { pfd?.close() } catch (_: Exception) {}
        pfd = null
        try { scope?.cancel() } catch (_: Exception) {}
        scope = null
        instance = null
    }

    /* ------------------------------------------------------------ */
    /*  Уведомление                                                  */
    /* ------------------------------------------------------------ */

    private fun createChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(NotificationManager::class.java) ?: return
        val main = NotificationChannel(
            CHANNEL_MAIN,
            getString(R.string.notif_channel_main),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.notif_channel_main_desc)
            setShowBadge(false)
        }
        val events = NotificationChannel(
            CHANNEL_EVENTS,
            getString(R.string.notif_channel_logs),
            NotificationManager.IMPORTANCE_DEFAULT
        )
        runCatching { nm.createNotificationChannel(main) }
        runCatching { nm.createNotificationChannel(events) }
    }

    private fun startForegroundSafe(profileName: String?) {
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else 0
        try {
            ServiceCompat.startForeground(this, NOTIFICATION_ID, buildNotification(profileName, 0), type)
        } catch (e: Exception) {
            LogManager.e("startForeground не удался", e)
        }
    }

    private fun updateNotification() {
        if (!running) return
        try {
            val nm = getSystemService(NotificationManager::class.java) ?: return
            val cfg = AppGraph.config.current
            nm.notify(NOTIFICATION_ID, buildNotification(profileName(cfg.profile), TrafficStats.activeConnections))
        } catch (e: Exception) {
            LogManager.d(LogTag.VPN, "notify: ${e.message}")
        }
    }

    /** [profileName] == null — туннель ещё поднимается, уведомление об этом. */
    private fun buildNotification(profileName: String?, connections: Int): Notification {
        val openIntent = PendingIntent.getActivity(
            this, 10, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = PendingIntent.getService(
            this, 11,
            Intent(this, ZapretVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_MAIN)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(
                if (profileName == null) getString(R.string.notif_title_starting)
                else getString(R.string.notif_title_running)
            )
            .setContentText(
                if (profileName == null) getString(R.string.notif_text_starting)
                else getString(R.string.notif_text_running, profileName, connections)
            )
            .setContentIntent(openIntent)
            .addAction(0, getString(R.string.notif_action_open), openIntent)
            .addAction(0, getString(R.string.notif_action_stop), stopIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setColor(ContextCompat.getColor(this, R.color.ic_launcher_background))
            .build()
    }

    private fun profileName(id: ProfileId): String = getString(
        when (id) {
            ProfileId.OFF -> R.string.profile_off
            ProfileId.YOUTUBE -> R.string.profile_youtube
            ProfileId.DISCORD -> R.string.profile_discord
            ProfileId.COMBINED -> R.string.profile_combined
            ProfileId.MAX -> R.string.profile_max
            ProfileId.CUSTOM -> R.string.profile_custom
        }
    )
}
