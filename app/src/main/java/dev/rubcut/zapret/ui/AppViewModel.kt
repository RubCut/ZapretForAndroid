package dev.rubcut.zapret.ui

import android.app.Application
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import dev.rubcut.zapret.AppGraph
import dev.rubcut.zapret.BuildConfig
import dev.rubcut.zapret.R
import dev.rubcut.zapret.core.ConnectionLog
import dev.rubcut.zapret.core.LogEntry
import dev.rubcut.zapret.core.LogManager
import dev.rubcut.zapret.core.RecentConnection
import dev.rubcut.zapret.core.SocketProtector
import dev.rubcut.zapret.core.StatsSnapshot
import dev.rubcut.zapret.core.TrafficStats
import dev.rubcut.zapret.core.desync.withTunedPerHost
import dev.rubcut.zapret.core.dns.DnsResolver
import dev.rubcut.zapret.core.dns.testResolver
import dev.rubcut.zapret.config.ParseResult
import dev.rubcut.zapret.config.ZapretArgsParser
import dev.rubcut.zapret.data.AccentPalette
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.HostListStore
import dev.rubcut.zapret.data.ThemeMode
import dev.rubcut.zapret.data.Presets
import dev.rubcut.zapret.data.ProfileId
import dev.rubcut.zapret.data.StrategyRule
import dev.rubcut.zapret.core.dns.DnsResult
import dev.rubcut.zapret.core.dns.DnsType
import dev.rubcut.zapret.core.stack.StrategyAutopilot
import dev.rubcut.zapret.vpn.VpnController
import dev.rubcut.zapret.vpn.VpnState
import dev.rubcut.zapret.vpn.ZapretVpnService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import java.net.DatagramSocket
import java.net.Socket

class AppViewModel(app: Application) : AndroidViewModel(app) {

    private val repo = AppGraph.config
    private val lists = AppGraph.lists

    val config: StateFlow<AppConfig> = repo.config
    val listSnapshot: StateFlow<HostListStore.Snapshot> = lists.snapshot
    val vpnState: StateFlow<VpnState> = VpnController.state
    val vpnError: StateFlow<String?> = VpnController.error
    val stats: StateFlow<StatsSnapshot> = TrafficStats.snapshot
    val recent: StateFlow<List<RecentConnection>> = ConnectionLog.entries
    val logs: StateFlow<List<LogEntry>> = LogManager.entries

    val snackbar = MutableStateFlow<String?>(null)

    /** Автоподбор стратегий: состояние и результат для экрана «Стратегия». */
    val autopilotRunning = MutableStateFlow(false)
    val autopilotResult = MutableStateFlow<String?>(null)

    /**
     * Живой прогресс подбора: какой хост и какой кандидат проверяются сейчас.
     *
     * Подбор идёт до 12 кандидатов на каждый хост с таймаутом 6 с, и без этого
     * экран молчал бы минуты-полторы, выглядя как зависший.
     */
    val autopilotProgress = MutableStateFlow<String?>(null)

    /* ------------------------------ конфигурация ------------------------------ */

    fun update(block: (AppConfig) -> AppConfig) {
        viewModelScope.launch { repo.update(block) }
    }

    /** Правка стратегии вручную автоматически переводит профиль в «Свой». */
    fun updateStrategy(block: (AppConfig) -> AppConfig) {
        viewModelScope.launch {
            repo.update { current ->
                val next = block(current)
                if (next.profile == ProfileId.OFF) next else next.copy(profile = ProfileId.CUSTOM)
            }
        }
    }

    fun setProfile(id: ProfileId) {
        viewModelScope.launch { repo.update { Presets.apply(id, it) } }
    }

    fun resetAll() {
        viewModelScope.launch {
            repo.reset()
            lists.resetToBuiltin()
            ConnectionLog.clear()
            notify(msg(R.string.msg_reset_all))
        }
    }

    /* ------------------------------ оформление ------------------------------ */

    fun setThemeMode(mode: ThemeMode) = update { it.copy(theme = mode) }

    fun setAccent(accent: AccentPalette) = update { it.copy(accent = accent) }

    fun setDynamicColor(enabled: Boolean) = update { it.copy(dynamicColor = enabled) }

    fun setAutostart(enabled: Boolean) = update { it.copy(autoStart = enabled) }

    fun setNotification(enabled: Boolean) = update { it.copy(notificationEnabled = enabled) }

    fun setVerboseLog(enabled: Boolean) {
        LogManager.verbose = enabled
        update { it.copy(verboseLog = enabled) }
    }

    /* ------------------------------ системные настройки ------------------------------ */

    /** Запрос на отключение оптимизации батареи — иначе Android убивает туннель в фоне. */
    fun openBatterySettings() {
        val ctx = getApplication<Application>()
        val ignoring = runCatching {
            val pm = ctx.getSystemService(Context.POWER_SERVICE) as? PowerManager
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
                pm?.isIgnoringBatteryOptimizations(ctx.packageName) == true
        }.getOrDefault(false)
        if (ignoring) {
            notify(msg(R.string.msg_battery_already_off))
            return
        }
        val direct = Intent(
            Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
            Uri.parse("package:" + ctx.packageName)
        )
        if (!launch(direct)) launch(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
    }

    fun openAlwaysOnSettings() {
        if (!launch(Intent(Settings.ACTION_VPN_SETTINGS))) openAppSettings()
    }

    fun openVpnSettings() = openAlwaysOnSettings()

    fun requestNotificationPermission() {
        val ctx = getApplication<Application>()
        val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
            .putExtra(Settings.EXTRA_APP_PACKAGE, ctx.packageName)
        if (!launch(intent)) openAppSettings()
    }

    fun openAppSettings() {
        val ctx = getApplication<Application>()
        launch(
            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + ctx.packageName))
        )
    }

    private fun launch(intent: Intent): Boolean = runCatching {
        getApplication<Application>().startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        true
    }.getOrDefault(false)

    /* ------------------------------ данные ------------------------------ */

    fun exportConfig(): String = repo.exportJson()

    fun exportJson(): String = repo.exportJson()

    fun importConfig(json: String) {
        viewModelScope.launch {
            val ok = repo.importJson(json)
            notify(msg(if (ok) R.string.msg_config_imported else R.string.msg_config_import_failed))
        }
    }

    /* ------------------------------ списки ------------------------------ */

    fun saveList(kind: HostListStore.Kind, text: String) {
        viewModelScope.launch {
            lists.save(kind, text)
            notify(msg(R.string.msg_list_saved))
        }
    }

    fun appendToList(kind: HostListStore.Kind, lines: List<String>) {
        viewModelScope.launch { lists.appendLines(kind, lines) }
    }

    fun resetLists() {
        viewModelScope.launch {
            lists.resetToBuiltin()
            notify(msg(R.string.msg_lists_restored))
        }
    }

    /* ------------------------------ правила ------------------------------ */

    fun upsertRule(rule: StrategyRule) {
        updateStrategy { cfg ->
            val index = cfg.rules.indexOfFirst { it.id == rule.id }
            val rules = if (index < 0) cfg.rules + rule else cfg.rules.toMutableList().also { it[index] = rule }
            cfg.copy(rules = rules)
        }
    }

    fun deleteRule(id: String) {
        updateStrategy { cfg -> cfg.copy(rules = cfg.rules.filterNot { it.id == id }) }
    }

    fun moveRule(id: String, delta: Int) {
        updateStrategy { cfg ->
            val index = cfg.rules.indexOfFirst { it.id == id }
            val target = index + delta
            if (index < 0 || target < 0 || target >= cfg.rules.size) return@updateStrategy cfg
            val rules = cfg.rules.toMutableList()
            val item = rules.removeAt(index)
            rules.add(target, item)
            cfg.copy(rules = rules)
        }
    }

    /* ------------------------------ аргументы zapret ------------------------------ */

    fun parseArgs(text: String): ParseResult = ZapretArgsParser.parse(text, repo.current)

    /** Разбирает строку и сразу применяет её к конфигурации. */
    fun applyArgs(text: String) {
        applyParsed(parseArgs(text))
    }

    fun applyParsed(result: ParseResult) {
        update { result.applyTo(it) }
        notify(msg(R.string.msg_args_applied))
    }

    fun generatedArgs(): String = ZapretArgsParser.generate(repo.current)

    /* ------------------------------ туннель ------------------------------ */

    fun prepareIntent(context: Context): Intent? = VpnController.prepareIntent(context)

    fun startTunnel(context: Context): Boolean = VpnController.requestStart(context)

    fun stopTunnel(context: Context) = VpnController.stop(context)

    fun toggleTunnel(context: Context): Boolean {
        if (VpnController.isRunning) {
            stopTunnel(context)
            return true
        }
        return startTunnel(context)
    }

    /**
     * Включение туннеля с гарантией, что профиль успеет смениться.
     *
     * Раньше UI делал `setProfile(COMBINED)` и тут же стартовал сервис. Запись в
     * DataStore асинхронна, сервис успевал прочитать старый профиль «Выключено»
     * и тут же себя останавливал — первое нажатие после выбора «Выключено»
     * выглядело как «ничего не произошло». Здесь смена профиля и запуск идут
     * в одной корутине и строго по порядку.
     */
    fun startTunnelWithDefaultProfile(context: Context) {
        if (prepareIntent(context) != null) return   // нужен диалог согласия — им займётся вызывающий
        viewModelScope.launch {
            if (repo.current.profile == ProfileId.OFF) {
                repo.update { Presets.apply(ProfileId.COMBINED, it) }
            }
            VpnController.startNow(context)
        }
    }

    fun clearRecent() = ConnectionLog.clear()

    fun clearLogs() = LogManager.clear()

    /**
     * Автоподбор стратегии обхода. Кандидаты прогоняются через живой стек
     * туннеля настоящим TLS ClientHello; побеждает тот, на которого сервер
     * ответил ServerHello. Пассивный режим проверяется первым: если DPI не
     * блокирует без обработки, обрабатывать нечего.
     */
    fun runAutopilot() {
        if (autopilotRunning.value) return
        viewModelScope.launch {
            val app = getApplication<Application>()
            val svc = ZapretVpnService.instance
            val stack = svc?.probeStack
            if (stack == null) {
                autopilotResult.value = app.getString(R.string.autopilot_need_vpn)
                return@launch
            }
            autopilotRunning.value = true
            autopilotResult.value = null
            autopilotProgress.value = null
            try {
                val hosts = when (config.value.profile) {
                    ProfileId.YOUTUBE -> listOf("www.youtube.com", "youtubei.googleapis.com")
                    ProfileId.DISCORD -> listOf("discord.com", "gateway.discord.gg")
                    ProfileId.COMBINED -> listOf("www.youtube.com", "discord.com")
                    ProfileId.MAX -> listOf("www.youtube.com", "www.google.com", "discord.com")
                    else -> listOf("www.google.com")
                }
                val resolver = svc.probeResolver
                val lookup: suspend (String) -> java.net.InetAddress? = { host ->
                    val r = resolver?.lookup(host, DnsType.A)
                    (r as? DnsResult.Addresses)?.list?.firstOrNull()
                }
                val current = config.value
                // По одному кандидату на хост: хосты блокируются по-разному, и
                // общий кандидат либо не подходит никому, либо ломает тех, кто
                // и так работает.
                val perHost = StrategyAutopilot(stack).tunePerHost(
                    hosts,
                    lookup = lookup,
                    onProgress = { autopilotProgress.value = it }
                )
                val winner = perHost.values.firstOrNull()?.second
                if (winner == null) {
                    autopilotResult.value = app.getString(R.string.autopilot_fail)
                } else {
                    // Сохраняем стратегию целиком: усечение до 4 полей молча
                    // выбрасывало sniCaseMix/poison/wssize — победивший приём
                    // не применялся бы, и следующий автоподбор находил бы то же самое.
                    update {
                        it.copy(
                            desync = winner.desync,
                            splitPositions = winner.splitPositions,
                            splitCustomPos = winner.splitCustomPos,
                            splitDelayMs = winner.splitDelayMs,
                            tlsrecParts = winner.tlsrecParts,
                            wssizeEnabled = winner.wssizeEnabled,
                            wssizePackets = winner.wssizePackets,
                            wssizeWindow = winner.wssizeWindow,
                            anyProtocol = winner.anyProtocol,
                            sniCaseMix = winner.sniCaseMix,
                            poisonEnabled = winner.poisonEnabled,
                            poisonSni = winner.poisonSni,
                            poisonDelayMs = winner.poisonDelayMs
                        ).withTunedPerHost(perHost, current.tcpPorts)
                    }
                    autopilotResult.value = app.getString(
                        R.string.autopilot_done,
                        perHost.values.first().first
                    )
                }
            } catch (e: Exception) {
                LogManager.w("Автоподбор не завершился: ${e.message}")
                autopilotResult.value = app.getString(R.string.autopilot_fail)
            } finally {
                autopilotRunning.value = false
                autopilotProgress.value = null
            }
        }
    }

    /**
     * Отчёт для поддержки одной кнопкой: конфигурация, состояние туннеля и
     * последние записи журнала обычным текстом. Его можно вставить в чат —
     * в отличие от скриншота он не теряет ни строки.
     */
    fun diagnosticsReport(): String {
        val cfg = config.value
        val svc = ZapretVpnService.instance
        val sb = StringBuilder()
        sb.appendLine("Zapret ${BuildConfig.GIT_SHA} · Android ${Build.VERSION.SDK_INT} · ${Build.MANUFACTURER} ${Build.MODEL}")
        sb.appendLine("туннель: ${vpnState.value}")
        sb.appendLine(
            "профиль=${cfg.profile} · desync=${cfg.desync} · pos=${cfg.splitPositions} · " +
                "tlsrec=${cfg.tlsrecParts} · задержка=${cfg.splitDelayMs}мс"
        )
        sb.appendLine("dns=${cfg.dnsMode} · перехват=${cfg.dnsHijack} · серверы=${cfg.dnsServers.replace("\n", ", ")}")
        sb.appendLine("mtu=${cfg.mtu} · mssClamp=${cfg.mssClamp} · приложения=${cfg.appScope} · udp=${cfg.udpMode}")
        sb.appendLine("туннель: " + (svc?.briefStats() ?: "сервис не запущен"))
        sb.appendLine("--- журнал (последние 40) ---")
        logs.value.takeLast(40).forEach { sb.appendLine("[${it.tag}] ${it.message}") }
        return sb.toString()
    }

    fun notify(message: String) {
        snackbar.value = message
    }

    /**
     * Текст всплывающего сообщения из ресурсов.
     *
     * Раньше такие строки были зашиты в коде по-русски, и пользователь с
     * английским интерфейсом получал русские сообщения — при том что весь
     * остальной интерфейс локализован.
     */
    private fun msg(id: Int): String = getApplication<Application>().getString(id)

    /** Короткое подтверждение действия (то же сообщение в snackbar). */
    fun toast(message: String) {
        snackbar.value = message
    }

    fun snackbarShown() {
        snackbar.value = null
    }

    /* ------------------------------ проверка DNS ------------------------------ */

    fun testDns(host: String, onResult: (String) -> Unit) {
        viewModelScope.launch {
            val protector: SocketProtector = ZapretVpnService.instance?.protector ?: DirectProtector
            val resolver = DnsResolver(
                context = getApplication(),
                configProvider = { repo.current },
                listsProvider = { lists.current },
                protector = protector
            )
            val text = try {
                testResolver(resolver, host)
            } catch (e: Exception) {
                e.message ?: e.javaClass.simpleName
            }
            resolver.close()
            onResult(text)
        }
    }

    private object DirectProtector : SocketProtector {
        override fun protect(socket: Socket) = false
        override fun protect(socket: DatagramSocket) = false
        override fun protect(fd: Int) = false
    }
}
