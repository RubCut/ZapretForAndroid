package dev.rubcut.zapret.data

/**
 * Текущая версия схемы [AppConfig].
 *
 * 1 — всё, что было до введения версионирования (без OOB/FAKE, со старыми
 *     правилами YouTube: смена регистра + разрыв по первому байту).
 * 2 — правила профилей освежены (tlsrec + середина домена, без смены
 *     регистра), добавлены поля urgentByte/fakeTtl.
 */
const val CURRENT_CONFIG_VERSION = 2

import org.json.JSONArray
import org.json.JSONObject

/**
 * Режим десинхронизации DPI.
 *
 * Оригинальный zapret умеет гораздо больше (fake, disorder, syndata, seqovl, rst, ipfrag…),
 * но все эти техники требуют подмены IP/TCP-заголовков исходящих пакетов, то есть raw-сокета
 * и root-прав. На Android без root исходящие пакеты формирует ядро, поэтому доступный
 * арсенал — это управление границами TCP-сегментов и переупаковка TLS-записей.
 */
enum class DesyncMode(val token: String) {
    NONE("none"),
    SPLIT("split"),
    MULTISPLIT("multisplit"),
    TLSREC("tlsrec"),
    MULTISPLIT_TLSREC("multisplit+tlsrec"),
    HOSTFAKESPLIT("hostfakesplit"),
    /**
     * Байт срочных данных после сегмента, аналог `--dpi-desync-oob`.
     *
     * Отличается от разбиения тем, что лишний байт уходит с флагом срочности
     * и в обычный поток получателя не попадает, хотя на проводе он есть.
     */
    OOB("oob"),
    /**
     * Пустышка с малым TTL перед настоящими данными, аналог `--dpi-desync-fake`.
     *
     * Пакет умирает на первом же хопе: сервер его не видит, а инлайновый
     * фильтр по пути — да. Требует управления TTL, доступного через
     * [dev.rubcut.zapret.core.stack.RawSocket] без root.
     */
    FAKE("fake");

    companion object {
        fun fromToken(token: String?): DesyncMode =
            values().firstOrNull { it.token.equals(token, true) } ?: NONE
    }
}

/** Точка разбиения первого блока данных клиента. Аналог --dpi-desync-split-pos. */
enum class SplitPos(val token: String) {
    FIRST("1"),
    MIDSNI("midsld"),
    SNIEND("sniend"),
    MIDDLE("middle"),
    CUSTOM("custom");

    companion object {
        fun fromToken(token: String?): SplitPos? {
            if (token == null) return null
            val t = token.trim()
            return when {
                t == "1" || t.equals("first", true) -> FIRST
                t.equals("midsld", true) || t.equals("midsni", true) -> MIDSNI
                t.equals("sniend", true) -> SNIEND
                t.equals("middle", true) || t.equals("mid", true) -> MIDDLE
                t.equals("custom", true) -> CUSTOM
                t.toIntOrNull() != null -> CUSTOM
                else -> null
            }
        }
    }
}

enum class HostlistMode(val token: String) {
    OFF("off"),
    INCLUDE("hostlist"),
    EXCLUDE("hostlist-exclude");

    companion object {
        fun fromToken(token: String?): HostlistMode =
            values().firstOrNull { it.token.equals(token, true) } ?: OFF
    }
}

enum class IpsetMode(val token: String) {
    OFF("off"),
    INCLUDE("ipset"),
    EXCLUDE("ipset-exclude");

    companion object {
        fun fromToken(token: String?): IpsetMode =
            values().firstOrNull { it.token.equals(token, true) } ?: OFF
    }
}

enum class UdpMode(val token: String) {
    RELAY("relay"),
    BLOCK_FILTERED("block-filtered"),
    BLOCK_ALL("block-all");

    companion object {
        fun fromToken(token: String?): UdpMode =
            values().firstOrNull { it.token.equals(token, true) } ?: RELAY
    }
}

enum class DnsMode(val token: String) {
    SYSTEM("system"),
    CUSTOM("custom"),
    DOH("doh"),
    DOT("dot");

    companion object {
        fun fromToken(token: String?): DnsMode =
            values().firstOrNull { it.token.equals(token, true) } ?: SYSTEM
    }
}

enum class ThemeMode { SYSTEM, LIGHT, DARK }

enum class AccentPalette { EMERALD, SKY, VIOLET, AMBER, ROSE, TEAL }

enum class AppScope { ALL, INCLUDE, EXCLUDE }

enum class ProfileId(val token: String) {
    OFF("off"),
    YOUTUBE("youtube"),
    DISCORD("discord"),
    COMBINED("combined"),
    MAX("max"),
    CUSTOM("custom");

    companion object {
        fun fromToken(token: String?): ProfileId =
            values().firstOrNull { it.token.equals(token, true) } ?: COMBINED
    }
}

/**
 * Фильтр портов в синтаксисе zapret: "80,443,50000-50100".
 * Пустая спецификация означает «все порты».
 */
class PortFilter private constructor(private val ranges: List<IntRange>) {

    val isAny: Boolean get() = ranges.isEmpty()

    fun matches(port: Int): Boolean {
        if (ranges.isEmpty()) return true
        for (r in ranges) if (port in r) return true
        return false
    }

    fun flatten(limit: Int = 64): List<Int> {
        if (ranges.isEmpty()) return emptyList()
        val out = ArrayList<Int>()
        for (r in ranges) {
            for (p in r) {
                out += p
                if (out.size >= limit) return out
            }
        }
        return out
    }

    override fun toString(): String =
        ranges.joinToString(",") { if (it.first == it.last) "${it.first}" else "${it.first}-${it.last}" }

    companion object {
        val ANY = PortFilter(emptyList())

        fun parse(spec: String?): PortFilter {
            val s = spec?.trim().orEmpty()
            if (s.isEmpty() || s == "*" || s == "0") return ANY
            val ranges = ArrayList<IntRange>()
            for (raw in s.split(',', ';', ' ').filter { it.isNotBlank() }) {
                val token = raw.trim()
                val dash = token.indexOf('-')
                if (dash > 0) {
                    val a = token.substring(0, dash).toIntOrNull() ?: continue
                    val b = token.substring(dash + 1).toIntOrNull() ?: continue
                    if (a in 1..65535 && b in 1..65535) ranges += (minOf(a, b)..maxOf(a, b))
                } else {
                    val v = token.toIntOrNull() ?: continue
                    if (v in 1..65535) ranges += (v..v)
                }
            }
            return if (ranges.isEmpty()) ANY else PortFilter(ranges)
        }
    }
}

/** Полная конфигурация приложения. Хранится одним JSON-документом в DataStore. */
data class AppConfig(
    // Общие
    val profile: ProfileId = ProfileId.COMBINED,
    val theme: ThemeMode = ThemeMode.SYSTEM,
    val dynamicColor: Boolean = true,
    val accent: AccentPalette = AccentPalette.EMERALD,
    val verboseLog: Boolean = false,
    val notificationEnabled: Boolean = true,
    val autoStart: Boolean = false,

    // Десинхронизация
    val desync: DesyncMode = DesyncMode.MULTISPLIT,
    val splitPositions: List<SplitPos> = listOf(SplitPos.MIDSNI),
    val splitCustomPos: Int = 2,
    val splitDelayMs: Int = 0,
    val cutoffChunks: Int = 1,
    val tlsrecParts: Int = 0,
    val wssizeEnabled: Boolean = false,
    val wssizePackets: Int = 6,
    val wssizeWindow: Int = 8192,
    val anyProtocol: Boolean = false,
    /**
     * Общая настройка: смешивать регистр в имени хоста для потоков, которые не
     * попали ни под одно правило. Сами правила переопределяют её полем
     * [Strategy.sniCaseMix].
     */
    val sniCaseMix: Boolean = false,
    /** Отравление разбора DPI подставной записью; см. [Strategy.poisonEnabled]. */
    val poisonEnabled: Boolean = false,
    /** Домен в подставной записи; пусто — домен по умолчанию. */
    val poisonSni: String = "",
    /** Пауза между подставой и настоящими данными, мс. */
    val poisonDelayMs: Int = 50,
    /** Байт срочных данных для общей OOB-стратегии; null — не задан. */
    val urgentByte: Int? = null,
    /** TTL пустышки для общей FAKE-стратегии; 0 — не подменять. */
    val fakeTtl: Int = 0,

    // Фильтры
    val tcpPorts: String = "80,443,2053,2082,2083,2086,2087,2095,2096,8443",
    val udpPorts: String = "443",
    val hostlistMode: HostlistMode = HostlistMode.INCLUDE,
    val ipsetMode: IpsetMode = IpsetMode.OFF,

    // UDP / QUIC
    val blockQuic: Boolean = true,
    val udpMode: UdpMode = UdpMode.RELAY,
    val udpTimeoutSec: Int = 60,

    // Цепочка стратегий (аналог блоков, разделённых --new в .bat-файлах zapret).
    // Пустой список — действует общая стратегия выше.
    val rules: List<StrategyRule> = emptyList(),

    // Сеть
    val ipv4: Boolean = true,
    val ipv6: Boolean = true,
    val mtu: Int = 1500,
    val mssClamp: Int = 1400,
    val connectTimeoutMs: Int = 8000,
    val tcpTimeoutSec: Int = 300,
    val maxConnections: Int = 512,
    val sendBufferKb: Int = 256,
    val appScope: AppScope = AppScope.ALL,
    val appPackages: Set<String> = emptySet(),

    // DNS
    val dnsMode: DnsMode = DnsMode.DOH,
    val dnsServers: String = "1.1.1.1\n8.8.8.8",
    val dohUrl: String = "https://dns.google/resolve",
    val dotHost: String = "dns.google",
    val dnsHijack: Boolean = true,
    val dnsCache: Boolean = true,
    val dnsCacheTtlSec: Int = 300,
    val dnsBlockAds: Boolean = false,
    val dnsFakeProtection: Boolean = true,
    /**
     * Версия схемы конфигурации. Нужна, чтобы обновление приложения могло
     * освежить устаревшие правила, не трогая настройки пользователя.
     * Без неё владельцы старых установок навсегда оставались на правилах
     * позапрошлой версии — и проверяли стратегию, которой уже нет.
     */
    val configVersion: Int = CURRENT_CONFIG_VERSION
) {
    val tcpFilter: PortFilter get() = PortFilter.parse(tcpPorts)
    val udpFilter: PortFilter get() = PortFilter.parse(udpPorts)

    /** Общая стратегия из плоских полей конфигурации. */
    fun toStrategy(): Strategy = Strategy(
        desync = desync,
        splitPositions = splitPositions,
        urgentByte = urgentByte,
        fakeTtl = fakeTtl,
        splitCustomPos = splitCustomPos,
        splitDelayMs = splitDelayMs,
        tlsrecParts = tlsrecParts,
        wssizeEnabled = wssizeEnabled,
        wssizePackets = wssizePackets,
        wssizeWindow = wssizeWindow,
        anyProtocol = anyProtocol,
        sniCaseMix = sniCaseMix,
        poisonEnabled = poisonEnabled,
        poisonSni = poisonSni,
        poisonDelayMs = poisonDelayMs
    )

    fun toJson(): JSONObject {
        val o = JSONObject()
        o.put("profile", profile.token)
        o.put("theme", theme.name)
        o.put("dynamicColor", dynamicColor)
        o.put("accent", accent.name)
        o.put("verboseLog", verboseLog)
        o.put("notificationEnabled", notificationEnabled)
        o.put("autoStart", autoStart)

        o.put("desync", desync.token)
        o.put("splitPositions", JSONArray(splitPositions.map { it.token }))
        o.put("splitCustomPos", splitCustomPos)
        o.put("splitDelayMs", splitDelayMs)
        o.put("cutoffChunks", cutoffChunks)
        o.put("tlsrecParts", tlsrecParts)
        o.put("wssizeEnabled", wssizeEnabled)
        o.put("wssizePackets", wssizePackets)
        o.put("wssizeWindow", wssizeWindow)
        o.put("anyProtocol", anyProtocol)
        o.put("sniCaseMix", sniCaseMix)
        o.put("poisonEnabled", poisonEnabled)
        o.put("poisonSni", poisonSni)
        o.put("poisonDelayMs", poisonDelayMs)
        urgentByte?.let { o.put("urgentByte", it) }
        o.put("fakeTtl", fakeTtl)

        o.put("tcpPorts", tcpPorts)
        o.put("udpPorts", udpPorts)
        o.put("hostlistMode", hostlistMode.token)
        o.put("ipsetMode", ipsetMode.token)

        o.put("blockQuic", blockQuic)
        o.put("udpMode", udpMode.token)
        o.put("udpTimeoutSec", udpTimeoutSec)

        val rulesArr = JSONArray()
        for (r in rules) rulesArr.put(r.toJson())
        o.put("rules", rulesArr)

        o.put("ipv4", ipv4)
        o.put("ipv6", ipv6)
        o.put("mtu", mtu)
        o.put("mssClamp", mssClamp)
        o.put("connectTimeoutMs", connectTimeoutMs)
        o.put("tcpTimeoutSec", tcpTimeoutSec)
        o.put("maxConnections", maxConnections)
        o.put("sendBufferKb", sendBufferKb)
        o.put("appScope", appScope.name)
        o.put("appPackages", JSONArray(appPackages.toList()))

        o.put("dnsMode", dnsMode.token)
        o.put("dnsServers", dnsServers)
        o.put("dohUrl", dohUrl)
        o.put("dotHost", dotHost)
        o.put("dnsHijack", dnsHijack)
        o.put("dnsCache", dnsCache)
        o.put("dnsCacheTtlSec", dnsCacheTtlSec)
        o.put("dnsBlockAds", dnsBlockAds)
        o.put("dnsFakeProtection", dnsFakeProtection)
        o.put("configVersion", configVersion)
        return o
    }

    companion object {
        fun fromJson(o: JSONObject?): AppConfig {
            val d = AppConfig()
            if (o == null) return d
            return d.copy(
                profile = ProfileId.fromToken(o.optString("profile", d.profile.token)),
                theme = runCatching { ThemeMode.valueOf(o.optString("theme", d.theme.name)) }.getOrDefault(d.theme),
                dynamicColor = o.optBoolean("dynamicColor", d.dynamicColor),
                accent = runCatching { AccentPalette.valueOf(o.optString("accent", d.accent.name)) }.getOrDefault(d.accent),
                verboseLog = o.optBoolean("verboseLog", d.verboseLog),
                notificationEnabled = o.optBoolean("notificationEnabled", d.notificationEnabled),
                autoStart = o.optBoolean("autoStart", d.autoStart),

                desync = DesyncMode.fromToken(o.optString("desync", d.desync.token)),
                splitPositions = readStringSet(o.optJSONArray("splitPositions"))
                    .mapNotNull { SplitPos.fromToken(it) }
                    .distinct()
                    .ifEmpty { d.splitPositions },
                splitCustomPos = o.optInt("splitCustomPos", d.splitCustomPos),
                splitDelayMs = o.optInt("splitDelayMs", d.splitDelayMs),
                cutoffChunks = o.optInt("cutoffChunks", d.cutoffChunks),
                tlsrecParts = o.optInt("tlsrecParts", d.tlsrecParts),
                wssizeEnabled = o.optBoolean("wssizeEnabled", d.wssizeEnabled),
                wssizePackets = o.optInt("wssizePackets", d.wssizePackets),
                wssizeWindow = o.optInt("wssizeWindow", d.wssizeWindow),
                anyProtocol = o.optBoolean("anyProtocol", d.anyProtocol),
                sniCaseMix = o.optBoolean("sniCaseMix", d.sniCaseMix),
                poisonEnabled = o.optBoolean("poisonEnabled", d.poisonEnabled),
                poisonSni = o.optString("poisonSni", d.poisonSni),
                poisonDelayMs = o.optInt("poisonDelayMs", d.poisonDelayMs),
                urgentByte = if (o.has("urgentByte")) o.getInt("urgentByte") else null,
                fakeTtl = o.optInt("fakeTtl", d.fakeTtl),

                tcpPorts = o.optString("tcpPorts", d.tcpPorts),
                udpPorts = o.optString("udpPorts", d.udpPorts),
                hostlistMode = HostlistMode.fromToken(o.optString("hostlistMode", d.hostlistMode.token)),
                ipsetMode = IpsetMode.fromToken(o.optString("ipsetMode", d.ipsetMode.token)),

                blockQuic = o.optBoolean("blockQuic", d.blockQuic),
                udpMode = UdpMode.fromToken(o.optString("udpMode", d.udpMode.token)),
                udpTimeoutSec = o.optInt("udpTimeoutSec", d.udpTimeoutSec),

                rules = o.optJSONArray("rules")?.let { arr ->
                    (0 until arr.length()).mapNotNull { i -> StrategyRule.fromJson(arr.optJSONObject(i)) }
                } ?: emptyList(),

                ipv4 = o.optBoolean("ipv4", d.ipv4),
                ipv6 = o.optBoolean("ipv6", d.ipv6),
                mtu = o.optInt("mtu", d.mtu),
                mssClamp = o.optInt("mssClamp", d.mssClamp),
                connectTimeoutMs = o.optInt("connectTimeoutMs", d.connectTimeoutMs),
                tcpTimeoutSec = o.optInt("tcpTimeoutSec", d.tcpTimeoutSec),
                maxConnections = o.optInt("maxConnections", d.maxConnections),
                sendBufferKb = o.optInt("sendBufferKb", d.sendBufferKb),
                appScope = runCatching { AppScope.valueOf(o.optString("appScope", d.appScope.name)) }.getOrDefault(d.appScope),
                appPackages = readStringSet(o.optJSONArray("appPackages")).toSet(),

                dnsMode = DnsMode.fromToken(o.optString("dnsMode", d.dnsMode.token)),
                dnsServers = o.optString("dnsServers", d.dnsServers),
                dohUrl = o.optString("dohUrl", d.dohUrl),
                dotHost = o.optString("dotHost", d.dotHost),
                dnsHijack = o.optBoolean("dnsHijack", d.dnsHijack),
                dnsCache = o.optBoolean("dnsCache", d.dnsCache),
                dnsCacheTtlSec = o.optInt("dnsCacheTtlSec", d.dnsCacheTtlSec),
                dnsBlockAds = o.optBoolean("dnsBlockAds", d.dnsBlockAds),
                dnsFakeProtection = o.optBoolean("dnsFakeProtection", d.dnsFakeProtection),
                // Старого JSON без версии — это всегда версия 1.
                configVersion = o.optInt("configVersion", 1)
            )
        }

        private fun readStringSet(a: JSONArray?): List<String> {
            if (a == null) return emptyList()
            val out = ArrayList<String>(a.length())
            for (i in 0 until a.length()) out += a.optString(i)
            return out
        }
    }
}
