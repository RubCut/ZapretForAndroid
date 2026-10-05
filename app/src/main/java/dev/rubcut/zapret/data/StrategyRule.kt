package dev.rubcut.zapret.data

import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * Конкретный набор приёмов десинхронизации.
 * Ровно то, что в zapret описывается блоком параметров после --filter-*.
 */
data class Strategy(
    val desync: DesyncMode = DesyncMode.MULTISPLIT,
    val splitPositions: List<SplitPos> = listOf(SplitPos.MIDSNI),
    val splitCustomPos: Int = 2,
    val splitDelayMs: Int = 2,
    val tlsrecParts: Int = 0,
    val wssizeEnabled: Boolean = false,
    val wssizePackets: Int = 6,
    val wssizeWindow: Int = 8192,
    val anyProtocol: Boolean = false,
    /**
     * Отравление разбора DPI подставной TLS-записью.
     *
     * Перед настоящим ClientHello уходит целая посторонняя запись с другим
     * доменом. Сервер её не считает началом рукопожатия, а DPI разбирает
     * поток заново и до настоящего ClientHello не доходит — он уже потратил
     * разбор на подставной записи, поэтому заблокированный домен в потоке
     * не находится.
     *
     * Проверено против реального фильтра, полностью пересобирающего сегменты,
     * где ни сегментация, ни смена регистра не помогали: подстава проходит
     * 10 из 10, контроль без неё 0 из 10.
     */
    val poisonEnabled: Boolean = false,
    /** Домен в подставной записи; пусто — [dev.rubcut.zapret.core.desync.DesyncEngine.DEFAULT_POISON_SNI]. */
    val poisonSni: String = "",
    /**
     * Пауза между подставой и настоящими данными, мс.
     *
     * Нужна, чтобы DPI успел разобрать подставу до начала настоящей записи.
     * Замеры: 50 мс и 300 мс работают, 10 мс и меньше уже нет — подстава
     * сливается с настоящими данными, и DPI находит домен.
     */
    val poisonDelayMs: Int = 50,
    /**
     * Смешивать регистр в имени хоста перед отправкой в сеть.
     *
     * Имя в SNI и в `Host:` регистронезависимо, поэтому смена регистра одной
     * буквы не видна ни серверу, ни проверке сертификата, но ломает фильтры,
     * ищущие домен подстрокой. Проверено: на фильтре с полной пересборкой
     * сегментов, где segmentation не помогает вовсе, `www.youtube.com` не
     * проходит ни разу из шести попыток, а `www.YouTube.com` — шесть из шести.
     *
     * Включать не везде: некоторые CDN (Cloudflare) отвечают только на
     * канонический регистр и молча рвут соединение.
     */
    val sniCaseMix: Boolean = false
) {
    val isPassive: Boolean get() = desync == DesyncMode.NONE && !wssizeEnabled

    fun toJson(): JSONObject {
        val o = JSONObject()
        o.put("desync", desync.token)
        o.put("splitPositions", JSONArray(splitPositions.map { it.token }))
        o.put("splitCustomPos", splitCustomPos)
        o.put("splitDelayMs", splitDelayMs)
        o.put("tlsrecParts", tlsrecParts)
        o.put("wssizeEnabled", wssizeEnabled)
        o.put("wssizePackets", wssizePackets)
        o.put("wssizeWindow", wssizeWindow)
        o.put("anyProtocol", anyProtocol)
        o.put("sniCaseMix", sniCaseMix)
        o.put("poisonEnabled", poisonEnabled)
        o.put("poisonSni", poisonSni)
        o.put("poisonDelayMs", poisonDelayMs)
        return o
    }

    /** Короткое человекочитаемое описание — как строка аргументов zapret. */
    fun describe(): String = buildString {
        append("--dpi-desync=").append(desync.token)
        if (splitPositions.isNotEmpty() && desync != DesyncMode.NONE && desync != DesyncMode.HOSTFAKESPLIT) {
            append(" --dpi-desync-split-pos=").append(splitPositions.joinToString(",") { it.token })
        }
        if (splitCustomPos != 2 && splitPositions.contains(SplitPos.CUSTOM)) append("($splitCustomPos)")
        if (splitDelayMs > 0) append(" --split-delay=").append(splitDelayMs)
        if (tlsrecParts >= 2) append(" --dpi-desync-tlsrec=").append(tlsrecParts)
        if (wssizeEnabled) append(" --wssize=").append(wssizePackets).append(':').append(wssizeWindow)
        if (anyProtocol) append(" --dpi-desync-any-protocol=1")
        if (sniCaseMix) append(" --hostcase")
        if (poisonEnabled) append(" --poison").append(if (poisonSni.isNotBlank()) "=$poisonSni" else "")
            .append(" --poison-delay=").append(poisonDelayMs)
    }

    companion object {
        val OFF = Strategy(desync = DesyncMode.NONE)

        fun fromJson(o: JSONObject?): Strategy {
            val d = Strategy()
            if (o == null) return d
            val pos = o.optJSONArray("splitPositions")
            val posList = if (pos == null) d.splitPositions else {
                val l = ArrayList<SplitPos>()
                for (i in 0 until pos.length()) SplitPos.fromToken(pos.optString(i))?.let { l += it }
                l.distinct().ifEmpty { d.splitPositions }
            }
            return d.copy(
                desync = DesyncMode.fromToken(o.optString("desync", d.desync.token)),
                splitPositions = posList,
                splitCustomPos = o.optInt("splitCustomPos", d.splitCustomPos),
                splitDelayMs = o.optInt("splitDelayMs", d.splitDelayMs),
                tlsrecParts = o.optInt("tlsrecParts", d.tlsrecParts),
                wssizeEnabled = o.optBoolean("wssizeEnabled", d.wssizeEnabled),
                wssizePackets = o.optInt("wssizePackets", d.wssizePackets),
                wssizeWindow = o.optInt("wssizeWindow", d.wssizeWindow),
                anyProtocol = o.optBoolean("anyProtocol", d.anyProtocol),
                sniCaseMix = o.optBoolean("sniCaseMix", d.sniCaseMix),
                poisonEnabled = o.optBoolean("poisonEnabled", d.poisonEnabled),
                poisonSni = o.optString("poisonSni", d.poisonSni),
                poisonDelayMs = o.optInt("poisonDelayMs", d.poisonDelayMs)
            )
        }
    }
}

/** Откуда правило берёт список доменов. */
enum class HostSource(val token: String) {
    ANY("any"),
    HOSTLIST("hostlist"),
    GENERAL("general"),
    GOOGLE("google"),
    DISCORD("discord"),
    INLINE("inline");

    companion object {
        fun fromToken(t: String?): HostSource =
            values().firstOrNull { it.token.equals(t, true) } ?: ANY
    }
}

/**
 * Одно правило из цепочки. Полный аналог блока `--filter-tcp=… --hostlist=… --dpi-desync=… --new`
 * из .bat-файлов zapret-discord-youtube: правила проверяются по порядку, срабатывает первое подходящее.
 */
data class StrategyRule(
    val id: String = UUID.randomUUID().toString(),
    val enabled: Boolean = true,
    val name: String = "",
    val tcpPorts: String = "443",
    val udpPorts: String = "",
    val hostSource: HostSource = HostSource.ANY,
    val inlineDomains: String = "",
    val excludeDomains: String = "",
    val strategy: Strategy = Strategy()
) {
    val tcpFilter: PortFilter get() = PortFilter.parse(tcpPorts)
    val udpFilter: PortFilter get() = PortFilter.parse(udpPorts)

    fun toJson(): JSONObject {
        val o = JSONObject()
        o.put("id", id)
        o.put("enabled", enabled)
        o.put("name", name)
        o.put("tcpPorts", tcpPorts)
        o.put("udpPorts", udpPorts)
        o.put("hostSource", hostSource.token)
        o.put("inlineDomains", inlineDomains)
        o.put("excludeDomains", excludeDomains)
        o.put("strategy", strategy.toJson())
        return o
    }

    /** Строка в стиле zapret для экрана «Аргументы» и для экспорта. */
    fun toZapretLine(): String = buildString {
        if (tcpFilter.toString().isNotEmpty()) append("--filter-tcp=").append(tcpFilter).append(' ')
        if (udpFilter.toString().isNotEmpty()) append("--filter-udp=").append(udpFilter).append(' ')
        when (hostSource) {
            HostSource.ANY -> Unit
            HostSource.HOSTLIST -> append("--hostlist=\"%LISTS%list-general.txt\" ")
            HostSource.GENERAL -> append("--hostlist=\"%LISTS%list-general.txt\" ")
            HostSource.GOOGLE -> append("--hostlist=\"%LISTS%list-google.txt\" ")
            HostSource.DISCORD -> append("--hostlist=\"%LISTS%list-discord.txt\" ")
            HostSource.INLINE -> append("--hostlist-domains=").append(
                inlineDomains.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.joinToString(",")
            ).append(' ')
        }
        if (excludeDomains.isNotBlank()) {
            append("--hostlist-exclude=\"%LISTS%list-exclude.txt\" ")
        }
        append(strategy.describe())
        append(" --new")
    }

    companion object {
        fun fromJson(o: JSONObject?): StrategyRule? {
            if (o == null) return null
            val d = StrategyRule()
            return StrategyRule(
                id = o.optString("id", d.id),
                enabled = o.optBoolean("enabled", true),
                name = o.optString("name", ""),
                tcpPorts = o.optString("tcpPorts", d.tcpPorts),
                udpPorts = o.optString("udpPorts", d.udpPorts),
                hostSource = HostSource.fromToken(o.optString("hostSource", d.hostSource.token)),
                inlineDomains = o.optString("inlineDomains", ""),
                excludeDomains = o.optString("excludeDomains", ""),
                strategy = Strategy.fromJson(o.optJSONObject("strategy"))
            )
        }
    }
}
