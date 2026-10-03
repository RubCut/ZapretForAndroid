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
    val anyProtocol: Boolean = false
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
                anyProtocol = o.optBoolean("anyProtocol", d.anyProtocol)
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
