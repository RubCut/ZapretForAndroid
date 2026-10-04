package dev.rubcut.zapret.data

import dev.rubcut.zapret.data.DesyncMode.HOSTFAKESPLIT
import dev.rubcut.zapret.data.DesyncMode.MULTISPLIT
import dev.rubcut.zapret.data.DesyncMode.MULTISPLIT_TLSREC
import dev.rubcut.zapret.data.HostSource.ANY
import dev.rubcut.zapret.data.HostSource.DISCORD
import dev.rubcut.zapret.data.HostSource.GOOGLE
import dev.rubcut.zapret.data.HostSource.HOSTLIST
import dev.rubcut.zapret.data.SplitPos.FIRST
import dev.rubcut.zapret.data.SplitPos.MIDSNI
import dev.rubcut.zapret.data.SplitPos.SNIEND

/**
 * Готовые профили — аналог .bat-файлов из zapret-discord-youtube.
 * Каждый профиль задаёт цепочку правил (блоки `--new`) и общие настройки.
 */
object Presets {

    private val TLS_PORTS = "443,8443,2053,2082,2083,2086,2087,2095,2096"
    private val HTTP_PORTS = "80,8080"
    private val DISCORD_UDP = "19294-19344,50000-50100,3478-3482"

    fun apply(id: ProfileId, base: AppConfig): AppConfig = when (id) {
        ProfileId.OFF -> base.copy(profile = id)
        ProfileId.CUSTOM -> base.copy(profile = id)
        ProfileId.YOUTUBE -> youtube(base)
        ProfileId.DISCORD -> discord(base)
        ProfileId.COMBINED -> combined(base)
        ProfileId.MAX -> maximal(base)
    }

    private fun youtube(base: AppConfig): AppConfig = base.copy(
        profile = ProfileId.YOUTUBE,
        desync = MULTISPLIT,
        splitPositions = listOf(FIRST, MIDSNI),
        splitCustomPos = 2,
        splitDelayMs = 2,
        cutoffChunks = 4,
        tlsrecParts = 0,
        wssizeEnabled = false,
        anyProtocol = false,
        tcpPorts = "$TLS_PORTS,$HTTP_PORTS",
        udpPorts = "443",
        hostlistMode = HostlistMode.INCLUDE,
        ipsetMode = IpsetMode.OFF,
        blockQuic = true,
        udpMode = UdpMode.RELAY,
        dnsMode = DnsMode.DOH,
        dohUrl = "https://dns.google/resolve",
        dnsFakeProtection = true,
        dnsCache = true,
        rules = youtubeRules()
    )

    private fun discord(base: AppConfig): AppConfig = base.copy(
        profile = ProfileId.DISCORD,
        desync = MULTISPLIT,
        splitPositions = listOf(FIRST, MIDSNI),
        splitDelayMs = 2,
        cutoffChunks = 4,
        tlsrecParts = 0,
        wssizeEnabled = false,
        anyProtocol = false,
        tcpPorts = "$TLS_PORTS,$HTTP_PORTS",
        udpPorts = DISCORD_UDP,
        hostlistMode = HostlistMode.INCLUDE,
        ipsetMode = IpsetMode.OFF,
        blockQuic = false,
        udpMode = UdpMode.RELAY,
        dnsMode = DnsMode.DOH,
        dohUrl = "https://dns.google/resolve",
        dnsFakeProtection = true,
        rules = discordRules()
    )

    private fun combined(base: AppConfig): AppConfig = base.copy(
        profile = ProfileId.COMBINED,
        desync = MULTISPLIT,
        splitPositions = listOf(FIRST, MIDSNI),
        splitDelayMs = 2,
        cutoffChunks = 4,
        tlsrecParts = 0,
        wssizeEnabled = false,
        anyProtocol = false,
        tcpPorts = "$TLS_PORTS,$HTTP_PORTS",
        udpPorts = "443,$DISCORD_UDP",
        hostlistMode = HostlistMode.INCLUDE,
        ipsetMode = IpsetMode.OFF,
        blockQuic = true,
        udpMode = UdpMode.RELAY,
        dnsMode = DnsMode.DOH,
        dohUrl = "https://dns.google/resolve",
        dnsFakeProtection = true,
        rules = youtubeRules() + discordRules() + listOf(
            StrategyRule(
                name = "Остальные хосты из списка",
                tcpPorts = "$TLS_PORTS,$HTTP_PORTS",
                hostSource = HOSTLIST,
                strategy = Strategy(desync = MULTISPLIT, splitPositions = listOf(MIDSNI), splitDelayMs = 2)
            )
        )
    )

    private fun maximal(base: AppConfig): AppConfig = base.copy(
        profile = ProfileId.MAX,
        desync = MULTISPLIT_TLSREC,
        splitPositions = listOf(FIRST, MIDSNI, SNIEND),
        splitDelayMs = 3,
        cutoffChunks = 6,
        tlsrecParts = 2,
        wssizeEnabled = true,
        wssizePackets = 6,
        wssizeWindow = 8192,
        anyProtocol = true,
        tcpPorts = "1-65535",
        udpPorts = "443,$DISCORD_UDP",
        hostlistMode = HostlistMode.INCLUDE,
        ipsetMode = IpsetMode.OFF,
        blockQuic = true,
        udpMode = UdpMode.RELAY,
        dnsMode = DnsMode.DOH,
        dohUrl = "https://dns.google/resolve",
        dnsFakeProtection = true,
        rules = youtubeRules() + discordRules() + listOf(
            StrategyRule(
                name = "Всё остальное · tlsrec + wssize",
                tcpPorts = "1-65535",
                hostSource = ANY,
                strategy = Strategy(
                    desync = MULTISPLIT_TLSREC,
                    splitPositions = listOf(FIRST, MIDSNI),
                    splitDelayMs = 3,
                    tlsrecParts = 2,
                    wssizeEnabled = true,
                    wssizePackets = 6,
                    wssizeWindow = 8192,
                    anyProtocol = true
                )
            )
        )
    )

    private fun youtubeRules(): List<StrategyRule> = listOf(
        StrategyRule(
            name = "YouTube / Google · TLS",
            tcpPorts = TLS_PORTS,
            hostSource = GOOGLE,
            strategy = Strategy(
                desync = MULTISPLIT,
                splitPositions = listOf(FIRST, MIDSNI),
                splitDelayMs = 2
            )
        ),
        StrategyRule(
            name = "YouTube / Google · HTTP",
            tcpPorts = HTTP_PORTS,
            hostSource = GOOGLE,
            strategy = Strategy(desync = HOSTFAKESPLIT, splitDelayMs = 2)
        )
    )

    private fun discordRules(): List<StrategyRule> = listOf(
        StrategyRule(
            name = "Discord · TLS",
            tcpPorts = TLS_PORTS,
            hostSource = DISCORD,
            strategy = Strategy(
                desync = MULTISPLIT,
                splitPositions = listOf(FIRST, MIDSNI),
                splitDelayMs = 2
            )
        ),
        StrategyRule(
            name = "Discord · голос и STUN (релей)",
            tcpPorts = "",
            udpPorts = DISCORD_UDP,
            hostSource = ANY,
            strategy = Strategy.OFF
        )
    )
}
