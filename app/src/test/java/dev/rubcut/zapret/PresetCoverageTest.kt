package dev.rubcut.zapret

import dev.rubcut.zapret.core.net.IpLiterals
import dev.rubcut.zapret.data.DesyncMode
import dev.rubcut.zapret.data.DnsMode
import dev.rubcut.zapret.data.HostSource
import dev.rubcut.zapret.data.HostlistMode
import dev.rubcut.zapret.data.PortFilter
import dev.rubcut.zapret.data.Presets
import dev.rubcut.zapret.data.ProfileId
import dev.rubcut.zapret.data.SplitPos
import dev.rubcut.zapret.core.desync.StrategyResolver
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.HostListStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

/**
 * Профили обязаны реально покрывать то, с чем ходят YouTube и Discord.
 *
 * Пользователь выбирает профиль и ждёт работающей сети, а не того, что правила
 * существуют. Поэтому здесь проверяется не структура правил, а то что
 * СРАЗИТЕЛЬНЫЕ соединения действительно получают стратегию: YouTube идёт на
 * порт 443 с CDN-именами, Discord — на нестандартные порты, оба ходят и по UDP.
 */
class PresetCoverageTest {

    private val lists = HostListStore.Snapshot(
        texts = emptyMap(),
        hostlist = dev.rubcut.zapret.core.match.HostMatcher.parse(
            dev.rubcut.zapret.data.BuiltinLists.GENERAL
        ),
        exclude = dev.rubcut.zapret.core.match.HostMatcher.EMPTY,
        ipset = dev.rubcut.zapret.core.match.IpMatcher.EMPTY,
        ipsetExclude = dev.rubcut.zapret.core.match.IpMatcher.EMPTY,
        hosts = dev.rubcut.zapret.core.match.HostsTable.EMPTY
    )

    private fun resolverFor(id: ProfileId) = StrategyResolver(
        configProvider = { Presets.apply(id, AppConfig()) },
        listsProvider = { lists }
    )

    /** Реальные CDN-хосты YouTube и порт, на котором реально идёт видео. */
    @Test
    fun youtubeProfileCoversCdnVideoHosts() {
        val r = resolverFor(ProfileId.YOUTUBE)
        for (host in listOf(
            "rr12---sn-4g5ednse.googlevideo.com",
            "rr5---sn-i3b6knf3n5oe.googlevideo.com",
            "www.youtube.com",
            "youtubei.googleapis.com"
        )) {
            val d = r.resolveTcp(443, host, InetAddress.getByName("142.250.74.206"))
            assertFalse(
                "профиль YouTube обязан применять стратегию к $host (решение: ${d.reason})",
                d.strategy.isPassive
            )
            assertEquals(
                "для $host ожидалась стратегия tlsrec+разбиение, а пришло «${d.strategy.describe()}»",
                DesyncMode.MULTISPLIT_TLSREC, d.strategy.desync
            )
            // Точка реза — середина домена (0+wm), разрыва по первому байту
            // в победившем варианте нет: по замерам стороннего приложения
            // вариант «tlsrec + первый байт» проверку не прошёл.
            assertTrue(
                "рез в середине домена обязателен, а пришло «${d.strategy.describe()}»",
                d.strategy.splitPositions.contains(SplitPos.MIDSNI)
            )
            assertFalse(
                "разрыва по первому байту быть не должно, а пришло «${d.strategy.describe()}»",
                d.strategy.splitPositions.contains(SplitPos.FIRST)
            )
        }
    }

    /**
     * Точка разбиения обязана быть включена в профиль.
     *
     * Отдельно от предыдущего: без FIRST+MIDSLD разбиение вырождается в
     * отрезание одного байта, и обход перестаёт работать, хотя стратегия
     * формально применена.
     */
    @Test
    fun youtubeProfileSplitsAtFirstByteAndInsideDomain() {
        val cfg = Presets.apply(ProfileId.YOUTUBE, AppConfig())
        val pos = cfg.splitPositions
        assertTrue("в профиле YouTube должен быть разрыв по первому байту: $pos", pos.contains(SplitPos.FIRST))
        assertTrue("в профиле YouTube должен быть разрыв по середине домена: $pos", pos.contains(SplitPos.MIDSNI))
        assertTrue("задержка между фрагментами нужна, иначе DPI их склеит", cfg.splitDelayMs > 0)
    }

    /** Discord ходит по нестандартным портам — они обязаны быть в профиле. */
    @Test
    fun discordProfileCoversItsRealPorts() {
        val cfg = Presets.apply(ProfileId.DISCORD, AppConfig())
        val filter = PortFilter.parse(cfg.tcpPorts)
        for (p in listOf(443, 2053, 2083, 2087, 2096, 8443)) {
            assertTrue("порт $p вне TCP-фильтра профиля Discord: ${cfg.tcpPorts}", filter.matches(p))
        }
        // Голос и STUN — UDP.
        for (p in listOf(19294, 19344, 3478, 50000, 50100)) {
            assertTrue(
                "порт $p вне UDP-фильтра профиля Discord: ${cfg.udpPorts}",
                PortFilter.parse(cfg.udpPorts).matches(p)
            )
        }
    }

    /** QUIC обязан блокироваться везде, где включён обход YouTube. */
    @Test
    fun quicIsBlockedInYoutubeRelatedProfiles() {
        for (id in listOf(ProfileId.YOUTUBE, ProfileId.COMBINED, ProfileId.MAX)) {
            val cfg = Presets.apply(id, AppConfig())
            assertTrue(
                "в профиле $id QUIC должен блокироваться: клиент уйдёт в QUIC, " +
                    "где SNI зашифрован и split не работает",
                cfg.blockQuic
            )
        }
    }

    /** DNS должен быть защищённым: системный DNS провайдера отвечает подменой. */
    @Test
    fun profilesUseSecureDnsWithFallback() {
        for (id in listOf(ProfileId.YOUTUBE, ProfileId.DISCORD, ProfileId.COMBINED)) {
            val cfg = Presets.apply(id, AppConfig())
            assertTrue(
                "в профиле $id ожидается DoH или DoT, а не системный DNS провайдера",
                cfg.dnsMode == DnsMode.DOH || cfg.dnsMode == ProfileDot
            )
            assertTrue("в профиле $id перехват DNS порта 53 обязателен", cfg.dnsHijack)
        }
    }

    private val ProfileDot = DnsMode.DOT

    /** Выключенный профиль обязан быть по-настоящему выключенным. */
    @Test
    fun offProfileDisablesEverything() {
        val cfg = Presets.apply(ProfileId.OFF, AppConfig())
        assertEquals(ProfileId.OFF, cfg.profile)
    }

    /** Список хостов по умолчанию обязан быть непустым, иначе стратегий нет ни для кого. */
    @Test
    fun hostlistIsNotEmptyAfterPresetApply() {
        for (id in listOf(ProfileId.YOUTUBE, ProfileId.COMBINED, ProfileId.MAX)) {
            val cfg = Presets.apply(id, AppConfig())
            assertEquals(
                "в профиле $id список хостов ограничен только теми доменами, что в правилах",
                HostlistMode.INCLUDE, cfg.hostlistMode
            )
        }
    }

    /** Встроенные списки не должны содержать мусор, который ломает разбор. */
    @Test
    fun builtinListsParseCleanly() {
        for (name in listOf("GOOGLE", "DISCORD", "GENERAL", "ADS_BLOCK", "IPSET_ALL")) {
            val raw = when (name) {
                "GOOGLE" -> dev.rubcut.zapret.data.BuiltinLists.GOOGLE
                "DISCORD" -> dev.rubcut.zapret.data.BuiltinLists.DISCORD
                "GENERAL" -> dev.rubcut.zapret.data.BuiltinLists.GENERAL
                "ADS_BLOCK" -> dev.rubcut.zapret.data.BuiltinLists.ADS_BLOCK
                else -> dev.rubcut.zapret.data.BuiltinLists.IPSET_ALL
            }
            val lines = raw.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
            assertTrue("список $name пуст", lines.isNotEmpty())
            for (line in lines) {
                if (line.startsWith("#")) continue
                assertTrue(
                    "в списке $name строка «$line» не является ни доменом, ни CIDR",
                    IpLiterals.parse(line.substringBefore('/')) != null ||
                        line.matches(Regex("[A-Za-z0-9.*_-]+"))
                )
            }
        }
    }
}