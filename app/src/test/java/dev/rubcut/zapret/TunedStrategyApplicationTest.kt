package dev.rubcut.zapret

import dev.rubcut.zapret.core.desync.StrategyResolver
import dev.rubcut.zapret.core.desync.withTunedPerHost
import dev.rubcut.zapret.core.match.HostMatcher
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.BuiltinLists
import dev.rubcut.zapret.data.DesyncMode
import dev.rubcut.zapret.data.HostListStore
import dev.rubcut.zapret.data.Presets
import dev.rubcut.zapret.data.ProfileId
import dev.rubcut.zapret.data.SplitPos
import dev.rubcut.zapret.data.Strategy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

/**
 * Результат автоподбора обязан реально доходить до трафика.
 *
 * Регрессия, найденная по журналу с устройства.
 *
 * [StrategyResolver] проверяет правила раньше общей стратегии и для подходящего
 * хоста возвращает стратегию **правила**. Автоподбор же записывал результат в
 * поля `AppConfig` (`desync`, `splitPositions`, …), которые применяются только
 * когда ни одно правило не подошло. Хосты из hostlist — то есть ровно те, ради
 * которых подбор запускается — всегда попадали в правило «YouTube / Google · TLS».
 *
 * Итог был такой: подбор отрабатывал, писал «стратегия применена», а
 * `www.youtube.com` продолжал идти со стратегией профиля. По логу это выглядело
 * как «автоподбор не помог», хотя на самом деле помог бы, если б записал результат
 * туда, откуда его реально читают.
 */
class TunedStrategyApplicationTest {

    private val lists = HostListStore.Snapshot(
        texts = emptyMap(),
        hostlist = HostMatcher.parse(BuiltinLists.GENERAL),
        exclude = HostMatcher.EMPTY,
        ipset = dev.rubcut.zapret.core.match.IpMatcher.EMPTY,
        ipsetExclude = dev.rubcut.zapret.core.match.IpMatcher.EMPTY,
        hosts = dev.rubcut.zapret.core.match.HostsTable.EMPTY
    )

    private fun resolverFor(cfg: AppConfig) =
        StrategyResolver(configProvider = { cfg }, listsProvider = { lists })

    /** Победивший кандидат обязан менять стратегию именно YouTube-потока. */
    @Test
    fun tunedStrategyReachesHostsThatRulesWouldOtherwiseSwallow() {
        val base = Presets.apply(ProfileId.YOUTUBE, AppConfig())
        val ip = InetAddress.getByName("142.250.74.206")

        // ДО подбора: хост уходит в правило профиля.
        val before = resolverFor(base).resolveTcp(443, "www.youtube.com", ip)
        assertTrue(
            "исходно www.youtube.com должен попадать под правило профиля, а не под общую стратегию",
            before.rule != null
        )

        // Кандидат, которого нет ни в одном поле профиля.
        val tuned = Strategy(
            desync = DesyncMode.MULTISPLIT,
            splitPositions = listOf(SplitPos.FIRST),
            splitDelayMs = 7,
            sniCaseMix = true
        )
        val afterCfg = base.withTunedPerHost(mapOf("www.youtube.com" to ("кандидат" to tuned)), base.tcpPorts)
        val after = resolverFor(afterCfg).resolveTcp(443, "www.youtube.com", ip)

        assertEquals(
            "после подбора стратегия YouTube обязана отличаться от стратегии профиля",
            tuned, after.strategy
        )
        assertEquals("задержка из подбора обязана действовать", 7, after.strategy.splitDelayMs)
    }

    /**
     * Подбор обязан перестать действовать для чужих хостов.
     *
     * Иначе неподходящая стратегия утекает на всё подряд и ломает то, что
     * работало: правила подбора живут в общей цепочке конфигурации.
     */
    @Test
    fun tunedStrategyDoesNotLeakToUnrelatedHosts() {
        val base = Presets.apply(ProfileId.YOUTUBE, AppConfig())
        val tuned = Strategy(desync = DesyncMode.SPLIT, splitPositions = listOf(SplitPos.FIRST))
        val cfg = base.withTunedPerHost(mapOf("www.youtube.com" to ("кандидат" to tuned)), base.tcpPorts)

        val resolver = resolverFor(cfg)
        val discord = resolver.resolveTcp(443, "discord.com", InetAddress.getByName("162.159.128.1"))
        assertNotEquals(
            "стратегия, подобранная под YouTube, не должна утекать на Discord",
            tuned, discord.strategy
        )
    }

    /** Повторный подбор не должен накапливать правила и в конце концов зациклиться. */
    @Test
    fun repeatedTuningReplacesGeneratedRules() {
        val base = Presets.apply(ProfileId.YOUTUBE, AppConfig())
        val original = base.rules.size

        val tuned = Strategy(desync = DesyncMode.MULTISPLIT, splitPositions = listOf(SplitPos.FIRST))
        val once = base.withTunedPerHost(mapOf("www.youtube.com" to ("a" to tuned)), base.tcpPorts)
        val twice = once.withTunedPerHost(
            mapOf("www.youtube.com" to ("b" to tuned), "i.ytimg.com" to ("c" to tuned)),
            base.tcpPorts
        )

        assertEquals(
            "после второго подбора должно остаться ровно два сгенерированных правила",
            2, twice.rules.count { it.isGenerated }
        )
        assertEquals(
            "исходные правила профиля должны сохраниться",
            original, twice.rules.count { !it.isGenerated }
        )
    }

    /** Сгенерированное правило не должно перехватывать чужие хосты из-за INLINE-совпадения. */
    @Test
    fun generatedRuleMatchesOnlyItsOwnHost() {
        val base = Presets.apply(ProfileId.YOUTUBE, AppConfig())
        val tuned = Strategy(desync = DesyncMode.MULTISPLIT, splitPositions = listOf(SplitPos.FIRST))
        val cfg = base.withTunedPerHost(mapOf("www.youtube.com" to ("a" to tuned)), base.tcpPorts)

        val generated = cfg.rules.first { it.isGenerated }
        assertEquals("www.youtube.com", generated.inlineDomains)

        val resolver = resolverFor(cfg)
        assertTrue(
            "для самого хоста должно применяться сгенерированное правило",
            resolver.resolveTcp(443, "www.youtube.com", InetAddress.getByName("142.250.74.206"))
                .rule?.isGenerated == true
        )
        // Правила может не быть вовсе: тогда решение приходит из общих фильтров.
        // Важно, чтобы оно не оказалось сгенерированным.
        assertTrue(
            "для постороннего хоста сгенерированное правило применяться не должно",
            resolver.resolveTcp(443, "example.com", InetAddress.getByName("8.6.112.5"))
                .rule?.isGenerated != true
        )
    }

    /** Правило подбора должно пережить перезапуск приложения: JSON-поля обратимы. */
    @Test
    fun generatedFlagSurvivesSerialization() {        val base = Presets.apply(ProfileId.YOUTUBE, AppConfig())
        val tuned = Strategy(desync = DesyncMode.MULTISPLIT, splitPositions = listOf(SplitPos.FIRST))
        val cfg = base.withTunedPerHost(mapOf("www.youtube.com" to ("a" to tuned)), base.tcpPorts)

        val restored = AppConfig.fromJson(cfg.toJson())
        assertEquals(
            "после экспорта/импорта сгенерированные правила должны остаться помеченными",
            1, restored.rules.count { it.isGenerated }
        )
        assertEquals(
            "стратегия правила обязана пережить сериализацию",
            cfg.rules.first { it.isGenerated }.strategy,
            restored.rules.first { it.isGenerated }.strategy
        )
    }

    /**
     * Параметры OOB/FAKE обязаны пережить сериализацию — и включая null.
     *
     * Именно здесь терялись новые поля: toJson их не писал, fromJson не читал,
     * и победа OOB/FAKE в автоподборе после рестарта применялась без параметров.
     */
    @Test
    fun oobFakeParamsSurviveSerialization() {
        val oob = Strategy(desync = DesyncMode.OOB, splitPositions = listOf(SplitPos.MIDSNI), urgentByte = 7)
        val fake = Strategy(desync = DesyncMode.FAKE, fakeTtl = 8)
        val plain = Strategy(desync = DesyncMode.SPLIT, urgentByte = null, fakeTtl = 0)

        for (s in listOf(oob, fake, plain)) {
            val restored = Strategy.fromJson(s.toJson())
            assertEquals("стратегия $s обязана пережить round-trip", s, restored)
        }

        // Явное отличие null от 0: 0x00 — законное значение байта.
        val withZero = Strategy(desync = DesyncMode.OOB, urgentByte = 0)
        assertEquals(0, Strategy.fromJson(withZero.toJson()).urgentByte)
        val without = Strategy(desync = DesyncMode.OOB, urgentByte = null)
        assertEquals(null, Strategy.fromJson(without.toJson()).urgentByte)
    }
}