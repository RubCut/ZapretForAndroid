package dev.rubcut.zapret

import dev.rubcut.zapret.config.ZapretArgsParser
import dev.rubcut.zapret.core.match.Cidr
import dev.rubcut.zapret.core.match.HostMatcher
import dev.rubcut.zapret.core.match.HostsTable
import dev.rubcut.zapret.core.net.IpLiterals
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.DesyncMode
import dev.rubcut.zapret.data.PortFilter
import dev.rubcut.zapret.data.SplitPos
import dev.rubcut.zapret.data.Strategy
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Регрессии батчей ревизии: персистентность, парсер аргументов, порты,
 * матчеры и литералы. Каждый тест фиксирует поведение, которое раньше
 * молча теряло данные или расширяло охват правил.
 */
class RevizFixesTest {

    // ---------- PortFilter ----------

    @Test
    fun portParseReportsDroppedTokens() {
        val (f, bad) = PortFilter.parseWithErrors("80,443a,50000-50100,zzz")
        assertTrue("80 обязан матчиться", f.matches(80))
        assertTrue("50001 обязан матчиться", f.matches(50001))
        assertEquals(listOf("443a", "zzz"), bad)
    }

    @Test
    fun portParseGarbageFallsBackToAnyButReports() {
        val (f, bad) = PortFilter.parseWithErrors("443a,zzz")
        assertTrue("пустой разбор — ANY по договорённости", f.isAny)
        assertEquals(2, bad.size)
    }

    @Test
    fun portParseBlankIsAnySilently() {
        val (f, bad) = PortFilter.parseWithErrors("  ")
        assertTrue(f.isAny)
        assertTrue(bad.isEmpty())
    }

    // ---------- splitPositions: отсутствие vs явное пусто ----------

    @Test
    fun emptySplitPositionsSurviveRoundTrip() {
        val cfg = AppConfig().copy(splitPositions = emptyList())
        val back = AppConfig.fromJson(cfg.toJson())
        assertTrue("явное [] не должно превращаться в [MIDSNI]", back.splitPositions.isEmpty())
    }

    @Test
    fun missingSplitPositionsDefaultToMidsni() {
        val back = AppConfig.fromJson(JSONObject("{}"))
        assertEquals(listOf(SplitPos.MIDSNI), back.splitPositions)
    }

    @Test
    fun strategyEmptySplitPositionsSurvive() {
        val s = Strategy().copy(splitPositions = emptyList())
        val back = Strategy.fromJson(s.toJson())
        assertTrue(back.splitPositions.isEmpty())
    }

    @Test
    fun stringUrgentByteDoesNotKillDocument() {
        val back = AppConfig.fromJson(JSONObject("{\"urgentByte\":\"oops\"}"))
        assertNull("чужой тип — null, а не падение всего JSON", back.urgentByte)
    }

    // ---------- ZapretArgsParser ----------

    @Test
    fun passiveRuleSurvivesFlush() {
        val r = ZapretArgsParser.parse("--dpi-desync=none", AppConfig())
        assertEquals("пассивный блок OFF+ANY обязан сохраняться", 1, r.rules.size)
        assertEquals(DesyncMode.NONE, r.rules[0].strategy.desync)
    }

    @Test
    fun blockParamsDoNotLeakAcrossNew() {
        val r = ZapretArgsParser.parse(
            "--dpi-desync-split-pos=midsld --dpi-desync-tlsrec=3 --split-delay=50 " +
                "--new --filter-tcp=443 --dpi-desync=split",
            AppConfig()
        )
        assertEquals(2, r.rules.size)
        assertEquals("tlsrec не должен течь во второе правило", 0, r.rules[1].strategy.tlsrecParts)
        assertEquals("delay не должен течь во второе правило", 0, r.rules[1].strategy.splitDelayMs)
    }

    @Test
    fun defaultStrategyComesFromFirstRule() {
        val r = ZapretArgsParser.parse(
            "--filter-tcp=443 --dpi-desync=split --new --filter-tcp=80 --dpi-desync=multisplit",
            AppConfig()
        )
        assertEquals(DesyncMode.SPLIT, r.defaultStrategy?.desync)
    }

    @Test
    fun cutoffSurvivesGenerate() {
        val text = ZapretArgsParser.generate(AppConfig().copy(cutoffChunks = 4))
        assertTrue("cutoff обязан экспортироваться:\n$text", text.contains("--dpi-desync-cutoff=n4"))
    }

    @Test
    fun invalidPortTokensAreReported() {
        val r = ZapretArgsParser.parse("--filter-tcp=443a,zzz --dpi-desync=split", AppConfig())
        assertTrue("битые токены портов обязаны попадать в errors: ${r.errors}",
            r.errors.any { it.contains("--filter-tcp") })
    }

    // ---------- Matchers: без DNS ----------

    @Test
    fun cidrHostnameIsRejectedWithoutDns() {
        // Раньше getByName уходил в реальный DNS на потоке парсинга.
        assertNull(Cidr.parse("example.com"))
        assertNull(Cidr.parse("example.com/24"))
        assertNotNull(Cidr.parse("10.0.0.0/8"))
        assertNotNull(Cidr.parse("fd00::/8"))
    }

    @Test
    fun hostsWildcardIsSubdomainsOnly() {
        val t = HostsTable.parse("1.2.3.4 *.example.com")
        assertNotNull(t.lookup("a.example.com"))
        assertNull("*.example.com не матчит голый домен", t.lookup("example.com"))
    }

    @Test
    fun hostsBareStarIsExact() {
        val t = HostsTable.parse("1.2.3.4 *example")
        assertNotNull(t.lookup("example"))
        assertNull("голый *name не должен матчить badexample.com", t.lookup("badexample.com"))
    }

    @Test
    fun hostMatcherStarIsExactOnly() {
        // Конвенция --hostlist-domains: `*` = точное совпадение.
        val m = HostMatcher.parse("*.example.com")
        assertTrue(m.matches("example.com"))
        assertTrue("поддомены здесь НЕ матчатся", !m.matches("a.example.com"))
    }

    // ---------- IpLiterals ----------

    @Test
    fun bareIpv6KeepsWholeHost() {
        val (host, port) = IpLiterals.parseHostPort("fd00::1", 53)!!
        assertEquals("fd00::1", host)
        assertEquals(53, port)
    }

    @Test
    fun hostPortFormsStillWork() {
        assertEquals("1.1.1.1" to 5353, IpLiterals.parseHostPort("1.1.1.1:5353", 53))
        assertEquals("fd00::1" to 5353, IpLiterals.parseHostPort("[fd00::1]:5353", 53))
        assertEquals("dns.google" to 853, IpLiterals.parseHostPort("dns.google", 853))
    }
}
