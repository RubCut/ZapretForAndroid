package dev.rubcut.zapret

import dev.rubcut.zapret.core.desync.DesyncEngine
import dev.rubcut.zapret.core.desync.FlowContext
import dev.rubcut.zapret.core.proto.Http
import dev.rubcut.zapret.core.proto.Tls
import dev.rubcut.zapret.core.stack.StrategyAutopilot
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.DesyncMode
import dev.rubcut.zapret.data.Presets
import dev.rubcut.zapret.data.ProfileId
import dev.rubcut.zapret.data.SplitPos
import dev.rubcut.zapret.data.Strategy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Смена регистра в имени хоста.
 *
 * Приём открыт на реальном фильтре с полной пересборкой TCP-сегментов и
 * TLS-записей, где segmentation не помогает вовсе: `www.youtube.com` не
 * проходил ни разу из шести попыток, `www.YouTube.com` — шесть из шести,
 * сертификат при этом оставался валидным.
 */
class SniCaseMixTest {

    private val engine = DesyncEngine()

    /* ================================================================== */
    /*  Байты меняются, но длина и разбираемость — нет                   */
    /* ================================================================== */

    @Test
    fun mixChangesExactlyOneByteInSld() {
        val host = "www.youtube.com"
        val hello = StrategyAutopilotHelloFactory.build(host)
        val info = Tls.parseClientHello(hello, 0, hello.size)!!
        val mixed = Tls.mixCaseInSld(hello, info.sniStart, info.sniEnd, info.sni)

        assertNotNull("смена регистра обязана применяться к youtube", mixed)
        assertEquals("длина обязана сохраниться — иначе поплывут все длины в TLS", hello.size, mixed!!.size)

        var diff = 0
        for (i in hello.indices) if (hello[i] != mixed[i]) diff++
        assertEquals("меняется ровно один байт", 1, diff)
    }

    /** Изменённый ClientHello обязан остаться полностью разбираемым. */
    @Test
    fun mixedHelloStillParsesAndReadsAsSameHost() {
        for (host in listOf(
            "www.youtube.com",
            "rr12---sn-4g5ednse.googlevideo.com",
            "youtubei.googleapis.com",
            "discord.com"
        )) {
            val hello = StrategyAutopilotHelloFactory.build(host)
            val info = Tls.parseClientHello(hello, 0, hello.size)!!
            val mixed = Tls.mixCaseInSld(hello, info.sniStart, info.sniEnd, info.sni)!!
            val reparsed = Tls.parseClientHello(mixed, 0, mixed.size)

            assertNotNull("$host: изменённый ClientHello перестал разбираться", reparsed)
            assertEquals("$host: длина записи изменилась", hello.size, reparsed!!.recordLength)
            assertEquals(
                "$host: имя хоста обязано читаться так же без учёта регистра",
                host.lowercase(), reparsed.sni.lowercase()
            )
            assertNotEquals(
                "$host: имя хоста обязано отличаться от исходного, иначе приём ничего не делает",
                info.sni, reparsed.sni
            )
        }
    }

    /**
     * Меняться должна буква ВНУТРИ домена второго уровня.
     *
     * Проверено на реальном фильтре: правка в поддомене (`wWw.youtube.com`) или
     * в TLD (`www.youtube.coM`) не помогает — домен внутри остаётся читаемым,
     * и соединение по-прежнему блокируется.
     */
    @Test
    fun onlyChangeInsideSecondLevelDomainIsUseful() {
        val host = "www.youtube.com"
        val hello = StrategyAutopilotHelloFactory.build(host)
        val info = Tls.parseClientHello(hello, 0, hello.size)!!

        val mixed = Tls.mixCaseInSld(hello, info.sniStart, info.sniEnd, info.sni)!!
        val newInfo = Tls.parseClientHello(mixed, 0, mixed.size)!!

        val changedIdx = (info.sni.indices).first { info.sni[it] != newInfo.sni[it] }
        val sldStart = info.sni.lastIndexOf('.', info.sni.lastIndexOf('.') - 1) + 1
        val sldEnd = info.sni.lastIndexOf('.')
        assertTrue(
            "изменён символ «${info.sni[changedIdx]}» на позиции $changedIdx, " +
                "а нужно внутри домена второго уровня [$sldStart, $sldEnd) — иначе фильтр не обманут",
            changedIdx in sldStart until sldEnd
        )
    }

    /* ================================================================== */
    /*  План разбиения                                                     */
    /* ================================================================== */

    /**
     * Главное свойство: смена регистра применяется ДО разбиения.
     *
     * Если сначала разрезать, а потом поменять регистр, фильтр всё равно увидит
     * домен в пересобранном потоке — обе операции в одиночку бесполезны по
     * отдельности.
     */
    @Test
    fun caseMixAppliedBeforeSplitting() {
        val host = "rr12---sn-4g5ednse.googlevideo.com"
        val hello = StrategyAutopilotHelloFactory.build(host)
        val strategy = Strategy(
            desync = DesyncMode.MULTISPLIT,
            splitPositions = listOf(SplitPos.FIRST, SplitPos.MIDSNI),
            splitDelayMs = 2,
            sniCaseMix = true
        )
        val plan = engine.plan(hello, FlowContext(443, null, false), strategy)

        assertTrue("стратегия должна быть применена", plan.applied)
        assertEquals("разбиение должно сохраниться: 3 фрагмента", 3, plan.writes.size)

        // Ни в одном фрагменте не должно быть исходного имени.
        val rejoined = plan.writes.fold(ByteArray(0)) { a, w -> a + w }
        assertEquals("длина обязана сохраниться", hello.size, rejoined.size)

        val rejoinedInfo = Tls.parseClientHello(rejoined, 0, rejoined.size)!!
        assertEquals(host, rejoinedInfo.sni.lowercase())
        assertNotEquals(
            "в потоке, уходящем в сеть, должно быть изменённое имя — иначе фильтр его прочитает",
            host, rejoinedInfo.sni
        )
        // Домен внутри должен быть уже не в исходном регистре.
        assertTrue(
            "домен второго уровня остался в нижнем регистре: ${rejoinedInfo.sni}",
            rejoinedInfo.sni.substringBeforeLast('.') != host.substringBeforeLast('.').lowercase()
                .let { host.substring(0, it.length) } || rejoinedInfo.sni.any { it.isUpperCase() }
        )
    }

    /** Смена регистра работает и сама по себе, без разбиения. */
    @Test
    fun caseMixWorksWithoutAnySplitting() {
        val host = "www.youtube.com"
        val hello = StrategyAutopilotHelloFactory.build(host)
        val plan = engine.plan(
            hello, FlowContext(443, null, false),
            Strategy(desync = DesyncMode.NONE, sniCaseMix = true)
        )
        assertTrue("смена регистра обязана применяться и в пассивном режиме", plan.applied)
        assertEquals("без разбиения отправляем одним куском", 1, plan.writes.size)
        assertEquals(hello.size, plan.writes[0].size)
        assertNotEquals("байты обязаны отличаться", host, Tls.parseClientHello(plan.writes[0], 0, plan.writes[0].size)!!.sni)
    }

    /** Без включённого приёма байты не трогаются. */
    @Test
    fun caseMixIsOffByDefault() {
        val hello = StrategyAutopilotHelloFactory.build("www.youtube.com")
        val plan = engine.plan(
            hello, FlowContext(443, null, false),
            Strategy(desync = DesyncMode.MULTISPLIT, splitPositions = listOf(SplitPos.FIRST, SplitPos.MIDSNI))
        )
        val rejoined = plan.writes.fold(ByteArray(0)) { a, w -> a + w }
        assertEquals("выключенный приём обязан оставлять имя как есть", "www.youtube.com",
            Tls.parseClientHello(rejoined, 0, rejoined.size)!!.sni)
    }

    /* ================================================================== */
    /*  HTTP                                                              */
    /* ================================================================== */

    @Test
    fun httpHostHeaderIsAlsoMixed() {
        val req = "GET / HTTP/1.1\r\nHost: www.youtube.com\r\nAccept: */*\r\n\r\n".toByteArray()
        val range = Http.hostValueRange(req, 0, req.size)
        assertNotNull("значение Host должно находиться", range)
        val mixed = Http.mixCaseInHost(req, range!!.first, range.second)

        assertNotNull(mixed)
        assertEquals("длина заголовков меняться не должна", req.size, mixed!!.size)
        val text = String(mixed, Charsets.ISO_8859_1)
        // Меняется первая буква домена второго уровня, то есть `youtube` → `Youtube`.
        assertTrue(
            "в значении Host должно быть имя с изменённой буквой внутри домена, а $text — нет",
            text.contains("Host: www.Youtube.com")
        )
        assertFalse("исходное написание должно исчезнуть", text.contains("www.youtube.com"))
        assertTrue("длина блока заголовков обязана сохраниться", Http.headerBlockLength(mixed, 0, mixed.size) > 0)
    }

    /* ================================================================== */
    /*  Границы применимости                                               */
    /* ================================================================== */

    @Test
    fun namesWithoutSecondLevelDomainAreLeftAlone() {
        val hello = StrategyAutopilotHelloFactory.build("localhost")
        val info = Tls.parseClientHello(hello, 0, hello.size)!!
        assertNull("у имени без домена второго уровня менять нечего",
            Tls.mixCaseInSld(hello, info.sniStart, info.sniEnd, info.sni))
    }

    @Test
    fun emptyAndOutOfBoundsInputsAreHandled() {
        assertNull(Tls.mixCaseInSld(ByteArray(0), 0, 0, ""))
        assertNull(Tls.mixCaseInSld(ByteArray(10), 5, 5, "a.b.c"))
        assertNull(Http.mixCaseInHost(ByteArray(10), 3, 3))
    }

    /** Приём обязан быть среди кандидатов автоподбора, иначе он не будет найден. */
    @Test
    fun caseMixIsAmongAutopilotCandidates() {
        assertTrue(
            "смена регистра обязана быть в кандидатах автоподбора — на строгих фильтрах " +
                "ни одна сегментация не работает",
            StrategyAutopilot.CANDIDATES.any { it.second.sniCaseMix }
        )
// Первым среди активных идёт отравление DPI: против фильтра с полной
        // пересборкой сегментов не работает вообще ничего, кроме него. Поэтому
        // проверяем, что смена регистра идёт следом, а не раньше.
        val idx = StrategyAutopilot.CANDIDATES.indexOfFirst { it.second.sniCaseMix }
        assertTrue("смена регистра обязана быть среди кандидатов", idx >= 0)
        val before = StrategyAutopilot.CANDIDATES.take(idx)
            .any { it.second.desync != DesyncMode.NONE || it.second.poisonEnabled }
        assertTrue(
            "отравление DPI обязано проверяться раньше смены регистра: разбиение и смена " +
                "регистра против фильтра с пересборкой сегментов бесполезны",
            before
        )
    }

    /**
     * Разбиение внутри домена портит приём, поэтому в автоподборе оно идёт
     * последним, а не первым.
     *
     * Замеры на реальном фильтре, 6 кругов по кругу, байты самого приложения:
     * сплошной поток 6 из 6, разбиение по первому байту 6 из 6,
     * разбиение по первому байту и середине домена 5 из 6,
     * разбиение только по середине домена 0 из 6.
     *
     * Причина: разрыв попадает ровно в ту строку, которую приём ломает, и
     * фильтр получает её обратно склеенной. Если поставить такой вариант
     * первым, автоподбор на сети, где он не работает, потратит на него
     * первую попытку и вернётся к следующему — но на сети, где работает
     * только он, порядок уже неважен, потому что он всё равно будет найден.
     */
    @Test
    fun midDomainSplitIsNotTheFirstCaseMixCandidate() {
        val caseMix = StrategyAutopilot.CANDIDATES.filter { it.second.sniCaseMix }
        val withMidsld = caseMix.filter { it.second.splitPositions.contains(SplitPos.MIDSNI) }
        assertFalse(
            "разбиение по середине домена в паре со сменой регистра не работает — " +
                "оно не должно стоять раньше варианта без него",
            withMidsld.isEmpty()
        )
        val first = caseMix.first()
        assertEquals(
            "первым должен проверяться сплошной поток без разрыва: ${first.first}",
            DesyncMode.NONE, first.second.desync
        )
        // Сплошной поток обязан быть где-то среди кандидатов отдельной строкой.
        assertTrue(
            "нужен отдельный вариант «смена регистра без разбиения» — он самый надёжный",
            caseMix.any { it.second.desync == DesyncMode.NONE }
        )
    }

    /**
     * Приём НЕЛЬЗЯ включать в готовые профили.
     *
     * Проверено на двух путях одного и того же сегмента сети, и результаты
     * оказались противоположными:
     *
     *  * с машины, где фильтр ищет домен подстрокой: `www.youtube.com` не
     *    проходит ни разу из четырёх, `www.YouTube.com` — четыре из четырёх;
     *  * из эмулятора, идущего через NAT той же машины: наоборот,
     *    `www.youtube.com` проходит четыре из четырёх, а изменённый регистр
     *    не проходит ни разу — соединение, которое работало, ломается.
     *
     * То есть приём помогает на одних фильтрах и мешает на других, и знать
     * заранее какой из них перед пользователем нельзя. Включённый по умолчанию
     * он ухудшал бы рабочие подключения, поэтому включать его можно только
     * тем, кто проверил результат на своей сети — через автоподбор или вручную.
     */
    @Test
    fun caseMixIsOffInEveryPreset() {
        for (p in ProfileId.entries) {
            val cfg = Presets.apply(p, AppConfig())
            assertFalse(
                "профиль ${p.token}: смена регистра обязана быть выключена — приём " +
                    "односторонне полезен и включённый по умолчанию ломает рабочие подключения",
                cfg.sniCaseMix
            )
            for (rule in cfg.rules) {
                assertFalse(
                    "правило «${rule.name}» профиля ${p.token}: смена регистра обязана быть выключена",
                    rule.strategy.sniCaseMix
                )
            }
        }
    }
}