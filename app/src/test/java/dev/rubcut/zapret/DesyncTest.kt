package dev.rubcut.zapret

import dev.rubcut.zapret.core.desync.DesyncEngine
import dev.rubcut.zapret.core.desync.FlowContext
import dev.rubcut.zapret.core.proto.Tls
import dev.rubcut.zapret.core.split.Segmenter
import dev.rubcut.zapret.data.DesyncMode
import dev.rubcut.zapret.data.SplitPos
import dev.rubcut.zapret.data.Strategy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Проверка самой механики обхода: куда именно попадает граница между
 * фрагментами ClientHello.
 *
 * Главный дефект, закрытый здесь, — точка разбиения считалась от середины
 * всей строки SNI. Для `www.google.com` это совпадает с серединой домена и
 * Google работает, поэтому дефект был не виден. Но видео YouTube идёт с
 * CDN-хостов `rr*.googlevideo.com`, где середина строки попадает в случайный
 * префикс, и разбиение не ломало DPI ничего.
 */
class DesyncTest {

    private val engine = DesyncEngine()

    private fun helloFor(sni: String): ByteArray = StrategyAutopilotHelloFactory.build(sni)

    private fun plan(sni: String, strategy: Strategy) =
        engine.plan(helloFor(sni), FlowContext(443, null, false), strategy)

    private fun planWrites(sni: String, strategy: Strategy): List<ByteArray> =
        plan(sni, strategy).writes

    /* ================================================================ */
    /*  Точка разбиения обязана лежать внутри домена второго уровня       */
    /* ================================================================ */

    /**
     * Точка разбиения должна оказаться ВНУТРИ значимой части имени — внутри
     * домена второго уровня. Это и есть смысл `midsld` в zapret: DPI ищет домен,
     * и разрыв должен быть именно там.
     */
    @Test
    fun splitPointLandsInsideSecondLevelDomain() {
        // Реальные CDN-хосты YouTube: длинный случайный префикс перед доменом.
        val cdnHosts = listOf(
            "rr12---sn-4g5ednse.googlevideo.com",
            "rr5---sn-i3b6knf3n5oe.googlevideo.com",
            "r1---sn-abcde.googlevideo.com",
            "rr3---sn-8oagn5g5g5oe.googlevideo.com"
        )

        val strategy = Strategy(desync = DesyncMode.SPLIT, splitPositions = listOf(SplitPos.MIDSNI))

        for (host in cdnHosts) {
            val hello = helloFor(host)
            val info = Tls.parseClientHello(hello, 0, hello.size)!!
            val point = info.midsldOffset

            assertTrue(
                "точка разбиения $point вне имени хоста [$info.sniStart, ${info.sniEnd}) для $host",
                point > info.sniStart && point < info.sniEnd
            )

            // Граница должна резать домен второго уровня, то есть
            // предпоследний ярлык.
            val sldStart = info.sniStart
            val sldEnd = info.sniStart + host.substringBeforeLast('.').length
            assertTrue(
                "точка $point должна быть внутри домена второго уровня [$sldStart, $sldEnd) для $host, " +
                    "иначе DPI склеит сегменты и увидит ${host.substring(sldStart - info.sniStart, sldEnd - info.sniStart)}",
                point > sldStart && point <= sldEnd
            )

            // И действительно разбиваем ровно там.
            val writes = planWrites(host, strategy)
            assertEquals("ожидались 2 сегмента для $host, получено ${writes.size}", 2, writes.size)
            val cut = writes[0].size
            assertEquals("граница фрагментов разошлась с точкой разбиения", point, cut)
        }
    }

    /** На коротких именах поведение не должно измениться. */
    @Test
    fun splitPointStillInsideHostForShortNames() {
        val strategy = Strategy(desync = DesyncMode.SPLIT, splitPositions = listOf(SplitPos.MIDSNI))
        for (host in listOf("www.google.com", "www.youtube.com", "a.ru", "discord.com")) {
            val hello = helloFor(host)
            val info = Tls.parseClientHello(hello, 0, hello.size)!!
            val point = info.midsldOffset
            assertTrue(
                "точка $point вне имени для $host",
                point > info.sniStart && point < info.sniEnd
            )
            assertEquals(2, planWrites(host, strategy).size)
        }
    }

    /* ================================================================ */
    /*  Точки разбиения не должны схлопываться в один бесполезный байт     */
    /* ================================================================ */

    /**
     * Профиль по умолчанию — `multisplit` с точками `1,midsld`. Раньше точки
     * сортировались, и `1` всегда отрезал один байт, а остальные смещения
     * оказывались за пределами первого сегмента: получалось два фрагмента, из
     * которых первый — пустой префикс. Теперь `1` и середина SLD дают три
     * осмысленных фрагмента.
     */
    @Test
    fun multisplitUsesEveryRequestedPoint() {
        val host = "rr12---sn-4g5ednse.googlevideo.com"
        val strategy = Strategy(
            desync = DesyncMode.MULTISPLIT,
            splitPositions = listOf(SplitPos.FIRST, SplitPos.MIDSNI)
        )
        val writes = planWrites(host, strategy)

        assertEquals("multisplit с двумя точками обязан дать три фрагмента", 3, writes.size)
        assertEquals("первый фрагмент — один байт (FIRST)", 1, writes[0].size)
        assertTrue(
            "второй фрагмент непустой и ведёт к точке разбиения",
            writes[1].size > 1
        )
        // Склейка фрагментов обязана дать исходный ClientHello байт в байт.
        val rejoined = writes.fold(ByteArray(0)) { acc, w -> acc + w }
        assertTrue(
            "фрагменты не склеились обратно в исходный ClientHello",
            rejoined.contentEquals(helloFor(host))
        )
    }

    /** Граница первого фрагмента обязана быть именно точкой midsld. */
    @Test
    fun multisplitSecondSegmentEndsAtSecondLevelDomain() {
        val host = "rr12---sn-4g5ednse.googlevideo.com"
        val hello = helloFor(host)
        val info = Tls.parseClientHello(hello, 0, hello.size)!!
        val strategy = Strategy(
            desync = DesyncMode.MULTISPLIT,
            splitPositions = listOf(SplitPos.FIRST, SplitPos.MIDSNI)
        )
        val writes = planWrites(host, strategy)
        assertEquals("граница первых двух сегментов = точка разбиения", info.midsldOffset, writes[0].size + writes[1].size)
    }

    /* ================================================================ */
    /*  Segmenter: границы, порядок, выход за пределы                     */
    /* ================================================================ */

    @Test
    fun segmenterProducesRequestedFragmentCount() {
        val data = ByteArray(20) { it.toByte() }
        val parts = Segmenter.split(data, listOf(5, 10, 15))
        assertEquals(4, parts.size)
        assertEquals(5, parts[0].size)
        assertEquals(5, parts[1].size)
        assertEquals(5, parts[2].size)
        assertEquals(5, parts[3].size)
    }

    @Test
    fun segmenterIsOrderIndependentAndDropsOutOfRange() {
        val data = ByteArray(10) { it.toByte() }
        val a = Segmenter.split(data, listOf(3, 7))
        val b = Segmenter.split(data, listOf(7, 3))
        assertEquals("порядок точек не должен влиять на результат", a.size, b.size)
        assertTrue(a[0].contentEquals(b[0]))

        // Точки вне полосы отбрасываются, а не роняют разбиение.
        val c = Segmenter.split(data, listOf(-5, 0, 3, 10, 99))
        assertEquals(2, c.size)
        assertEquals(3, c[0].size)
        assertEquals(7, c[1].size)
    }

    @Test
    fun segmenterWithoutValidBoundsReturnsWholePayload() {
        val data = ByteArray(8) { 1 }
        assertEquals(1, Segmenter.split(data, emptyList()).size)
        assertEquals(1, Segmenter.split(data, listOf(0, -1)).size)
        assertTrue(Segmenter.split(data, listOf(0, -1))[0].contentEquals(data))
    }

    @Test
    fun segmenterRoundTripsExactly() {
        val rnd = java.util.Random(7)
        repeat(200) {
            val n = 1 + rnd.nextInt(200)
            val data = ByteArray(n).also { rnd.nextBytes(it) }
            val bounds = (1 until n).filter { rnd.nextBoolean() }.take(6)
            val parts = Segmenter.split(data, bounds)
            val rejoined = parts.fold(ByteArray(0)) { acc, w -> acc + w }
            assertTrue("разбиение изменило данные", rejoined.contentEquals(data))
        }
    }

    /* ================================================================ */
    /*  Приёмы на параметрах сокета: OOB и FAKE                          */
    /* ================================================================ */

    /**
     * OOB обязан дать разбиение И байт для отправки: без любого из двух план
     * бесполезен. Сам байт движок не отправляет — это делает сокет, — но план
     * обязан его нести, иначе соединение уйдёт обычным разрезом молча.
     */
    @Test
    fun oobBranchEmitsSplitWithUrgentByte() {
        val p = plan(
            "www.youtube.com",
            Strategy(desync = DesyncMode.OOB, splitPositions = listOf(SplitPos.MIDSNI), urgentByte = 0)
        )
        assertTrue("OOB обязан применяться", p.applied)
        assertTrue("OOB без разбиения бессмысленен: ${p.writes.size}", p.writes.size >= 2)
        assertEquals("байт обязан дойти до сокета", 0, p.urgentByte)
    }

    /** OOB без заданного байта (null) — отказ, а не молчаливый разрез. */
    @Test
    fun oobWithoutByteGivesUp() {
        val p = plan(
            "www.youtube.com",
            Strategy(desync = DesyncMode.OOB, splitPositions = listOf(SplitPos.MIDSNI), urgentByte = null)
        )
        assertTrue("без байта OOB обязан отказаться, а не резать молча", !p.applied)
    }

    /**
     * FAKE несёт безвредную пустышку, а не настоящий ClientHello: слать туда
     * настоящие данные бессмысленно — фильтр найдёт в них тот же SNI.
     */
    @Test
    fun fakeBranchCarriesBenignDummy() {
        val p = plan(
            "www.youtube.com",
            Strategy(desync = DesyncMode.FAKE, fakeTtl = 8)
        )
        assertTrue("FAKE обязан применяться", p.applied)
        assertEquals(8, p.fakeTtl)
        val dummy = p.fakeDummy
        assertTrue("пустышка обязана быть", dummy != null)
        dummy!!
        val sni = Tls.parseClientHello(dummy, 0, dummy.size)?.sni
        assertTrue(
            "в пустышке не должно быть запрещённого имени, а там $sni",
            sni != null && "youtube" !in sni
        )
    }

    /** FAKE без TTL или не для TLS — отказ. */
    @Test
    fun fakeWithoutTtlGivesUp() {
        val p = plan(
            "www.youtube.com",
            Strategy(desync = DesyncMode.FAKE, fakeTtl = 0)
        )
        assertTrue("FAKE без TTL обязан отказаться", !p.applied)
    }
}

/**
 * Сборка настоящего ClientHello для тестов: только то, что нужно движку для
 * разбора SNI. Качество шифров здесь не важно — сервер мы не зовём.
 */
internal object StrategyAutopilotHelloFactory {
    fun build(host: String): ByteArray {
        val name = host.toByteArray(Charsets.US_ASCII)
        val entry = 1 + 2 + name.size
        val sni = java.io.ByteArrayOutputStream().apply {
            write((entry ushr 8) and 0xFF); write(entry and 0xFF)
            write(0)
            write((name.size ushr 8) and 0xFF); write(name.size and 0xFF)
            write(name)
        }.toByteArray()
        val ext = java.io.ByteArrayOutputStream().apply {
            write(0); write(0)                              // server_name
            write((sni.size ushr 8) and 0xFF); write(sni.size and 0xFF)
            write(sni)
        }.toByteArray()
        val suites = intArrayOf(0xC02F, 0xC030, 0x009C, 0x009D)
        val body = java.io.ByteArrayOutputStream().apply {
            write(3); write(3)
            write(ByteArray(32) { 7 })
            write(0)
            // Длина набора шифров — в БАЙТАХ, по 2 на каждый шифр.
            write((suites.size * 2 ushr 8) and 0xFF)
            write((suites.size * 2) and 0xFF)
            for (s in suites) { write((s ushr 8) and 0xFF); write(s and 0xFF) }
            write(1); write(0)
            write((ext.size ushr 8) and 0xFF); write(ext.size and 0xFF)
            write(ext)
        }.toByteArray()
        val hs = java.io.ByteArrayOutputStream().apply {
            write(1)
            write((body.size ushr 16) and 0xFF)
            write((body.size ushr 8) and 0xFF)
            write(body.size and 0xFF)
            write(body)
        }.toByteArray()
        return java.io.ByteArrayOutputStream().apply {
            write(0x16); write(3); write(1)
            write((hs.size ushr 8) and 0xFF); write(hs.size and 0xFF)
            write(hs)
        }.toByteArray()
    }
}