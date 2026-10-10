package dev.rubcut.zapret

import dev.rubcut.zapret.core.desync.DesyncEngine
import dev.rubcut.zapret.core.desync.FlowContext
import dev.rubcut.zapret.core.net.getU16
import dev.rubcut.zapret.core.proto.Tls
import dev.rubcut.zapret.data.DesyncMode
import dev.rubcut.zapret.data.SplitPos
import dev.rubcut.zapret.data.Strategy
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `MULTISPLIT_TLSREC` обязан делать обе половины своего названия.
 *
 * Регрессия: ветка переупаковки записей возвращалась раньше общего кода и брала
 * только границы переупакованных записей. Точки из `splitPositions` игнорировались
 * полностью — то есть заявленная комбинация «TLS-записи + разбиение» на деле
 * была просто «TLS-записи».
 *
 * На реальном фильтре, судя по журналу стороннего приложения, именно эта
 * комбинация и была единственной рабочей для YouTube, поэтому поломка была не
 * косметической.
 */
class TlsrecWithSplitTest {

    private val engine = DesyncEngine()

    @Test
    fun tlsrecRepackAloneSplitsAtRecordBoundaries() {
        val hello = StrategyAutopilotHelloFactory.build("www.youtube.com")
        val plain = Strategy(desync = DesyncMode.TLSREC, tlsrecParts = 2)
        val plan = engine.plan(hello, FlowContext(443, null, false), plain)

        assertTrue("переупаковка обязана применяться", plan.applied)
        assertTrue("ожидалось не меньше двух записей, получено ${plan.writes.size}", plan.writes.size >= 2)
        assertEquals("длина потока не должна меняться", hello.size, plan.writes.sumOf { it.size })
    }

    /**
     * Ключевая проверка: разрыв из `splitPositions` обязан применяться ВМЕСТЕ с
     * переупаковкой, а не вместо неё.
     */
    @Test
    fun multisplitTlsrecAppliesBothHalves() {
        val hello = StrategyAutopilotHelloFactory.build("www.youtube.com")

        val tlsrecOnly = engine.plan(
            hello, FlowContext(443, null, false),
            Strategy(desync = DesyncMode.TLSREC, tlsrecParts = 2)
        )
        val both = engine.plan(
            hello, FlowContext(443, null, false),
            Strategy(
                desync = DesyncMode.MULTISPLIT_TLSREC,
                tlsrecParts = 2,
                splitPositions = listOf(SplitPos.FIRST)
            )
        )

        assertTrue("multisplit+tlsrec обязан применять стратегию", both.applied)
        assertTrue(
            "разрыв по первому байту обязан добавить запись: было ${tlsrecOnly.writes.size}, " +
                "стало ${both.writes.size}",
            both.writes.size > tlsrecOnly.writes.size
        )
        assertEquals(
            "первая запись при разрыве по первому байту — ровно один байт",
            1, both.writes.first().size
        )
    }

    /**
     * Точный рез записи: граница обязана лежать там, где попросили, а тело —
     * собраться обратно байт в байт.
     *
     * Это ядро приёма `--tlsrec=0+wm --split=0+wm`. Если вторая часть
     * начнётся не с того места, граница записей уедет, и фильтр склеит ClientHello
     * обратно — техника та же, а обхода нет.
     */
    @Test
    fun repackRecordAtCutsAtTheExactOffset() {
        val hello = StrategyAutopilotHelloFactory.build("www.youtube.com")
        val recLen = Tls.recordTotalLength(hello, 0, hello.size)
        assertTrue("в тесте нужен корректный ClientHello", recLen > 0)
        val bodyLen = recLen - Tls.RECORD_HEADER
        val at = Tls.RECORD_HEADER + bodyLen / 3

        val out = Tls.repackRecordAt(hello, 0, hello.size, at)
        assertTrue("рез по смещению обязан сработать", out != null)
        out!!

        val bounds = Tls.recordBoundaries(out, 0, out.size)
        assertEquals("ожидались ровно две записи", 2, bounds.size)

        // Граница между записями — ровно запрошенная точка.
        val firstRecLen = getU16(out, 3)
        assertEquals("граница записей должна быть там, где просили", at, Tls.RECORD_HEADER + firstRecLen)
        assertEquals("тело второй записи — остаток", recLen - at, getU16(out, at + 3))
    }

    /** Рез не должен ни терять, ни дублировать байты. */
    @Test
    fun repackRecordAtPreservesBody() {
        val hello = StrategyAutopilotHelloFactory.build("rr1---sn-gxuo03g-ig3s.googlevideo.com")
        val recLen = Tls.recordTotalLength(hello, 0, hello.size)
        assertTrue("в тесте нужен корректный ClientHello", recLen > 0)
        val at = Tls.RECORD_HEADER + (recLen - Tls.RECORD_HEADER) / 2

        val out = Tls.repackRecordAt(hello, 0, hello.size, at) ?: error("рез не сработал")
        val rebuilt = Tls.recordBoundaries(out, 0, out.size).fold(ByteArray(0)) { acc, from ->
            val len = getU16(out, from + 3)
            acc + out.copyOfRange(from + Tls.RECORD_HEADER, from + Tls.RECORD_HEADER + len)
        }
        assertArrayEquals(
            "тело записи обязано собраться обратно без потерь",
            hello.copyOfRange(Tls.RECORD_HEADER, recLen),
            rebuilt
        )
    }

    /** Точка вне тела записи — не повод резать наугад. */
    @Test
    fun repackRecordAtRejectsOffsetsOutsideBody() {
        val hello = StrategyAutopilotHelloFactory.build("www.youtube.com")
        assertNull("смещение в заголовке отвергается", Tls.repackRecordAt(hello, 0, hello.size, 3))
        assertNull("смещение за концом записи отвергается", Tls.repackRecordAt(hello, 0, hello.size, hello.size))
    }

    /** После переупаковки SNI разбирается заново: смещения сдвинуты. */
    @Test
    fun sniSurvivesRepacking() {
        val hello = StrategyAutopilotHelloFactory.build("rr1---sn-gxuo03g-ig3s.googlevideo.com")
        val plan = engine.plan(
            hello, FlowContext(443, null, false),
            Strategy(
                desync = DesyncMode.MULTISPLIT_TLSREC,
                tlsrecParts = 2,
                splitPositions = listOf(SplitPos.MIDSNI)
            )
        )
        assertTrue("стратегия обязана применяться", plan.applied)
        val rebuilt = plan.writes.fold(ByteArray(0)) { acc, w -> acc + w }
        assertEquals(
            "SNI обязан остаться читаемым после переупаковки",
            "rr1---sn-gxuo03g-ig3s.googlevideo.com",
            Tls.parseClientHello(rebuilt, 0, rebuilt.size)?.sni
        )
    }
}