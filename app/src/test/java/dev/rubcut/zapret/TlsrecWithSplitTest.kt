package dev.rubcut.zapret

import dev.rubcut.zapret.core.desync.DesyncEngine
import dev.rubcut.zapret.core.desync.FlowContext
import dev.rubcut.zapret.core.proto.Tls
import dev.rubcut.zapret.data.DesyncMode
import dev.rubcut.zapret.data.SplitPos
import dev.rubcut.zapret.data.Strategy
import org.junit.Assert.assertEquals
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