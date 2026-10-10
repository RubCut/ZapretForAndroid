package dev.rubcut.zapret

import dev.rubcut.zapret.core.desync.DesyncEngine
import dev.rubcut.zapret.core.desync.FlowContext
import dev.rubcut.zapret.core.stack.StrategyAutopilot
import dev.rubcut.zapret.data.DesyncMode
import dev.rubcut.zapret.data.SplitPos
import dev.rubcut.zapret.data.Strategy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Кандидаты автоподбора обязаны быть рабочими, а не только разнообразными.
 *
 * Подбор перебирает стратегии в этом порядке и применяет первую, ответившую
 * сервером. Значит слабый кандидат в начале списка не просто «не сработает» —
 * он перекроет сильные варианты: тот, кто ответил, и так нашёлся бы позже.
 */
class AutopilotCandidatesTest {

    private val engine = DesyncEngine()

    /** Кандидат обязан реально разбивать ClientHello с SNI хоста YouTube. */
    @Test
    fun everySplittingCandidateActuallySplitsCdnHostname() {
        val host = "rr12---sn-4g5ednse.googlevideo.com"
        val hello = StrategyAutopilotHelloFactory.build(host)
        val info = dev.rubcut.zapret.core.proto.Tls.parseClientHello(hello, 0, hello.size)!!

        val broken = mutableListOf<String>()
        for ((name, strategy) in StrategyAutopilot.CANDIDATES) {
            // Тест про разбиение: варианты без десинхронизации работают другим
            // приёмом (пассивный — никак, «только смена регистра» — подменой
            // байта без фрагментов) и разбиения давать не обязаны.
            if (strategy.desync == DesyncMode.NONE) continue
            val plan = engine.plan(hello, FlowContext(443, null, false), strategy)
            if (!plan.applied || plan.writes.size < 2) {
                broken += "$name (фрагментов: ${plan.writes.size})"
                continue
            }
            // Границы обязаны быть непустыми фрагментами, а не нулями.
            if (plan.writes.any { it.isEmpty() }) {
                broken += "$name (пустой фрагмент)"
            }
        }
        assertTrue("эти кандидаты не дают разбиения: $broken", broken.isEmpty())
        assertEquals(
            "разбиение должно уходить внутри домена, а не в префикс",
            true,
            run {
                val s = StrategyAutopilot.CANDIDATES.first { it.first.startsWith("multisplit · первый байт +") }.second
                val plan = engine.plan(hello, FlowContext(443, null, false), s)
                val boundary = plan.writes[0].size + plan.writes[1].size
                val sldEnd = info.sniStart + host.substringBeforeLast('.').length
                boundary > info.sniStart && boundary <= sldEnd
            }
        )
    }

    /**
     * Первым среди разбиений должен идти самый сильный вариант.
     *
     * Подбор применяет первую сработавшую стратегию, поэтому порядок
     * определяет результат.
     */
    @Test
    fun strongestSplitCandidateComesFirst() {
        // Варианты со сменой регистра проверяются отдельно: они описывают другой
        // приём и обходятся собственным тестом, здесь важна только их роль
        // разбивающих кандидатов без смены регистра.
        //
        // Первым разбивающим идёт tlsrec + середина домена (0+wm): именно эта
        // комбинация победила на реальном фильтре, поэтому она проверяется
        // раньше всех остальных активных кандидатов.
        val firstSplit = StrategyAutopilot.CANDIDATES
            .first {
                it.second.desync != dev.rubcut.zapret.data.DesyncMode.NONE &&
                    !it.second.sniCaseMix
            }
        val strategy = firstSplit.second
        assertEquals(
            "первым разбивающим должен идти tlsrec-вариант, а идёт ${firstSplit.first}",
            dev.rubcut.zapret.data.DesyncMode.MULTISPLIT_TLSREC, strategy.desync
        )
        assertTrue(
            "точка реза первого кандидата — середина домена (0+wm), а не первый байт: ${strategy.splitPositions}",
            strategy.splitPositions.contains(SplitPos.MIDSNI)
        )
    }

    /** У пассивного кандидата разбиения быть не должно — иначе подбор начнёт ломать сеть. */
    @Test
    fun passiveCandidateIsFirstAndDoesNotSplit() {
        val first = StrategyAutopilot.CANDIDATES.first()
        assertTrue("первым должен идти пассивный кандидат: ${first.first}", first.second.isPassive)

        val hello = StrategyAutopilotHelloFactory.build("www.youtube.com")
        val plan = engine.plan(hello, FlowContext(443, null, false), first.second)
        assertTrue("пассивный кандидат обязан передавать поток как есть", !plan.applied)
        assertEquals(1, plan.writes.size)
    }

    /**
     * «Смена регистра без разбиения» — активная стратегия без фрагментов.
     *
     * Регрессия: флаг sniCaseMix не входил в [Strategy.isPassive], поэтому
     * короткое замыкание на пассивность отбрасывало приём до вызова движка —
     * кандидат автоподбора был мёртвым, а техника 6/6 не применялась.
     */
    @Test
    fun caseMixOnlyCandidateAppliesWithoutSplitting() {
        val entry = StrategyAutopilot.CANDIDATES.first { it.second.sniCaseMix && it.second.desync == DesyncMode.NONE }
        assertTrue("кандидат «только смена регистра» обязан быть активным", !entry.second.isPassive)

        val host = "www.youtube.com"
        val hello = StrategyAutopilotHelloFactory.build(host)
        val plain = engine.plan(hello, FlowContext(443, null, false), Strategy(desync = DesyncMode.NONE))
        assertTrue("база сравнения: пассивный план не применяется", !plain.applied)

        val plan = engine.plan(hello, FlowContext(443, null, false), entry.second)
        assertTrue("смена регистра обязана применяться и без разбиения", plan.applied)
        assertEquals("без разбиения запись обязана быть одна", 1, plan.writes.size)
        assertTrue(
            "байты обязаны отличаться от исходных ровно сменой регистра",
            !plan.writes[0].contentEquals(hello) && plan.writes[0].size == hello.size
        )
    }
}
