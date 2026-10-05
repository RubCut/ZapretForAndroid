package dev.rubcut.zapret

import dev.rubcut.zapret.core.desync.DesyncEngine
import dev.rubcut.zapret.core.desync.FlowContext
import dev.rubcut.zapret.core.stack.StrategyAutopilot
import dev.rubcut.zapret.data.SplitPos
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
            if (strategy.isPassive) continue          // «без обработки» разбивать не должна
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
        val firstSplit = StrategyAutopilot.CANDIDATES
            .first {
                it.second.desync != dev.rubcut.zapret.data.DesyncMode.NONE &&
                    !it.second.sniCaseMix
            }
        val positions = firstSplit.second.splitPositions
        assertTrue(
            "первый разбивающий кандидат должен содержать обе точки (FIRST и MIDSNI), а содержит $positions",
            positions.contains(SplitPos.FIRST) && positions.contains(SplitPos.MIDSNI)
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
}