package dev.rubcut.zapret.core.desync

import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.HostSource
import dev.rubcut.zapret.data.Strategy
import dev.rubcut.zapret.data.StrategyRule

/**
 * Раскладывает походовые стратегии в правила с конкретными доменами.
 *
 * Подобранная стратегия кладётся в правило, у которого в `inlineDomains` стоят
 * ровно те хосты, для которых она и была проверена. Такое правило стоит в цепочке
 * **первым**, поэтому перехватывает именно их, и общие правила профиля
 * («YouTube / Google · TLS») к ним больше не применяются.
 *
 * Старые сгенерированные правила убираются: иначе они копились бы от подбора к
 * подбору и в конце концов начали бы перехватывать трафик сами у себя.
 *
 * @param perHost результат [dev.rubcut.zapret.core.stack.StrategyAutopilot.tunePerHost].
 */
fun AppConfig.withTunedPerHost(
    perHost: Map<String, Pair<String, Strategy>>,
    tcpPorts: String
): AppConfig {
    val kept = rules.filterNot { it.isGenerated }

    val generated = perHost.entries.map { entry ->
        val (host, named) = entry
        val (candidateName, strategy) = named
        StrategyRule(
            enabled = true,
            name = "Подбор: $host ($candidateName)",
            tcpPorts = tcpPorts,
            udpPorts = "",
            hostSource = HostSource.INLINE,
            inlineDomains = host,
            strategy = strategy,
            isGenerated = true
        )
    }

    // Сначала правила подбора, потом обычные правила профиля.
    return copy(rules = generated + kept)
}