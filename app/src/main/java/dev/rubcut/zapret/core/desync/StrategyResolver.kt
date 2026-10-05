package dev.rubcut.zapret.core.desync

import dev.rubcut.zapret.core.match.HostMatcher
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.HostSource
import dev.rubcut.zapret.data.HostListStore
import dev.rubcut.zapret.data.HostlistMode
import dev.rubcut.zapret.data.IpsetMode
import dev.rubcut.zapret.data.Strategy
import dev.rubcut.zapret.data.StrategyRule
import java.net.InetAddress

/**
 * Выбор стратегии для конкретного потока.
 *
 * Логика полностью повторяет zapret: правила проверяются по порядку, срабатывает первое
 * подходящее (в .bat-файлах такие блоки разделены ключом --new). Если ни одно правило
 * не подошло — действуют общие фильтры (--wf-tcp/--wf-udp, --hostlist, --ipset) и
 * общая стратегия из профиля.
 */
class StrategyResolver(
    private val configProvider: () -> AppConfig,
    private val listsProvider: () -> HostListStore.Snapshot
) {

    class Decision(val strategy: Strategy, val rule: StrategyRule?, val reason: String)

    fun resolveTcp(port: Int, host: String?, ip: InetAddress?): Decision =
        resolve(isTcp = true, port = port, host = host, ip = ip)

    fun resolveUdp(port: Int, host: String?, ip: InetAddress?): Decision =
        resolve(isTcp = false, port = port, host = host, ip = ip)

    private fun resolve(isTcp: Boolean, port: Int, host: String?, ip: InetAddress?): Decision {
        val cfg = configProvider()
        val lists = listsProvider()

        for (rule in cfg.rules) {
            if (!rule.enabled) continue
            // Правило действует только на тот протокол, для которого задан фильтр.
            val spec = if (isTcp) rule.tcpPorts else rule.udpPorts
            if (spec.isBlank()) continue
            val filter = if (isTcp) rule.tcpFilter else rule.udpFilter
            if (!filter.matches(port)) continue
            if (!hostMatches(rule, host, lists)) continue
            if (rule.excludeDomains.isNotBlank() && HostMatcher.parse(rule.excludeDomains).matches(host)) {
                return Decision(Strategy.OFF, null, "исключено правилом «${rule.displayName()}»")
            }
            return Decision(rule.strategy, rule, "правило «${rule.displayName()}»")
        }

        // Общие фильтры
        val globalFilter = if (isTcp) cfg.tcpFilter else cfg.udpFilter
        if (!globalFilter.matches(port)) return Decision(Strategy.OFF, null, "порт $port вне фильтра")

        val excludedByHost = lists.exclude.matches(host)
        if (excludedByHost) return Decision(Strategy.OFF, null, "$host в hostlist-exclude")

        when (cfg.hostlistMode) {
            HostlistMode.OFF -> Unit
            HostlistMode.INCLUDE -> if (!lists.hostlist.matches(host)) {
                return Decision(Strategy.OFF, null, "${host ?: "?"} не в hostlist")
            }
            HostlistMode.EXCLUDE -> if (lists.hostlist.matches(host)) {
                return Decision(Strategy.OFF, null, "${host ?: "?"} в hostlist-exclude")
            }
        }

        when (cfg.ipsetMode) {
            IpsetMode.OFF -> Unit
            IpsetMode.INCLUDE -> if (!lists.ipset.matches(ip)) {
                return Decision(Strategy.OFF, null, "${ip?.hostAddress ?: "?"} не в ipset")
            }
            IpsetMode.EXCLUDE -> if (lists.ipsetExclude.matches(ip)) {
                return Decision(Strategy.OFF, null, "${ip?.hostAddress ?: "?"} в ipset-exclude")
            }
        }

        return Decision(cfg.toStrategy().copy(sniCaseMix = cfg.sniCaseMix), null, "общая стратегия профиля")
    }

    /**
     * Попадает ли имя в область действия обхода: по любому включённому правилу
     * (порты не проверяются — для DNS-запроса порт ещё неизвестен) либо по
     * общим фильтрам hostlist.
     *
     * Нужно DNS-перехвату: домены ВНЕ области обхода обязаны получать ответ
     * провайдера без изменений. Иначе получается, что приложение «реагирует»
     * на весь интернет, а не только на домены из списка.
     */
    fun hostInScope(host: String?): Boolean {
        if (host.isNullOrEmpty()) return false
        val cfg = configProvider()
        val lists = listsProvider()
        if (lists.exclude.matches(host)) return false
        for (rule in cfg.rules) {
            if (!rule.enabled) continue
            if (!hostMatches(rule, host, lists)) continue
            if (rule.excludeDomains.isNotBlank() && HostMatcher.parse(rule.excludeDomains).matches(host)) continue
            return true
        }
        return when (cfg.hostlistMode) {
            HostlistMode.OFF -> true
            HostlistMode.INCLUDE -> lists.hostlist.matches(host)
            HostlistMode.EXCLUDE -> !lists.hostlist.matches(host)
        }
    }

    private fun hostMatches(rule: StrategyRule, host: String?, lists: HostListStore.Snapshot): Boolean {
        if (rule.hostSource == HostSource.ANY) return true
        if (host.isNullOrEmpty()) return false
        val matcher = when (rule.hostSource) {
            HostSource.ANY -> return true
            HostSource.HOSTLIST -> lists.hostlist
            HostSource.GENERAL -> HostListStore.GENERAL_MATCHER
            HostSource.GOOGLE -> HostListStore.GOOGLE_MATCHER
            HostSource.DISCORD -> HostListStore.DISCORD_MATCHER
            HostSource.INLINE -> HostMatcher.parse(rule.inlineDomains)
        }
        return matcher.matches(host)
    }
}

fun StrategyRule.displayName(): String =
    name.ifBlank { "${if (tcpPorts.isNotBlank()) "tcp/$tcpPorts" else ""}${if (udpPorts.isNotBlank()) " udp/$udpPorts" else ""}".trim() }

/** Кэш «IP → домен», наполняется DNS-резолвером и используется до получения SNI. */
object ReverseHostCache {
    private const val MAX = 4096
    private val map = object : LinkedHashMap<String, String>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, String>?): Boolean = size > MAX
    }

    @Synchronized
    fun put(ip: InetAddress, host: String) {
        map[ip.hostAddress ?: return] = host
    }

    @Synchronized
    fun get(ip: InetAddress?): String? {
        if (ip == null) return null
        return map[ip.hostAddress]
    }

    @Synchronized
    fun clear() = map.clear()
}
