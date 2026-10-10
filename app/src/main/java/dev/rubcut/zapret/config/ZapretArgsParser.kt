package dev.rubcut.zapret.config

import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.DesyncMode
import dev.rubcut.zapret.data.HostSource
import dev.rubcut.zapret.data.HostlistMode
import dev.rubcut.zapret.data.IpsetMode
import dev.rubcut.zapret.data.ProfileId
import dev.rubcut.zapret.data.SplitPos
import dev.rubcut.zapret.data.Strategy
import dev.rubcut.zapret.data.StrategyRule

class ParseResult(
    val rules: List<StrategyRule>,
    val globalTcpPorts: String?,
    val globalUdpPorts: String?,
    val hostlistMode: HostlistMode?,
    val ipsetMode: IpsetMode?,
    val defaultStrategy: Strategy?,
    val cutoffChunks: Int?,
    val anyProtocol: Boolean?,
    val sniCaseMix: Boolean? = null,
    val poisonEnabled: Boolean? = null,
    val supported: List<String>,
    val ignored: List<String>,
    val unknown: List<String>,
    val errors: List<String>
) {
    val isEmpty: Boolean get() = supported.isEmpty() && ignored.isEmpty() && unknown.isEmpty() && errors.isEmpty()

    fun applyTo(base: AppConfig): AppConfig = base.copy(
        profile = ProfileId.CUSTOM,
        tcpPorts = globalTcpPorts ?: base.tcpPorts,
        udpPorts = globalUdpPorts ?: base.udpPorts,
        hostlistMode = hostlistMode ?: base.hostlistMode,
        ipsetMode = ipsetMode ?: base.ipsetMode,
        rules = if (rules.isNotEmpty()) rules else base.rules,
        desync = defaultStrategy?.desync ?: base.desync,
        splitPositions = defaultStrategy?.splitPositions ?: base.splitPositions,
        splitCustomPos = defaultStrategy?.splitCustomPos ?: base.splitCustomPos,
        splitDelayMs = defaultStrategy?.splitDelayMs ?: base.splitDelayMs,
        tlsrecParts = defaultStrategy?.tlsrecParts ?: base.tlsrecParts,
        wssizeEnabled = defaultStrategy?.wssizeEnabled ?: base.wssizeEnabled,
        wssizePackets = defaultStrategy?.wssizePackets ?: base.wssizePackets,
        wssizeWindow = defaultStrategy?.wssizeWindow ?: base.wssizeWindow,
        anyProtocol = anyProtocol ?: defaultStrategy?.anyProtocol ?: base.anyProtocol,
        sniCaseMix = sniCaseMix ?: defaultStrategy?.sniCaseMix ?: base.sniCaseMix,
        poisonEnabled = poisonEnabled ?: defaultStrategy?.poisonEnabled ?: base.poisonEnabled,
        poisonSni = defaultStrategy?.poisonSni?.takeIf { it.isNotBlank() } ?: base.poisonSni,
        poisonDelayMs = defaultStrategy?.poisonDelayMs ?: base.poisonDelayMs,
        urgentByte = defaultStrategy?.urgentByte ?: base.urgentByte,
        fakeTtl = defaultStrategy?.fakeTtl ?: base.fakeTtl,
        cutoffChunks = cutoffChunks ?: base.cutoffChunks
    )
}

/**
 * Разбор командной строки zapret (winws/nfqws) в настройки приложения.
 *
 * Понимает блоки, разделённые `--new`, переносы строк `^` из .bat-файлов и кавычки.
 * Параметры, которые физически невозможно реализовать без root (подмена seq,
 * rst/ipfrag/fooling вне потока, правка IP-заголовков), попадают в список
 * «проигнорировано» с объяснением, а не молча отбрасываются.
 *
 * OOB/FAKE работают БЕЗ root через android.system.Os на дескрипторе обычного
 * сокета — так делает ZapretYT (r1.a/r1.b + sendfile): поэтому `oob`/`fake`
 * здесь поддерживаются, а не игнорируются.
 */
object ZapretArgsParser {

    private val ROOT_ONLY = mapOf(
        "fakeknown" to "требует raw-сокетов (root)",
        "syndata" to "требует raw-сокетов (root)",
        "synack" to "требует raw-сокетов (root)",
        "fakeddisorder" to "требует raw-сокетов (root)",
        "rst" to "требует raw-сокетов (root)",
        "rstack" to "требует raw-сокетов (root)",
        "hopbyhop" to "требует raw-сокетов (root)",
        "destopt" to "требует raw-сокетов (root)",
        "ipfrag" to "требует raw-сокетов (root)",
        "ipfrag1" to "требует raw-сокетов (root)",
        "ipfrag2" to "требует raw-сокетов (root)",
        "seqovl" to "требует raw-сокетов (root)",
        "tamper" to "требует raw-сокетов (root)",
        "udplen" to "требует raw-сокетов (root)",
        "block" to "блокировка пакетов вместо ретрансляции (root)"
    )

    fun parse(text: String, base: AppConfig): ParseResult {
        val supported = ArrayList<String>()
        val ignored = ArrayList<String>()
        val unknown = ArrayList<String>()
        val errors = ArrayList<String>()

        val normalized = text.replace("^", " ")
            .replace("%BIN%", "")
            .replace("%LISTS%", "")
            .replace(Regex("(?im)^\\s*(start|@echo|chcp|cd|call|set|echo)\\b.*$"), " ")

        val tokens = tokenize(normalized)
        if (tokens.isEmpty()) return ParseResult(
            rules = emptyList(), globalTcpPorts = null, globalUdpPorts = null,
            hostlistMode = null, ipsetMode = null, defaultStrategy = null,
            cutoffChunks = null, anyProtocol = null, sniCaseMix = null, poisonEnabled = null,
            supported = supported, ignored = ignored, unknown = unknown, errors = errors
        )

        val rules = ArrayList<StrategyRule>()
        var globalTcp: String? = null
        var globalUdp: String? = null
        var hostlistMode: HostlistMode? = null
        var ipsetMode: IpsetMode? = null
        var cutoff: Int? = null
        var anyProtocol: Boolean? = null
        var sniCaseMix: Boolean? = null
        var poisonEnabled: Boolean? = null

        var curTcp = ""
        var curUdp = ""
        var curDomains = ""
        var curExclude = ""
        var curHostSource = HostSource.ANY
        var curDesync = DesyncMode.NONE
        var curPositions = ArrayList<SplitPos>()
        var curCustomPos = base.splitCustomPos
        var curDelay = base.splitDelayMs
        var curTlsrec = base.tlsrecParts
        var curWssizeOn = base.wssizeEnabled
        var curWssizePackets = base.wssizePackets
        var curWssizeWindow = base.wssizeWindow
        var curAnyProto = base.anyProtocol
        var curCaseMix = base.sniCaseMix
        var curPoison = base.poisonEnabled
        var curPoisonSni = base.poisonSni
        var curPoisonDelay = base.poisonDelayMs
        var curUrgentByte: Int? = base.urgentByte
        var curFakeTtl = base.fakeTtl
        var ruleName = ""

        fun flush() {
            if (curTcp.isBlank() && curUdp.isBlank() && curDesync == DesyncMode.NONE && curDomains.isBlank()) return
            val strategy = Strategy(
                desync = curDesync,
                splitPositions = curPositions.distinct().ifEmpty { listOf(SplitPos.MIDSNI) },
                splitCustomPos = curCustomPos,
                splitDelayMs = curDelay,
                tlsrecParts = if (curDesync == DesyncMode.TLSREC || curDesync == DesyncMode.MULTISPLIT_TLSREC) curTlsrec.coerceAtLeast(2) else curTlsrec,
                wssizeEnabled = curWssizeOn,
                wssizePackets = curWssizePackets,
                wssizeWindow = curWssizeWindow,
                anyProtocol = curAnyProto,
                sniCaseMix = curCaseMix,
                poisonEnabled = curPoison,
                poisonSni = curPoisonSni,
                poisonDelayMs = curPoisonDelay,
                urgentByte = curUrgentByte,
                fakeTtl = curFakeTtl
            )
            rules += StrategyRule(
                name = ruleName.ifBlank { defaultRuleName(curTcp, curUdp, curDesync) },
                tcpPorts = curTcp,
                udpPorts = curUdp,
                hostSource = curHostSource,
                inlineDomains = curDomains,
                excludeDomains = curExclude,
                strategy = strategy
            )
            curTcp = ""; curUdp = ""; curDomains = ""; curExclude = ""
            curHostSource = HostSource.ANY
            curDesync = DesyncMode.NONE
            curPositions = ArrayList()
            curAnyProto = base.anyProtocol
            curCaseMix = base.sniCaseMix
            curPoison = base.poisonEnabled
            curPoisonSni = base.poisonSni
            curPoisonDelay = base.poisonDelayMs
            ruleName = ""
        }

        var i = 0
        while (i < tokens.size) {
            val raw = tokens[i]
            val (key, inlineValue) = splitKeyValue(raw)
            val value: String? = inlineValue ?: tokens.getOrNull(i + 1)?.takeIf { !it.startsWith("--") }?.also { i++ }
            val k = key.lowercase()

            when {
                k == "--new" -> flush()

                k == "--wf-tcp" -> { globalTcp = value.orEmpty(); supported += "--wf-tcp=$globalTcp (общий фильтр TCP)" }
                k == "--wf-udp" -> { globalUdp = value.orEmpty(); supported += "--wf-udp=$globalUdp (общий фильтр UDP)" }
                k == "--filter-tcp" -> { curTcp = value.orEmpty(); supported += "--filter-tcp=$curTcp" }
                k == "--filter-udp" -> { curUdp = value.orEmpty(); supported += "--filter-udp=$curUdp" }
                k == "--filter-l7" -> ignored += "--filter-l7=$value (определение протокола по содержимому UDP не переносится без root)"

                k == "--hostlist" -> {
                    hostlistMode = HostlistMode.INCLUDE
                    curHostSource = HostSource.HOSTLIST
                    supported += "--hostlist (используется список «Хосты» из раздела «Списки»)"
                }
                k == "--hostlist-exclude" -> {
                    supported += "--hostlist-exclude (содержимое берётся из списка «Исключения»)"
                }
                k == "--hostlist-domains" -> {
                    curDomains = (value.orEmpty()).split(',').joinToString("\n") { it.trim() }
                    curHostSource = HostSource.INLINE
                    supported += "--hostlist-domains=" + value
                }
                k == "--ipset" -> { ipsetMode = IpsetMode.INCLUDE; supported += "--ipset (список «IP-сети»)" }
                k == "--ipset-exclude" -> { ipsetMode = IpsetMode.EXCLUDE; supported += "--ipset-exclude (список «Исключения IP»)" }

                k == "--dpi-desync" -> {
                    val modes = parseDesync(value.orEmpty(), supported, ignored)
                    if (modes != null) curDesync = modes
                }
                k == "--dpi-desync-split-pos" -> {
                    val parsed = parseSplitPos(value.orEmpty(), base.splitCustomPos)
                    curPositions = ArrayList(parsed.first)
                    curCustomPos = parsed.second
                    if (parsed.first.isNotEmpty()) supported += "--dpi-desync-split-pos=$value" else errors += "не разобрал --dpi-desync-split-pos=$value"
                }
                k == "--dpi-desync-tlsrec" -> {
                    val n = value?.trim()?.toIntOrNull() ?: 2
                    curTlsrec = n.coerceIn(2, 8)
                    supported += "--dpi-desync-tlsrec=$curTlsrec"
                    if (curDesync == DesyncMode.MULTISPLIT) curDesync = DesyncMode.MULTISPLIT_TLSREC
                    else if (curDesync == DesyncMode.SPLIT || curDesync == DesyncMode.NONE) curDesync = DesyncMode.TLSREC
                }
                k == "--dpi-desync-any-protocol" -> {
                    curAnyProto = value == null || value == "1" || value.equals("true", true)
                    anyProtocol = curAnyProto
                    supported += "--dpi-desync-any-protocol"
                }
                k == "--dpi-desync-oob" -> {
                    val n = value?.trim()?.toIntOrNull() ?: 0
                    curUrgentByte = n and 0xFF
                    if (curDesync == DesyncMode.NONE) curDesync = DesyncMode.OOB
                    supported += "--dpi-desync-oob=$curUrgentByte"
                }
                k == "--dpi-desync-fake-ttl" -> {
                    val n = value?.trim()?.toIntOrNull()
                    if (n != null && n > 0) {
                        curFakeTtl = n.coerceIn(1, 30)
                        if (curDesync == DesyncMode.NONE) curDesync = DesyncMode.FAKE
                        supported += "--dpi-desync-fake-ttl=$curFakeTtl"
                    } else errors += "не разобрал --dpi-desync-fake-ttl=$value"
                }
                k == "--hostcase" -> {
                    curCaseMix = true
                    sniCaseMix = true
                    supported += "--hostcase (смена регистра в имени хоста)"
                }
                k == "--poison" -> {
                    curPoison = true
                    poisonEnabled = true
                    // Значение после --poison, если оно есть, — домен подставы.
                    if (!value.isNullOrBlank() && !value.startsWith("-") && value.contains('.')) {
                        curPoisonSni = value.trim()
                    }
                    supported += "--poison (подставная запись перед рукопожатием)"
                }
                k == "--poison-sni" -> {
                    val d = value?.trim()
                    if (!d.isNullOrBlank() && d.contains('.')) curPoisonSni = d
                    else errors += "--poison-sni требует домен, получено «${value ?: ""}»"
                }
                k == "--poison-delay" -> {
                    val n = value?.trim()?.toIntOrNull()
                    if (n != null && n >= 0) curPoisonDelay = n
                    else errors += "--poison-delay требует целое число мс, получено «${value ?: ""}»"
                }
                k == "--dpi-desync-cutoff" -> {
                    val n = value?.trim()?.trimStart('n', 'd')?.toIntOrNull()
                    if (n != null) {
                        cutoff = n.coerceIn(1, 16)
                        supported += "--dpi-desync-cutoff=n$n → обрабатываем первые $cutoff блоков клиента"
                    }
                    else errors += "не разобрал --dpi-desync-cutoff=$value"
                }
                k == "--wssize" -> {
                    val parts = (value.orEmpty()).split(':')
                    val packets = parts.getOrNull(0)?.trim()?.toIntOrNull()
                    val window = parts.getOrNull(1)?.trim()?.toIntOrNull()
                    if (packets != null && packets > 0) {
                        curWssizeOn = true
                        curWssizePackets = packets.coerceIn(1, 64)
                        curWssizeWindow = (window ?: 1).coerceAtLeast(4096)
                        supported += "--wssize=$value → первые $curWssizePackets пакетов с окном $curWssizeWindow Б"
                    } else errors += "не разобрал --wssize=$value"
                }
                k == "--split-delay" -> {
                    val n = value?.trim()?.toIntOrNull()
                    if (n != null) { curDelay = n.coerceIn(0, 200); supported += "--split-delay=$curDelay (расширение Zapret for Android)" }
                    else errors += "не разобрал --split-delay=$value"
                }
                k == "--rule-name" -> ruleName = value.orEmpty()

                // --dpi-desync-fake-ttl разобран выше точным совпадением; сюда
                // попадают только неподдерживаемые fake-подключи (fake-tls и т.п.).
                k.startsWith("--dpi-desync-fake") ||
                    k.startsWith("--dpi-desync-split-seqovl") ||
                    k == "--dpi-desync-fooling" ||
                    k == "--dpi-desync-autottl" ||
                    k == "--dpi-desync-ttl" ||
                    k == "--dpi-desync-repeats" ||
                    k == "--dpi-desync-badseq-increment" ||
                    k == "--dpi-desync-badseq-plen" ||
                    k == "--dpi-desync-start" ||
                    k == "--dpi-desync-hostfakesplit-mod" ||
                    k == "--dpi-desync-fake-tls-mod" ||
                    k == "--dpi-desync-udplen-increment" ||
                    k == "--dpi-desync-udplen-pattern" ||
                    k == "--dpi-desync-fakedsplit-pattern" ||
                    k == "--dpi-desync-skip-nosni" ->
                    ignored += "$k=$value (требуется подмена заголовков исходящих пакетов — только с root)"

                k == "--ip-id" || k == "--ip-id-increment" -> ignored += "$k=$value (идентификатор IP задаёт ядро — только с root)"
                k == "--dns-redirect" || k == "--dns-redirect-port" || k == "--dns-redirect-addr" ->
                    ignored += "$k (DNS настраивается в разделе «DNS»)"
                k == "--daemon" || k == "--pidfile" || k == "--user" || k == "--group" || k == "--wssize-incoming" ->
                    ignored += "$k (служебный параметр десктопной версии)"

                else -> unknown += raw
            }
            i++
        }
        flush()

        return ParseResult(
            rules = rules,
            globalTcpPorts = globalTcp,
            globalUdpPorts = globalUdp,
            hostlistMode = hostlistMode,
            ipsetMode = ipsetMode,
            defaultStrategy = if (rules.isEmpty()) null else rules.last().strategy,
            cutoffChunks = cutoff,
            anyProtocol = anyProtocol,
            sniCaseMix = sniCaseMix,
            poisonEnabled = poisonEnabled,
            supported = supported.distinct(),
            ignored = ignored.distinct(),
            unknown = unknown.distinct(),
            errors = errors.distinct()
        )
    }

    private fun defaultRuleName(tcp: String, udp: String, desync: DesyncMode): String {
        val proto = when {
            tcp.isNotBlank() && udp.isNotBlank() -> "tcp/$tcp udp/$udp"
            tcp.isNotBlank() -> "tcp/$tcp"
            udp.isNotBlank() -> "udp/$udp"
            else -> "все порты"
        }
        return "$proto · ${desync.token}"
    }

    private fun parseDesync(value: String, supported: MutableList<String>, ignored: MutableList<String>): DesyncMode? {
        val parts = value.split(',', '+', ';').map { it.trim().lowercase() }.filter { it.isNotEmpty() }
        if (parts.isEmpty()) return null
        var mode: DesyncMode? = null
        var tlsrec = false
        for (p in parts) {
            when (p) {
                "split", "split2", "fakedsplit" -> if (mode == null || mode == DesyncMode.NONE) mode = DesyncMode.SPLIT
                "multisplit" -> mode = DesyncMode.MULTISPLIT
                "tlsrec" -> tlsrec = true
                "oob" -> mode = DesyncMode.OOB
                "disorder", "multidisorder", "disorder2" -> mode = DesyncMode.DISORDER
                "disoob" -> mode = DesyncMode.DISOOB
                "fake" -> mode = DesyncMode.FAKE
                "hostfakesplit" -> mode = DesyncMode.HOSTFAKESPLIT
                "none", "off" -> mode = DesyncMode.NONE
                else -> {
                    val reason = ROOT_ONLY[p]
                    if (reason != null) ignored += "--dpi-desync=$p — $reason"
                    else ignored += "--dpi-desync=$p (не переносится)"
                }
            }
        }
        val resolved = when {
            mode == null && tlsrec -> DesyncMode.TLSREC
            mode == DesyncMode.MULTISPLIT && tlsrec -> DesyncMode.MULTISPLIT_TLSREC
            mode == DesyncMode.SPLIT && tlsrec -> DesyncMode.TLSREC
            mode != null -> mode
            else -> return null
        }
        supported += "--dpi-desync=$value → ${resolved.token}"
        return resolved
    }

    private fun parseSplitPos(value: String, currentCustom: Int): Pair<List<SplitPos>, Int> {
        val out = ArrayList<SplitPos>()
        var custom = currentCustom
        for (raw in value.split(',', ';', ' ').filter { it.isNotBlank() }) {
            val t = raw.trim().lowercase()
            // Синтаксис ZapretYT/ByeDPI: `0+wm`, `1+s`, `0+sm`, `3+s` и т.п.
            // (см. y1.a.V: base[:c[:d]]+flags, где w=слово/second-level,
            // s=sni, m=середина, e=конец, r=случайно). Наши SplitPos грубее,
            // поэтому отображаем флаги на ближайший смысл без потери приёма:
            // `wm`/`sm`/`midsni`/`midsld` → середина домена, `se`/`endsni` → конец.
            if ('+' in t) {
                val flags = t.substringAfter('+', "")
                when {
                    "wm" in flags || "sm" in flags || "midsni" in flags || "midsld" in flags || "middom" in flags -> {
                        out += SplitPos.MIDSNI; continue
                    }
                    "se" in flags || "endsni" in flags || "sniend" in flags || "enddom" in flags -> {
                        out += SplitPos.SNIEND; continue
                    }
                    flags.startsWith("s") || flags == "sni" || "sniext" in flags || "dom" in flags -> {
                        // `1+s` = SNI+1: разрыв сразу за началом имени — ближе
                        // всего к FIRST по эффекту на DPI, но точнее — начало SNI.
                        // Отдельного SplitPos для него нет, поэтому берём MIDSNI
                        // только если base==0 (середина слова уже учтена выше);
                        // иначе это разрыв у начала имени → FIRST.
                        val baseNum = t.substringBefore('+', "").substringBefore(':', "").toIntOrNull() ?: 0
                        if (baseNum <= 1) out += SplitPos.FIRST else out += SplitPos.MIDSNI
                        continue
                    }
                }
            }
            val asInt = t.toIntOrNull()
            when {
                asInt != null -> { out += SplitPos.CUSTOM; custom = asInt.coerceIn(1, 65535) }
                else -> SplitPos.fromToken(t)?.let { out += it }
            }
        }
        return out.distinct() to custom
    }

    private fun splitKeyValue(token: String): Pair<String, String?> {
        val eq = token.indexOf('=')
        if (eq <= 0) return token to null
        return token.substring(0, eq) to token.substring(eq + 1).trim('"', '\'')
    }

    private fun tokenize(text: String): List<String> {
        val out = ArrayList<String>()
        val sb = StringBuilder()
        var quote: Char? = null
        for (c in text) {
            when {
                quote != null -> {
                    if (c == quote) quote = null else sb.append(c)
                }
                c == '"' || c == '\'' -> quote = c
                c.isWhitespace() -> {
                    if (sb.isNotEmpty()) { out += sb.toString(); sb.setLength(0) }
                }
                else -> sb.append(c)
            }
        }
        if (sb.isNotEmpty()) out += sb.toString()
        return out
    }

    /** Обратная генерация: текущая конфигурация → строка в стиле zapret. */
    fun generate(cfg: AppConfig): String = buildString {
        append("# Эквивалент текущих настроек Zapret for Android\n")
        append("# Общий фильтр (как --wf-* в winws)\n")
        append("--wf-tcp=").append(cfg.tcpPorts.ifBlank { "1-65535" }).append('\n')
        append("--wf-udp=").append(cfg.udpPorts.ifBlank { "*" }).append('\n')
        when (cfg.hostlistMode) {
            HostlistMode.OFF -> Unit
            HostlistMode.INCLUDE -> append("--hostlist=\"%LISTS%list-general.txt\"\n")
            HostlistMode.EXCLUDE -> append("--hostlist-exclude=\"%LISTS%list-general.txt\"\n")
        }
        when (cfg.ipsetMode) {
            IpsetMode.OFF -> Unit
            IpsetMode.INCLUDE -> append("--ipset=\"%LISTS%ipset-all.txt\"\n")
            IpsetMode.EXCLUDE -> append("--ipset-exclude=\"%LISTS%ipset-exclude.txt\"\n")
        }
        if (cfg.rules.isEmpty()) {
            append(cfg.toStrategy().describe()).append('\n')
        } else {
            append('\n')
            for (r in cfg.rules) {
                if (!r.enabled) append("# (выключено) ")
                append(r.toZapretLine()).append('\n')
            }
        }
        if (cfg.blockQuic) append("\n# --filter-udp=443 с полным дропом: QUIC блокируется, браузеры уходят на TCP\n")
    }
}
