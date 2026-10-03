package dev.rubcut.zapret.core.match

import java.net.InetAddress
import java.net.UnknownHostException

/**
 * Соответствие домена списку хостов в семантике zapret.
 *
 *  * `googlevideo.com` — совпадает и с доменом, и со всеми поддоменами;
 *  * `*.googlevideo.com` — только точное совпадение (аналог --hostlist-domains);
 *  * пустые строки и комментарии (`#`, `;`) игнорируются.
 */
class HostMatcher private constructor(
    private val suffixes: Set<String>,
    private val exacts: Set<String>
) {
    val size: Int get() = suffixes.size + exacts.size
    val isEmpty: Boolean get() = size == 0

    fun matches(hostRaw: String?): Boolean {
        if (hostRaw.isNullOrEmpty() || isEmpty) return false
        var host = hostRaw.trim().lowercase()
        if (host.endsWith(".")) host = host.dropLast(1)
        if (host.isEmpty()) return false
        if (exacts.contains(host)) return true
        if (suffixes.isEmpty()) return false
        var idx = 0
        while (true) {
            if (suffixes.contains(host.substring(idx))) return true
            val dot = host.indexOf('.', idx)
            if (dot < 0) return false
            idx = dot + 1
            if (idx >= host.length) return false
        }
    }

    companion object {
        val EMPTY = HostMatcher(emptySet(), emptySet())

        fun parse(text: String?): HostMatcher {
            if (text.isNullOrBlank()) return EMPTY
            val suffixes = HashSet<String>()
            val exacts = HashSet<String>()
            for (rawLine in text.lineSequence()) {
                var line = rawLine.trim()
                if (line.isEmpty()) continue
                if (line[0] == '#' || line[0] == ';') continue
                val comment = line.indexOfFirst { it == '#' || it == ';' }
                if (comment >= 0) line = line.substring(0, comment).trim()
                if (line.isEmpty()) continue
                val exactOnly = line.startsWith("*")
                if (exactOnly) line = line.trimStart('*').trim()
                line = line.lowercase().trimEnd('.')
                if (line.isEmpty()) continue
                if (exactOnly) exacts += line else suffixes += line
            }
            if (suffixes.isEmpty() && exacts.isEmpty()) return EMPTY
            return HostMatcher(suffixes, exacts)
        }
    }
}

class Cidr private constructor(val bytes: ByteArray, val prefix: Int) {
    val v6: Boolean get() = bytes.size == 16

    fun contains(addr: InetAddress): Boolean {
        val other = addr.address ?: return false
        if (other.size != bytes.size) return false
        val fullBytes = prefix / 8
        for (i in 0 until fullBytes) if (other[i] != bytes[i]) return false
        val rem = prefix % 8
        if (rem != 0 && fullBytes < bytes.size) {
            val mask = (0xFF shl (8 - rem)) and 0xFF
            if ((other[fullBytes].toInt() and mask) != (bytes[fullBytes].toInt() and mask)) return false
        }
        return true
    }

    override fun toString(): String {
        val ip = try { InetAddress.getByAddress(bytes).hostAddress } catch (e: UnknownHostException) { "?" }
        return "$ip/$prefix"
    }

    companion object {
        fun parse(token: String): Cidr? {
            val t = token.trim()
            if (t.isEmpty() || t.startsWith("#") || t.startsWith(";")) return null
            val slash = t.indexOf('/')
            val ipPart = if (slash >= 0) t.substring(0, slash) else t
            val addr = try {
                InetAddress.getByName(stripBrackets(ipPart))
            } catch (e: Exception) {
                return null
            }
            val raw = addr.address ?: return null
            val maxPrefix = raw.size * 8
            val prefix = if (slash >= 0) t.substring(slash + 1).toIntOrNull() ?: maxPrefix else maxPrefix
            if (prefix < 0 || prefix > maxPrefix) return null
            return Cidr(raw, prefix)
        }

        private fun stripBrackets(s: String): String =
            if (s.length > 1 && s.startsWith("[") && s.endsWith("]")) s.substring(1, s.length - 1) else s
    }
}

/** Аналог ipset из zapret: набор CIDR-диапазонов. */
class IpMatcher private constructor(val cidrs: List<Cidr>) {
    val size: Int get() = cidrs.size
    val isEmpty: Boolean get() = cidrs.isEmpty()

    fun matches(addr: InetAddress?): Boolean {
        if (addr == null || cidrs.isEmpty()) return false
        for (c in cidrs) if (c.contains(addr)) return true
        return false
    }

    companion object {
        val EMPTY = IpMatcher(emptyList())
        fun parse(text: String?): IpMatcher {
            if (text.isNullOrBlank()) return EMPTY
            val list = ArrayList<Cidr>()
            for (line in text.lineSequence()) {
                val c = Cidr.parse(line) ?: continue
                list += c
            }
            return if (list.isEmpty()) EMPTY else IpMatcher(list)
        }
    }
}

/**
 * Таблица hosts, применяемая внутри туннеля на этапе разрешения имён.
 * Синтаксис: `IP домен [домен2 …]`, допускаются маски вида `*.example.com`.
 */
class HostsTable private constructor(
    private val exact: Map<String, List<InetAddress>>,
    private val wildcards: List<Pair<String, List<InetAddress>>>
) {
    val size: Int get() = exact.size + wildcards.size
    val isEmpty: Boolean get() = exact.isEmpty() && wildcards.isEmpty()

    /** Возвращает адреса из таблицы hosts или null, если имя не описано. */
    fun lookup(hostRaw: String?): List<InetAddress>? {
        if (hostRaw.isNullOrEmpty() || isEmpty) return null
        val host = hostRaw.trim().lowercase().trimEnd('.')
        if (host.isEmpty()) return null
        exact[host]?.let { return it }
        for ((suffix, addrs) in wildcards) if (host.endsWith(suffix)) return addrs
        return null
    }

    /** true, если имя явно заблокировано (адрес 0.0.0.0 / ::). */
    fun isBlocked(addrs: List<InetAddress>): Boolean =
        addrs.all { it.address.all { b -> b == 0.toByte() } }

    companion object {
        val EMPTY = HostsTable(emptyMap(), emptyList())

        fun parse(text: String?): HostsTable {
            if (text.isNullOrBlank()) return EMPTY
            val exact = HashMap<String, List<InetAddress>>()
            val wild = ArrayList<Pair<String, List<InetAddress>>>()
            for (rawLine in text.lineSequence()) {
                var line = rawLine.trim()
                if (line.isEmpty() || line[0] == '#' || line[0] == ';') continue
                val comment = line.indexOf('#')
                if (comment >= 0) line = line.substring(0, comment).trim()
                val parts = line.split(Regex("\\s+")).filter { it.isNotEmpty() }
                if (parts.size < 2) continue
                val ipText = parts[0].let {
                    if (it.length > 1 && it.startsWith("[") && it.endsWith("]")) it.substring(1, it.length - 1) else it
                }
                val addr = try {
                    InetAddress.getByName(ipText)
                } catch (e: Exception) {
                    continue
                }
                for (i in 1 until parts.size) {
                    val name = parts[i].lowercase()
                    if (name.startsWith("*.")) {
                        wild += name.substring(1) to listOf(addr)
                    } else if (name.startsWith("*")) {
                        wild += name.substring(1) to listOf(addr)
                    } else {
                        val key = name.trimEnd('.')
                        val prev = exact[key]
                        exact[key] = if (prev == null) listOf(addr) else prev + addr
                    }
                }
            }
            if (exact.isEmpty() && wild.isEmpty()) return EMPTY
            return HostsTable(exact, wild)
        }
    }
}
