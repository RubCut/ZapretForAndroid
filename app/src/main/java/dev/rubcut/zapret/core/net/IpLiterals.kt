package dev.rubcut.zapret.core.net

import java.net.InetAddress

/**
 * Строгий разбор IP-литералов. Нужен потому, что `InetAddress.getByName()` для строки,
 * похожей на имя, уходит в реальный DNS-запрос — внутри туннеля это привело бы к рекурсии.
 */
object IpLiterals {

    fun parse(text: String?): InetAddress? {
        val s = text?.trim().orEmpty()
        if (s.isEmpty()) return null
        val clean = if (s.length > 1 && s.startsWith("[") && s.endsWith("]")) s.substring(1, s.length - 1) else s
        return if (clean.contains(':')) parseV6(clean) else parseV4(clean)
    }

    fun parseV4(text: String): InetAddress? {
        val parts = text.split('.')
        if (parts.size != 4) return null
        val bytes = ByteArray(4)
        for (i in 0..3) {
            val p = parts[i]
            if (p.isEmpty() || p.length > 3) return null
            for (c in p) if (!c.isDigit()) return null
            val v = p.toInt()
            if (v > 255) return null
            bytes[i] = v.toByte()
        }
        return try {
            InetAddress.getByAddress(bytes)
        } catch (e: Exception) {
            null
        }
    }

    fun parseV6(text: String): InetAddress? {
        val bytes = ByteArray(16)
        val groups = IntArray(8)
        var count = 0
        var doubleColonAt = -1

        var s = text
        // Встроенный IPv4 в хвосте (::ffff:1.2.3.4)
        val lastColon = s.lastIndexOf(':')
        if (lastColon >= 0 && s.substring(lastColon + 1).contains('.')) {
            val v4 = parseV4(s.substring(lastColon + 1)) ?: return null
            val a = v4.address
            s = s.substring(0, lastColon + 1) +
                String.format(java.util.Locale.US, "%x:%x", ((a[0].toInt() and 0xFF) shl 8) or (a[1].toInt() and 0xFF),
                    ((a[2].toInt() and 0xFF) shl 8) or (a[3].toInt() and 0xFF))
        }

        val halves = s.split("::")
        if (halves.size > 2) return null

        fun parseGroups(part: String): List<Int>? {
            if (part.isEmpty()) return emptyList()
            val out = ArrayList<Int>()
            for (g in part.split(':')) {
                if (g.isEmpty() || g.length > 4) return null
                for (c in g) if (!isHex(c)) return null
                out += g.toInt(16)
            }
            return out
        }

        val head = parseGroups(halves[0]) ?: return null
        val tail = if (halves.size == 2) parseGroups(halves[1]) ?: return null else emptyList()

        if (halves.size == 1) {
            if (head.size != 8) return null
            for (i in 0..7) groups[i] = head[i]
            count = 8
        } else {
            if (head.size + tail.size > 7) return null
            for (i in head.indices) groups[i] = head[i]
            doubleColonAt = head.size
            val zeroFill = 8 - head.size - tail.size
            for (i in tail.indices) groups[head.size + zeroFill + i] = tail[i]
            count = 8
        }
        if (doubleColonAt < 0 && count != 8) return null

        for (i in 0..7) {
            bytes[i * 2] = ((groups[i] ushr 8) and 0xFF).toByte()
            bytes[i * 2 + 1] = (groups[i] and 0xFF).toByte()
        }
        return try {
            InetAddress.getByAddress(bytes)
        } catch (e: Exception) {
            null
        }
    }

    private fun isHex(c: Char): Boolean =
        c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'

    /** Разбор "host[:port]" / "[v6]:port". */
    fun parseHostPort(text: String, defaultPort: Int): Pair<String, Int>? {
        val t = text.trim()
        if (t.isEmpty()) return null
        if (t.startsWith("[")) {
            val close = t.indexOf(']')
            if (close < 0) return null
            val host = t.substring(1, close)
            val rest = t.substring(close + 1)
            val port = if (rest.startsWith(":")) rest.substring(1).toIntOrNull() ?: defaultPort else defaultPort
            return host to port
        }
        val colon = t.indexOf(':')
        if (colon < 0) return t to defaultPort
        val port = t.substring(colon + 1).toIntOrNull() ?: defaultPort
        return t.substring(0, colon) to port
    }

    fun isPrivate(addr: InetAddress): Boolean {
        val b = addr.address ?: return false
        if (b.size == 4) {
            val first = b[0].toInt() and 0xFF
            val second = b[1].toInt() and 0xFF
            return first == 10 || first == 127 ||
                (first == 192 && second == 168) ||
                (first == 172 && second in 16..31) ||
                (first == 169 && second == 254) ||
                (first == 100 && second in 64..127)
        }
        return (b[0].toInt() and 0xFF) == 0xfd || (b[0].toInt() and 0xFF) == 0xfe || addr.isLoopbackAddress
    }
}
