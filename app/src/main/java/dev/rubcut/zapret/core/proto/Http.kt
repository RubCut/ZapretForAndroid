package dev.rubcut.zapret.core.proto

import dev.rubcut.zapret.core.net.getU8

/** Разбор начала plaintext-HTTP запроса. */
object Http {

    private val METHODS = listOf(
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ", "PRI "
    )

    fun looksLikeRequest(b: ByteArray, off: Int, len: Int): Boolean {
        if (len < 4 || off + 4 > b.size) return false
        val head = String(b, off, minOf(10, len), Charsets.US_ASCII)
        return METHODS.any { head.startsWith(it) }
    }

    /** Длина блока заголовков вместе с завершающим CRLFCRLF; -1 если заголовки ещё не пришли целиком. */
    fun headerBlockLength(b: ByteArray, off: Int, len: Int): Int {
        val end = minOf(off + len, b.size)
        for (i in off until end - 3) {
            if (b[i] == '\r'.code.toByte() && b[i + 1] == '\n'.code.toByte() &&
                b[i + 2] == '\r'.code.toByte() && b[i + 3] == '\n'.code.toByte()
            ) return i + 4 - off
            // Некоторые клиенты шлют только LF.
            if (b[i] == '\n'.code.toByte() && b[i + 1] == '\n'.code.toByte()) return i + 2 - off
        }
        return -1
    }

    /**
     * Диапазон значения заголовка Host (без учёта порта). Возвращает Pair(start, endExclusive)
     * в абсолютных смещениях буфера.
     */
    fun hostValueRange(b: ByteArray, off: Int, len: Int): Pair<Int, Int>? {
        val end = minOf(off + len, b.size)
        if (end <= off) return null
        val text = String(b, off, end - off, Charsets.ISO_8859_1)
        val lower = text.lowercase()
        val idx = lower.indexOf("\nhost:")
        val valueStartRel = when {
            idx >= 0 -> idx + 6
            lower.startsWith("host:") -> 5
            else -> return null
        }
        var i = valueStartRel
        while (i < text.length && (text[i] == ' ' || text[i] == '\t')) i++
        var j = i
        while (j < text.length && text[j] != '\r' && text[j] != '\n') j++
        while (j > i && (text[j - 1] == ' ' || text[j - 1] == '\t')) j--
        if (j <= i) return null
        return (off + i) to (off + j)
    }

    /**
     * Меняет регистр одной буквы в домене втором уровне значения `Host`.
     *
     * Приём тот же, что и для TLS SNI (см. [Tls.mixFirstLabel]): имя хоста в
     * HTTP регистронезависимо по RFC 7230, а фильтры ищут его подстрокой.
     * Длина не меняется, поэтому разбирать запрос заново не нужно.
     *
     * @return копия [b] либо null, если менять нечего.
     */
    fun mixFirstHostLabel(b: ByteArray, hostStart: Int, hostEnd: Int): ByteArray? {
        val span = hostEnd - hostStart
        if (span <= 0) return null
        val host = String(b, hostStart, span, Charsets.ISO_8859_1)
        // Первый ярлык, а не домен второго уровня — см. Tls.mixFirstLabel.
        val dot = host.indexOf('.')
        val to = if (dot > 0) dot else host.length
        if (to < 1) return null
        val idx = (0 until to).firstOrNull { host[it].isLetter() } ?: return null
        val out = b.copyOf()
        val off = hostStart + idx
        val c: Int = out[off].toInt()
        if (c < 'a'.code || c > 'z'.code) {
            if (c < 'A'.code || c > 'Z'.code) return null
        }
        out[off] = ((c xor 0x20) and 0xFF).toByte()
        return out
    }

    /** Заголовки HTTP-запроса целиком (для логов). */
    fun firstLine(b: ByteArray, off: Int, len: Int): String {
        val end = minOf(off + len, b.size)
        var i = off
        while (i < end && b[i] != '\r'.code.toByte() && b[i] != '\n'.code.toByte()) i++
        return String(b, off, i - off, Charsets.ISO_8859_1)
    }

    fun isTlsPort(port: Int): Boolean =
        port == 443 || port == 8443 || port == 2053 || port == 2083 || port == 2087 ||
            port == 2096 || port == 853 || port == 993 || port == 465

    fun isPlainHttpPort(port: Int): Boolean = port == 80 || port == 8080 || port == 8081

    fun firstByteType(b: ByteArray, off: Int, len: Int): Int =
        if (len > 0 && off < b.size) getU8(b, off) else -1
}
