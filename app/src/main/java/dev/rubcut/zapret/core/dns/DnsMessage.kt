package dev.rubcut.zapret.core.dns

import dev.rubcut.zapret.core.net.getU16
import java.io.ByteArrayOutputStream
import java.net.InetAddress

object DnsType {
    const val A = 1
    const val NS = 2
    const val CNAME = 5
    const val SOA = 6
    const val PTR = 12
    const val MX = 15
    const val TXT = 16
    const val AAAA = 28
    const val SRV = 33
    const val HTTPS = 65
}

class DnsQuery(
    val id: Int,
    val flags: Int,
    val name: String,
    val type: Int,
    val rawQuestion: ByteArray
) {
    val wantsA: Boolean get() = type == DnsType.A
    val wantsAAAA: Boolean get() = type == DnsType.AAAA
    val isAddressQuery: Boolean get() = wantsA || wantsAAAA
}

/** Минимальный кодек DNS-сообщений: ровно то, что нужно для перехвата и подмены ответов. */
object DnsMessage {

    private const val FLAG_QR = 0x8000
    private const val FLAG_RD = 0x0100
    private const val FLAG_RA = 0x0080

    fun parseQuery(data: ByteArray, len: Int): DnsQuery? {
        if (len < 12) return null
        val id = getU16(data, 0)
        val flags = getU16(data, 2)
        val qd = getU16(data, 4)
        if (qd < 1) return null
        val (name, pos) = readName(data, len, 12) ?: return null
        if (pos + 4 > len) return null
        val type = getU16(data, pos)
        val questionEnd = pos + 4
        if (questionEnd > len) return null
        return DnsQuery(id, flags, name, type, data.copyOfRange(12, questionEnd))
    }

    /** Ответ с набором адресов. Пустой список + rcode=3 даёт NXDOMAIN. */
    fun buildAddressResponse(
        query: DnsQuery,
        addresses: List<InetAddress>,
        ttl: Int,
        rcode: Int = 0
    ): ByteArray {
        val out = ByteArrayOutputStream(128)
        val answers = addresses.filter { it.address.size == if (query.wantsAAAA) 16 else 4 }
        val ancount = if (rcode != 0) 0 else answers.size

        putU16Buf(out, query.id)
        putU16Buf(out, FLAG_QR or FLAG_RA or (query.flags and FLAG_RD) or (rcode and 0xF))
        putU16Buf(out, 1)          // qdcount
        putU16Buf(out, ancount)    // ancount
        putU16Buf(out, 0)          // nscount
        putU16Buf(out, 0)          // arcount

        out.write(query.rawQuestion)

        val recordType = if (query.wantsAAAA) DnsType.AAAA else DnsType.A
        for (a in answers) {
            putU16Buf(out, 0xC00C)          // указатель на имя в секции вопросов
            putU16Buf(out, recordType)
            putU16Buf(out, 1)               // IN
            putU32Buf(out, ttl)
            putU16Buf(out, a.address.size)
            out.write(a.address)
        }
        return out.toByteArray()
    }

    fun buildEmptyResponse(query: DnsQuery, rcode: Int): ByteArray =
        buildAddressResponse(query, emptyList(), 0, rcode)

    /** Разбор ответов A/AAAA из DNS-сообщения. */
    fun parseAddresses(data: ByteArray, len: Int): List<InetAddress> {
        if (len < 12) return emptyList()
        val qd = getU16(data, 4)
        val an = getU16(data, 6)
        var pos = 12
        repeat(qd.coerceAtMost(4)) {
            val r = readName(data, len, pos) ?: return emptyList()
            pos = r.second + 4
        }
        val out = ArrayList<InetAddress>()
        repeat(an.coerceAtMost(32)) {
            val r = readName(data, len, pos) ?: return out
            pos = r.second
            if (pos + 10 > len) return out
            val type = getU16(data, pos)
            val rdlen = getU16(data, pos + 8)
            pos += 10
            if (pos + rdlen > len) return out
            if ((type == DnsType.A && rdlen == 4) || (type == DnsType.AAAA && rdlen == 16)) {
                try {
                    out += InetAddress.getByAddress(data.copyOfRange(pos, pos + rdlen))
                } catch (_: Exception) {
                }
            }
            pos += rdlen
        }
        return out
    }

    fun rcode(data: ByteArray, len: Int): Int = if (len >= 12) getU16(data, 2) and 0xF else -1

    /** Читает доменное имя, поддерживает сжатие указателями. Возвращает имя и новую позицию. */
    private fun readName(data: ByteArray, len: Int, start: Int): Pair<String, Int>? {
        val sb = StringBuilder()
        var pos = start
        var afterPointer = -1
        var jumps = 0
        while (pos < len) {
            val labelLen = data[pos].toInt() and 0xFF
            if (labelLen == 0) {
                pos++
                break
            }
            if ((labelLen and 0xC0) == 0xC0) {
                if (pos + 1 >= len) return null
                val ptr = ((labelLen and 0x3F) shl 8) or (data[pos + 1].toInt() and 0xFF)
                if (afterPointer < 0) afterPointer = pos + 2
                if (jumps++ > 8 || ptr >= len) return null
                pos = ptr
                continue
            }
            if (labelLen > 63 || pos + 1 + labelLen > len) return null
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(data, pos + 1, labelLen, Charsets.US_ASCII))
            pos += 1 + labelLen
        }
        val end = if (afterPointer >= 0) afterPointer else pos
        return sb.toString() to end
    }

    fun encodeName(name: String): ByteArray {
        val out = ByteArrayOutputStream()
        for (label in name.split('.')) {
            if (label.isEmpty()) continue
            val b = label.toByteArray(Charsets.US_ASCII)
            if (b.size > 63) continue
            out.write(b.size)
            out.write(b)
        }
        out.write(0)
        return out.toByteArray()
    }

    fun buildQuery(id: Int, name: String, type: Int): ByteArray {
        val out = ByteArrayOutputStream(64)
        putU16Buf(out, id)
        putU16Buf(out, FLAG_RD)
        putU16Buf(out, 1)
        putU16Buf(out, 0)
        putU16Buf(out, 0)
        putU16Buf(out, 0)
        out.write(encodeName(name))
        putU16Buf(out, type)
        putU16Buf(out, 1)
        return out.toByteArray()
    }

    private fun putU16Buf(out: ByteArrayOutputStream, v: Int) {
        out.write((v ushr 8) and 0xFF)
        out.write(v and 0xFF)
    }

    private fun putU32Buf(out: ByteArrayOutputStream, v: Int) {
        out.write((v ushr 24) and 0xFF)
        out.write((v ushr 16) and 0xFF)
        out.write((v ushr 8) and 0xFF)
        out.write(v and 0xFF)
    }
}
