package dev.rubcut.zapret.core.net

import java.net.InetAddress
import java.net.UnknownHostException

/* ------------------------------------------------------------------ */
/*  Примитивы чтения/записи                                            */
/* ------------------------------------------------------------------ */

fun getU8(b: ByteArray, o: Int): Int = b[o].toInt() and 0xFF

fun getU16(b: ByteArray, o: Int): Int =
    ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

fun getU32(b: ByteArray, o: Int): Int =
    (getU16(b, o) shl 16) or getU16(b, o + 2)

fun putU8(b: ByteArray, o: Int, v: Int) { b[o] = (v and 0xFF).toByte() }

fun putU16(b: ByteArray, o: Int, v: Int) {
    b[o] = ((v ushr 8) and 0xFF).toByte()
    b[o + 1] = (v and 0xFF).toByte()
}

fun putU32(b: ByteArray, o: Int, v: Int) {
    putU16(b, o, (v ushr 16) and 0xFFFF)
    putU16(b, o + 2, v and 0xFFFF)
}

/** Сравнение 32-битных TCP sequence number с учётом переполнения (RFC 1982). */
fun seqCompare(a: Int, b: Int): Int {
    val d = a - b
    return when {
        d == 0 -> 0
        d < 0 -> -1
        else -> 1
    }
}

fun seqAdd(a: Int, b: Int): Int = a + b

/* ------------------------------------------------------------------ */
/*  Контрольная сумма                                                  */
/* ------------------------------------------------------------------ */

/** Накопитель однодополнительной контрольной суммы Internet (RFC 1071). */
class Checksum {
    private var sum: Long = 0L
    private var carry: Int = -1

    fun update(b: ByteArray, off: Int, len: Int) {
        var i = off
        val end = off + len
        if (carry >= 0) {
            if (i < end) {
                sum += ((carry shl 8) or (b[i].toInt() and 0xFF)).toLong()
                carry = -1
                i++
            }
        }
        while (i + 1 < end) {
            sum += (((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)).toLong()
            i += 2
            if ((sum and 0xFFFF0000L) != 0L) sum = (sum and 0xFFFFL) + (sum ushr 16)
        }
        if (i < end) carry = b[i].toInt() and 0xFF
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFFL) + (sum ushr 16)
    }

    fun updateU16(v: Int) {
        sum += (v and 0xFFFF).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFFL) + (sum ushr 16)
    }

    fun value(): Int {
        if (carry >= 0) {
            sum += (carry shl 8).toLong()
            carry = -1
        }
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFFL) + (sum ushr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }
}

/* ------------------------------------------------------------------ */
/*  IP                                                                 */
/* ------------------------------------------------------------------ */

object IpProto {
    const val ICMP = 1
    const val TCP = 6
    const val UDP = 17
    const val ICMPV6 = 58
}

class IpHeader(
    val v6: Boolean,
    val headerLen: Int,
    val totalLen: Int,
    val protocol: Int,
    val ttl: Int,
    val src: InetAddress,
    val dst: InetAddress,
    val buffer: ByteArray
) {
    val payloadOffset: Int get() = headerLen
    val payloadLength: Int get() = (totalLen - headerLen).coerceAtLeast(0)
    val isTcp: Boolean get() = protocol == IpProto.TCP
    val isUdp: Boolean get() = protocol == IpProto.UDP
}

fun parseIp(buf: ByteArray, len: Int): IpHeader? {
    if (len < 1) return null
    return when ((buf[0].toInt() ushr 4) and 0xF) {
        4 -> parseIp4(buf, len)
        6 -> parseIp6(buf, len)
        else -> null
    }
}

private fun parseIp4(buf: ByteArray, len: Int): IpHeader? {
    if (len < 20) return null
    val ihl = (buf[0].toInt() and 0x0F) * 4
    if (ihl < 20 || len < ihl) return null
    var total = getU16(buf, 2)
    if (total < ihl) return null
    if (total > len) total = len
    val src = addr(buf, 12, 4) ?: return null
    val dst = addr(buf, 16, 4) ?: return null
    return IpHeader(
        v6 = false,
        headerLen = ihl,
        totalLen = total,
        protocol = getU8(buf, 9),
        ttl = getU8(buf, 8),
        src = src,
        dst = dst,
        buffer = buf
    )
}

private fun parseIp6(buf: ByteArray, len: Int): IpHeader? {
    if (len < 40) return null
    var payloadLen = getU16(buf, 4)
    var next = getU8(buf, 6)
    var headerLen = 40

    // Простейшая прогулка по extension-заголовкам.
    var guard = 0
    while (next == 0 || next == 43 || next == 44 || next == 60) {
        if (headerLen + 2 > len || guard++ > 8) return null
        val extLen = if (next == 44) 8 else (getU8(buf, headerLen + 1) + 1) * 8
        val newNext = getU8(buf, headerLen)
        headerLen += extLen
        if (headerLen > len) return null
        next = newNext
    }

    if (40 + payloadLen > len) payloadLen = len - 40
    val src = addr(buf, 8, 16) ?: return null
    val dst = addr(buf, 24, 16) ?: return null
    return IpHeader(
        v6 = true,
        headerLen = headerLen,
        totalLen = headerLen + payloadLen,
        protocol = next,
        ttl = getU8(buf, 7),
        src = src,
        dst = dst,
        buffer = buf
    )
}

private fun addr(buf: ByteArray, off: Int, len: Int): InetAddress? = try {
    InetAddress.getByAddress(buf.copyOfRange(off, off + len))
} catch (e: UnknownHostException) {
    null
}

/* ------------------------------------------------------------------ */
/*  TCP                                                                */
/* ------------------------------------------------------------------ */

object TcpFlag {
    const val FIN = 0x01
    const val SYN = 0x02
    const val RST = 0x04
    const val PSH = 0x08
    const val ACK = 0x10
    const val URG = 0x20
    const val ECE = 0x40
    const val CWR = 0x80
}

class TcpSegment(
    val srcPort: Int,
    val dstPort: Int,
    val seq: Int,
    val ack: Int,
    val flags: Int,
    val window: Int,
    val headerLen: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
    val mss: Int,
    val wscale: Int,
    val sackPermitted: Boolean,
    val hasTimestamp: Boolean,
    val tsValue: Int,
    val tsEchoReply: Int,
    val buffer: ByteArray
) {
    val isSyn: Boolean get() = flags and TcpFlag.SYN != 0
    val isAck: Boolean get() = flags and TcpFlag.ACK != 0
    val isFin: Boolean get() = flags and TcpFlag.FIN != 0
    val isRst: Boolean get() = flags and TcpFlag.RST != 0
    val isSynAck: Boolean get() = isSyn && isAck

    fun flagString(): String = buildString {
        if (flags and TcpFlag.SYN != 0) append('S')
        if (flags and TcpFlag.ACK != 0) append('A')
        if (flags and TcpFlag.FIN != 0) append('F')
        if (flags and TcpFlag.RST != 0) append('R')
        if (flags and TcpFlag.PSH != 0) append('P')
    }
}

fun parseTcp(buf: ByteArray, off: Int, len: Int): TcpSegment? {
    if (len < 20 || off + 20 > buf.size) return null
    val dataOffset = ((getU8(buf, off + 12) ushr 4) and 0xF) * 4
    if (dataOffset < 20 || off + dataOffset > buf.size) return null
    val payloadLen = (len - dataOffset).coerceAtLeast(0)

    var mss = 536
    var wscale = -1
    var sackPerm = false
    var hasTs = false
    var tsVal = 0
    var tsEcr = 0

    var i = off + 20
    val optEnd = off + dataOffset
    var guard = 0
    while (i < optEnd && guard++ < 64) {
        val kind = getU8(buf, i)
        if (kind == 0) break
        if (kind == 1) { i++; continue }
        if (i + 1 >= optEnd) break
        val olen = getU8(buf, i + 1)
        if (olen < 2 || i + olen > optEnd) break
        when (kind) {
            2 -> if (olen == 4) mss = getU16(buf, i + 2)
            3 -> if (olen == 3) wscale = getU8(buf, i + 2) and 0x0F
            4 -> sackPerm = true
            8 -> if (olen == 10) {
                hasTs = true
                tsVal = getU32(buf, i + 2)
                tsEcr = getU32(buf, i + 6)
            }
        }
        i += olen
    }

    return TcpSegment(
        srcPort = getU16(buf, off),
        dstPort = getU16(buf, off + 2),
        seq = getU32(buf, off + 4),
        ack = getU32(buf, off + 8),
        flags = getU8(buf, off + 13),
        window = getU16(buf, off + 14),
        headerLen = dataOffset,
        payloadOffset = off + dataOffset,
        payloadLength = payloadLen,
        mss = mss,
        wscale = wscale,
        sackPermitted = sackPerm,
        hasTimestamp = hasTs,
        tsValue = tsVal,
        tsEchoReply = tsEcr,
        buffer = buf
    )
}

/* ------------------------------------------------------------------ */
/*  UDP                                                                */
/* ------------------------------------------------------------------ */

class UdpDatagram(
    val srcPort: Int,
    val dstPort: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
    val buffer: ByteArray
)

fun parseUdp(buf: ByteArray, off: Int, len: Int): UdpDatagram? {
    if (len < 8 || off + 8 > buf.size) return null
    val declared = getU16(buf, off + 4)
    val payloadLen = ((if (declared >= 8) declared else len) - 8).coerceAtMost(len - 8).coerceAtLeast(0)
    return UdpDatagram(
        srcPort = getU16(buf, off),
        dstPort = getU16(buf, off + 2),
        payloadOffset = off + 8,
        payloadLength = payloadLen,
        buffer = buf
    )
}

/* ------------------------------------------------------------------ */
/*  Сборка пакетов в сторону клиента                                   */
/* ------------------------------------------------------------------ */

object PacketBuilder {

    private const val DEFAULT_TTL = 64

    /**
     * Собирает IP+TCP пакет. [options] — уже закодированные и выровненные до 4 байт опции.
     * Возвращает пару «массив / используемая длина».
     */
    fun tcp(
        v6: Boolean,
        src: InetAddress,
        dst: InetAddress,
        srcPort: Int,
        dstPort: Int,
        seq: Int,
        ack: Int,
        flags: Int,
        window: Int,
        options: ByteArray? = null,
        payload: ByteArray? = null,
        payloadOff: Int = 0,
        payloadLen: Int = 0,
        tsValue: Int = 0,
        tsEcho: Int = 0,
        useTimestamp: Boolean = false,
        ttl: Int = DEFAULT_TTL
    ): ByteArray {
        val optLen = (options?.size ?: 0) + (if (useTimestamp) 12 else 0)
        val tcpHeaderLen = 20 + optLen
        val ipHeaderLen = if (v6) 40 else 20
        val out = ByteArray(ipHeaderLen + tcpHeaderLen + payloadLen)

        val t = ipHeaderLen
        putU16(out, t, srcPort)
        putU16(out, t + 2, dstPort)
        putU32(out, t + 4, seq)
        putU32(out, t + 8, ack)
        putU8(out, t + 12, ((tcpHeaderLen / 4) shl 4) and 0xF0)
        putU8(out, t + 13, flags)
        putU16(out, t + 14, window)
        putU16(out, t + 16, 0) // checksum placeholder
        putU16(out, t + 18, 0) // urgent pointer

        var o = t + 20
        if (options != null && options.isNotEmpty()) {
            System.arraycopy(options, 0, out, o, options.size)
            o += options.size
        }
        if (useTimestamp) {
            putU8(out, o, 8); putU8(out, o + 1, 10)
            putU32(out, o + 2, tsValue)
            putU32(out, o + 6, tsEcho)
            o += 10
            putU8(out, o, 1); putU8(out, o + 1, 1)
            o += 2
        }

        if (payloadLen > 0 && payload != null) {
            System.arraycopy(payload, payloadOff, out, t + tcpHeaderLen, payloadLen)
        }

        if (v6) buildIp6Header(out, src, dst, IpProto.TCP, tcpHeaderLen + payloadLen, ttl)
        else buildIp4Header(out, src, dst, IpProto.TCP, tcpHeaderLen + payloadLen, ttl)

        putU16(out, t + 16, tcpChecksum(v6, src, dst, IpProto.TCP, out, t, tcpHeaderLen + payloadLen))
        return out
    }

    fun udp(
        v6: Boolean,
        src: InetAddress,
        dst: InetAddress,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
        payloadOff: Int = 0,
        payloadLen: Int = payload.size,
        ttl: Int = DEFAULT_TTL
    ): ByteArray {
        val udpLen = 8 + payloadLen
        val ipHeaderLen = if (v6) 40 else 20
        val out = ByteArray(ipHeaderLen + udpLen)
        val u = ipHeaderLen
        putU16(out, u, srcPort)
        putU16(out, u + 2, dstPort)
        putU16(out, u + 4, udpLen)
        putU16(out, u + 6, 0)
        System.arraycopy(payload, payloadOff, out, u + 8, payloadLen)

        if (v6) buildIp6Header(out, src, dst, IpProto.UDP, udpLen, ttl)
        else buildIp4Header(out, src, dst, IpProto.UDP, udpLen, ttl)

        putU16(out, u + 6, tcpChecksum(v6, src, dst, IpProto.UDP, out, u, udpLen))
        return out
    }

    fun rst(
        v6: Boolean,
        src: InetAddress,
        dst: InetAddress,
        srcPort: Int,
        dstPort: Int,
        seq: Int,
        ack: Int
    ): ByteArray = tcp(
        v6 = v6, src = src, dst = dst, srcPort = srcPort, dstPort = dstPort,
        seq = seq, ack = ack, flags = TcpFlag.RST or TcpFlag.ACK, window = 0
    )

    private fun buildIp4Header(
        out: ByteArray, src: InetAddress, dst: InetAddress, proto: Int, payloadLen: Int, ttl: Int
    ) {
        out[0] = 0x45
        out[1] = 0
        putU16(out, 2, 20 + payloadLen)
        putU16(out, 4, 0) // identification
        putU16(out, 6, 0x4000) // Don't Fragment
        putU8(out, 8, ttl)
        putU8(out, 9, proto)
        putU16(out, 10, 0)
        System.arraycopy(src.address, 0, out, 12, 4)
        System.arraycopy(dst.address, 0, out, 16, 4)
        putU16(out, 10, ip4HeaderChecksum(out))
    }

    private fun buildIp6Header(
        out: ByteArray, src: InetAddress, dst: InetAddress, proto: Int, payloadLen: Int, ttl: Int
    ) {
        out[0] = 0x60
        out[1] = 0; out[2] = 0; out[3] = 0
        putU16(out, 4, payloadLen)
        putU8(out, 6, proto)
        putU8(out, 7, ttl)
        System.arraycopy(src.address, 0, out, 8, 16)
        System.arraycopy(dst.address, 0, out, 24, 16)
    }

    private fun ip4HeaderChecksum(header: ByteArray): Int {
        val cs = Checksum()
        cs.update(header, 0, 20)
        return cs.value()
    }

    /** Контрольная сумма TCP/UDP вместе с псевдозаголовком. */
    private fun tcpChecksum(
        v6: Boolean, src: InetAddress, dst: InetAddress, proto: Int,
        segment: ByteArray, segOff: Int, segLen: Int
    ): Int {
        val cs = Checksum()
        if (v6) {
            cs.update(src.address, 0, 16)
            cs.update(dst.address, 0, 16)
            cs.updateU16((segLen ushr 16) and 0xFFFF)
            cs.updateU16(segLen and 0xFFFF)
            cs.updateU16(0)
            cs.updateU16(proto and 0xFF)
        } else {
            cs.update(src.address, 0, 4)
            cs.update(dst.address, 0, 4)
            cs.updateU16((proto shl 8) or (segLen and 0xFFFF))
        }
        cs.update(segment, segOff, segLen)
        return cs.value()
    }

    /**
     * Кодирование опций SYN-ACK: MSS, SACK-permitted, NOP/NOP, Window Scale, NOP.
     * Итого 12 байт — кратно четырём, как требует TCP.
     */
    fun synAckOptions(mss: Int, sackPerm: Boolean, wscale: Int): ByteArray {
        val b = ByteArray(12)
        var o = 0
        b[o] = 2; b[o + 1] = 4
        putU16(b, o + 2, mss)
        o += 4
        if (sackPerm) { b[o] = 4; b[o + 1] = 2 } else { b[o] = 1; b[o + 1] = 1 }
        o += 2
        b[o] = 1; b[o + 1] = 1
        o += 2
        b[o] = 3; b[o + 1] = 3; b[o + 2] = (wscale and 0x0F).toByte()
        o += 3
        b[o] = 1
        return b
    }
}
