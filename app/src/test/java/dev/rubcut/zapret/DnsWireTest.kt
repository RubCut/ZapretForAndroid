package dev.rubcut.zapret

import dev.rubcut.zapret.core.dns.DnsMessage
import dev.rubcut.zapret.core.dns.DnsType
import dev.rubcut.zapret.core.dns.DnsWireResult
import dev.rubcut.zapret.core.dns.MAX_HTTP_BODY
import dev.rubcut.zapret.core.dns.base64UrlEncode
import dev.rubcut.zapret.core.dns.checkContentLength
import dev.rubcut.zapret.core.dns.parseWireResponse
import dev.rubcut.zapret.data.AppConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.net.InetAddress

/**
 * Wire-уровень DNS (RFC 8484): base64url, кап тела, разбор бинарных ответов,
 * строгий режим в конфиге. Чистые JVM-тесты без сети.
 */
class DnsWireTest {

    @Test
    fun base64UrlVectors() {
        // Векторы RFC 4648 §10 + url-алфавит без паддинга.
        assertEquals("", base64UrlEncode(ByteArray(0)))
        assertEquals("Zg", base64UrlEncode("f".toByteArray()))
        assertEquals("Zm8", base64UrlEncode("fo".toByteArray()))
        assertEquals("Zm9v", base64UrlEncode("foo".toByteArray()))
        assertEquals("Zm9vYg", base64UrlEncode("foob".toByteArray()))
        assertEquals("Zm9vYmE", base64UrlEncode("fooba".toByteArray()))
        assertEquals("Zm9vYmFy", base64UrlEncode("foobar".toByteArray()))
        // 0xFB 0xFF дают '+'/'/' в обычном base64 — здесь обязаны быть '-'/'_'.
        val s = base64UrlEncode(byteArrayOf(0xFB.toByte(), 0xFF.toByte(), 0xFE.toByte()))
        assertTrue("url-алфавит без +/: $s", s.all { it.isLetterOrDigit() || it == '-' || it == '_' })
        assertEquals("-__-", s)
    }

    @Test
    fun contentLengthGuard() {
        assertEquals(0, checkContentLength(0))
        assertEquals(100, checkContentLength(100))
        assertEquals(MAX_HTTP_BODY, checkContentLength(MAX_HTTP_BODY))
        try {
            checkContentLength(-1)
            fail("отрицательный Content-Length обязан бросать")
        } catch (e: IllegalArgumentException) {
            // ok
        }
        try {
            checkContentLength(MAX_HTTP_BODY + 1)
            fail("тело сверх лимита обязано бросать")
        } catch (e: IllegalArgumentException) {
            // ok
        }
    }

    @Test
    fun wireResponseRoundTrip() {
        val id = 0x1234
        val q = DnsMessage.buildQuery(id, "example.com", DnsType.A)
        val query = DnsMessage.parseQuery(q, q.size)!!
        val resp = DnsMessage.buildAddressResponse(query, listOf(InetAddress.getByName("93.184.216.34")), 60)
        when (val r = parseWireResponse(resp, id)) {
            is DnsWireResult.Addresses ->
                assertEquals(listOf(InetAddress.getByName("93.184.216.34")), r.list)
            else -> fail("ожидались адреса, получено $r")
        }
    }

    @Test
    fun wireResponseIdMismatch() {
        val q = DnsMessage.buildQuery(0x1234, "example.com", DnsType.A)
        val query = DnsMessage.parseQuery(q, q.size)!!
        val resp = DnsMessage.buildAddressResponse(query, listOf(InetAddress.getByName("93.184.216.34")), 60)
        // Портим младший байт ID: ответ чужой.
        resp[1] = (resp[1] + 1).toByte()
        val r = parseWireResponse(resp, 0x1234)
        assertTrue("чужой TXID обязан быть Failed, получено $r", r is DnsWireResult.Failed)
    }

    @Test
    fun wireNxdomainIsBlocked() {
        val q = DnsMessage.buildQuery(0x1234, "nope.invalid", DnsType.A)
        val query = DnsMessage.parseQuery(q, q.size)!!
        val resp = DnsMessage.buildEmptyResponse(query, 3)
        assertTrue(parseWireResponse(resp, 0x1234) is DnsWireResult.Blocked)
    }

    @Test
    fun wireShortAndErrorAreFailed() {
        assertTrue(parseWireResponse(ByteArray(5), 1) is DnsWireResult.Failed)
        val q = DnsMessage.buildQuery(0x1234, "example.com", DnsType.A)
        val query = DnsMessage.parseQuery(q, q.size)!!
        val resp = DnsMessage.buildEmptyResponse(query, 2)
        assertTrue(parseWireResponse(resp, 0x1234) is DnsWireResult.Failed)
    }

    @Test
    fun strictDnsRoundTrip() {
        assertEquals(false, AppConfig().strictDns)
        val back = AppConfig.fromJson(AppConfig().copy(strictDns = true).toJson())
        assertEquals(true, back.strictDns)
    }
}
