package dev.rubcut.zapret

import dev.rubcut.zapret.core.SocketProtector
import dev.rubcut.zapret.core.net.getU16
import dev.rubcut.zapret.core.net.IpLiterals
import dev.rubcut.zapret.core.net.parseIp
import dev.rubcut.zapret.core.net.parseTcp
import dev.rubcut.zapret.core.proto.Tls
import dev.rubcut.zapret.core.stack.PacketWriter
import dev.rubcut.zapret.core.stack.StrategyAutopilot
import dev.rubcut.zapret.core.stack.TcpStack
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.HostListStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.OutputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Регрессии на баги, найденные при проверке приложения на устройстве.
 *
 * Каждый тест соответствует конкретной поломке, из-за которой обход либо
 * не работал вовсе, либо выглядел сломанным.
 */
class RegressionsTest {

    private val packets = CopyOnWriteArrayList<ByteArray>()
    private val sink = object : OutputStream() {
        override fun write(b: Int) {}
        override fun write(b: ByteArray, off: Int, len: Int) {
            packets.add(b.copyOfRange(off, off + len))
        }
    }
    private val writer = PacketWriter(sink)
    private val protector = object : SocketProtector {
        override fun protect(socket: Socket) = true
        override fun protect(socket: DatagramSocket) = true
        override fun protect(fd: Int) = true
    }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val config = AppConfig()
    private val clientAddr = InetAddress.getByName("10.9.0.7")

    /* ================================================================== */
    /*  1. ClientHello автоподбора должен приниматься настоящим сервером     */
    /* ================================================================== */

    /**
     * Зонд обязан получать ServerHello, а не alert. Сервер выбирает версию по
     * legacy_version, если нет supported_versions, поэтому набор шифров должен
     * содержать хотя бы один шифр, существующий в TLS 1.2.
     *
     * Именно этого не хватало: предлагался один лишь 0x1301 (TLS 1.3), и Google
     * с Cloudflare отвечали handshake_failure (alert 40). Автоподбор и
     * самоисцеление при этом выглядели рабочими, но всегда проваливались.
     */
    @Test
    fun probeClientHelloOffersTls12UsableCipher() {
        for (host in listOf("www.google.com", "www.youtube.com", "discord.com", "example.com")) {
            val hello = StrategyAutopilot.clientHelloFor(host)
            val parsed = parseClientHello(hello)
                ?: throw AssertionError("ClientHello для $host не разобран")

            assertEquals(
                "для $host legacy_version обязан быть TLS 1.2 (0x0303)",
                0x0303, parsed.legacyVersion
            )

            val tls13Only = parsed.cipherSuites.filter { it in TLS13_ONLY_SUITES }
            if (tls13Only.isNotEmpty()) {
                assertTrue(
                    "шифры $tls13Only существуют только в TLS 1.3, но supported_versions " +
                        "не отправлен — сервер выберет TLS 1.2 и ответит handshake_failure",
                    parsed.supportedVersions.isNotEmpty()
                )
            }
            assertTrue(
                "нечего предлагать серверу: ни одного шифра из TLS 1.2 (набор: ${parsed.cipherSuites})",
                parsed.cipherSuites.any { it !in TLS13_ONLY_SUITES }
            )
        }
    }

    /** Наш собственный парсер обязан видеть SNI в том же ClientHello. */
    @Test
    fun probeClientHelloKeepsSniParsable() {
        val host = "www.youtube.com"
        val hello = StrategyAutopilot.clientHelloFor(host)
        val info = Tls.parseClientHello(hello, 0, hello.size)
        assertNotNull("синтетический ClientHello не распознан", info)
        assertEquals(host, info!!.sni)
        assertEquals(hello.size, info.recordLength)
    }

    /* ================================================================== */
    /*  2. Виртуальные адреса DNS нельзя сравнивать по строке                */
    /* ================================================================== */

    /**
     * `Inet6Address.getHostAddress()` печатает адрес развёрнутым, поэтому
     * литерал «fd61:7a6f:ee7::2» с ним не совпадает. Сравнение обязано идти по
     * самим адресам — иначе на двухстёковых сетях не работали ни перехват
     * TCP-DNS, ни защита от петли, и каждый запрос к своему же DNS-адресу
     * висел на таймауте.
     */
    @Test
    fun virtualDnsAddressesMatchByAddressNotByText() {
        // Разбор через тот же IpLiterals, что и в боевом коде: VIRTUAL_DNS_ADDRESSES
        // собирается именно им, и ошибка разбора IPv6 тихо оставила бы набор пустым.
        val v4 = IpLiterals.parse("10.211.0.2")
        val v6 = IpLiterals.parse("fd61:7a6f:ee7::2")
        assertNotNull("10.211.0.2 не разобран", v4)
        assertNotNull("fd61:7a6f:ee7::2 не разобран", v6)

        assertEquals("10.211.0.2", v4!!.hostAddress)
        assertTrue(
            "IPv6-адрес выводится развёрнутым, строковое сравнение не годится",
            v6!!.hostAddress != "fd61:7a6f:ee7::2"
        )
        assertEquals(
            "разбор IPv6 обязан дать те же 16 байт, что и getByName",
            InetAddress.getByName("fd61:7a6f:ee7::2").address.toList(),
            v6.address.toList()
        )

        val stack = newStack(virtualDns = setOf(v4, v6))
        assertTrue("IPv4-адрес DNS должен узнаваться", stack.isVirtualDns(v4))
        assertTrue("IPv6-адрес DNS должен узнаваться", stack.isVirtualDns(v6))
        assertTrue("равный по значению адрес тоже", stack.isVirtualDns(InetAddress.getByName("fd61:7a6f:ee7::2")))
        assertTrue("null не является виртуальным адресом", !stack.isVirtualDns(null))
        stack.shutdown()
    }

    /* ================================================================== */
    /*  3. TCP к виртуальному DNS: 53 — перенаправлять, остальное — RST     */
    /* ================================================================== */

    /**
     * netd (системный резолвер) иногда шлёт TCP не на 53, а на 853, пробуя
     * DoT. Такой запрос уходил в виртуальный адрес и висел полный
     * connectTimeout — сеть выглядела «есть, но всё очень медленно».
     */
    @Test
    fun tcpToVirtualDnsNon53PortIsResetImmediately() {
        val stack = newStack(virtualDns = setOf(IpLiterals.parse("10.211.0.2")!!))
        try {
            val dns = IpLiterals.parse("10.211.0.2")!!
            feed(stack, syn(dns, dstPort = 853))

            val rst = await { p ->
                val ip = parseIp(p, p.size) ?: return@await false
                val seg = parseTcp(p, ip.payloadOffset, ip.payloadLength) ?: return@await false
                seg.isRst && seg.dstPort == 854
            }
            assertNotNull("на TCP к виртуальному DNS нужен немедленный RST, а не попытка соединения", rst)
            assertEquals("соединение создаваться не должно было", 0, stack.activeCount)
        } finally {
            stack.shutdown()
        }
    }

    /** TCP/53 к виртуальному DNS обязан доходить до стека и уходить на резолвер. */
    @Test
    fun tcpToVirtualDnsPort53IsAccepted() {
        val stack = newStack(virtualDns = setOf(IpLiterals.parse("10.211.0.2")!!))
        stack.dnsRedirect = InetAddress.getByName("127.0.0.1")
        try {
            val dns = IpLiterals.parse("10.211.0.2")!!
            feed(stack, syn(dns, dstPort = 53))
            val synAck = await { p ->
                val ip = parseIp(p, p.size) ?: return@await false
                val seg = parseTcp(p, ip.payloadOffset, ip.payloadLength) ?: return@await false
                seg.isSynAck && seg.dstPort == 854
            }
            assertNotNull("TCP/53 к виртуальному DNS должен обрабатываться, а не отбиваться", synAck)
        } finally {
            stack.shutdown()
        }
    }

    /* ================================================================== */

    private fun newStack(virtualDns: Set<InetAddress>): TcpStack = TcpStack(
        writer = writer,
        protector = protector,
        scope = scope,
        configProvider = { config },
        listsProvider = { HostListStore.Snapshot.EMPTY },
        virtualDns = virtualDns
    )

    private fun await(timeoutMs: Long = 4000, pred: (ByteArray) -> Boolean): ByteArray? {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            for (p in packets) if (pred(p)) return p
            Thread.sleep(10)
        }
        return null
    }

    private fun feed(stack: TcpStack, packet: ByteArray) {
        val ip = parseIp(packet, packet.size)!!
        stack.onPacket(ip, parseTcp(packet, ip.payloadOffset, ip.payloadLength)!!)
    }

    private fun syn(dst: InetAddress, srcPort: Int = 854, dstPort: Int): ByteArray {
        val p = ByteArray(40)
        p[0] = 0x45
        p[2] = 0; p[3] = 40.toByte()
        p[6] = 0x40
        p[8] = 64; p[9] = 6
        System.arraycopy(clientAddr.address, 0, p, 12, 4)
        System.arraycopy(dst.address, 0, p, 16, 4)
        p[20] = (srcPort ushr 8).toByte(); p[21] = (srcPort and 0xFF).toByte()
        p[22] = (dstPort ushr 8).toByte(); p[23] = (dstPort and 0xFF).toByte()
        // seq = 0x01000000, ack = 0, dataOffset = 5 (20 байт), flags = SYN, window = 65535
        p[24] = 1; p[25] = 0; p[26] = 0; p[27] = 0
        p[32] = 0x50; p[33] = 0x02
        p[34] = 0xFF.toByte(); p[35] = 0xFF.toByte()
        return p
    }

    /* ------------------------------------------------------------------ */

    private class ParsedHello(
        val legacyVersion: Int,
        val cipherSuites: List<Int>,
        val supportedVersions: List<Int>
    )

    /** Разбор ClientHello ровно так, как это сделал бы сервер. */
    private fun parseClientHello(b: ByteArray): ParsedHello? {
        if (b.size < 9) return null
        if ((b[0].toInt() and 0xFF) != 0x16) return null
        var p = 5
        if ((b[p].toInt() and 0xFF) != 1) return null          // client_hello
        p += 4
        val legacyVersion = getU16(b, p); p += 2
        p += 32                                                // random
        p += 1 + (b[p].toInt() and 0xFF)                        // session id
        val csLen = getU16(b, p); p += 2
        val suites = (0 until csLen step 2).map { getU16(b, p + it) }
        p += csLen
        p += 1 + (b[p].toInt() and 0xFF)                        // compression
        val extTotal = getU16(b, p); p += 2
        val extEnd = p + extTotal
        var versions: List<Int> = emptyList()
        while (p + 4 <= extEnd && p + 4 <= b.size) {
            val type = getU16(b, p)
            val len = getU16(b, p + 2)
            p += 4
            if (p + len > b.size) break
            if (type == 0x002B && len >= 2) {
                val listLen = getU16(b, p)
                versions = (0 until listLen step 2)
                    .take((listLen + 1) / 2)
                    .map { getU16(b, p + 2 + it) }
            }
            p += len
        }
        return ParsedHello(legacyVersion, suites, versions)
    }

    private companion object {
        /** Наборы шифров, которых нет в TLS 1.2 — предлагать их без
         *  supported_versions бессмысленно: сервер обязан выбрать TLS 1.2. */
        val TLS13_ONLY_SUITES = setOf(
            0x1301, 0x1302, 0x1303, 0x1304, 0x1305,
            0x1306, 0x1307, 0x1308, 0x1309, 0x130A
        )
    }
}