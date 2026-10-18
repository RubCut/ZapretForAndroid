package dev.rubcut.zapret

import android.content.ContextWrapper
import dev.rubcut.zapret.core.SocketProtector
import dev.rubcut.zapret.core.dns.DnsMessage
import dev.rubcut.zapret.core.dns.DnsResolver
import dev.rubcut.zapret.core.dns.DnsResult
import dev.rubcut.zapret.core.dns.DnsType
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.DnsMode
import dev.rubcut.zapret.data.HostListStore
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/**
 * «Врущий» protect() не должен убивать обычный UDP-DNS.
 *
 * Регрессия поля: на части прошивок protect() spuriously возвращает false
 * (наблюдалось в бою — мгновенные RST всех upstream-соединений при живом
 * DoH/диагностике). TCP и UDP-релей, а также каналы DoH/DoT уже смягчены
 * (warn + счётчик вместо throw), а [DnsResolver.viaUdp] оставался жёстким —
 * единственное место, где отказ изоляции уносил с собой SYSTEM/CUSTOM DNS
 * и весь резерв. После этого автоподбор не мог разрешить даже имена
 * проверяемых хостов и сообщал «имя не разрешилось, пропускаю».
 *
 * Здесь это проверено на живой паре сокетов: мини-сервер DNS на 127.0.0.1
 * отвечает A-записью, резолвер обязан её получить, хотя protect() = false.
 */
class DnsSoftIsolationTest {

    /** protect() всегда «не удался» — как на проблемной прошивке. */
    private val lyingProtector = object : SocketProtector {
        val calls = AtomicInteger()
        override fun protect(socket: java.net.Socket): Boolean {
            calls.incrementAndGet()
            return false
        }

        override fun protect(socket: DatagramSocket): Boolean {
            calls.incrementAndGet()
            return false
        }

        override fun protect(fd: Int): Boolean {
            calls.incrementAndGet()
            return false
        }
    }

    @Test
    fun udpLookupStillWorksWhenProtectLies() {
        val server = MiniDnsServer()
        try {
            val cfg = AppConfig(
                dnsMode = DnsMode.CUSTOM,
                dnsServers = "127.0.0.1:${server.port}",
                dnsCache = false,
                dnsFakeProtection = true
            )
            val resolver = DnsResolver(
                context = ContextWrapper(null),
                configProvider = { cfg },
                listsProvider = { HostListStore.Snapshot.EMPTY },
                protector = lyingProtector,
                failClosed = true
            )

            val result = runBlocking { resolver.lookup("example.test", DnsType.A) }

            assertTrue(
                "protect() вернул false — резолвер обязан продолжить без изоляции, " +
                    "а не уронить DNS; получено: $result",
                result is DnsResult.Addresses
            )
            assertEquals(
                "адрес из ответа мини-сервера обязан дойти до вызывающей стороны",
                "203.0.113.5",
                (result as DnsResult.Addresses).list.single().hostAddress
            )
            assertTrue(
                "сценарий обязан был реально пройти через отказ protect()",
                lyingProtector.calls.get() > 0
            )
        } finally {
            server.close()
        }
    }

    /**
     * UDP-сервер DNS на 127.0.0.1: отвечает одной A-записью на любой запрос.
     * Обработка в отдельном потоке — сокет блокирующий.
     */
    private class MiniDnsServer {
        private val socket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val port: Int get() = socket.localPort
        private val address = InetAddress.getByName("203.0.113.5")

        init {
            thread(name = "mini-dns") {
                val buf = ByteArray(512)
                try {
                    while (!socket.isClosed) {
                        val packet = DatagramPacket(buf, buf.size)
                        socket.receive(packet)
                        val query = DnsMessage.parseQuery(packet.data, packet.length) ?: continue
                        val response = DnsMessage.buildAddressResponse(query, listOf(address), ttl = 60)
                        socket.send(
                            DatagramPacket(
                                response, response.size,
                                packet.address, packet.port
                            )
                        )
                    }
                } catch (_: Throwable) {
                    // Сокет закрыт в close() — штатное завершение потока.
                }
            }
        }

        fun close() = socket.close()
    }
}
