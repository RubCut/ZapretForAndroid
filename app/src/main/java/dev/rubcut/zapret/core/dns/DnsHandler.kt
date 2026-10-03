package dev.rubcut.zapret.core.dns

import dev.rubcut.zapret.core.LogManager
import dev.rubcut.zapret.core.LogTag
import dev.rubcut.zapret.core.SocketProtector
import dev.rubcut.zapret.core.TrafficStats
import dev.rubcut.zapret.core.net.IpHeader
import dev.rubcut.zapret.core.net.PacketBuilder
import dev.rubcut.zapret.core.net.UdpDatagram
import dev.rubcut.zapret.core.stack.PacketWriter
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.HostListStore
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/**
 * Перехват DNS внутри туннеля.
 *
 * Именно здесь работает «изменение hosts в подключении»: таблица hosts и список
 * блокировки применяются до выхода в сеть, а ответы приходят от выбранного
 * резолвера (системного, своего, DoH или DoT), а не от того, кого выбрал провайдер.
 */
class DnsHandler(
    private val writer: PacketWriter,
    protector: SocketProtector,
    private val scope: CoroutineScope,
    private val io: CoroutineDispatcher,
    private val configProvider: () -> AppConfig,
    listsProvider: () -> HostListStore.Snapshot,
    private val virtualServers: Set<String>
) {

    val resolver = DnsResolver(
        context = AppContextProvider.context,
        configProvider = configProvider,
        listsProvider = listsProvider,
        protector = protector
    )

    /** Возвращает true, если пакет обработан как DNS и дальше его передавать не нужно. */
    fun handle(ip: IpHeader, dgram: UdpDatagram): Boolean {
        val cfg = configProvider()
        if (dgram.dstPort != 53) return false
        val dstAddress = ip.dst.hostAddress ?: return false
        if (!cfg.dnsHijack && !virtualServers.contains(dstAddress)) return false
        if (dgram.payloadLength < 12) return false

        val payload = dgram.buffer.copyOfRange(dgram.payloadOffset, dgram.payloadOffset + dgram.payloadLength)
        val query = DnsMessage.parseQuery(payload, payload.size) ?: return false

        val v6 = ip.v6
        val srcAddr = ip.src
        val dstAddr = ip.dst
        val srcPort = dgram.srcPort

        scope.launch(io) {
            TrafficStats.dnsQueried()
            var response: ByteArray? = null

            if (!cfg.dnsFakeProtection) {
                // Прозрачный режим: пересылаем запрос ровно туда, куда просило приложение.
                response = resolver.forwardRaw(payload, payload.size, dstAddr, 53)
            }

            if (response == null) {
                response = if (query.isAddressQuery) {
                    when (val result = resolver.lookup(query.name, query.type)) {
                        is DnsResult.Addresses -> DnsMessage.buildAddressResponse(query, result.list, result.ttl)
                        is DnsResult.Blocked -> {
                            LogManager.d(LogTag.DNS, "DNS: ${query.name} заблокировано")
                            DnsMessage.buildEmptyResponse(query, 3)
                        }
                        is DnsResult.Failed -> {
                            LogManager.d(LogTag.DNS, "DNS: ${query.name} — ${result.reason}")
                            DnsMessage.buildEmptyResponse(query, 2)
                        }
                    }
                } else {
                    resolver.forwardQueryBytes(payload, payload.size)
                        ?: DnsMessage.buildEmptyResponse(query, 2)
                }
            }

            try {
                val packet = PacketBuilder.udp(
                    v6 = v6, src = dstAddr, dst = srcAddr,
                    srcPort = 53, dstPort = srcPort,
                    payload = response
                )
                writer.write(packet)
                LogManager.d(LogTag.DNS, "DNS ← ${query.name} (${response.size} байт)")
            } catch (e: Exception) {
                LogManager.d(LogTag.DNS, "DNS: не удалось отправить ответ: ${e.message}")
            }
        }
        return true
    }

    fun close() = resolver.close()
}

/**
 * Application context для компонентов, которые живут вне Activity/Service.
 * Заполняется в [dev.rubcut.zapret.ZapretApplication].
 */
object AppContextProvider {
    @Volatile
    lateinit var context: android.content.Context

    fun init(context: android.content.Context) {
        this.context = context.applicationContext
    }
}
