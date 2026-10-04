package dev.rubcut.zapret.core.dns

import dev.rubcut.zapret.core.LogManager
import dev.rubcut.zapret.core.LogTag
import dev.rubcut.zapret.core.SocketProtector
import dev.rubcut.zapret.core.TrafficStats
import dev.rubcut.zapret.core.desync.StrategyResolver
import dev.rubcut.zapret.core.net.IpHeader
import dev.rubcut.zapret.core.net.PacketBuilder
import dev.rubcut.zapret.core.net.UdpDatagram
import dev.rubcut.zapret.core.stack.PacketWriter
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.HostListStore
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicInteger

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
    private val listsProvider: () -> HostListStore.Snapshot,
    private val virtualServers: Set<String>,
    /** Те же виртуальные адреса, но сравнением по [InetAddress], а не по строке. */
    private val virtualAddresses: Set<InetAddress> = emptySet()
) {

    val resolver = DnsResolver(
        context = AppContextProvider.context,
        configProvider = configProvider,
        listsProvider = listsProvider,
        protector = protector
    )

    /** Область действия обхода: домены вне неё DNS не трогает вообще. */
    private val strategies = StrategyResolver(configProvider, listsProvider)

    private val inFlight = AtomicInteger()
    private val successReported = AtomicInteger()
    private val passthroughReported = AtomicInteger()

    /** Возвращает true, если пакет обработан как DNS и дальше его передавать не нужно. */
    fun handle(ip: IpHeader, dgram: UdpDatagram): Boolean {
        val cfg = configProvider()
        if (dgram.dstPort != 53) return false
        val dstAddress = ip.dst.hostAddress ?: return false
        if (!cfg.dnsHijack && !isVirtual(dstAddress, ip.dst)) return false
        if (dgram.payloadLength < 12) return false

        val payload = dgram.buffer.copyOfRange(dgram.payloadOffset, dgram.payloadOffset + dgram.payloadLength)
        val query = DnsMessage.parseQuery(payload, payload.size) ?: return false

        val v6 = ip.v6
        val dstAddr = ip.dst
        val srcAddr = ip.src
        val srcPort = dgram.srcPort

        fun send(response: ByteArray) {
            try {
                writer.write(
                    PacketBuilder.udp(
                        v6 = v6, src = dstAddr, dst = srcAddr,
                        srcPort = 53, dstPort = srcPort,
                        payload = response
                    )
                )
            } catch (e: Exception) {
                LogManager.d(LogTag.DNS, "DNS: не удалось отправить ответ: ${e.message}")
            }
        }

        // Ограничитель очереди. Без него любая авария резолвера превращалась в
        // лавину висящих корутин: приложения не получали ни ответа, ни ошибки.
        if (inFlight.incrementAndGet() > MAX_IN_FLIGHT) {
            inFlight.decrementAndGet()
            LogManager.w("DNS: очередь переполнена (${MAX_IN_FLIGHT}), ${query.name} → SERVFAIL")
            send(DnsMessage.buildEmptyResponse(query, RCODE_SERVFAIL))
            return true
        }

        scope.launch(io) {
            try {
                TrafficStats.dnsQueried()
                val response = withTimeoutOrNull(RESOLVE_TIMEOUT_MS) { resolve(cfg, query, payload, dstAddr) }
                if (response == null) {
                    LogManager.w("DNS: ${query.name} — нет ответа за ${RESOLVE_TIMEOUT_MS} мс")
                    send(DnsMessage.buildEmptyResponse(query, RCODE_SERVFAIL))
                } else {
                    send(response)
                    if (successReported.getAndIncrement() == 0) {
                        LogManager.i(LogTag.DNS, "DNS отвечает: ${query.name} (${response.size} байт)")
                    } else {
                        LogManager.d(LogTag.DNS, "DNS ← ${query.name} (${response.size} байт)")
                    }
                }
            } catch (e: Exception) {
                LogManager.w("DNS: сбой обработки ${query.name}: ${e.message}")
                runCatching { send(DnsMessage.buildEmptyResponse(query, RCODE_SERVFAIL)) }
            } finally {
                inFlight.decrementAndGet()
            }
        }
        return true
    }

    /**
     * Сравнение с виртуальными адресами.
     *
     * Строковое сравнение по `hostAddress` не работает для IPv6: Java печатает
     * адрес развёрнутым («fd61:7a6f:ee07:0:0:0:0:2»), поэтому литерал из
     * константы никогда не совпадал и запросы к нашему же DNS-адресу уходили
     * «самому себе». Сначала сверяем точные [InetAddress], а строкой — только
     * как запасной путь для IPv4.
     */
    private fun isVirtual(hostAddress: String?, addr: InetAddress): Boolean =
        virtualAddresses.contains(addr) || virtualServers.contains(hostAddress ?: "")

    private suspend fun resolve(
        cfg: AppConfig,
        query: DnsQuery,
        payload: ByteArray,
        requestedServer: InetAddress
    ): ByteArray {
        // Если приложение спросило наш же виртуальный DNS-сервер, пересылать
        // запрос «туда же» нельзя — это петля. Тогда идём в системные/свои.
        fun forward(verbatim: Boolean): ByteArray? =
            if (isVirtual(requestedServer.hostAddress, requestedServer)) {
                resolver.forwardQueryBytes(payload, payload.size)
            } else if (verbatim) {
                resolver.forwardRaw(payload, payload.size, requestedServer, 53)
            } else {
                resolver.forwardQueryBytes(payload, payload.size)
            }

        if (!cfg.dnsFakeProtection) {
            // Прозрачный режим: пересылаем запрос ровно туда, куда просило приложение.
            forward(true)?.let { return it }
        }

        // Домены ВНЕ списка обхода отдаём нетронутыми: ответ провайдера
        // возвращается байт в байт. Hosts-таблица и список блокировки при этом
        // сохраняют силу — это явная воля пользователя, а не обход DPI.
        val lists = listsProvider()
        val overridden = lists.hosts.lookup(query.name) != null
        val adBlocked = cfg.dnsBlockAds && HostListStore.ADS_MATCHER.matches(query.name)
        if (!overridden && !adBlocked && query.isAddressQuery && !strategies.hostInScope(query.name)) {
            val raw = forward(true)
            if (raw != null) {
                if (passthroughReported.getAndIncrement() < 3) {
                    LogManager.i(
                        LogTag.DNS,
                        "DNS: ${query.name} вне списка обхода — ответ провайдера отдан без изменений"
                    )
                }
                return raw
            }
            // Провайдер не ответил — падаем в собственный резолвер, чтобы
            // домен не оказался «мёртвым» из-за чужого сбоя.
        }

        return if (query.isAddressQuery) {
            when (val result = resolver.lookup(query.name, query.type)) {
                is DnsResult.Addresses -> DnsMessage.buildAddressResponse(query, result.list, result.ttl)
                is DnsResult.Blocked -> {
                    LogManager.d(LogTag.DNS, "DNS: ${query.name} заблокировано")
                    DnsMessage.buildEmptyResponse(query, RCODE_NXDOMAIN)
                }
                is DnsResult.Failed -> {
                    LogManager.d(LogTag.DNS, "DNS: ${query.name} — ${result.reason}")
                    DnsMessage.buildEmptyResponse(query, RCODE_SERVFAIL)
                }
            }
        } else {
            // MX/SRV/PTR/TXT и прочие: пробрасываем запрос как есть.
            resolver.forwardQueryBytes(payload, payload.size)
                ?: DnsMessage.buildEmptyResponse(query, RCODE_SERVFAIL)
        }
    }

    fun close() = resolver.close()

    private companion object {
        const val MAX_IN_FLIGHT = 96
        const val RESOLVE_TIMEOUT_MS = 12_000L
        const val RCODE_SERVFAIL = 2
        const val RCODE_NXDOMAIN = 3
    }
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
