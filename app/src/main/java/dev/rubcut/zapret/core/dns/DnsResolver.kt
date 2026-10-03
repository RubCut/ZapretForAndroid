package dev.rubcut.zapret.core.dns

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import dev.rubcut.zapret.core.LogManager
import dev.rubcut.zapret.core.LogTag
import dev.rubcut.zapret.core.SocketProtector
import dev.rubcut.zapret.core.desync.ReverseHostCache
import dev.rubcut.zapret.core.net.IpLiterals
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.DnsMode
import dev.rubcut.zapret.data.HostListStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.IOException
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SNIServerName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

sealed class DnsResult {
    class Addresses(val list: List<InetAddress>, val ttl: Int) : DnsResult()
    object Blocked : DnsResult()
    class Failed(val reason: String) : DnsResult()
}

/**
 * Резолвер, работающий внутри туннеля.
 *
 * Поддерживает системные серверы текущей сети, произвольные UDP/TCP-серверы,
 * DNS-over-HTTPS и DNS-over-TLS, а также таблицу hosts и список блокировки.
 * Все сокеты обязательно проходят через [SocketProtector], иначе их трафик
 * вернулся бы в наш же туннель.
 */
class DnsResolver(
    private val context: Context,
    private val configProvider: () -> AppConfig,
    private val listsProvider: () -> HostListStore.Snapshot,
    private val protector: SocketProtector
) {

    private class CacheEntry(val addresses: List<InetAddress>, val expireAt: Long)

    private val cache = object : LinkedHashMap<String, CacheEntry>(64, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, CacheEntry>?): Boolean = size > 2048
    }

    private val bootstrapCache = HashMap<String, Pair<InetAddress, Long>>()

    @Volatile
    private var dohChannel: DohChannel? = null
    @Volatile
    private var dohUrlInUse: String? = null
    @Volatile
    private var dotChannel: DotChannel? = null
    @Volatile
    private var dotHostInUse: String? = null

    /* ---------------------------------------------------------------- */

    suspend fun lookup(name: String, type: Int): DnsResult = withContext(Dispatchers.IO) {
        val cfg = configProvider()
        val lists = listsProvider()

        lists.hosts.lookup(name)?.let { addrs ->
            return@withContext if (HostsTableIsBlock(addrs)) {
                LogManager.d(LogTag.DNS, "hosts: $name заблокировано")
                DnsResult.Blocked
            } else {
                val result = addrs.filter { (it.address.size == 16) == (type == DnsType.AAAA) }
                LogManager.d(LogTag.DNS, "hosts: $name → ${result.joinToString { it.hostAddress ?: "?" }}")
                DnsResult.Addresses(result, cfg.dnsCacheTtlSec.coerceAtLeast(1))
            }
        }

        if (cfg.dnsBlockAds && HostListStore.ADS_MATCHER.matches(name)) {
            return@withContext DnsResult.Blocked
        }

        val key = "$name:$type"
        if (cfg.dnsCache) {
            val now = System.currentTimeMillis()
            val hit = synchronized(cache) { cache[key] }
            if (hit != null && hit.expireAt > now) return@withContext DnsResult.Addresses(hit.addresses, ((hit.expireAt - now) / 1000).toInt())
        }

        val result = resolveUpstream(cfg, name, type)
        if (result is DnsResult.Addresses && cfg.dnsCache && result.list.isNotEmpty()) {
            val ttl = result.ttl.coerceIn(5, 86400)
            synchronized(cache) {
                cache[key] = CacheEntry(result.list, System.currentTimeMillis() + ttl * 1000L)
            }
            for (a in result.list) ReverseHostCache.put(a, name)
        }
        result
    }

    private fun resolveUpstream(cfg: AppConfig, name: String, type: Int): DnsResult {
        val primary = try {
            when (cfg.dnsMode) {
                DnsMode.SYSTEM -> viaUdp(cfg, name, type, systemServers(), "system")
                DnsMode.CUSTOM -> viaUdp(cfg, name, type, configuredServers(cfg), "custom")
                DnsMode.DOH -> viaDoh(cfg, name, type)
                DnsMode.DOT -> viaDot(cfg, name, type)
            }
        } catch (e: Exception) {
            LogManager.e("DNS: сбой ${cfg.dnsMode} для $name", e)
            DnsResult.Failed(e.message ?: "unknown")
        }
        // DnsResult.Blocked (NXDOMAIN/блок-лист) — это ответ, а не авария:
        // откатываться на другой сервер здесь нельзя, иначе блок-лист не сработает.
        if (primary !is DnsResult.Failed) return primary
        if (cfg.dnsMode == DnsMode.SYSTEM) return primary

        // Запасной путь. Без него любая авария DoH/DoT выглядела бы для
        // пользователя как «интернет не работает вовсе».
        val backup = systemServers() + FALLBACK_SERVERS.map { InetSocketAddress(it.first, it.second) }
        return try {
            val r = viaUdp(cfg, name, type, backup, "fallback")
            if (r is DnsResult.Failed) {
                LogManager.w("DNS: $name не разрешилось ни через ${cfg.dnsMode}, ни через резерв (${r.reason})")
            }
            r
        } catch (e2: Exception) {
            DnsResult.Failed(e2.message ?: "unknown")
        }
    }

    /* ---------------------------------------------------------------- */
    /*  Bootstrap-резолвер для DoH/DoT                                   */
    /* ---------------------------------------------------------------- */

    /**
     * Разрешает имя DoH/DoT-сервера, НЕ обращаясь ни к netd, ни к нашему
     * собственному резолверу.
     *
     * Почему это обязательно: `InetSocketAddress("dns.google", 443)` внутри
     * вызывает `InetAddress.getByName`, а тот идёт через netd в сеть по
     * умолчанию. Сеть по умолчанию у нас — наш же VPN, поэтому запрос
     * возвращался в [DnsHandler], тот снова лез в DoH, и всё разрешение имён
     * зависало намертво (дополнительно канал заблокирован на `@Synchronized`).
     * Здесь используются только защищённые сокеты и литеральные адреса
     * серверов — рекурсия невозможна по построению.
     */
    fun bootstrapResolve(host: String): InetAddress? {
        IpLiterals.parse(host)?.let { return it }
        val key = host.lowercase().trim().trimEnd('.')
        if (key.isEmpty()) return null

        WELL_KNOWN[key]?.let { IpLiterals.parse(it)?.let { a -> return a } }

        val now = System.currentTimeMillis()
        synchronized(bootstrapCache) {
            val hit = bootstrapCache[key]
            if (hit != null && hit.second > now) return hit.first
        }

        val cfg = configProvider()
        val servers = systemServers() + FALLBACK_SERVERS.map { InetSocketAddress(it.first, it.second) }
        val r = viaUdp(cfg, key, DnsType.A, servers, "bootstrap")
        if (r is DnsResult.Addresses && r.list.isNotEmpty()) {
            val addr = r.list.first()
            synchronized(bootstrapCache) {
                bootstrapCache[key] = addr to (now + BOOTSTRAP_TTL_MS)
            }
            LogManager.d(LogTag.DNS, "bootstrap: $key → ${addr.hostAddress}")
            return addr
        }
        LogManager.w("bootstrap: не удалось определить адрес $key (${if (r is DnsResult.Failed) r.reason else "нет A-записи"})")
        return null
    }

    /** Прозрачная пересылка исходного запроса на тот сервер, который выбрало приложение. */
    fun forwardRaw(query: ByteArray, len: Int, server: InetAddress, port: Int): ByteArray? {
        var socket: DatagramSocket? = null
        return try {
            socket = DatagramSocket()
            protector.protect(socket)
            socket.soTimeout = 4000
            socket.send(DatagramPacket(query, len, server, port))
            val buf = ByteArray(4096)
            val packet = DatagramPacket(buf, buf.size)
            socket.receive(packet)
            buf.copyOf(packet.length)
        } catch (e: Exception) {
            LogManager.d(LogTag.DNS, "forward DNS → $server: ${e.message}")
            null
        } finally {
            socket?.close()
        }
    }

    private fun viaUdp(cfg: AppConfig, name: String, type: Int, servers: List<InetSocketAddress>, label: String): DnsResult {
        if (servers.isEmpty()) return DnsResult.Failed("нет серверов")
        val query = DnsMessage.buildQuery((Math.random() * 65535).toInt() and 0xFFFF, name, type)
        var lastError = "нет ответа"
        for (s in servers) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                protector.protect(socket)
                socket.soTimeout = 3500
                socket.send(DatagramPacket(query, query.size, s.address, s.port))
                val buf = ByteArray(4096)
                val packet = DatagramPacket(buf, buf.size)
                socket.receive(packet)
                val len = packet.length
                val rcode = DnsMessage.rcode(buf, len)
                if (rcode == 3) return DnsResult.Blocked
                if (rcode != 0) { lastError = "rcode=$rcode"; continue }
                val addrs = DnsMessage.parseAddresses(buf, len)
                if (addrs.isNotEmpty()) {
                    LogManager.d(LogTag.DNS, "$label DNS: $name → ${addrs.size} адресов")
                    return DnsResult.Addresses(addrs, cfg.dnsCacheTtlSec.coerceAtLeast(30))
                }
                lastError = "пустой ответ"
            } catch (e: Exception) {
                lastError = e.message ?: e.javaClass.simpleName
            } finally {
                socket?.close()
            }
        }
        return DnsResult.Failed(lastError)
    }

    private fun viaDoh(cfg: AppConfig, name: String, type: Int): DnsResult {
        val url = cfg.dohUrl.trim()
        if (url.isEmpty()) return DnsResult.Failed("не задан URL DoH")
        var channel = dohChannel
        if (channel == null || dohUrlInUse != url) {
            channel?.close()
            channel = DohChannel(url)
            dohChannel = channel
            dohUrlInUse = url
        }
        val typeName = if (type == DnsType.AAAA) "AAAA" else "A"
        val data = channel.query(name, typeName) ?: return DnsResult.Failed("DoH недоступен")
        val addrs = data.mapNotNull { IpLiterals.parse(it) }
        if (addrs.isEmpty()) return if (data.isEmpty()) DnsResult.Blocked else DnsResult.Failed("DoH: нет адресов")
        return DnsResult.Addresses(addrs, cfg.dnsCacheTtlSec.coerceAtLeast(30))
    }

    private fun viaDot(cfg: AppConfig, name: String, type: Int): DnsResult {
        val host = cfg.dotHost.trim()
        if (host.isEmpty()) return DnsResult.Failed("не задан хост DoT")
        var channel = dotChannel
        if (channel == null || dotHostInUse != host) {
            channel?.close()
            channel = DotChannel(host)
            dotChannel = channel
            dotHostInUse = host
        }
        val addrs = channel.query(name, type)
        if (addrs == null) return DnsResult.Failed("DoT недоступен")
        if (addrs.isEmpty()) return DnsResult.Blocked
        return DnsResult.Addresses(addrs, cfg.dnsCacheTtlSec.coerceAtLeast(30))
    }

    private fun systemServers(): List<InetSocketAddress> =
        systemDnsServers().map { InetSocketAddress(it, 53) }

    fun systemDnsServers(): List<InetAddress> {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return FALLBACK_SERVERS.map { it.first }
        val networks = try {
            cm.allNetworks
        } catch (e: Exception) {
            return FALLBACK_SERVERS.map { it.first }
        }
        for (n in networks) {
            val caps = try {
                cm.getNetworkCapabilities(n)
            } catch (e: Exception) {
                null
            } ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            val lp = try {
                cm.getLinkProperties(n)
            } catch (e: Exception) {
                null
            } ?: continue
            val dns = lp.dnsServers
            if (dns != null && dns.isNotEmpty()) return dns
        }
        return FALLBACK_SERVERS.map { it.first }
    }

    private fun configuredServers(cfg: AppConfig): List<InetSocketAddress> {
        val out = ArrayList<InetSocketAddress>()
        for (line in cfg.dnsServers.lineSequence()) {
            val t = line.trim()
            if (t.isEmpty() || t.startsWith("#")) continue
            val hp = IpLiterals.parseHostPort(t, 53) ?: continue
            val addr = IpLiterals.parse(hp.first) ?: continue
            out += InetSocketAddress(addr, hp.second)
        }
        if (out.isEmpty()) return FALLBACK_SERVERS.map { InetSocketAddress(it.first, it.second) }
        return out
    }

    /** Пересылка «сырого» DNS-запроса на первый доступный сервер (для неадресных типов). */
    fun forwardQueryBytes(query: ByteArray, len: Int): ByteArray? {
        val cfg = configProvider()
        val servers = if (cfg.dnsMode == DnsMode.CUSTOM) configuredServers(cfg) else systemServers()
        for (s in servers) {
            val r = forwardRaw(query, len, s.address, s.port)
            if (r != null) return r
        }
        return null
    }

    fun clearCache() {
        synchronized(cache) { cache.clear() }
    }

    fun close() {
        dohChannel?.close(); dohChannel = null
        dotChannel?.close(); dotChannel = null
    }

    private companion object {
        const val BOOTSTRAP_TTL_MS = 10 * 60 * 1000L
        const val CONNECT_TIMEOUT_MS = 6000
        const val READ_TIMEOUT_MS = 6000

        /**
         * Адреса крупнейших публичных DoH/DoT-серверов. Они десятилетиями не
         * меняются и позволяют поднять защищённый канал вообще без единого
         * DNS-запроса — важно для первого запуска и для сетей, где DNS уже
         * сломан. Всё остальное доопределяется через bootstrap-запрос.
         */
        val WELL_KNOWN: Map<String, String> = mapOf(
            "dns.google" to "8.8.8.8",
            "dns.google.com" to "8.8.8.8",
            "8.8.8.8" to "8.8.8.8",
            "one.one.one.one" to "1.1.1.1",
            "cloudflare-dns.com" to "1.1.1.1",
            "1.1.1.1" to "1.1.1.1",
            "dns.quad9.net" to "9.9.9.9",
            "9.9.9.9" to "9.9.9.9"
        )

        val FALLBACK_SERVERS: List<Pair<InetAddress, Int>> = listOfNotNull(
            IpLiterals.parse("1.1.1.1")?.let { it to 53 },
            IpLiterals.parse("8.8.8.8")?.let { it to 53 }
        )

        fun HostsTableIsBlock(addrs: List<InetAddress>): Boolean =
            addrs.isNotEmpty() && addrs.all { a -> a.address.all { it == 0.toByte() } }
    }

    /* ---------------------------------------------------------------- */
    /*  DNS-over-HTTPS (JSON API)                                        */
    /* ---------------------------------------------------------------- */

    private inner class DohChannel(url: String) {
        private var host: String = ""
        private var port: Int = 443
        private var path: String = "/resolve"
        private var socket: SSLSocket? = null
        private var input: InputStream? = null
        private var output: OutputStream? = null
        private var keepAlive = true

        init {
            var u = url.trim()
            if (!u.startsWith("https://", true)) u = "https://$u"
            val rest = u.substring("https://".length)
            val slash = rest.indexOf('/')
            val hostPart = if (slash >= 0) rest.substring(0, slash) else rest
            path = if (slash >= 0) rest.substring(slash) else "/resolve"
            if (path.contains('?')) path = path.substringBefore('?')
            val hp = IpLiterals.parseHostPort(hostPart, 443)
            host = hp?.first ?: hostPart
            port = hp?.second ?: 443
        }

        @Synchronized
        fun query(name: String, type: String): List<String>? {
            return try {
                if (socket == null) connect()
                doQuery(name, type)
            } catch (e: Exception) {
                LogManager.d(LogTag.DNS, "DoH: ${e.message}")
                try {
                    reconnect()
                    doQuery(name, type)
                } catch (e2: Exception) {
                    close()
                    null
                }
            }
        }

        private fun reconnect() {
            closeSocket()
            connect()
        }

        private fun connect() {
            val addr = bootstrapResolve(host)
                ?: throw IOException("адрес DoH-сервера $host не определён")
            val s = SSLSocketFactory.getDefault().createSocket() as SSLSocket
            protector.protect(s)
            // Подключаемся к литеральному адресу: иначе getByName ушёл бы в наш же туннель.
            s.connect(InetSocketAddress(addr, port), CONNECT_TIMEOUT_MS)
            s.soTimeout = READ_TIMEOUT_MS
            s.tcpNoDelay = true
            applySni(s, host)
            s.startHandshake()
            verifyHost(s, host)
            socket = s
            input = BufferedInputStream(s.inputStream, 8192)
            output = s.outputStream
            keepAlive = true
            LogManager.d(LogTag.DNS, "DoH: канал к $host (${addr.hostAddress}) установлен")
        }

        private fun doQuery(name: String, type: String): List<String>? {
            val out = output ?: return null
            val inp = input ?: return null
            val request = "GET " + path + "?name=" + urlEncode(name) + "&type=" + type + " HTTP/1.1\r\n" +
                "Host: " + host + "\r\n" +
                "Accept: application/dns-json\r\n" +
                "User-Agent: Zapret-Android/1.0\r\n" +
                "Connection: keep-alive\r\n\r\n"
            out.write(request.toByteArray(Charsets.US_ASCII))
            out.flush()

            val status = readLine(inp) ?: return null
            val code = status.split(' ').getOrNull(1)?.toIntOrNull() ?: -1
            val headers = HashMap<String, String>()
            while (true) {
                val line = readLine(inp) ?: break
                if (line.isEmpty()) break
                val c = line.indexOf(':')
                if (c > 0) headers[line.substring(0, c).trim().lowercase()] = line.substring(c + 1).trim()
            }
            if (code != 200) return null

            val body: ByteArray = when {
                headers["content-length"]?.toIntOrNull() != null -> {
                    readFixed(inp, headers["content-length"]!!.toInt()) ?: return null
                }
                headers["transfer-encoding"]?.contains("chunked", true) == true -> readChunked(inp)
                else -> {
                    keepAlive = false
                    readAll(inp)
                }
            }
            return parseJson(String(body, Charsets.UTF_8), name, type)
        }

        private fun parseJson(json: String, name: String, type: String): List<String>? {
            return try {
                val o = JSONObject(json)
                val status = o.optInt("Status", 0)
                if (status == 3) return emptyList()
                if (status != 0) return null
                val answers = o.optJSONArray("Answer") ?: return emptyList()
                val wanted = if (type == "AAAA") 28 else 1
                val out = ArrayList<String>()
                var cname: String? = null
                for (i in 0 until answers.length()) {
                    val item = answers.optJSONObject(i) ?: continue
                    val t = item.optInt("type")
                    val d = item.optString("data")
                    if (t == wanted && d.isNotEmpty()) out += d
                    else if (t == 5 && d.isNotEmpty()) cname = d.trimEnd('.')
                }
                if (out.isEmpty() && cname != null && cname != name) {
                    val nested = doQuery(cname, type)
                    if (nested != null) out += nested
                }
                out
            } catch (e: Exception) {
                null
            }
        }

        @Synchronized
        fun close() {
            closeSocket()
        }

        private fun closeSocket() {
            try { socket?.close() } catch (_: Exception) {}
            socket = null; input = null; output = null
        }

        private fun urlEncode(s: String): String =
            s.replace("%", "%25").replace("&", "%26").replace("=", "%3D").replace(" ", "%20")
    }

    /* ---------------------------------------------------------------- */
    /*  DNS-over-TLS                                                     */
    /* ---------------------------------------------------------------- */

    private inner class DotChannel(hostSpec: String) {
        private val host: String
        private val port: Int
        private var socket: SSLSocket? = null
        private var input: InputStream? = null
        private var output: OutputStream? = null
        private var nextId = 1

        init {
            val hp = IpLiterals.parseHostPort(hostSpec, 853)
            host = hp?.first ?: hostSpec
            port = hp?.second ?: 853
        }

        @Synchronized
        fun query(name: String, type: Int): List<InetAddress>? {
            try {
                if (socket == null) connect()
                return doQuery(name, type)
            } catch (e: Exception) {
                LogManager.d(LogTag.DNS, "DoT: ${e.message}")
                closeSocket()
                try {
                    connect()
                    return doQuery(name, type)
                } catch (e2: Exception) {
                    closeSocket()
                    return null
                }
            }
        }

        private fun connect() {
            val addr = bootstrapResolve(host)
                ?: throw IOException("адрес DoT-сервера $host не определён")
            val s = SSLSocketFactory.getDefault().createSocket() as SSLSocket
            protector.protect(s)
            s.connect(InetSocketAddress(addr, port), CONNECT_TIMEOUT_MS)
            s.soTimeout = READ_TIMEOUT_MS
            s.tcpNoDelay = true
            applySni(s, host)
            s.startHandshake()
            verifyHost(s, host)
            socket = s
            input = BufferedInputStream(s.inputStream, 4096)
            output = s.outputStream
            LogManager.d(LogTag.DNS, "DoT: канал к $host (${addr.hostAddress}) установлен")
        }

        private fun doQuery(name: String, type: Int): List<InetAddress>? {
            val out = output ?: return null
            val inp = input ?: return null
            val id = (nextId++ and 0xFFFF)
            val msg = DnsMessage.buildQuery(id, name, type)
            out.write((msg.size ushr 8) and 0xFF)
            out.write(msg.size and 0xFF)
            out.write(msg)
            out.flush()

            val hi = inp.read(); if (hi < 0) return null
            val lo = inp.read(); if (lo < 0) return null
            val len = (hi shl 8) or lo
            if (len <= 0 || len > 8192) return null
            val resp = readFixed(inp, len) ?: return null
            val rcode = DnsMessage.rcode(resp, resp.size)
            if (rcode == 3) return emptyList()
            if (rcode != 0) return null
            return DnsMessage.parseAddresses(resp, resp.size)
        }

        @Synchronized
        fun close() = closeSocket()

        private fun closeSocket() {
            try { socket?.close() } catch (_: Exception) {}
            socket = null; input = null; output = null
        }
    }

    /* ---------------------------------------------------------------- */
    /*  Общие вспомогательные функции                                    */
    /* ---------------------------------------------------------------- */

    /**
     * SNI выставляется вручную. Сокет подключён к IP-адресу, поэтому сам он
     * имени сервера не знает, а без SNI Google/Cloudflare отдают сертификат не
     * того виртуального хоста и соединение рвётся.
     */
    private fun applySni(socket: SSLSocket, host: String) {
        try {
            val params = socket.sslParameters
            params.serverNames = listOf<SNIServerName>(SNIHostName(host))
            // Штатную проверку имени НЕ включаем: она сверяется с peerHost, а там
            // у нас IP — рукопожатие падало бы даже с совершенно правильным
            // сертификатом. Проверяем сами в [verifyHost] после рукопожатия.
            params.endpointIdentificationAlgorithm = null
            socket.sslParameters = params
        } catch (e: Exception) {
            LogManager.d(LogTag.DNS, "SNI для $host не выставлен: ${e.message}")
        }
    }

    /** Проверка имени хоста по сертификату после рукопожатия. */
    private fun verifyHost(socket: SSLSocket, host: String) {
        val verifier = HttpsURLConnection.getDefaultHostnameVerifier()
        if (!verifier.verify(host, socket.session)) {
            throw IOException("сертификат $host не прошёл проверку имени")
        }
    }

    private fun readLine(inp: InputStream): String? {
        val buf = ByteArrayOutputStream(64)
        while (true) {
            val b = inp.read()
            if (b < 0) return if (buf.size() == 0) null else buf.toString("UTF-8")
            if (b == '\n'.code) break
            if (b != '\r'.code) buf.write(b)
            if (buf.size() > 8192) break
        }
        return buf.toString("UTF-8")
    }

    private fun readFixed(inp: InputStream, len: Int): ByteArray? {
        val out = ByteArray(len)
        var off = 0
        while (off < len) {
            val n = inp.read(out, off, len - off)
            if (n < 0) return null
            off += n
        }
        return out
    }

    private fun readChunked(inp: InputStream): ByteArray {
        val out = ByteArrayOutputStream(512)
        while (true) {
            val line = readLine(inp) ?: break
            val sizeHex = line.substringBefore(';').trim()
            val size = try {
                Integer.parseInt(sizeHex, 16)
            } catch (e: Exception) {
                break
            }
            if (size <= 0) {
                readLine(inp)
                break
            }
            val chunk = readFixed(inp, size) ?: break
            out.write(chunk)
            readLine(inp) // завершающий CRLF
            if (out.size() > 256 * 1024) break
        }
        return out.toByteArray()
    }

    private fun readAll(inp: InputStream): ByteArray {
        val out = ByteArrayOutputStream(512)
        val buf = ByteArray(2048)
        while (true) {
            val n = try {
                inp.read(buf)
            } catch (e: Exception) {
                -1
            }
            if (n <= 0) break
            out.write(buf, 0, n)
            if (out.size() > 256 * 1024) break
        }
        return out.toByteArray()
    }
}

/** Простая проверка доступности резолвера из UI. */
suspend fun testResolver(resolver: DnsResolver, host: String = "www.google.com"): String {
    val r = resolver.lookup(host, DnsType.A)
    return when (r) {
        is DnsResult.Addresses -> r.list.joinToString(", ") { it.hostAddress ?: "?" }
        is DnsResult.Blocked -> "заблокировано"
        is DnsResult.Failed -> r.reason
    }
}
