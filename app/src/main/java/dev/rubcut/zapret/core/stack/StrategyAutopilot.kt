package dev.rubcut.zapret.core.stack

import dev.rubcut.zapret.core.LogManager
import dev.rubcut.zapret.core.LogTag
import dev.rubcut.zapret.core.net.PacketBuilder
import dev.rubcut.zapret.core.net.TcpFlag
import dev.rubcut.zapret.core.net.parseIp
import dev.rubcut.zapret.core.net.parseTcp
import dev.rubcut.zapret.data.DesyncMode
import dev.rubcut.zapret.data.SplitPos
import dev.rubcut.zapret.data.Strategy
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeoutOrNull
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random

/** Результат подбора: человекочитаемое имя, сама стратегия и счёт проверок. */
data class TuneResult(val name: String, val strategy: Strategy, val ok: Int, val total: Int)

/**
 * Автоподбор стратегии обхода.
 *
 * Стратегий много, и «правильная» зависит от конкретного DPI на пути. Подбор
 * работает честно: через собственный TCP-стек прогоняется НАСТОЯЩИЙ TLS
 * ClientHello с SNI проверяемого хоста, к первым байтам применяются
 * кандидаты-стратегии, а успехом считается приход ServerHello (0x16) от
 * сервера. Всё происходит внутри туннеля, поэтому проверяется ровно тот путь,
 * по которому потом пойдёт трафик приложений.
 *
 * Пассивный кандидат идёт первым: если DPI не блокирует без обработки, лучше
 * не обрабатывать вовсе — это быстрее и надёжнее.
 */
class StrategyAutopilot(private val stack: TcpStack) {

    private val portCounter = AtomicInteger(45000)

    companion object {
        val CANDIDATES: List<Pair<String, Strategy>> = listOf(
            "без обработки (прозрачно)" to Strategy(desync = DesyncMode.NONE),

            // Доказанный победитель идёт ПЕРВЫМ среди активных вариантов.
            //
            // Порядок здесь не косметика: подбор останавливается на первом
            // успешном кандидате, а каждый провал стоит полный таймаут (6 с).
            // Стоял девятым — проверенный вариант находился только после восьми
            // заведомо бесполезных попыток.
            //
            // Замеры чужого приложения (ZapretYT 1.0.7) на том же провайдере,
            // где наш профиль не проходил, 18 замеров каждого варианта:
            //
            //   TLS-записи + разбиение   18/18 ·  379 мс · 1,8 МБ/с → 1177 мс
            //   ByeDPI 19                18/18 ·  383 мс · 1011 КБ/с → 1629 мс
            //   OOB по слову             18/18 ·  431 мс · 1,0 МБ/с → 2055 мс
            //   ByeDPI 28                18/18 ·  953 мс → 1516 мс
            //
            // То есть побеждает не ByeDPI, а переупаковка ClientHello в
            // несколько TLS-записей вместе с разрывом потока. Это и самый
            // быстрый вариант, и с наибольшей пропускной способностью, и он
            // не опирается на намеренно некорректные handshake-ы, на которых
            // фильтры учатся учиться. Варианты ByeDPI в РФ сейчас отмирают.
            "multisplit · tlsrec + середина домена (0+wm)" to Strategy(
                desync = DesyncMode.MULTISPLIT_TLSREC,
                splitPositions = listOf(SplitPos.MIDSNI),
                splitDelayMs = 2,
                tlsrecParts = 2
            ),

            // Смена регистра в имени хоста: обходит фильтры, которые полностью
            // пересобирают сегменты, где разбиение не помогает вовсе. На других
            // сетях это единственная рабочая стратегия, поэтому из подбора её
            // не убираем — просто проверяем позже доказанного варианта.
            //
            // Порядок внутри — по замерам на реальном фильтре, 6 кругов:
            //
            //   смена регистра, одним куском            6 из 6
            //   смена регистра + разбиение по 1 байту   6 из 6
            //   смена регистра + 1,midsld               5 из 6
            //   смена регистра + разбиение по midsld     0 из 6
            //
            // То есть разбиение внутри самого домена приём портит: разрыв
            // попадает ровно в ту строку, которую приём и ломает, и фильтр
            // получает её обратно склеенной.
            "смена регистра, без разбиения" to Strategy(
                desync = DesyncMode.NONE,
                sniCaseMix = true
            ),
            "смена регистра + первый байт" to Strategy(
                desync = DesyncMode.MULTISPLIT,
                splitPositions = listOf(SplitPos.FIRST),
                splitDelayMs = 2,
                sniCaseMix = true
            ),
            // Комбинация с midsld и сменой регистра — худшая по замерам (5 из 6),
            // поэтому уходит в самый конец списка.
            "смена регистра + первый байт + середина домена" to Strategy(
                desync = DesyncMode.MULTISPLIT,
                splitPositions = listOf(SplitPos.FIRST, SplitPos.MIDSNI),
                splitDelayMs = 2,
                sniCaseMix = true
            ),

            // Комбинация FIRST + MIDSNI без смены регистра: на фильтрах, которые
            // смотрят только на первые сегменты, разбиения достаточно, а смена
            // регистра там не нужна и может навредить строгим CDN.
            "multisplit · первый байт + середина домена" to Strategy(
                desync = DesyncMode.MULTISPLIT,
                splitPositions = listOf(SplitPos.FIRST, SplitPos.MIDSNI),
                splitDelayMs = 2
            ),
            "tlsrec · две части" to Strategy(desync = DesyncMode.TLSREC, tlsrecParts = 2),
            "multisplit · первый байт + середина домена + задержка 40 мс" to Strategy(
                desync = DesyncMode.MULTISPLIT,
                splitPositions = listOf(SplitPos.FIRST, SplitPos.MIDSNI),
                splitDelayMs = 40
            ),
            "multisplit · первый байт" to Strategy(desync = DesyncMode.MULTISPLIT, splitPositions = listOf(SplitPos.FIRST)),
            "multisplit · середина домена" to Strategy(
                desync = DesyncMode.MULTISPLIT,
                splitPositions = listOf(SplitPos.MIDSNI)
            ),
            "split · середина домена" to Strategy(desync = DesyncMode.SPLIT, splitPositions = listOf(SplitPos.MIDSNI)),
            // Точка SNIEND в одиночку бесполезна: если SNI заканчивается последним байтом
            // приветствия (а у минимальных ClientHello так и есть), разбивать
            // просто нечего и получается один фрагмент. Поэтому в паре с FIRST.
            "multisplit · первый байт + конец SNI" to Strategy(
                desync = DesyncMode.MULTISPLIT,
                splitPositions = listOf(SplitPos.FIRST, SplitPos.SNIEND)
            )
        )

            /**
             * Минимальный TLS ClientHello с SNI. Вынесен в компаньон: его же
             * проверяет JVM-тест — если наш парсер не найдёт здесь SNI, то и
             * split по «середине SNI» работать не будет.
             *
             * Содержимое подобрано так, чтобы СЕРВЕР действительно ответил
             * ServerHello, а не alert. Это главное требование к зонду: раньше
             * здесь предлагался единственный набор шифров TLS 1.3 (0x1301) при
             * legacy_version = TLS 1.2 и вовсе без supported_versions. Сервер
             * обязан был выбрать TLS 1.2, где такого шифра не существует, и
             * отвечал `handshake_failure` (alert 40) — зонд всегда считал
             * стратегию нерабочей, и автоподбор с самоисцелением были мертвы.
             *
             * Поэтому: legacy_version = TLS 1.2, расширения supported_versions
             * нет, а набор шифров — только TLS 1.2, который принимает абсолютно
             * любой сервер. Проверено на google/youtube/fastly/cloudflare.
             */
            fun clientHelloFor(host: String): ByteArray {
                val name = host.toByteArray(Charsets.US_ASCII)
                val ext = ByteArrayOutputStream()
                // server_name: тело расширения — [2] длина ServerNameList, затем
                // запись [1] name_type, [2] длина имени, [n] имя.
                writeExt(ext, 0x0000) {
                    val entry = 1 + 2 + name.size
                    val b = ByteArrayOutputStream()
                    putU16Buf(b, entry)
                    b.write(0)
                    putU16Buf(b, name.size)
                    b.write(name)
                    b.toByteArray()
                }
                // ec_point_formats: uncompressed — иначе сервер не возьмёт ECDHE
                writeExt(ext, 0x000B) { byteArrayOf(2, 1, 0) }
                // supported_groups — без него нет общих групп для ECDHE
                writeExt(ext, 0x000A) {
                    val groups = intArrayOf(0x001D, 0x0017, 0x0018)
                    val b = ByteArrayOutputStream()
                    putU16Buf(b, groups.size * 2)
                    for (g in groups) putU16Buf(b, g)
                    b.toByteArray()
                }
                // signature_algorithms — без него нет пары для подписи
                writeExt(ext, 0x000D) {
                    val sigs = intArrayOf(
                        0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
                        0x0401, 0x0501, 0x0201
                    )
                    val b = ByteArrayOutputStream()
                    putU16Buf(b, sigs.size * 2)
                    for (s in sigs) putU16Buf(b, s)
                    b.toByteArray()
                }
                // ALPN: h2 + http/1.1. Его отсутствие выдаёт синтетику — 99%
                // реальных клиентов его шлют. Фильтр с отпечатками (JA3) режет
                // такие hello молча, и автоподбор тогда видит «не работает
                // ничего», хотя настоящему трафику отвечает.
                writeExt(ext, 0x0010) {
                    val inner = ByteArrayOutputStream()
                    for (p in listOf("h2", "http/1.1")) {
                        val pb = p.toByteArray(Charsets.US_ASCII)
                        inner.write(pb.size)
                        inner.write(pb)
                    }
                    val ib = inner.toByteArray()
                    val b = ByteArrayOutputStream()
                    putU16Buf(b, ib.size)
                    b.write(ib)
                    b.toByteArray()
                }
                // supported_versions: TLS 1.3 + 1.2. Шифры только из 1.2,
                // поэтому сервер выберет 1.2 — противоречия нет, а отпечаток
                // как у браузера.
                writeExt(ext, 0x002B) {
                    val b = ByteArrayOutputStream()
                    b.write(4)
                    putU16Buf(b, 0x0304)
                    putU16Buf(b, 0x0303)
                    b.toByteArray()
                }
                // GREASE: «мусорное» расширение нулевой длины, как у Chrome.
                writeExt(ext, 0x0A0A) { ByteArray(0) }

                val body = ByteArrayOutputStream()
                body.write(3); body.write(3)                                // legacy_version = TLS 1.2
                body.write(ByteArray(32) { 7 })                             // random
                body.write(0)                                               // session id
                val suites = intArrayOf(
                    0xC02F, // ECDHE_RSA_AES128_GCM_SHA256
                    0xC030, // ECDHE_RSA_AES256_GCM_SHA384
                    0xC02B, // ECDHE_ECDSA_AES128_GCM_SHA256
                    0xC02C, // ECDHE_ECDSA_AES256_GCM_SHA384
                    0x009C, // RSA_AES128_GCM_SHA256
                    0x009D, // RSA_AES256_GCM_SHA384
                    0x002F, // RSA_AES128_CBC_SHA
                    0x0035  // RSA_AES256_CBC_SHA
                )
                putU16Buf(body, suites.size * 2)
                for (s in suites) putU16Buf(body, s)
                body.write(1); body.write(0)                                // compression
                putU16Buf(body, ext.size())
                body.write(ext.toByteArray())
                val bodyBytes = body.toByteArray()

                val hs = ByteArrayOutputStream()
                hs.write(1)                                                 // client_hello
                hs.write((bodyBytes.size ushr 16) and 0xFF)
                hs.write((bodyBytes.size ushr 8) and 0xFF)
                hs.write(bodyBytes.size and 0xFF)
                hs.write(bodyBytes)
                val hsBytes = hs.toByteArray()

                val rec = ByteArrayOutputStream()
                rec.write(0x16); rec.write(3); rec.write(1)
                putU16Buf(rec, hsBytes.size)
                rec.write(hsBytes)
                return rec.toByteArray()
            }

            private fun writeExt(out: ByteArrayOutputStream, type: Int, body: () -> ByteArray) {
                val b = body()
                putU16Buf(out, type)
                putU16Buf(out, b.size)
                out.write(b)
            }

            private fun putU16Buf(out: ByteArrayOutputStream, v: Int) {
                out.write((v ushr 8) and 0xFF)
                out.write(v and 0xFF)
            }
    }

    /**
     * Перебирает кандидатов на [hosts] и возвращает лучшего. null — не подошёл
     * никто (например, хосты вообще недоступны).
     *
     * Кандидат считается победителем, только если прошёл ВСЕ хосты. Раньше
     * проверка шла по набору целиком, из-за чего подбор для YouTube не давал
     * ничего: YouTube блокируется, Discord — нет, и ни один кандидат не
     * набирал 2 из 2, поэтому лучший результат отбрасывался.
     *
     * Поэтому хосты проверяются по одному: для каждого ищется свой победитель,
     * и стратегии собираются в правила с конкретными доменами. Так обход
     * настраивается отдельно под YouTube и отдельно под Discord.
     */
    suspend fun tune(
        hosts: List<String>,
        perHostTimeoutMs: Long = 6000,
        lookup: suspend (String) -> InetAddress?
    ): TuneResult? {
        var best: TuneResult? = null
        for ((name, strategy) in CANDIDATES) {
            var ok = 0
            for (host in hosts) {
                val addr = withTimeoutOrNull(5000) { lookup(host) } ?: continue
                if (probe(addr, 443, host, strategy, perHostTimeoutMs)) ok++
            }
            LogManager.i(LogTag.DPI, "Автоподбор: $name → $ok/${hosts.size}")
            if (ok == hosts.size && hosts.isNotEmpty()) return TuneResult(name, strategy, ok, hosts.size)
            if (ok > 0 && (best == null || ok > best.ok)) best = TuneResult(name, strategy, ok, hosts.size)
        }
        return best
    }

    /**
     * Подбор отдельно для каждого хоста.
     *
     * Возвращает стратегию для каждого хоста, для которого нашёлся хоть один
     * рабочий кандидат. Это то, что нужно, когда хосты блокируются по-разному:
     * один общий кандидат на всех либо не подходит никому, либо ломает тех,
     * кто и так работает.
     *
     * @return карта «хост → имя победившего кандидата» и его стратегия.
     */
    suspend fun tunePerHost(
        hosts: List<String>,
        perHostTimeoutMs: Long = 6000,
        lookup: suspend (String) -> InetAddress?,
        onProgress: (String) -> Unit = {}
    ): Map<String, Pair<String, Strategy>> {
        val out = LinkedHashMap<String, Pair<String, Strategy>>()
        val total = CANDIDATES.size
        for (host in hosts) {
            onProgress("$host: разрешаю имя…")
            val addr = withTimeoutOrNull(5000) { lookup(host) }
            if (addr == null) {
                onProgress("$host: имя не разрешилось, пропускаю")
                LogManager.w("DPI: автоподбор: $host не разрешился")
                continue
            }
            for ((index, candidate) in CANDIDATES.withIndex()) {
                val (name, strategy) = candidate
                onProgress("$host · ${index + 1}/$total · $name")
                LogManager.d(LogTag.DPI, "Автоподбор: $host, ${index + 1}/$total · $name")
                if (probe(addr, 443, host, strategy, perHostTimeoutMs)) {
                    out[host] = name to strategy
                    onProgress("$host: подошло «$name»")
                    LogManager.i(LogTag.DPI, "Автоподбор: $host → подошло «$name»")
                    break
                }
            }
            if (!out.containsKey(host)) {
                onProgress("$host: ни один кандидат не подошёл")
                LogManager.w("DPI: автоподбор: для $host не подошёл ни один кандидат")
            }
        }
        return out
    }

    /** Одна проверка: полный рукопожатный цикл через стек с принудительной стратегией. */
    suspend fun probe(
        addr: InetAddress,
        port: Int,
        host: String,
        strategy: Strategy,
        timeoutMs: Long = 6000
    ): Boolean = withTimeoutOrNull(timeoutMs) {
        // Эфемерные порты, а не весь диапазон: младшие (<1024) привилегированы,
        // а 0 и вовсе недопустим как порт источника.
        val clientPort = 32768 + (portCounter.incrementAndGet() % 28232)
        val clientIsn = Random.nextInt()
        val captured = Channel<ByteArray>(Channel.UNLIMITED)
        val tap: (ByteArray) -> Unit = { p -> captured.trySend(p) }
        var result = false
        stack.packetWriter.tap = tap
        stack.probeFor = clientPort to strategy
        try {
            val syn = clientTcp(addr, clientPort, port, clientIsn, 0, TcpFlag.SYN, options = synOptions())
            feed(syn)

            val synAck = receive(captured, 4000) { p ->
                val ip = parseIp(p, p.size) ?: return@receive false
                val seg = parseTcp(p, ip.payloadOffset, ip.payloadLength) ?: return@receive false
                seg.isSynAck && seg.dstPort == clientPort
            } ?: run {
                // Молчание на этом этапе — не DPI, а мёртвый IP или сеть:
                // до отправки ClientHello дело вообще не дошло.
                LogManager.d(LogTag.DPI, "зонд $host:${port} «${strategyLabel(strategy)}» → нет SYN-ACK за 4 с")
                return@withTimeoutOrNull false
            }
            val saIp = parseIp(synAck, synAck.size)!!
            val sa = parseTcp(synAck, saIp.payloadOffset, saIp.payloadLength)!!
            val serverIsn = sa.seq

            feed(clientTcp(addr, clientPort, port, clientIsn + 1, serverIsn + 1, TcpFlag.ACK))
            val hello = clientHelloFor(host)
            feed(
                clientTcp(
                    addr, clientPort, port, clientIsn + 1, serverIsn + 1,
                    TcpFlag.ACK or TcpFlag.PSH, payload = hello
                )
            )

            // Внутренний таймаут приёма ОБЯЗАН быть короче внешнего: при глухом
            // фильтре (SYN-ACK есть, ответа нет) иначе первым срабатывает
            // внешний withTimeoutOrNull, и зонд умирает молча — строка
            // диагностики ниже недостижима в принципе. Именно так пропали все
            // строки зонда из журналов: каждый кандидат упирался в стену 6 с.
            // Запас 2 с — на установку соединения и отправку hello.
            val down = receive(captured, (timeoutMs - 2000).coerceAtLeast(2000)) { p ->
                val ip = parseIp(p, p.size) ?: return@receive false
                val seg = parseTcp(p, ip.payloadOffset, ip.payloadLength) ?: return@receive false
                seg.dstPort == clientPort && !seg.isSynAck && seg.payloadLength > 0
            } ?: run {
                // SYN-ACK был, а ответа на ClientHello нет — вот это уже
                // почерк DPI: рукопожатие дошло до сервера, дальше тишина.
                LogManager.d(LogTag.DPI, "зонд $host:${port} «${strategyLabel(strategy)}» → SYN-ACK есть, ответа на ClientHello нет")
                return@withTimeoutOrNull false
            }

            val ip = parseIp(down, down.size)!!
            val seg = parseTcp(down, ip.payloadOffset, ip.payloadLength)!!
            val first = down[ip.payloadOffset + seg.headerLen].toInt() and 0xFF
            // 0x16 — TLS Handshake: сервер дошёл до ответа на ClientHello.
            // 0x15 (alert) и мусор означают, что обход не сработал.
            result = first == 0x16
            LogManager.d(
                LogTag.DPI,
                "зонд $host:${port} «${strategyLabel(strategy)}» → ответ 0x%02x (%s)".format(
                    first,
                    if (result) "ServerHello" else "отказ сервера или обхода"
                )
            )
        } finally {
            stack.probeFor = null
            stack.packetWriter.tap = null
            runCatching {
                feed(
                    clientTcp(addr, clientPort, port, clientIsn + 1, 0, TcpFlag.RST)
                )
            }
        }
        result
    } ?: false

    /* ------------------------------------------------------------ */

    /** Человекочитаемое имя стратегии для журнала. */
    private fun strategyLabel(s: Strategy): String = buildString {
        append(s.desync.token)
        if (s.splitPositions.isNotEmpty()) {
            append(' ').append(s.splitPositions.joinToString(",") { it.token })
        }
        if (s.splitDelayMs > 0) append(" +${s.splitDelayMs}мс")
        if (s.tlsrecParts > 0) append(" tlsrec=${s.tlsrecParts}")
    }

    private suspend fun receive(ch: Channel<ByteArray>, timeoutMs: Long, pred: (ByteArray) -> Boolean): ByteArray? =
        withTimeoutOrNull(timeoutMs) {
            while (true) {
                val p = ch.receive()
                if (pred(p)) return@withTimeoutOrNull p
            }
            @Suppress("UNREACHABLE_CODE")
            null
        }

    private fun feed(packet: ByteArray) {
        val ip = parseIp(packet, packet.size) ?: return
        val seg = parseTcp(packet, ip.payloadOffset, ip.payloadLength) ?: return
        stack.onPacket(ip, seg)
    }

    private val probeSource = InetAddress.getByName("10.9.0.9")

    private fun synOptions(): ByteArray {
        val b = ByteArrayOutputStream()
        b.write(byteArrayOf(2, 4, 5, 188.toByte()))
        b.write(byteArrayOf(3, 3, 7))
        b.write(byteArrayOf(4, 2))
        b.write(1)
        return b.toByteArray()
    }

    private fun clientTcp(
        dst: InetAddress,
        srcPort: Int,
        dstPort: Int,
        seq: Int,
        ack: Int,
        flags: Int,
        options: ByteArray? = null,
        payload: ByteArray = ByteArray(0)
    ): ByteArray {
        val tcpHeaderLen = 20 + (options?.size ?: 0)
        val total = 20 + tcpHeaderLen + payload.size
        val p = ByteArrayOutputStream()
        p.write(0x45); p.write(0)
        p.write((total ushr 8) and 0xFF); p.write(total and 0xFF)
        p.write(0); p.write(0); p.write(0x40); p.write(0)
        p.write(64); p.write(6); p.write(0); p.write(0)
        p.write(probeSource.address)
        p.write(dst.address)
        p.write((srcPort ushr 8) and 0xFF); p.write(srcPort and 0xFF)
        p.write((dstPort ushr 8) and 0xFF); p.write(dstPort and 0xFF)
        p.write(seq ushr 24 and 0xFF); p.write(seq ushr 16 and 0xFF); p.write(seq ushr 8 and 0xFF); p.write(seq and 0xFF)
        p.write(ack ushr 24 and 0xFF); p.write(ack ushr 16 and 0xFF); p.write(ack ushr 8 and 0xFF); p.write(ack and 0xFF)
        p.write(((tcpHeaderLen / 4) shl 4) and 0xF0)
        p.write(flags and 0xFF)
        p.write(65535 ushr 8 and 0xFF); p.write(65535 and 0xFF)
        p.write(0); p.write(0); p.write(0); p.write(0)
        if (options != null) p.write(options)
        p.write(payload)
        val bytes = p.toByteArray()
        val segment = bytes.copyOfRange(20, bytes.size)
        val cs = checksum(probeSource, dst, 6, segment)
        bytes[36] = (cs ushr 8 and 0xFF).toByte()
        bytes[37] = (cs and 0xFF).toByte()
        return bytes
    }

    private fun checksum(src: InetAddress, dst: InetAddress, proto: Int, segment: ByteArray): Int {
        val pseudo = ByteArrayOutputStream()
        pseudo.write(src.address)
        pseudo.write(dst.address)
        pseudo.write(0)
        pseudo.write(proto)
        pseudo.write((segment.size ushr 8) and 0xFF)
        pseudo.write(segment.size and 0xFF)
        val all = pseudo.toByteArray() + segment
        var sum = 0L
        var i = 0
        while (i + 1 < all.size) {
            sum += ((all[i].toInt() and 0xFF) shl 8) or (all[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < all.size) sum += (all[i].toInt() and 0xFF) shl 8
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

}
