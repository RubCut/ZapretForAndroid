package dev.rubcut.zapret.core.stack

import android.os.SystemClock
import dev.rubcut.zapret.core.LogManager
import dev.rubcut.zapret.core.LogTag
import dev.rubcut.zapret.core.TrafficStats
import dev.rubcut.zapret.core.desync.FlowContext
import dev.rubcut.zapret.core.desync.ReverseHostCache
import dev.rubcut.zapret.core.net.IpHeader
import dev.rubcut.zapret.core.net.PacketBuilder
import dev.rubcut.zapret.core.net.TcpFlag
import dev.rubcut.zapret.core.net.TcpSegment
import dev.rubcut.zapret.core.net.seqAdd
import dev.rubcut.zapret.core.net.seqCompare
import dev.rubcut.zapret.core.proto.Http
import dev.rubcut.zapret.core.proto.Tls
import dev.rubcut.zapret.data.Strategy
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.min
import kotlin.random.Random

/**
 * Одно TCP-соединение внутри туннеля.
 *
 * Для приложения мы играем роль сервера: сами отвечаем на SYN, подтверждаем данные и
 * ретранслируем их при необходимости. Для интернета мы обычный клиент: открываем
 * реальный сокет и полностью управляем тем, какими порциями байты уходят в сеть —
 * именно это и есть точка применения стратегий zapret.
 */
class TcpConnection(
    private val stack: TcpStack,
    val key: TcpKey,
    ip: IpHeader,
    private val syn: TcpSegment
) {

    enum class State { SYN_RCVD, SYN_SENT_UPSTREAM, ESTABLISHED, FIN_WAIT, CLOSED }

    private class Chunk(val seq: Int, val data: ByteArray) {
        val len: Int get() = data.size
    }

    private val cfg get() = stack.config
    private val v6 = ip.v6
    val serverAddr: InetAddress = ip.dst
    val serverPort: Int = syn.dstPort

    /**
     * Куда реально подключаемся. Отличается от [serverAddr] для DNS-трафика поверх TCP:
     * виртуальный адрес туннеля не существует в сети, поэтому подменяем его на резолвер.
     */
    private val upstreamAddr: InetAddress
    val clientAddr: InetAddress = ip.src
    val clientPort: Int = syn.srcPort

    @Volatile
    var state: State = State.SYN_RCVD
        private set

    @Volatile
    private var closed = false

    @Volatile
    var detectedHost: String? = null
        private set

    @Volatile
    var desyncApplied: String? = null
        private set

    private val lock = Any()

    private val clientIsn: Int = syn.seq
    private val ourIsn: Int = Random.nextInt()

    // Читаются из потока насоса, пишутся из потока чтения tun — без volatile
    // компилятор вправе закэшировать значения и отправить клиенту сегмент
    // со старым ack, который он отбросит как дубликат.
    @Volatile
    private var rcvNext: Int = seqAdd(clientIsn, 1)

    @Volatile
    private var sndUna: Int = seqAdd(ourIsn, 1)

    @Volatile
    private var sndNxt: Int = seqAdd(ourIsn, 1)
    private var queueTailSeq: Int = sndNxt

    private val clientUsesTimestamps = syn.hasTimestamp
    private var clientTsVal: Int = syn.tsValue
    private val ourWscale = 7
    private val clientWscale = if (syn.wscale in 0..14) syn.wscale else 0
    private var clientWindow = 65535
    private val mss: Int

    private val unacked = ArrayDeque<Chunk>()
    private var queue = ArrayDeque<Chunk>()
    private var inflight = 0
    private var queuedBytes = 0
    private var dupAcks = 0
    private var rtoMs = 800L
    private var retransmits = 0
    private var lastProgress = SystemClock.elapsedRealtime()
    private var lastActivity = SystemClock.elapsedRealtime()

    private var finFromUpstream = false
    private var finSent = false
    private var finAcked = false
    private var finFromClient = false

    private val inbound = Channel<ByteArray?>(Channel.UNLIMITED)
    private var upstream: Socket? = null
    private var jobs = mutableListOf<Job>()

    private val inboundBytes = AtomicInteger(0)

    /**
     * Мы уже объявили клиенту нулевое окно и ждём, пока он перестанет слать.
     *
     * Пока флаг стоит, насос обязан отправлять обновление окна, иначе клиент
     * остаётся с нулевым окном навсегда: новых сегментов от него не будет, а
     * окно мы пересчитываем только внутри отправляемых пакетов. Восстановление
     * зависело лишь от того, что клиент сам пришлёт zero-window probe, и видео
     * выглядело как «вечная буферизация».
     */
    @Volatile
    private var zeroWindowAdvertised = false

    /** Рекламируемое окно с учётом заполненности входящей очереди. */
    private fun advertiseWindow(): Int {
        val free = INBOUND_LIMIT - inboundBytes.get()
        val value = when {
            free <= 0 -> 0
            free < 64 * 1024 -> ((free shr ourWscale) + 1).coerceIn(1, WINDOW_FIELD)
            else -> WINDOW_FIELD
        }
        if (value == 0) zeroWindowAdvertised = true
        return value
    }

    /**
     * Обновить окно, если раньше оно было нулевым, а очередь уже разгружена.
     *
     * Отправляется ровно один сегмент с чистым ACK — этого достаточно, чтобы
     * клиент продолжил передачу.
     */
    private fun releaseZeroWindow() {
        if (!zeroWindowAdvertised) return
        if (inboundBytes.get() > INBOUND_LIMIT - 64 * 1024) return
        zeroWindowAdvertised = false
        sendAck()
    }

    private var wssizeBytesSeen = 0
    private var windowRestored = true
    private var connectStrategy: Strategy = Strategy()

    init {
        // Наш виртуальный DNS в сети не существует, поэтому любой TCP к нему
        // (в том числе отправленный системным резолвером) уходит в настоящий
        // DNS-сервер. Для чужих хостов на порту 53 перенаправление тоже
        // безвредно — так мы перехватываем DNS поверх TCP целиком.
        upstreamAddr =
            if (serverPort == 53 || stack.isVirtualDns(serverAddr)) {
                stack.dnsRedirectTarget() ?: serverAddr
            } else {
                serverAddr
            }
        val mtu = cfg.mtu.coerceIn(576, 10000)
        val overhead = (if (v6) 40 else 20) + 20 + (if (clientUsesTimestamps) 12 else 0)
        val maxSeg = (mtu - overhead).coerceAtLeast(536)
        mss = min(min(syn.mss, cfg.mssClamp.coerceIn(536, 8960)), maxSeg).coerceAtLeast(536)
    }

    val description: String get() = "$clientAddr:$clientPort → $serverAddr:$serverPort"

    /* ------------------------------------------------------------ */
    /*  Жизненный цикл                                              */
    /* ------------------------------------------------------------ */

    fun start() {
        TrafficStats.connectionOpened()
        sendSynAck()
        connectStrategy = stack.resolveFor(serverPort, ReverseHostCache.get(serverAddr), serverAddr, clientPort).strategy
        val scope = stack.scope
        jobs += scope.launch(stack.io) { runConnection() }
        jobs += scope.launch(stack.io) { watchdog() }
    }

    private suspend fun runConnection() {
        var socket: Socket? = null
        // Первые несколько соединений пишем обычным уровнем: по журналу сразу
        // видно, доходит ли дело до upstream-сокета и что именно его рвёт.
        val slot = stack.nextDiagSlot()
        val verboseSlot = slot <= 5
        val t0 = android.os.SystemClock.elapsedRealtime()
        try {
            socket = openUpstream()
            stack.establishedTotal.incrementAndGet()
            if (verboseSlot) {
                LogManager.i(
                    LogTag.TCP,
                    "TCP #$slot → ${upstreamAddr.hostAddress}:$serverPort открыт за ${android.os.SystemClock.elapsedRealtime() - t0} мс"
                )
            }
            upstream = socket
            val pumpUp = launchPumpToUpstream(socket)
            val pumpDown = launchPumpFromUpstream(socket)
            pumpUp.join()
            pumpDown.join()
            gracefulClose()
        } catch (e: Exception) {
            stack.failedTotal.incrementAndGet()
            if (!closed) {
                val msg = "upstream $description: ${e.javaClass.simpleName}: ${e.message}"
                if (verboseSlot) LogManager.i(LogTag.TCP, "TCP #$slot · ОШИБКА · $msg") else LogManager.d(LogTag.TCP, msg)
                sendReset()
            }
            close()
        } finally {
            try { socket?.close() } catch (_: Exception) {}
        }
    }

    private suspend fun openUpstream(): Socket {
        val socket = Socket()
        stack.protector.protect(socket)
        socket.tcpNoDelay = true
        socket.keepAlive = false
        val s = connectStrategy
        if (s.wssizeEnabled) {
            windowRestored = false
            try {
                socket.receiveBufferSize = s.wssizeWindow.coerceIn(2048, 65535)
            } catch (_: Exception) {
            }
        } else {
            try {
                socket.receiveBufferSize = 256 * 1024
            } catch (_: Exception) {
            }
        }
        withContext(stack.io) {
            socket.connect(InetSocketAddress(upstreamAddr, serverPort), cfg.connectTimeoutMs.coerceIn(1000, 60000))
        }
        return socket
    }

    private fun launchPumpToUpstream(socket: Socket): Job = stack.scope.launch(stack.io) {
        try {
            pumpToUpstream(socket)
        } catch (e: Exception) {
            if (!closed) LogManager.d(LogTag.TCP, "pump↑ $description: ${e.message}")
        }
    }

    private fun launchPumpFromUpstream(socket: Socket): Job = stack.scope.launch(stack.io) {
        try {
            pumpFromUpstream(socket)
        } catch (e: Exception) {
            if (!closed) LogManager.d(LogTag.TCP, "pump↓ $description: ${e.message}")
        }
    }

    /* ------------------------------------------------------------ */
    /*  Клиент → интернет (точка применения стратегий zapret)      */
    /* ------------------------------------------------------------ */

    private suspend fun pumpToUpstream(socket: Socket) {
        val out = socket.getOutputStream()
        // Сколько пакетов клиента копим перед применением стратегии. Раньше здесь
        // стоял жёсткий предел в 1–16 чанков, из-за чего клиент, который дробит
        // ClientHello на несколько сегментов (Chromium с Kyber так делает почти
        // всегда), отдавал нам неполное рукопожатие: SNI не находился и
        // десинхронизация не применялась вовсе.
        val maxChunks = cfg.cutoffChunks.coerceIn(1, 64)

        // Фаза 1: копим стартовый блок, пока не сойдётся первая TLS-запись
        // (или не выберем не-TLS протокол).
        var initial: ByteArray? = null
        var chunksSeen = 0
        loop@ while (chunksSeen < maxChunks) {
            // Таймаут обязателен: клиент может прислать половину рукопожатия и
            // замолчать. Без таймаута receive() ждал бы вечно, и соединение
            // висело до общей проверки простоя — то есть минутами.
            val chunk = withTimeoutOrNull(ASSEMBLY_WAIT_MS) { inbound.receive() }
            if (chunk == null) {
                // receive() вернул null — это всегда FIN, а не «таймаут»:
                // withTimeoutOrNull отменяет внутренний receive(), и отменённый
                // receive() тоже даёт null. Поэтому FIN и тишину приходится
                // различать состоянием самой очереди.
                val queued = inbound.tryReceive()
                if (!queued.isSuccess) {
                    // Очередь пуста: клиент замолчал, не присылая ни данных,
                    // ни FIN. Ждать больше нечего.
                    if (initial != null) {
                        // Отправляем недописанное рукопожатие и закрываем
                        // соединение целиком. Сервер на обрезанной TLS-записи
                        // ничего ответить не может, так что держать соединение
                        // дальше незачем: оно зря занимает слот в maxConnections
                        // и живёт до общего таймаута простоя (минуты).
                        writePlain(out, initial)
                        close()
                    } else {
                        // Ничего не отправляли — просто убираем соединение.
                        safeShutdownOutput(socket)
                        close()
                    }
                    return
                }
                val pending = queued.getOrNull()
                if (pending == null) {
                    // Настоящий FIN в очереди: это штатное закрытие, а не обрыв.
                    // Полусловесное закрытие здесь корректно — сервер успевает
                    // дописать ответ, и соединение закроется штатно.
                    finFromClient = true
                    if (initial != null) writePlain(out, initial)
                    safeShutdownOutput(socket)
                    return
                }
                if (pending.isEmpty()) continue@loop
                inboundBytes.addAndGet(-pending.size)
                chunksSeen++
                val mergedNow = if (initial == null) pending else concat(initial, pending)
                initial = mergedNow
                if (mergedNow.size >= MAX_INITIAL_BLOCK) break@loop
                if (blockComplete(mergedNow)) break@loop
                if (!isTlsRecord(mergedNow)) break@loop
                continue@loop
            }
            if (chunk.isEmpty()) continue@loop
            inboundBytes.addAndGet(-chunk.size)
            chunksSeen++
            val merged = if (initial == null) chunk else concat(initial, chunk)
            initial = merged
            if (merged.size >= MAX_INITIAL_BLOCK) break@loop
            if (blockComplete(merged)) break@loop
            // Не-TLS поток (HTTP и прочее) не требует ожидания: он и так не
            // держится в буфере сколько-то чанков.
            if (!isTlsRecord(merged)) break@loop
        }

        val first = initial ?: ByteArray(0)
        // Стартовый блок уже разобран — если до этого было объявлено нулевое
        // окно, клиент должен получить обновление, иначе он не начнёт слать
        // Application Data (HTTP/2 целиком идёт после рукопожатия).
        releaseZeroWindow()
        if (first.isNotEmpty()) {
            deliverInitial(out, socket, first)
        }

        // Фаза 2: обычный релей.
        while (true) {
            val chunk = inbound.receive()
            if (chunk == null) break
            if (chunk.isEmpty()) continue
            inboundBytes.addAndGet(-chunk.size)
            releaseZeroWindow()
            out.write(chunk)
            out.flush()
            TrafficStats.up(chunk.size)
        }
        finFromClient = true
        safeShutdownOutput(socket)
    }

    private suspend fun deliverInitial(out: java.io.OutputStream, socket: Socket, payload: ByteArray) {
        val knownHost = ReverseHostCache.get(serverAddr)
        val ctx = FlowContext(serverPort, knownHost, v6)

        // До получения SNI стратегия выбиралась по порту и обратному кэшу DNS —
        // теперь хост известен точно, перепроверяем правило.
        val sni = Tls.parseClientHello(payload, 0, payload.size)?.sni
            ?: Http.hostValueRange(payload, 0, payload.size)
                ?.let { String(payload, it.first, it.second - it.first, Charsets.ISO_8859_1) }
            ?: knownHost
        if (sni != null) detectedHost = sni

        val decision = stack.resolveFor(serverPort, sni, serverAddr, clientPort)
        val strategy = decision.strategy

        if (strategy.isPassive) {
            writePlain(out, payload)
            stack.track(this, detectedHost, "без обработки", false)
            return
        }

        val plan = stack.engine.plan(payload, ctx, strategy)

        // Приёмы, которым нужны параметры ядра, живут на дескрипторе самого
        // сокета. Создаётся лениво — для обычных стратегий он не нужен вовсе.
        val raw = if (plan.urgentByte != null || plan.fakeTtl > 0 || plan.ttl1Indices.isNotEmpty()) {
            runCatching { RawSocket(socket) }.getOrNull()
        } else {
            null
        }

        try {
            // Подставная запись уходит отдельной записью ДО настоящих данных и с
            // паузой после: DPI должен успеть разобрать её и споткнуться, пока
            // настоящий ClientHello ещё не начал приходить. Без паузы замеры
            // показывают обратное — подстава сливается с настоящей записью, DPI
            // разбирает обе вместе и находит заблокированный домен.
            plan.poison?.let { poison ->
                out.write(poison)
                out.flush()
                TrafficStats.up(poison.size)
                if (plan.poisonDelayMs > 0) delay(plan.poisonDelayMs.toLong())
            }

            // Пустышка с малым TTL уходит ПЕРВОЙ: она должна умереть на
            // первом хопе, до сервера не дойти, но инлайновый фильтр по пути
            // её увидит. Содержимое — заведомо безвредное hello из плана, а не
            // настоящие данные: слать туда настоящий ClientHello бессмысленно,
            // фильтр найдёт в нём тот же SNI. Настоящие данные идут следом с
            // обычным TTL, иначе соединение просто не доедет.
            //
            // Как у эталона (r1.b + sendfile): TTL выставляется ДО отправки
            // пустышки и возвращается ПОСЛЕ в finally. Если TTL не взялся —
            // пустышка НЕ отправляется вовсе: без малого TTL она дошла бы до
            // сервера как обычные данные и сломала бы рукопожатие.
            if (plan.fakeTtl > 0 && plan.fakeDummy != null) {
                var sent = false
                if (raw != null) {
                    if (raw.setTtl(plan.fakeTtl)) {
                        try {
                            out.write(plan.fakeDummy)
                            out.flush()
                            sent = true
                        } catch (_: Exception) {
                            sent = false
                        } finally {
                            raw.resetTtl()
                        }
                    } else {
                        LogManager.w("DPI: TTL недоступен — fake пропущен (приём не сработает)")
                    }
                } else {
                    // Без управления TTL пустышка ушла бы как обычные данные и
                    // дошла до сервера. Не отправляем вовсе — приём не сработает,
                    // но рукопожатие не сломается.
                    LogManager.w("DPI: TTL недоступен — fake пропущен (приём не сработает)")
                }
                if (sent) {
                    TrafficStats.up(plan.fakeDummy.size)
                }
                // Пауза нужна, чтобы DPI успел разобрать пустышку до настоящих
                // данных — та же причина, что у poisonDelayMs. Эталон спит 3 мс
                // после sendfile, поэтому минимум — 3 мс даже при нулевых
                // задержках в настройках.
                val pause = maxOf(strategy.splitDelayMs, plan.poisonDelayMs, 3)
                if (pause > 0) delay(pause.toLong())
            }

            // Порядок и параметры отправки фрагментов — из плана, механика
            // ByeDPI desync.c (там же работает без root на обычном сокете):
            // - oob: [голова + байт] одним sendto(MSG_OOB), остаток — обычно;
            // - disoob (tailFirst): сначала хвост обычно, затем [голова + байт]
            //   через MSG_OOB — на проводе обратный порядок, сервер собирает
            //   по sequence, срочный байт из потока выпадает;
            // - disorder (ttl1Indices): помеченные фрагменты уходят с TTL=1 и
            //   гибнут на первом хопе, ядро само их переотправляет после SACK —
            //   порядок на проводе ломается, поток цел.
            // Не взялся MSG_OOB/TTL — фрагмент уходит обычной записью: приём
            // вырождается в разрез, но поток не ломается.
            var oobOk = plan.urgentByte == null
            var ttl1Ok = plan.ttl1Indices.isEmpty()
            val urgent = (plan.urgentByte ?: 0) and 0xFF
            val order: List<Int> =
                if (plan.tailFirst && plan.writes.size >= 2) {
                    (1 until plan.writes.size).toList() + listOf(0)
                } else {
                    plan.writes.indices.toList()
                }
            for ((step, idx) in order.withIndex()) {
                val write = plan.writes[idx]
                when {
                    plan.urgentByte != null && idx == 0 -> {
                        oobOk = raw?.sendWithOob(write, urgent) == true
                        if (!oobOk) {
                            LogManager.w("DPI: OOB не взялся — ушёл обычный разрез")
                            out.write(write)
                            out.flush()
                        }
                        TrafficStats.up(write.size)
                    }
                    plan.ttl1Indices.contains(idx) -> {
                        var sent = false
                        if (raw != null && raw.setTtl(DISORDER_TTL1)) {
                            try {
                                out.write(write)
                                out.flush()
                                sent = true
                            } catch (_: Exception) {
                                sent = false
                            } finally {
                                raw.resetTtl()
                            }
                        }
                        if (!sent) {
                            ttl1Ok = false
                            LogManager.w("DPI: TTL=1 недоступен — disorder вырождается в разрез")
                            out.write(write)
                            out.flush()
                        }
                        TrafficStats.up(write.size)
                    }
                    else -> {
                        out.write(write)
                        out.flush()
                        TrafficStats.up(write.size)
                    }
                }
                if (step < order.size - 1 && strategy.splitDelayMs > 0) {
                    delay(strategy.splitDelayMs.toLong())
                }
            }
            // Если приёмы не взялись, в журнал честно пишем разрез: хвастаться
            // несработавшим приёмом нельзя.
            var technique = plan.technique
            if (plan.applied && plan.urgentByte != null && !oobOk) technique += " (без oob)"
            if (plan.applied && plan.ttl1Indices.isNotEmpty() && !ttl1Ok) technique += " (без ttl1)"
            if (plan.applied) {
                TrafficStats.desynced()
                desyncApplied = technique
                LogManager.i(
                    LogTag.DPI,
                    "$technique · ${plan.host ?: serverAddr.hostAddress}:$serverPort · ${decision.reason}"
                )
            } else if (cfg.verboseLog) {
                LogManager.d(LogTag.DPI, "пропуск ${plan.host ?: serverAddr.hostAddress}:$serverPort — ${plan.technique}")
            }
            stack.track(this, detectedHost, technique, plan.applied)
        } finally {
            // Дескриптор держит ссылку на сокет: без закрытия он переживёт
            // соединение и утёкнет. Именно try/finally, а не close() в конце:
            // out.write бросает исключение на оборванном соединении, и без
            // finally дескриптор тёк бы на каждом таком обрыве.
            raw?.close()
        }
    }

    private fun writePlain(out: java.io.OutputStream, payload: ByteArray) {
        out.write(payload)
        out.flush()
        TrafficStats.up(payload.size)
    }

    private fun blockComplete(b: ByteArray): Boolean {
        if (Tls.isRecordType(b, 0, b.size)) {
            val total = Tls.recordTotalLength(b, 0, b.size)
            return total > 0 && b.size >= total
        }
        if (Http.looksLikeRequest(b, 0, b.size)) {
            return Http.headerBlockLength(b, 0, b.size) > 0
        }
        return true
    }

    /** Похоже ли начало потока на TLS-запись (нужно, чтобы понять: ждать дальше или нет). */
    private fun isTlsRecord(b: ByteArray): Boolean = Tls.isRecordType(b, 0, b.size)

    private fun concat(a: ByteArray, b: ByteArray): ByteArray {
        val out = ByteArray(a.size + b.size)
        System.arraycopy(a, 0, out, 0, a.size)
        System.arraycopy(b, 0, out, a.size, b.size)
        return out
    }

    /* ------------------------------------------------------------ */
    /*  Интернет → клиент                                            */
    /* ------------------------------------------------------------ */

    private suspend fun pumpFromUpstream(socket: Socket) {
        val input = socket.getInputStream()
        val buf = ByteArray(mss * 4)
        val limit = cfg.sendBufferKb.coerceIn(32, 8192) * 1024
        val wssizeLimit = connectStrategy.wssizePackets.coerceIn(1, 64) * mss

        while (!closed) {
            var waited = 0
            while (queuedBytes > limit && !closed) {
                delay(4)
                waited += 4
                if (waited > cfg.tcpTimeoutSec * 1000L) break
            }
            if (closed) break

            val n: Int = withContext(stack.io) {
                try {
                    input.read(buf)
                } catch (e: Exception) {
                    if (!closed) LogManager.d(LogTag.TCP, "read↓ $description: ${e.message}")
                    Int.MIN_VALUE
                }
            }
            if (n == Int.MIN_VALUE) break
            if (n < 0) {
                synchronized(lock) {
                    finFromUpstream = true
                }
                maybeSend()
                break
            }
            if (n == 0) continue

            if (!windowRestored) {
                wssizeBytesSeen += n
                if (wssizeBytesSeen >= wssizeLimit) {
                    windowRestored = true
                    try {
                        socket.receiveBufferSize = 512 * 1024
                    } catch (_: Exception) {
                    }
                }
            }

            appendToQueue(buf, n)
            maybeSend()
        }
    }

    private fun appendToQueue(buf: ByteArray, len: Int) {
        synchronized(lock) {
            var off = 0
            while (off < len) {
                val n = min(mss, len - off)
                val data = buf.copyOfRange(off, off + n)
                queue.addLast(Chunk(queueTailSeq, data))
                queueTailSeq = seqAdd(queueTailSeq, n)
                queuedBytes += n
                off += n
            }
        }
    }

    private fun maybeSend() {
        synchronized(lock) {
            if (closed) return
            val now = SystemClock.elapsedRealtime()
            var guard = 0
            while (queue.isNotEmpty() && guard++ < 1024) {
                val c = queue.first()
                val window = clientWindow - inflight
                if (c.len > window) break
                if (inflight + c.len > MAX_INFLIGHT) break
                queue.removeFirst()
                queuedBytes -= c.len
                val psh = queue.isEmpty() && !finFromUpstream
                transmit(c, psh)
                lastProgress = now
            }
            if (queue.isEmpty() && finFromUpstream && !finSent) sendFinLocked()
        }
    }

    /** Должно вызываться под [lock]. */
    private fun transmit(c: Chunk, psh: Boolean) {
        val flags = TcpFlag.ACK or (if (psh) TcpFlag.PSH else 0)
        val pkt = PacketBuilder.tcp(
            v6 = v6, src = serverAddr, dst = clientAddr,
            srcPort = serverPort, dstPort = clientPort,
            seq = c.seq, ack = rcvNext, flags = flags, window = advertiseWindow(),
            payload = c.data, payloadOff = 0, payloadLen = c.len,
            tsValue = ourTimestamp(), tsEcho = clientTsVal,
            useTimestamp = clientUsesTimestamps
        )
        stack.writer.write(pkt)
        TrafficStats.down(c.len)
        unacked.addLast(c)
        inflight += c.len
        sndNxt = seqAdd(sndNxt, c.len)
    }

    private fun sendAck() {
        synchronized(lock) {
            if (closed || state == State.SYN_RCVD) return
            val pkt = PacketBuilder.tcp(
                v6 = v6, src = serverAddr, dst = clientAddr,
                srcPort = serverPort, dstPort = clientPort,
                seq = sndNxt, ack = rcvNext, flags = TcpFlag.ACK, window = advertiseWindow(),
                tsValue = ourTimestamp(), tsEcho = clientTsVal,
                useTimestamp = clientUsesTimestamps
            )
            stack.writer.write(pkt)
            TrafficStats.down(0)
        }
    }

    private fun sendSynAck() {
        val opts = PacketBuilder.synAckOptions(mss, sackPerm = true, wscale = ourWscale)
        val pkt = PacketBuilder.tcp(
            v6 = v6, src = serverAddr, dst = clientAddr,
            srcPort = serverPort, dstPort = clientPort,
            seq = ourIsn, ack = rcvNext,
            flags = TcpFlag.SYN or TcpFlag.ACK,
            window = WINDOW_FIELD,
            options = opts,
            tsValue = ourTimestamp(), tsEcho = syn.tsValue,
            useTimestamp = clientUsesTimestamps
        )
        stack.writer.write(pkt)
        TrafficStats.down(0)
        LogManager.d(LogTag.TCP, "SYN-ACK → $description (mss=$mss)")
    }

    private fun sendFinLocked() {
        if (finSent) return
        val pkt = PacketBuilder.tcp(
            v6 = v6, src = serverAddr, dst = clientAddr,
            srcPort = serverPort, dstPort = clientPort,
            seq = sndNxt, ack = rcvNext,
            flags = TcpFlag.FIN or TcpFlag.ACK, window = advertiseWindow(),
            tsValue = ourTimestamp(), tsEcho = clientTsVal,
            useTimestamp = clientUsesTimestamps
        )
        stack.writer.write(pkt)
        sndNxt = seqAdd(sndNxt, 1)
        finSent = true
        state = State.FIN_WAIT
        TrafficStats.down(0)
    }

    private fun sendReset() {
        try {
            val pkt = PacketBuilder.rst(v6, serverAddr, clientAddr, serverPort, clientPort, sndNxt, rcvNext)
            stack.writer.write(pkt)
        } catch (_: Exception) {
        }
    }

    /* ------------------------------------------------------------ */
    /*  Приём сегментов от клиента                                   */
    /* ------------------------------------------------------------ */

    fun onSegment(seg: TcpSegment) {
        if (closed) return
        lastActivity = SystemClock.elapsedRealtime()
        if (seg.hasTimestamp) clientTsVal = seg.tsValue

        if (seg.isRst) {
            close()
            return
        }

        when (state) {
            State.SYN_RCVD -> {
                if (seg.isSyn && !seg.isAck) { sendSynAck(); return }
                if (seg.isAck) {
                    state = State.ESTABLISHED
                    clientWindow = scaleWindow(seg.window)
                } else return
            }
            else -> {
                if (seg.isSyn) { sendSynAck(); return }
            }
        }

        if (seg.isAck) handleAck(seg)
        if (seg.payloadLength > 0) handlePayload(seg)
        if (seg.isFin) handleClientFin(seg)
    }

    private fun scaleWindow(field: Int): Int {
        val w = if (clientWscale > 0) field shl clientWscale else field
        return w.coerceIn(1024, 8 * 1024 * 1024)
    }

    private fun handleAck(seg: TcpSegment) {
        var retransmitNow = false
        synchronized(lock) {
            clientWindow = scaleWindow(seg.window)
            val ack = seg.ack
            if (seqCompare(ack, sndUna) > 0 && seqCompare(ack, sndNxt) <= 0) {
                while (unacked.isNotEmpty()) {
                    val c = unacked.first()
                    if (seqCompare(seqAdd(c.seq, c.len), ack) <= 0) {
                        unacked.removeFirst()
                        inflight -= c.len
                        sndUna = seqAdd(sndUna, c.len)
                    } else break
                }
                dupAcks = 0
                rtoMs = 800L
                retransmits = 0
                lastProgress = SystemClock.elapsedRealtime()
                if (finSent && seqCompare(ack, sndNxt) >= 0) finAcked = true
            } else if (seqCompare(ack, sndUna) == 0 && unacked.isNotEmpty()) {
                dupAcks++
                if (dupAcks >= 3) { dupAcks = 0; retransmitNow = true }
            }
        }
        if (retransmitNow) retransmitAll() else maybeSend()
    }

    private fun handlePayload(seg: TcpSegment) {
        val payloadStart = seg.payloadOffset
        val payloadLen = seg.payloadLength
        val delta = seg.seq - rcvNext          // знаковая разница с учётом переполнения
        val deliver: Int
        val deliverOff: Int
        when {
            delta == 0 -> { deliver = payloadLen; deliverOff = payloadStart }
            delta < 0 -> {
                val overlap = -delta
                if (overlap >= payloadLen) { sendAck(); return }
                deliver = payloadLen - overlap
                deliverOff = payloadStart + overlap
            }
            else -> { sendAck(); return }      // дыра в потоке — ждём ретрансмиссии
        }

        if (inboundBytes.get() + deliver > INBOUND_LIMIT) {
            TrafficStats.dropped()
            sendAck()
            return
        }
        val data = seg.buffer.copyOfRange(deliverOff, deliverOff + deliver)
        rcvNext = seqAdd(rcvNext, deliver)
        if (!inbound.trySend(data).isSuccess) {
            rcvNext = seqAdd(rcvNext, -deliver)
            TrafficStats.dropped()
        } else {
            inboundBytes.addAndGet(deliver)
        }
        sendAck()
    }

    private fun handleClientFin(seg: TcpSegment) {
        if (finFromClient) return
        rcvNext = seqAdd(rcvNext, 1)
        finFromClient = true
        sendAck()
        inbound.trySend(null)
    }

    private fun safeShutdownOutput(socket: Socket) {
        try {
            if (!socket.isOutputShutdown) socket.shutdownOutput()
        } catch (_: Exception) {
        }
    }

    /* ------------------------------------------------------------ */
    /*  Ретрансмиссии, таймауты, закрытие                            */
    /* ------------------------------------------------------------ */

    private fun retransmitAll() {
        synchronized(lock) {
            if (unacked.isEmpty()) return
            val rest = ArrayList<Chunk>(unacked)
            unacked.clear()
            inflight = 0
            sndNxt = sndUna
            val merged = ArrayDeque<Chunk>()
            merged.addAll(rest)
            merged.addAll(queue)
            queue = merged
            retransmits++
            rtoMs = min(rtoMs * 2, 16000L)
            lastProgress = SystemClock.elapsedRealtime()
        }
        LogManager.d(LogTag.TCP, "ретрансмиссия #$retransmits $description")
        if (retransmits > MAX_RETRANSMITS) {
            sendReset()
            close()
            return
        }
        maybeSend()
    }

    private suspend fun watchdog() {
        val idleLimit = cfg.tcpTimeoutSec.coerceIn(30, 7200) * 1000L
        while (stack.scope.isActive && !closed) {
            delay(500)
            val now = SystemClock.elapsedRealtime()
            if (now - lastActivity > idleLimit) {
                LogManager.d(LogTag.TCP, "таймаут простоя $description")
                close()
                break
            }
            val needRto: Boolean
            synchronized(lock) {
                needRto = inflight > 0 && now - lastProgress >= rtoMs
            }
            if (needRto) retransmitAll()
            if (finSent && finAcked && queueIsEmpty()) {
                delay(1000)
                close()
                break
            }
            if (finFromClient && finSent && finAcked) {
                delay(1500)
                close()
                break
            }
        }
    }

    private fun queueIsEmpty(): Boolean = synchronized(lock) { queue.isEmpty() && unacked.isEmpty() }

    private fun gracefulClose() {
        if (closed) return
        synchronized(lock) {
            finFromUpstream = true
        }
        maybeSend()
        // Даём клиенту время подтвердить FIN, затем закрываем безусловно.
        stack.scope.launch(stack.io) {
            delay(4000)
            close()
        }
    }

    fun close() {
        if (closed) return
        closed = true
        state = State.CLOSED
        try { upstream?.close() } catch (_: Exception) {}
        inbound.close()
        for (j in jobs) {
            try { j.cancel() } catch (_: Exception) {}
        }
        synchronized(lock) { queue.clear(); unacked.clear(); inflight = 0; queuedBytes = 0 }
        stack.remove(this)
    }

    fun isClosed(): Boolean = closed

    private fun ourTimestamp(): Int = (SystemClock.elapsedRealtime() and 0x7FFFFFFFL).toInt()

    private companion object {
        const val WINDOW_FIELD = 65535
        /**
         * TTL гибнущей копии для `--disorder` — буквально как в ByeDPI
         * (`setttl(sfd, 1)`): пакет умирает на первом хопе, DPI его видит,
         * а сервер — нет; ядро переотправляет фрагмент само.
         */
        const val DISORDER_TTL1 = 1
        const val MAX_INFLIGHT = 512 * 1024
        const val MAX_RETRANSMITS = 9
        const val MAX_INITIAL_BLOCK = 32 * 1024
        const val INBOUND_LIMIT = 1024 * 1024

        /**
         * Сколько ждём следующий сегмент, пока собираем ClientHello.
         *
         * Раньше ожидание было бесконечным: клиент, приславший часть
         * рукопожатия и замолчавший, держал соединение открытым до общей
         * проверки простоя — а это минуты. Теперь тишина означает «дописывать
         * нечего», и мы отправляем что есть.
         *
         * Значение с запасом больше времени сборки ClientHello несколькими
         * сегментами: обычно это десятки миллисекунд.
         */
        const val ASSEMBLY_WAIT_MS = 4000L
    }
}
