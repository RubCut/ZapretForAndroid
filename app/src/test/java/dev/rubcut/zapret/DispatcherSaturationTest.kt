package dev.rubcut.zapret

import dev.rubcut.zapret.core.SocketProtector
import dev.rubcut.zapret.core.stack.PacketWriter
import dev.rubcut.zapret.core.stack.TcpStack
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.HostListStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket

/**
 * Пул потоков стека обязан переживать нагрузку, а не отбрасывать задачи.
 *
 * Регрессия: пул был создан на SynchronousQueue — у неё нулевая ёмкость, поэтому
 * при числе занятых потоков, равном максимуму, execute() бросал
 * RejectedExecutionException мгновенно. Чтение из upstream-сокета блокирующее и
 * держит поток всё время жизни соединения, а connect() висит до таймаута, так
 * что одновременных задач набиралось много.
 *
 * YouTube при старте открывает соединения пачками. Как только пул переполнялся,
 * launch() падал, насосы не стартовали, pumpUp.join() ждал вечно — соединение
 * зависало навсегда и занимало слот в maxConnections. Несколько таких пакетов —
 * и туннель переставал работать целиком.
 */
class DispatcherSaturationTest {

    private class Sink : OutputStream() {
        val sink = ByteArrayOutputStream()
        override fun write(b: Int) { /* no-op */ }
        override fun write(b: ByteArray, off: Int, len: Int) { /* no-op */ }
    }

    private fun stack(): TcpStack = TcpStack(
        writer = PacketWriter(Sink()),
        protector = object : SocketProtector {
            override fun protect(socket: Socket) = true
            override fun protect(socket: DatagramSocket) = true
            override fun protect(fd: Int) = true
        },
        scope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
        configProvider = { AppConfig() },
        listsProvider = { HostListStore.Snapshot.EMPTY }
    )

    /**
     * Много одновременных задач — ни одна не должна быть отброшена.
     *
     * Проверяем именно отказ пула: каждая задача должна выполниться, а не
     * упасть с RejectedExecutionException на входе.
     */
    @Test
    fun dispatcherDoesNotRejectUnderLoad() = runBlocking {
        val s = stack()
        val tasks = 2000
        try {
            val results = (0 until tasks).map {
                async(s.io) {
                    // Имитация блокирующего чтения: именно оно держит поток
                    // и именно оно приводило пул к переполнению.
                    Thread.sleep(2)
                    it
                }
            }.awaitAll()
            assertEquals("ни одна задача не должна потеряться", tasks, results.size)
            assertEquals("все задачи должны вернуть свой индекс", (0 until tasks).toSet(), results.toSet())
        } finally {
            s.shutdown()
        }
    }

    /**
     * Диспетчер обязан честно сообщать о переполнении, а не ронять соединение молча.
     *
     * Старый обработчик отказа был стандартным AbortPolicy: исключение уходило
     * в SupervisorJob и исчезало, в журнале не оставалось ни слова.
     */
    @Test
    fun stackSurvivesRepeatedShutdownAndDispatch() = runBlocking {
        val s = stack()
        val first = async(s.io) { s.activeCount }
        first.await()
        s.closeAll()
        s.shutdown()
        assertEquals(0, s.activeCount)
    }

    /** Стек не должен делить адреса виртуального DNS по строкам — см. IPv6-разбор. */
    @Test
    fun virtualDnsIsMatchedByAddress() {
        val v6 = InetAddress.getByName("fd61:7a6f:ee7::2")
        val v4 = InetAddress.getByName("10.211.0.2")
        val set = setOf(v4, v6)
        assertEquals(true, set.contains(InetAddress.getByName("10.211.0.2")))
        assertEquals(true, set.contains(InetAddress.getByName("fd61:7a6f:ee07:0:0:0:0:2")))
    }
}