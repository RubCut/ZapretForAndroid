package dev.rubcut.zapret.core.stack

import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.IOException
import java.net.Socket

/**
 * Сокет для приёмов, которым нужны параметры уровня ядра.
 *
 * Приёмы `--oob` (байт срочных данных) и `--fake`/`--disorder` (малый TTL)
 * устроены в ядре: обычный `Socket` их не предоставляет, а сырые сокеты
 * приложению на Android недоступны.
 *
 * Решение, найденное в декомпиляции ZapretYT: файловый дескриптор берётся у
 * уже соединённого обычного сокета через [ParcelFileDescriptor.fromSocket],
 * и на нём зовут `Os.setsockoptInt`/`Os.sendto` от `android.system`. Никаких
 * привилегий: это те же права, что у обычного сокета приложения.
 *
 * Заголовок TCP при этом остаётся в ведении ядра — приложение не собирает
 * сегменты вручную, что и делает приём безопасным.
 */
class RawSocket(private val socket: Socket) : AutoCloseable {

    private var pfd: ParcelFileDescriptor? = null

    /** Признак, что TTL менялся и его надо вернуть перед закрытием соединения. */
    var ttlTouched: Boolean = false
        private set

    private fun fd(): java.io.FileDescriptor? {
        try {
            pfd?.let { return it.fileDescriptor }
            val created = ParcelFileDescriptor.fromSocket(socket)
            pfd = created
            return created.fileDescriptor
        } catch (e: Exception) {
            LogManager.d(LogTag.TCP, "Не удалось получить дескриптор сокета: ${e.message}")
            return null
        }
    }

    /**
     * Задать TTL исходящих пакетов.
     *
     * Малое значение (1–8) заставляет пакет умереть на первом же хопе: до
     * сервера он не дойдёт, но инлайновый фильтр по пути его увидит.
     */
    fun setTtl(ttl: Int): Boolean {
        val descriptor = fd() ?: return false
        return try {
            Os.setsockoptInt(descriptor, OsConstants.IPPROTO_IP, OsConstants.IP_TTL, ttl)
            ttlTouched = ttl != DEFAULT_TTL
            true
        } catch (e: ErrnoException) {
            LogManager.d(LogTag.TCP, "Не удалось задать TTL $ttl: ${e.message}")
            false
        } catch (e: Exception) {
            LogManager.d(LogTag.TCP, "TTL недоступен: ${e.message}")
            false
        }
    }

    /** Вернуть обычный TTL: соединение живёт долго, и тихий TTL=1 его убьёт. */
    fun resetTtl(): Boolean = if (ttlTouched) setTtl(DEFAULT_TTL) else false

    /**
     * Отправить данные так, чтобы последний байт ушёл как срочный.
     *
     * На проводе появляется байт, которого нет в обычном потоке: получатель
     * отдаст его отдельно, а фильтр, читающий поток как есть, увидит другой
     * порядок байт — из-за этого и не находит имя.
     *
     * @param urgent значение байта срочных данных.
     * @return удалось ли отправить именно так; при false данные уйдут обычным
     *   способом, и приём просто не сработает, но и не сломает соединение.
     */
    fun sendWithUrgent(data: ByteArray, urgent: Int): Boolean {
        val descriptor = fd() ?: return false
        val buffer = ByteArray(data.size + 1)
        System.arraycopy(data, 0, buffer, 0, data.size)
        buffer[data.size] = urgent.toByte()
        return try {
            Os.sendto(descriptor, buffer, 0, buffer.size, OsConstants.MSG_OOB, null, 0)
            true
        } catch (e: ErrnoException) {
            LogManager.d(LogTag.TCP, "OOB не отправился (${e.message}) — уйдёт как обычные данные")
            false
        } catch (e: Exception) {
            LogManager.d(LogTag.TCP, "OOB недоступен: ${e.message}")
            false
        }
    }

    override fun close() {
        try {
            pfd?.close()
        } catch (_: Exception) {
        }
        pfd = null
    }

    companion object {
        /** Обычный TTL, который система ставит новому сокету. */
        const val DEFAULT_TTL = 64
    }
}