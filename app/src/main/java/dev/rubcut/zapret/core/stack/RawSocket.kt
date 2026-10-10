package dev.rubcut.zapret.core.stack

import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import dev.rubcut.zapret.core.LogManager
import dev.rubcut.zapret.core.LogTag
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
     * Для IPv6 управляется другой опцией — уровень и имя выбираются по
     * размеру адреса, иначе вызов молча не действует.
     */
    fun setTtl(ttl: Int): Boolean {
        val descriptor = fd() ?: return false
        val isV6 = try {
            socket.inetAddress?.address?.size == 16
        } catch (_: Exception) {
            false
        }
        val level = if (isV6) OsConstants.IPPROTO_IPV6 else OsConstants.IPPROTO_IP
        val opt = if (isV6) OsConstants.IPV6_UNICAST_HOPS else OsConstants.IP_TTL
        return try {
            Os.setsockoptInt(descriptor, level, opt, ttl)
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
     * Отправить один байт срочных данных.
     *
     * Вызывается МЕЖДУ обычными записями: до — первая часть потока, после —
     * вторая. На проводе байт есть, а сервер, читающий обычный поток, его
     * пропускает (urgent держится отдельно от очереди данных) — из-за этого
     * разбор имени у фильтра, читающего поток как есть, сбивается.
     *
     * Важно: срочным уходит ТОЛЬКО этот байт. Отправлять вместе с ним данные
     * обычным способом нельзя — они ушли бы дублем и сломали бы поток.
     * Именно так делает и эталон: их `r1.a` шлёт `[данные + 1 байт]` одним
     * вызовом `sendto(MSG_OOB)`, а остаток — обычной записью следом.
     *
     * @return удалось ли отправить именно так; при false вызывающий обязан
     *   записать байт обычным способом, иначе поток потеряет байт.
     */
    fun sendUrgentByte(urgent: Int): Boolean {
        val descriptor = fd() ?: return false
        return try {
            Os.sendto(descriptor, byteArrayOf(urgent.toByte()), 0, 1, OsConstants.MSG_OOB, null, 0)
            true
        } catch (e: ErrnoException) {
            LogManager.d(LogTag.TCP, "OOB не отправился (${e.message})")
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