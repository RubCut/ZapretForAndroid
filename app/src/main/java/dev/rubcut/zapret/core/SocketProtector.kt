package dev.rubcut.zapret.core

import java.net.DatagramSocket
import java.net.Socket

/**
 * Абстракция над [android.net.VpnService.protect]. Без неё upstream-сокеты самого
 * приложения снова попадали бы в наш туннель, образуя бесконечную рекурсию.
 */
interface SocketProtector {
    fun protect(socket: Socket): Boolean
    fun protect(socket: DatagramSocket): Boolean
    fun protect(fd: Int): Boolean
}
