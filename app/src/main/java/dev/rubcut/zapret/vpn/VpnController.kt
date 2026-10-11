package dev.rubcut.zapret.vpn

import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

enum class VpnState { STOPPED, STARTING, RUNNING, ERROR }

/**
 * Единственная точка управления туннелем для UI, плитки и автозапуска.
 */
object VpnController {

    private val _state = MutableStateFlow(VpnState.STOPPED)
    val state: StateFlow<VpnState> = _state

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error

    val isRunning: Boolean get() = _state.value == VpnState.RUNNING

    /** Поднимается или уже поднят: повторный start вместо stop запрещён. */
    val isActive: Boolean get() = _state.value == VpnState.RUNNING || _state.value == VpnState.STARTING

    fun markStarting() {
        _state.value = VpnState.STARTING
        _error.value = null
    }

    fun markRunning() {
        _state.value = VpnState.RUNNING
        _error.value = null
    }

    fun markStopped() {
        _state.value = VpnState.STOPPED
    }

    fun markError(message: String?) {
        _state.value = VpnState.ERROR
        _error.value = message
    }

    /**
     * Intent системного диалога «Разрешить VPN?» или null, если разрешение уже есть.
     * Запускать его нужно из Activity — иначе Android не покажет диалог.
     */
    fun prepareIntent(context: Context): Intent? =
        try {
            VpnService.prepare(context)
        } catch (e: Exception) {
            null
        }

    fun startNow(context: Context) {
        markStarting()
        val intent = Intent(context, ZapretVpnService::class.java).setAction(ZapretVpnService.ACTION_START)
        try {
            ContextCompat.startForegroundService(context, intent)
        } catch (e: Exception) {
            // Android 12+: старт FGS из фона бросает
            // ForegroundServiceStartNotAllowedException — раньше это был
            // молчаливый незапуск с зависшим STARTING.
            markError(e.message ?: e.javaClass.simpleName)
        }
    }

    fun stop(context: Context) {
        // Сервис мёртв и не стартует — не создаём процесс ради остановки.
        // Раньше startService(ACTION_STOP) поднимал сервис только чтобы тут
        // же вызвать stopSelf().
        if (ZapretVpnService.instance == null && _state.value != VpnState.STARTING) {
            markStopped()
            return
        }
        val intent = Intent(context, ZapretVpnService::class.java).setAction(ZapretVpnService.ACTION_STOP)
        try {
            context.startService(intent)
        } catch (e: Exception) {
            markStopped()
        }
    }

    /**
     * @return true, если туннель поднимается без участия пользователя;
     *         false — требуется диалог согласия (вернёт [prepareIntent]).
     */
    fun requestStart(context: Context): Boolean {
        if (prepareIntent(context) != null) return false
        startNow(context)
        return true
    }

    fun toggle(context: Context): Boolean {
        // Во время STARTING повторный start давал двойной
        // startForegroundService — гасим старт вместо нового запуска.
        if (isActive) {
            stop(context)
            return true
        }
        return requestStart(context)
    }
}
