package dev.rubcut.zapret.service

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import dev.rubcut.zapret.AppGraph
import dev.rubcut.zapret.R
import dev.rubcut.zapret.core.LogManager
import dev.rubcut.zapret.core.LogTag
import dev.rubcut.zapret.vpn.VpnController
import dev.rubcut.zapret.vpn.VpnState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Плитка быстрых настроек: одно нажатие включает/выключает туннель.
 *
 * Если системное разрешение на VPN ещё не выдано, плитка не может поднять диалог
 * сама — она сворачивается и открывает MainActivity, где пользователь нажимает
 * «Разрешить». После этого разрешение остаётся навсегда, и плитка работает
 * автономно (в том числе из-под блокировки экрана, если включён Always-on VPN).
 */
class ZapretTileService : TileService() {

    private var scope: CoroutineScope? = null
    private var job: Job? = null

    override fun onStartListening() {
        super.onStartListening()
        render(VpnController.state.value)
        val s = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        scope = s
        job = s.launch {
            VpnController.state.collect { render(it) }
        }
    }

    override fun onStopListening() {
        job?.cancel()
        job = null
        scope?.cancel()
        scope = null
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        try {
            AppGraph.init(this)
            val state = VpnController.state.value
            if (state == VpnState.RUNNING || state == VpnState.STARTING) {
                VpnController.stop(this)
                render(VpnState.STOPPED)
                return
            }

            val consent = VpnController.prepareIntent(this)
            if (consent != null) {
                // Разрешение ещё не выдано — нужен пользователь.
                openConsentDialog(consent)
            } else {
                VpnController.startNow(this)
                render(VpnState.STARTING)
            }
        } catch (e: Exception) {
            LogManager.w("Плитка не смогла переключить туннель: ${e.message}")
        }
    }

    private fun openConsentDialog(prepareIntent: Intent) {
        prepareIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pending = PendingIntent.getActivity(
                this,
                0,
                prepareIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            startActivityAndCollapse(pending)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(prepareIntent)
        }
    }

    private fun render(state: VpnState) {
        val tile: Tile = qsTile ?: return
        try {
            val active = state == VpnState.RUNNING || state == VpnState.STARTING
            tile.state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
            tile.label = getString(
                when (state) {
                    VpnState.RUNNING -> R.string.tile_running
                    VpnState.STARTING -> R.string.tile_starting
                    VpnState.ERROR -> R.string.tile_error
                    VpnState.STOPPED -> R.string.tile_label
                }
            )
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                tile.subtitle = when (state) {
                    VpnState.RUNNING -> {
                        val profile = runCatching { AppGraph.config.current.profile.name.lowercase() }.getOrNull()
                        profile?.let { getString(R.string.tile_subtitle_profile, it) } ?: getString(R.string.tile_subtitle)
                    }

                    VpnState.STARTING -> getString(R.string.tile_starting)
                    VpnState.ERROR -> VpnController.error.value ?: getString(R.string.tile_error)
                    VpnState.STOPPED -> getString(R.string.tile_subtitle)
                }
            }
            runCatching { tile.icon = Icon.createWithResource(this, R.drawable.ic_tile_bolt) }
            tile.updateTile()
        } catch (e: Exception) {
            LogManager.d(LogTag.VPN, "Плитка не обновилась: ${e.message}")
        }
    }
}
