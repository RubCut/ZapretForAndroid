package dev.rubcut.zapret.ui

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.rubcut.zapret.R
import dev.rubcut.zapret.data.ThemeMode
import dev.rubcut.zapret.ui.theme.ZapretTheme
import dev.rubcut.zapret.vpn.VpnController

class MainActivity : ComponentActivity() {

    private val viewModel: AppViewModel by viewModels()

    private val vpnConsent =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == RESULT_OK) {
                VpnController.startNow(this)
            } else {
                VpnController.markError(getString(R.string.err_vpn_denied))
            }
        }

    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (!granted) viewModel.notify("Без уведомления Android может остановить туннель")
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val cfg by viewModel.config.collectAsStateWithLifecycle()
            val dark = when (cfg.theme) {
                ThemeMode.SYSTEM -> isSystemInDarkTheme()
                ThemeMode.LIGHT -> false
                ThemeMode.DARK -> true
            }
            ZapretTheme(
                darkTheme = dark,
                dynamicColor = cfg.dynamicColor,
                accent = cfg.accent
            ) {
                ZapretApp(
                    viewModel = viewModel,
                    onVpnPermission = { intent: Intent -> vpnConsent.launch(intent) },
                    onRequestNotificationPermission = {
                        notificationPermission.launch(android.Manifest.permission.POST_NOTIFICATIONS)
                    }
                )
            }
        }
    }
}
