package dev.rubcut.zapret.ui.screens

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowBack
import androidx.compose.material.icons.rounded.BatterySaver
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.DeleteForever
import androidx.compose.material.icons.rounded.Download
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Notifications
import androidx.compose.material.icons.rounded.Palette
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Upload
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavHostController
import dev.rubcut.zapret.BuildConfig
import dev.rubcut.zapret.R
import dev.rubcut.zapret.core.LogManager
import dev.rubcut.zapret.data.AccentPalette
import dev.rubcut.zapret.data.ThemeMode
import dev.rubcut.zapret.ui.AppViewModel
import dev.rubcut.zapret.ui.back
import dev.rubcut.zapret.ui.components.ClickableRow
import dev.rubcut.zapret.ui.components.ChipSelector
import dev.rubcut.zapret.ui.components.SectionCard
import dev.rubcut.zapret.ui.components.SwitchRow
import dev.rubcut.zapret.ui.theme.accentPreviewColor

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(vm: AppViewModel, navController: NavHostController) {
    val cfg by vm.config.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val supportsDynamic = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S

    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri -> uri?.let { writeText(context, it, vm.exportJson()) } }

    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> uri?.let { u -> readText(context, u)?.let { json -> vm.importConfig(json) } } }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings_title)) },
                navigationIcon = {
                    IconButton(onClick = { navController.back() }) {
                        Icon(Icons.Rounded.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent)
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            item {
                SectionCard(title = stringResource(R.string.settings_appearance), icon = Icons.Rounded.Palette) {
                    Text(stringResource(R.string.settings_theme), style = MaterialTheme.typography.titleSmall)
                    Spacer(Modifier.height(8.dp))
                    ChipSelector(
                        options = listOf(
                            stringResource(R.string.theme_system),
                            stringResource(R.string.theme_light),
                            stringResource(R.string.theme_dark)
                        ),
                        selectedIndex = ThemeMode.values().indexOf(cfg.theme),
                        onSelect = { i -> vm.setThemeMode(ThemeMode.values()[i]) }
                    )

                    if (supportsDynamic) {
                        Spacer(Modifier.height(12.dp))
                        SwitchRow(
                            title = stringResource(R.string.settings_dynamic_color),
                            subtitle = stringResource(R.string.settings_dynamic_color_hint),
                            checked = cfg.dynamicColor,
                            onCheckedChange = { vm.setDynamicColor(it) }
                        )
                    }

                    Spacer(Modifier.height(14.dp))
                    Text(stringResource(R.string.settings_accent), style = MaterialTheme.typography.titleSmall)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        stringResource(R.string.settings_accent_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        AccentPalette.values().forEach { palette ->
                            val selected = cfg.accent == palette && !(supportsDynamic && cfg.dynamicColor)
                            Box(
                                modifier = Modifier
                                    .size(42.dp)
                                    .clip(CircleShape)
                                    .background(accentPreviewColor(palette))
                                    .border(
                                        width = if (selected) 3.dp else 0.dp,
                                        color = if (selected) MaterialTheme.colorScheme.onSurface else Color.Transparent,
                                        shape = CircleShape
                                    )
                                    .clickable { vm.setAccent(palette) },
                                contentAlignment = Alignment.Center
                            ) {
                                if (selected) {
                                    Icon(
                                        Icons.Rounded.Check, contentDescription = null,
                                        tint = Color.White, modifier = Modifier.size(20.dp)
                                    )
                                }
                            }
                        }
                    }
                }
            }

            item {
                SectionCard(title = stringResource(R.string.settings_behavior), icon = Icons.Rounded.Settings) {
                    SwitchRow(
                        title = stringResource(R.string.settings_autostart),
                        subtitle = stringResource(R.string.settings_autostart_hint),
                        checked = cfg.autoStart,
                        onCheckedChange = { vm.setAutostart(it) }
                    )
                    SwitchRow(
                        title = stringResource(R.string.settings_notification),
                        checked = cfg.notificationEnabled,
                        onCheckedChange = { vm.setNotification(it) }
                    )
                    SwitchRow(
                        title = stringResource(R.string.settings_verbose_log),
                        subtitle = stringResource(R.string.settings_verbose_log_hint),
                        checked = cfg.verboseLog,
                        onCheckedChange = { vm.setVerboseLog(it) }
                    )
                }
            }

            item {
                SectionCard(title = stringResource(R.string.settings_group_system), icon = Icons.Rounded.Lock) {
                    ClickableRow(
                        title = stringResource(R.string.settings_battery),
                        subtitle = stringResource(R.string.settings_battery_hint),
                        icon = Icons.Rounded.BatterySaver,
                        onClick = { vm.openBatterySettings() }
                    )
                    ClickableRow(
                        title = stringResource(R.string.settings_always_on),
                        subtitle = stringResource(R.string.settings_always_on_hint),
                        icon = Icons.Rounded.Lock,
                        onClick = { vm.openAlwaysOnSettings() }
                    )
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        ClickableRow(
                            title = stringResource(R.string.settings_notification_permission),
                            subtitle = stringResource(R.string.settings_notification_permission_hint),
                            icon = Icons.Rounded.Notifications,
                            onClick = { vm.requestNotificationPermission() }
                        )
                    }
                    ClickableRow(
                        title = stringResource(R.string.settings_vpn_settings),
                        icon = Icons.Rounded.Settings,
                        onClick = { vm.openVpnSettings() }
                    )
                }
            }

            item {
                SectionCard(title = stringResource(R.string.settings_data), icon = Icons.Rounded.Upload) {
                    ClickableRow(
                        title = stringResource(R.string.settings_export_config),
                        subtitle = stringResource(R.string.settings_export_hint),
                        icon = Icons.Rounded.Download,
                        onClick = { runCatching { exportLauncher.launch("zapret-config.json") } }
                    )
                    ClickableRow(
                        title = stringResource(R.string.settings_import_config),
                        subtitle = stringResource(R.string.settings_import_hint),
                        icon = Icons.Rounded.Upload,
                        onClick = {
                            runCatching { importLauncher.launch(arrayOf("application/json", "text/plain", "*/*")) }
                        }
                    )
                    ClickableRow(
                        title = stringResource(R.string.settings_share_logs),
                        icon = Icons.Rounded.Notifications,
                        onClick = {
                            val text = LogManager.entries.value.joinToString("\n") {
                                "[${it.tag.label}] ${it.message}"
                            }
                            runCatching {
                                context.startActivity(
                                    Intent.createChooser(
                                        Intent(Intent.ACTION_SEND).apply {
                                            type = "text/plain"
                                            putExtra(Intent.EXTRA_TEXT, text)
                                        },
                                        null
                                    )
                                )
                            }
                        }
                    )
                    ClickableRow(
                        title = stringResource(R.string.settings_reset_all),
                        subtitle = stringResource(R.string.settings_reset_confirm),
                        icon = Icons.Rounded.DeleteForever,
                        onClick = { vm.resetLists() }
                    )
                }
            }

            item {
                Column(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        stringResource(R.string.app_full_name),
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.SemiBold
                    )
                    Spacer(Modifier.height(2.dp))
                    Text(
                        stringResource(R.string.about_version, BuildConfig.VERSION_NAME, BuildConfig.VERSION_CODE),
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.height(2.dp))
                    Text(
                        stringResource(R.string.about_license),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Android API ${Build.VERSION.SDK_INT} · build ${BuildConfig.BUILD_TYPE}",
                        style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                        color = MaterialTheme.colorScheme.outline
                    )
                }
            }
        }
    }
}

private fun writeText(context: Context, uri: Uri, text: String) {
    runCatching {
        context.contentResolver.openOutputStream(uri)?.use { it.write(text.toByteArray(Charsets.UTF_8)) }
    }
}

private fun readText(context: Context, uri: Uri): String? = runCatching {
    context.contentResolver.openInputStream(uri)?.use { it.readBytes().decodeToString() }
}.getOrNull()
