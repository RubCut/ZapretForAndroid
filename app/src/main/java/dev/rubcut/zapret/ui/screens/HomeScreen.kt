package dev.rubcut.zapret.ui.screens

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Bolt
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.NotificationsActive
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.SwapVert
import androidx.compose.material.icons.rounded.VpnKey
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationManagerCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavHostController
import dev.rubcut.zapret.R
import dev.rubcut.zapret.core.RecentConnection
import dev.rubcut.zapret.core.StatsSnapshot
import dev.rubcut.zapret.core.formatBytes
import dev.rubcut.zapret.core.formatUptime
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.ProfileId
import dev.rubcut.zapret.ui.AppViewModel
import dev.rubcut.zapret.ui.Routes
import dev.rubcut.zapret.ui.components.InfoBanner
import dev.rubcut.zapret.ui.components.SectionCard
import dev.rubcut.zapret.vpn.VpnState
import kotlinx.coroutines.delay
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    vm: AppViewModel,
    navController: NavHostController,
    onVpnPermission: (Intent) -> Unit,
    onRequestNotificationPermission: () -> Unit
) {
    val context = LocalContext.current
    val cfg by vm.config.collectAsStateWithLifecycle()
    val state by vm.vpnState.collectAsStateWithLifecycle()
    val error by vm.vpnError.collectAsStateWithLifecycle()
    val stats by vm.stats.collectAsStateWithLifecycle()
    val recent by vm.recent.collectAsStateWithLifecycle()

    var tick by remember { mutableIntStateOf(0) }
    LaunchedEffect(state) {
        while (true) {
            delay(1000)
            tick++
        }
    }

    val running = state == VpnState.RUNNING
    val starting = state == VpnState.STARTING

    fun power() {
        if (running) {
            vm.stopTunnel(context)
            return
        }
        if (cfg.profile == ProfileId.OFF) vm.setProfile(ProfileId.COMBINED)
        val consent = vm.prepareIntent(context)
        if (consent != null) onVpnPermission(consent) else vm.startTunnel(context)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            stringResource(R.string.app_full_name),
                            style = MaterialTheme.typography.titleLarge
                        )
                        Text(
                            stringResource(
                                when (state) {
                                    VpnState.STOPPED -> R.string.home_state_off
                                    VpnState.STARTING -> R.string.home_state_starting
                                    VpnState.RUNNING -> R.string.home_state_on
                                    VpnState.ERROR -> R.string.home_state_error
                                }
                            ),
                            style = MaterialTheme.typography.bodySmall,
                            color = when (state) {
                                VpnState.RUNNING -> MaterialTheme.colorScheme.primary
                                VpnState.ERROR -> MaterialTheme.colorScheme.error
                                else -> MaterialTheme.colorScheme.onSurfaceVariant
                            }
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = Color.Transparent,
                    scrolledContainerColor = Color.Transparent
                )
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
            item { PowerCard(running = running, starting = starting, onClick = ::power) }

            if (state == VpnState.ERROR && !error.isNullOrEmpty()) {
                item {
                    InfoBanner(
                        text = stringResource(R.string.err_vpn_start, error ?: ""),
                        icon = Icons.Rounded.ErrorOutline,
                        containerColor = MaterialTheme.colorScheme.errorContainer,
                        contentColor = MaterialTheme.colorScheme.onErrorContainer
                    )
                }
            }

            item { StatsGrid(stats, tick) }

            item { ProfileCard(cfg, running) { navController.navigate(Routes.PROFILES) } }

            if (recent.isNotEmpty()) {
                item {
                    SectionCard(
                        title = stringResource(R.string.home_recent),
                        icon = Icons.Rounded.SwapVert,
                        subtitle = null
                    ) {
                        recent.take(6).forEachIndexed { index, entry ->
                            if (index > 0) Spacer(Modifier.height(10.dp))
                            RecentRow(entry)
                        }
                    }
                }
            } else {
                item {
                    InfoBanner(
                        text = stringResource(R.string.home_recent_empty),
                        icon = Icons.Rounded.Public
                    )
                }
            }

            item {
                ChecklistCard(
                    notificationsGranted = remember(state, tick) {
                        if (Build.VERSION.SDK_INT < 33) true
                        else NotificationManagerCompat.from(context).areNotificationsEnabled()
                    },
                    onGrantNotifications = onRequestNotificationPermission,
                    batteryGranted = remember(state, tick) {
                        val pm = context.getSystemService(PowerManager::class.java)
                        pm?.isIgnoringBatteryOptimizations(context.packageName) ?: false
                    },
                    onBattery = {
                        runCatching {
                            val i = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                                .setData(Uri.parse("package:${context.packageName}"))
                            context.startActivity(i)
                        }.onFailure {
                            runCatching { context.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) }
                        }
                    },
                    onAlwaysOn = {
                        runCatching { context.startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }
                    }
                )
            }

            item { InfoBanner(stringResource(R.string.home_no_root_note), icon = Icons.Rounded.VpnKey) }
        }
    }
}

/* ------------------------------------------------------------------ */

@Composable
private fun PowerCard(running: Boolean, starting: Boolean, onClick: () -> Unit) {
    val scheme = MaterialTheme.colorScheme
    val scale by animateFloatAsState(
        targetValue = if (running) 1f else 0.88f,
        animationSpec = spring(dampingRatio = 0.55f, stiffness = 260f),
        label = "dial"
    )
    val transition = rememberInfiniteTransition(label = "halo")
    val pulse by transition.animateFloat(
        initialValue = 0.75f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1800), RepeatMode.Reverse),
        label = "pulse"
    )

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.extraLarge,
        colors = CardDefaults.cardColors(containerColor = scheme.surfaceContainerHigh),
        elevation = CardDefaults.cardElevation(0.dp)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    Brush.verticalGradient(
                        listOf(
                            if (running) scheme.primaryContainer.copy(alpha = 0.55f) else scheme.surfaceContainerHigh,
                            scheme.surfaceContainerHigh
                        )
                    )
                )
                .padding(vertical = 26.dp),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Box(contentAlignment = Alignment.Center) {
                    if (running || starting) {
                        Box(
                            modifier = Modifier
                                .size((196 * pulse).dp)
                                .clip(CircleShape)
                                .background(
                                    Brush.radialGradient(
                                        listOf(scheme.primary.copy(alpha = 0.30f), Color.Transparent)
                                    )
                                )
                        )
                    }
                    Box(
                        modifier = Modifier
                            .size(148.dp)
                            .scale(scale)
                            .clip(CircleShape)
                            .background(
                                Brush.linearGradient(
                                    listOf(
                                        if (running) scheme.primary else scheme.surfaceVariant,
                                        if (running) scheme.tertiary else scheme.surfaceContainerHighest
                                    )
                                )
                            )
                            .clickable(onClick = onClick),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            Icons.Rounded.Bolt,
                            contentDescription = null,
                            tint = if (running) scheme.onPrimary else scheme.onSurfaceVariant,
                            modifier = Modifier.size(62.dp)
                        )
                    }
                }
                Spacer(Modifier.height(22.dp))
                Text(
                    stringResource(
                        when {
                            starting -> R.string.home_state_starting
                            running -> R.string.home_state_on
                            else -> R.string.home_state_off
                        }
                    ),
                    style = MaterialTheme.typography.headlineSmall,
                    color = if (running) scheme.primary else scheme.onSurface
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    stringResource(if (running) R.string.home_power_stop else R.string.home_power_start),
                    style = MaterialTheme.typography.bodySmall,
                    color = scheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun StatsGrid(stats: StatsSnapshot, tick: Int) {
    val scheme = MaterialTheme.colorScheme
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatTile(
                modifier = Modifier.weight(1f),
                icon = Icons.Rounded.Speed,
                label = stringResource(R.string.home_stats_connections),
                value = "${stats.activeConnections}",
                tint = scheme.primary
            )
            StatTile(
                modifier = Modifier.weight(1f),
                icon = Icons.Rounded.SwapVert,
                label = stringResource(R.string.home_stats_traffic_down),
                value = formatBytes(stats.bytesDown),
                tint = scheme.tertiary
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatTile(
                modifier = Modifier.weight(1f),
                icon = Icons.Rounded.Bolt,
                label = stringResource(R.string.home_stats_desynced),
                value = "${stats.desyncedConnections}",
                tint = scheme.secondary
            )
            StatTile(
                modifier = Modifier.weight(1f),
                icon = Icons.Rounded.Dns,
                label = stringResource(R.string.home_stats_dns),
                value = "${stats.dnsQueries}",
                tint = scheme.primary
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatTile(
                modifier = Modifier.weight(1f),
                icon = Icons.Rounded.Public,
                label = stringResource(R.string.home_stats_traffic_up),
                value = formatBytes(stats.bytesUp),
                tint = scheme.secondary
            )
            StatTile(
                modifier = Modifier.weight(1f),
                icon = Icons.Rounded.Speed,
                label = stringResource(R.string.home_stats_uptime),
                value = formatUptime(if (tick >= 0) stats.uptimeMs else 0L),
                tint = scheme.tertiary
            )
        }
    }
}

@Composable
private fun StatTile(
    modifier: Modifier = Modifier,
    icon: ImageVector,
    label: String,
    value: String,
    tint: Color
) {
    Card(
        modifier = modifier,
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
        elevation = CardDefaults.cardElevation(0.dp)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(38.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(tint.copy(alpha = 0.16f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(20.dp))
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    value,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    label,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

@Composable
private fun ProfileCard(cfg: AppConfig, running: Boolean, onClick: () -> Unit) {
    val name = stringResource(
        when (cfg.profile) {
            ProfileId.OFF -> R.string.profile_off
            ProfileId.YOUTUBE -> R.string.profile_youtube
            ProfileId.DISCORD -> R.string.profile_discord
            ProfileId.COMBINED -> R.string.profile_combined
            ProfileId.MAX -> R.string.profile_max
            ProfileId.CUSTOM -> R.string.profile_custom
        }
    )
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.large)
            .clickable(onClick = onClick),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
        elevation = CardDefaults.cardElevation(0.dp)
    ) {
      Column(Modifier.padding(18.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.Rounded.Bolt, contentDescription = null,
                tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp)
            )
            Spacer(Modifier.width(10.dp))
            Text(
                stringResource(R.string.home_active_profile),
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.weight(1f)
            )
            Text(
                name,
                style = MaterialTheme.typography.titleMedium,
                color = if (running) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
            )
        }
        Spacer(Modifier.height(12.dp))
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    cfg.toStrategy().describe(),
                    style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    buildString {
                        append("tcp: ").append(cfg.tcpPorts.ifBlank { "*" })
                        append("  ·  udp: ").append(cfg.udpPorts.ifBlank { "*" })
                        append("  ·  правил: ").append(cfg.rules.size)
                    },
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
      }
    }
}

@Composable
private fun RecentRow(entry: RecentConnection) {
    val scheme = MaterialTheme.colorScheme
    val time = remember(entry.at) {
        SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(entry.at))
    }
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(if (entry.applied) scheme.primary else scheme.outlineVariant)
            )
            Spacer(Modifier.width(10.dp))
            Text(
                entry.host,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Medium,
                modifier = Modifier.weight(1f),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Spacer(Modifier.width(8.dp))
            Text(
                time,
                style = MaterialTheme.typography.labelSmall,
                color = scheme.onSurfaceVariant,
                fontFamily = FontFamily.Monospace
            )
        }
        if (entry.technique != null) {
            Spacer(Modifier.height(3.dp))
            Text(
                "${if (entry.v6) "IPv6" else "IPv4"} · :${entry.port} · ${entry.technique}",
                style = MaterialTheme.typography.bodySmall.copy(fontSize = 11.sp),
                color = scheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun ChecklistCard(
    notificationsGranted: Boolean,
    onGrantNotifications: () -> Unit,
    batteryGranted: Boolean,
    onBattery: () -> Unit,
    onAlwaysOn: () -> Unit
) {
    SectionCard(title = stringResource(R.string.home_checklist), icon = Icons.Rounded.CheckCircle) {
        ChecklistRow(
            title = stringResource(R.string.home_check_notification),
            done = notificationsGranted,
            onClick = onGrantNotifications
        )
        ChecklistRow(
            title = stringResource(R.string.home_check_battery),
            done = batteryGranted,
            onClick = onBattery
        )
        ChecklistRow(
            title = stringResource(R.string.home_check_alwayson),
            done = false,
            alwaysAvailable = true,
            onClick = onAlwaysOn
        )
    }
}

@Composable
private fun ChecklistRow(title: String, done: Boolean, alwaysAvailable: Boolean = false, onClick: () -> Unit) {
    val scheme = MaterialTheme.colorScheme
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .clickable(onClick = onClick)
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            if (done) Icons.Rounded.CheckCircle else Icons.Rounded.NotificationsActive,
            contentDescription = null,
            tint = if (done) scheme.primary else if (alwaysAvailable) scheme.outline else scheme.error,
            modifier = Modifier.size(20.dp)
        )
        Spacer(Modifier.width(12.dp))
        Text(title, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Text(
            stringResource(if (done) R.string.home_check_done else R.string.home_check_todo),
            style = MaterialTheme.typography.labelSmall,
            color = if (done) scheme.primary else scheme.onSurfaceVariant
        )
    }
}
