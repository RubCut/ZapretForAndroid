package dev.rubcut.zapret.ui.screens

import androidx.compose.foundation.Image
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Lan
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavHostController
import dev.rubcut.zapret.BuildConfig
import dev.rubcut.zapret.R
import dev.rubcut.zapret.data.AppScope
import dev.rubcut.zapret.ui.AppViewModel
import dev.rubcut.zapret.ui.back
import dev.rubcut.zapret.ui.components.ChipSelector
import dev.rubcut.zapret.ui.components.SectionCard
import dev.rubcut.zapret.ui.components.SliderRow
import dev.rubcut.zapret.ui.components.SwitchRow

private data class AppEntry(val pkg: String, val label: String)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NetworkScreen(vm: AppViewModel, navController: NavHostController) {
    val cfg by vm.config.collectAsStateWithLifecycle()
    var picking by remember { mutableStateOf(false) }
    val unitBytes = stringResource(R.string.unit_bytes_short)
    val unitSec = stringResource(R.string.unit_sec_short)
    val unitKib = stringResource(R.string.unit_kib)

    if (picking) {
        AppPicker(
            selected = cfg.appPackages.toSet(),
            onDone = { set -> vm.update { it.copy(appPackages = set.toList()) }; picking = false },
            onCancel = { picking = false }
        )
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.net_title)) },
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
                Text(
                    stringResource(R.string.net_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            item {
                SectionCard(title = stringResource(R.string.net_group_tunnel), icon = Icons.Rounded.Lan) {
                    SwitchRow(
                        title = stringResource(R.string.net_ipv4),
                        checked = cfg.ipv4,
                        onCheckedChange = { v -> vm.update { it.copy(ipv4 = v) } }
                    )
                    SwitchRow(
                        title = stringResource(R.string.net_ipv6),
                        subtitle = stringResource(R.string.net_ipv6_hint),
                        checked = cfg.ipv6,
                        onCheckedChange = { v -> vm.update { it.copy(ipv6 = v) } }
                    )
                    SliderRow(
                        title = stringResource(R.string.net_mtu),
                        subtitle = stringResource(R.string.net_mtu_hint),
                        value = cfg.mtu.toFloat(),
                        valueRange = 1280f..1500f,
                        steps = 21,
                        onValueChange = { v -> vm.update { it.copy(mtu = v.toInt()) } },
                        format = { "${it.toInt()} $unitBytes" }
                    )
                    SliderRow(
                        title = stringResource(R.string.net_mss),
                        subtitle = stringResource(R.string.net_mss_clamp_hint),
                        value = cfg.mssClamp.toFloat(),
                        valueRange = 536f..1460f,
                        steps = 91,
                        onValueChange = { v -> vm.update { it.copy(mssClamp = v.toInt()) } },
                        format = { "${it.toInt()} $unitBytes" }
                    )
                    Spacer(Modifier.height(8.dp))
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .background(MaterialTheme.colorScheme.surfaceContainerHigh)
                            .padding(12.dp)
                    ) {
                        Text(stringResource(R.string.net_tunnel_addresses), style = MaterialTheme.typography.labelLarge)
                        Spacer(Modifier.height(6.dp))
                        Text(
                            "IPv4: 10.211.0.1/32 · 0.0.0.0/0\nDNS: 10.211.0.2\nIPv6: fd61:7a6f:ee7::1/128 · ::/0",
                            style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            item {
                SectionCard(title = stringResource(R.string.net_apps), icon = Icons.Rounded.Apps) {
                    ChipSelector(
                        options = listOf(
                            stringResource(R.string.net_apps_all),
                            stringResource(R.string.net_apps_selected),
                            stringResource(R.string.net_apps_excluded)
                        ),
                        selectedIndex = AppScope.values().indexOf(cfg.appScope),
                        onSelect = { i -> vm.update { c -> c.copy(appScope = AppScope.values()[i]) } }
                    )
                    Spacer(Modifier.height(14.dp))
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .clickable(enabled = cfg.appScope != AppScope.ALL) { picking = true }
                            .background(
                                if (cfg.appScope == AppScope.ALL)
                                    MaterialTheme.colorScheme.surfaceContainerLow
                                else
                                    MaterialTheme.colorScheme.surfaceContainerHigh
                            )
                            .padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(
                                stringResource(R.string.net_apps_count, cfg.appPackages.size),
                                style = MaterialTheme.typography.bodyMedium
                            )
                            if (cfg.appScope == AppScope.ALL) {
                                Text(
                                    stringResource(R.string.net_app_scope_all_hint),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                        if (cfg.appScope != AppScope.ALL) {
                            Icon(Icons.Rounded.Tune, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                        }
                    }
                }
            }

            item {
                SectionCard(title = stringResource(R.string.net_advanced), icon = Icons.Rounded.Speed) {
                    SliderRow(
                        title = stringResource(R.string.net_conn_timeout),
                        value = cfg.connectTimeoutMs.toFloat(),
                        valueRange = 2000f..30000f,
                        onValueChange = { v -> vm.update { it.copy(connectTimeoutMs = v.toInt()) } },
                        format = { "${(it / 1000).toInt()} $unitSec" }
                    )
                    SliderRow(
                        title = stringResource(R.string.net_tcp_timeout),
                        value = cfg.tcpTimeoutSec.toFloat(),
                        valueRange = 30f..1800f,
                        onValueChange = { v -> vm.update { it.copy(tcpTimeoutSec = v.toInt()) } },
                        format = { "${it.toInt()} $unitSec" }
                    )
                    SliderRow(
                        title = stringResource(R.string.net_max_conns),
                        subtitle = stringResource(R.string.net_max_connections_hint),
                        value = cfg.maxConnections.toFloat(),
                        valueRange = 64f..2048f,
                        onValueChange = { v -> vm.update { it.copy(maxConnections = v.toInt()) } },
                        format = { it.toInt().toString() }
                    )
                    SliderRow(
                        title = stringResource(R.string.net_buffer),
                        value = cfg.sendBufferKb.toFloat(),
                        valueRange = 64f..1024f,
                        onValueChange = { v -> vm.update { it.copy(sendBufferKb = v.toInt()) } },
                        format = { "${it.toInt()} $unitKib" }
                    )
                    Text(
                        stringResource(R.string.net_advanced_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 10.dp)
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AppPicker(
    selected: Set<String>,
    onDone: (Set<String>) -> Unit,
    onCancel: () -> Unit
) {
    val context = LocalContext.current
    var query by remember { mutableStateOf("") }
    var checked by remember { mutableStateOf(selected) }

    val apps = remember {
        runCatching {
            val pm = context.packageManager
            pm.getInstalledApplications(0)
                .asSequence()
                .filter { it.packageName != BuildConfig.APPLICATION_ID }
                .mapNotNull { info ->
                    val launch = runCatching { pm.getLaunchIntentForPackage(info.packageName) }.getOrNull()
                    if (launch == null) return@mapNotNull null
                    AppEntry(info.packageName, info.loadLabel(pm).toString())
                }
                .sortedBy { it.label.lowercase() }
                .toList()
        }.getOrElse { emptyList() }
    }

    val filtered = remember(apps, query) {
        if (query.isBlank()) apps
        else apps.filter {
            it.label.contains(query, ignoreCase = true) || it.pkg.contains(query, ignoreCase = true)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(stringResource(R.string.net_apps_count, checked.size))
                },
                navigationIcon = {
                    IconButton(onClick = onCancel) {
                        Icon(Icons.Rounded.Close, contentDescription = stringResource(R.string.action_cancel))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent),
                actions = {
                    IconButton(onClick = { onDone(checked) }) {
                        Icon(
                            Icons.Rounded.Check, contentDescription = stringResource(R.string.action_save),
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            )
        }
    ) { padding ->
        Column(Modifier.padding(padding)) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
                placeholder = { Text(stringResource(R.string.action_search)) },
                leadingIcon = { Icon(Icons.Rounded.Search, contentDescription = null) },
                singleLine = true,
                shape = MaterialTheme.shapes.large
            )
            LazyColumn(contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp)) {
                items(filtered.size) { index ->
                    val app = filtered[index]
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(10.dp))
                            .clickable {
                                checked = if (app.pkg in checked) checked - app.pkg else checked + app.pkg
                            }
                            .padding(horizontal = 8.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        AppIcon(app.pkg)
                        Spacer(Modifier.width(14.dp))
                        Column(Modifier.weight(1f)) {
                            Text(
                                app.label,
                                style = MaterialTheme.typography.bodyMedium,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                app.pkg,
                                style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        Checkbox(
                            checked = app.pkg in checked,
                            onCheckedChange = null
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun AppIcon(pkg: String) {
    val context = LocalContext.current
    val bitmap = remember(pkg) {
        runCatching {
            context.packageManager.getApplicationIcon(pkg).toBitmap(64, 64).asImageBitmap()
        }.getOrNull()
    }
    Box(
        modifier = Modifier
            .size(40.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(MaterialTheme.colorScheme.surfaceContainerHighest),
        contentAlignment = Alignment.Center
    ) {
        if (bitmap != null) {
            Image(bitmap = bitmap, contentDescription = null, modifier = Modifier.size(40.dp))
        } else {
            Icon(
                Icons.Rounded.Apps, contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(20.dp)
            )
        }
    }
}
