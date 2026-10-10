package dev.rubcut.zapret.ui.screens

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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.ArrowBack
import androidx.compose.material.icons.rounded.ArrowDownward
import androidx.compose.material.icons.rounded.ArrowUpward
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.DragIndicator
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.FilterAlt
import androidx.compose.material.icons.rounded.Router
import androidx.compose.material.icons.rounded.Save
import androidx.compose.material.icons.rounded.Speed
import androidx.compose.material.icons.rounded.SwapVert
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavHostController
import dev.rubcut.zapret.R
import dev.rubcut.zapret.data.DesyncMode
import dev.rubcut.zapret.data.HostSource
import dev.rubcut.zapret.data.HostlistMode
import dev.rubcut.zapret.data.IpsetMode
import dev.rubcut.zapret.data.SplitPos
import dev.rubcut.zapret.data.Strategy
import dev.rubcut.zapret.data.StrategyRule
import dev.rubcut.zapret.data.UdpMode
import dev.rubcut.zapret.ui.AppViewModel
import dev.rubcut.zapret.ui.Routes
import dev.rubcut.zapret.ui.back
import dev.rubcut.zapret.ui.components.ChipSelector
import dev.rubcut.zapret.ui.components.InfoBanner
import dev.rubcut.zapret.ui.components.LabeledTextField
import dev.rubcut.zapret.ui.components.MultiChipSelector
import dev.rubcut.zapret.ui.components.SectionCard
import dev.rubcut.zapret.ui.components.SliderRow
import dev.rubcut.zapret.ui.components.SwitchRow

private val desyncModes = listOf(
    DesyncMode.NONE, DesyncMode.SPLIT, DesyncMode.MULTISPLIT,
    DesyncMode.TLSREC, DesyncMode.MULTISPLIT_TLSREC, DesyncMode.HOSTFAKESPLIT
)

private val desyncLabels = listOf(
    R.string.desync_none, R.string.desync_split, R.string.desync_multisplit,
    R.string.desync_tlsrec, R.string.desync_multitlsrec, R.string.desync_hostfakesplit
)

private val splitPositions = listOf(
    SplitPos.FIRST, SplitPos.MIDSNI, SplitPos.SNIEND, SplitPos.MIDDLE, SplitPos.CUSTOM
)

private val splitPosLabels = listOf(
    R.string.split_pos_1, R.string.split_pos_midsni, R.string.split_pos_sniend,
    R.string.split_pos_middle, R.string.split_pos_custom
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StrategyScreen(vm: AppViewModel, navController: NavHostController) {
    val cfg by vm.config.collectAsStateWithLifecycle()
    val unitSec = stringResource(R.string.unit_sec_short)
    val udpTimeoutFormat: (Float) -> String = { "${it.toInt()} $unitSec" }
    var editing by remember { mutableStateOf<StrategyRule?>(null) }

    if (editing != null) {
        RuleEditor(
            rule = editing!!,
            onSave = { vm.upsertRule(it); editing = null },
            onDelete = { editing?.let { r -> vm.deleteRule(r.id) }; editing = null },
            onCancel = { editing = null }
        )
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.strategy_title)) },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent),
                actions = {
                    IconButton(onClick = { navController.navigate(Routes.ARGS) }) {
                        Icon(Icons.Rounded.Tune, contentDescription = stringResource(R.string.args_title))
                    }
                }
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
                    stringResource(R.string.strategy_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            item {
                val apRunning by vm.autopilotRunning.collectAsStateWithLifecycle()
                val apResult by vm.autopilotResult.collectAsStateWithLifecycle()
                val apProgress by vm.autopilotProgress.collectAsStateWithLifecycle()
                SectionCard(title = stringResource(R.string.autopilot_title), icon = Icons.Rounded.Speed) {
                    Text(
                        stringResource(R.string.autopilot_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.height(10.dp))
                    Button(
                        onClick = { vm.runAutopilot() },
                        enabled = !apRunning,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(if (apRunning) stringResource(R.string.autopilot_running) else stringResource(R.string.autopilot_start))
                    }
                    // Живой прогресс: подбор занимает минуты, и без этой строки
                    // экран выглядит зависшим на все время проверки.
                    if (apRunning && apProgress != null) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            apProgress!!,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                    if (apResult != null) {
                        Spacer(Modifier.height(8.dp))
                        InfoBanner(apResult!!)
                    }
                }
            }

            item {
                SectionCard(
                    title = stringResource(R.string.strategy_group_desync),
                    icon = Icons.Rounded.Speed,
                    subtitle = stringResource(R.string.strategy_desync_hint)
                ) {
                    StrategyControls(
                        strategy = cfg.toStrategy(),
                        onChange = { s ->
                            vm.updateStrategy { c ->
                                c.copy(
                                    desync = s.desync,
                                    splitPositions = s.splitPositions,
                                    splitCustomPos = s.splitCustomPos,
                                    splitDelayMs = s.splitDelayMs,
                                    tlsrecParts = s.tlsrecParts,
                                    wssizeEnabled = s.wssizeEnabled,
                                    wssizePackets = s.wssizePackets,
                                    wssizeWindow = s.wssizeWindow,
                                    anyProtocol = s.anyProtocol,
                                    sniCaseMix = s.sniCaseMix,
                                    poisonEnabled = s.poisonEnabled,
                                    poisonSni = s.poisonSni,
                                    poisonDelayMs = s.poisonDelayMs
                                )
                            }
                        }
                    )
                    SliderRow(
                        title = stringResource(R.string.strategy_cutoff),
                        subtitle = stringResource(R.string.strategy_cutoff_hint),
                        value = cfg.cutoffChunks.toFloat(),
                        valueRange = 1f..12f,
                        steps = 10,
                        onValueChange = { v -> vm.updateStrategy { it.copy(cutoffChunks = v.toInt()) } }
                    )
                }
            }

            item {
                SectionCard(
                    title = stringResource(R.string.strategy_rules_title),
                    icon = Icons.Rounded.DragIndicator,
                    subtitle = stringResource(R.string.strategy_rules_subtitle)
                ) {
                    if (cfg.rules.isEmpty()) {
                        Text(
                            stringResource(R.string.strategy_rules_empty),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    } else {
                        cfg.rules.forEachIndexed { index, rule ->
                            RuleRow(
                                rule = rule,
                                index = index,
                                total = cfg.rules.size,
                                onToggle = { vm.upsertRule(rule.copy(enabled = !rule.enabled)) },
                                onEdit = { editing = rule },
                                onMove = { delta -> vm.moveRule(rule.id, delta) },
                                onDelete = { vm.deleteRule(rule.id) }
                            )
                        }
                    }
                    Spacer(Modifier.height(12.dp))
                    Button(
                        onClick = { editing = StrategyRule(name = "", strategy = cfg.toStrategy()) },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Rounded.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.action_add))
                    }
                }
            }

            item {
                SectionCard(title = stringResource(R.string.strategy_group_filter), icon = Icons.Rounded.FilterAlt) {
                    LabeledTextField(
                        label = stringResource(R.string.strategy_tcp_ports),
                        value = cfg.tcpPorts,
                        onValueChange = { v -> vm.updateStrategy { it.copy(tcpPorts = v) } },
                        monospace = true,
                        placeholder = "80,443,2053-2096",
                        supportingText = stringResource(R.string.strategy_ports_hint)
                    )
                    Spacer(Modifier.height(10.dp))
                    LabeledTextField(
                        label = stringResource(R.string.strategy_udp_ports),
                        value = cfg.udpPorts,
                        onValueChange = { v -> vm.updateStrategy { it.copy(udpPorts = v) } },
                        monospace = true,
                        placeholder = "443,19294-19344"
                    )
                    Spacer(Modifier.height(14.dp))
                    Text(
                        stringResource(R.string.strategy_hostlist_mode),
                        style = MaterialTheme.typography.titleSmall
                    )
                    Spacer(Modifier.height(8.dp))
                    ChipSelector(
                        options = listOf(
                            stringResource(R.string.hostlist_mode_off),
                            stringResource(R.string.hostlist_mode_include),
                            stringResource(R.string.hostlist_mode_exclude)
                        ),
                        selectedIndex = HostlistMode.values().indexOf(cfg.hostlistMode),
                        onSelect = { i -> vm.updateStrategy { it.copy(hostlistMode = HostlistMode.values()[i]) } }
                    )
                    Spacer(Modifier.height(14.dp))
                    ChipSelector(
                        options = listOf(
                            "ipset: " + stringResource(R.string.hostlist_mode_off),
                            stringResource(R.string.lists_ipset_title),
                            stringResource(R.string.lists_ipset_exclude_title)
                        ),
                        selectedIndex = IpsetMode.values().indexOf(cfg.ipsetMode),
                        onSelect = { i -> vm.updateStrategy { it.copy(ipsetMode = IpsetMode.values()[i]) } }
                    )
                }
            }

            item {
                SectionCard(title = stringResource(R.string.strategy_group_udp), icon = Icons.Rounded.SwapVert) {
                    SwitchRow(
                        title = stringResource(R.string.strategy_block_quic),
                        subtitle = stringResource(R.string.strategy_block_quic_hint),
                        checked = cfg.blockQuic,
                        onCheckedChange = { v -> vm.updateStrategy { it.copy(blockQuic = v) } }
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(stringResource(R.string.strategy_udp_mode), style = MaterialTheme.typography.titleSmall)
                    Spacer(Modifier.height(8.dp))
                    ChipSelector(
                        options = listOf(
                            stringResource(R.string.udp_mode_relay),
                            stringResource(R.string.udp_mode_block_filtered),
                            stringResource(R.string.udp_mode_block_all)
                        ),
                        selectedIndex = UdpMode.values().indexOf(cfg.udpMode),
                        onSelect = { i -> vm.updateStrategy { it.copy(udpMode = UdpMode.values()[i]) } }
                    )
                    SliderRow(
                        title = stringResource(R.string.strategy_udp_timeout),
                        value = cfg.udpTimeoutSec.toFloat(),
                        valueRange = 10f..600f,
                        onValueChange = { v -> vm.updateStrategy { it.copy(udpTimeoutSec = v.toInt()) } },
                        format = udpTimeoutFormat
                    )
                }
            }

            item {
                InfoBanner(stringResource(R.string.home_no_root_note), icon = Icons.Rounded.Router)
            }
        }
    }
}

/* ------------------------------------------------------------------ */

@Composable
fun StrategyControls(strategy: Strategy, onChange: (Strategy) -> Unit) {
    val unitBytes = stringResource(R.string.unit_bytes_short)
    val unitMs = stringResource(R.string.unit_ms_short)
    val unitPackets = stringResource(R.string.unit_packets_short)

    ChipSelector(
        options = desyncLabels.map { stringResource(it) },
        selectedIndex = desyncModes.indexOf(strategy.desync).coerceAtLeast(0),
        onSelect = { i -> onChange(strategy.copy(desync = desyncModes[i])) }
    )

    Spacer(Modifier.height(16.dp))
    Text(stringResource(R.string.strategy_split_pos), style = MaterialTheme.typography.titleSmall)
    Spacer(Modifier.height(4.dp))
    Text(
        stringResource(R.string.strategy_split_pos_hint),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    Spacer(Modifier.height(8.dp))
    MultiChipSelector(
        options = splitPosLabels.mapIndexed { i, res -> stringResource(res) to strategy.splitPositions.contains(splitPositions[i]) },
        onToggle = { i ->
            val pos = splitPositions[i]
            val next = if (strategy.splitPositions.contains(pos)) strategy.splitPositions - pos
            else strategy.splitPositions + pos
            onChange(strategy.copy(splitPositions = next))
        }
    )

    if (strategy.splitPositions.contains(SplitPos.CUSTOM)) {
        SliderRow(
            title = stringResource(R.string.strategy_split_custom_pos),
            value = strategy.splitCustomPos.toFloat().coerceIn(1f, 1500f),
            valueRange = 1f..1500f,
            onValueChange = { v -> onChange(strategy.copy(splitCustomPos = v.toInt())) },
            format = { "${it.toInt()} $unitBytes" }
        )
    }

    val tlsMode = strategy.desync == DesyncMode.TLSREC || strategy.desync == DesyncMode.MULTISPLIT_TLSREC
    if (tlsMode) {
        SliderRow(
            title = stringResource(R.string.strategy_tlsrec_size),
            subtitle = stringResource(R.string.strategy_tlsrec_hint),
            value = strategy.tlsrecParts.coerceAtLeast(2).toFloat(),
            valueRange = 2f..8f,
            steps = 5,
            onValueChange = { v -> onChange(strategy.copy(tlsrecParts = v.toInt())) },
            format = { "x${it.toInt()}" }
        )
    }

    SliderRow(
        title = stringResource(R.string.strategy_split_delay),
        subtitle = stringResource(R.string.strategy_split_delay_hint),
        value = strategy.splitDelayMs.toFloat(),
        valueRange = 0f..50f,
        onValueChange = { v -> onChange(strategy.copy(splitDelayMs = v.toInt())) },
        format = { "${it.toInt()} $unitMs" }
    )

    SwitchRow(
        title = stringResource(R.string.strategy_wssize),
        subtitle = stringResource(R.string.strategy_wssize_hint),
        checked = strategy.wssizeEnabled,
        onCheckedChange = { v -> onChange(strategy.copy(wssizeEnabled = v)) }
    )
    if (strategy.wssizeEnabled) {
        SliderRow(
            title = stringResource(R.string.strategy_wssize_bytes),
            value = strategy.wssizePackets.toFloat(),
            valueRange = 1f..40f,
            steps = 38,
            onValueChange = { v -> onChange(strategy.copy(wssizePackets = v.toInt())) },
            format = { "${it.toInt()} $unitPackets" }
        )
        SliderRow(
            title = stringResource(R.string.strategy_wssize_window),
            value = strategy.wssizeWindow.toFloat(),
            valueRange = 2048f..65535f,
            onValueChange = { v -> onChange(strategy.copy(wssizeWindow = v.toInt())) },
            format = { "${it.toInt()} $unitBytes" }
        )
    }

    SwitchRow(
        title = stringResource(R.string.strategy_any_protocol),
        checked = strategy.anyProtocol,
        onCheckedChange = { v -> onChange(strategy.copy(anyProtocol = v)) }
    )
    SwitchRow(
        title = stringResource(R.string.strategy_poison),
        checked = strategy.poisonEnabled,
        onCheckedChange = { v -> onChange(strategy.copy(poisonEnabled = v)) },
        subtitle = stringResource(R.string.strategy_poison_hint)
    )
    if (strategy.poisonEnabled) {
        SliderRow(
            title = stringResource(R.string.strategy_poison_delay),
            value = strategy.poisonDelayMs.toFloat().coerceIn(0f, 500f),
            valueRange = 0f..500f,
            onValueChange = { v -> onChange(strategy.copy(poisonDelayMs = v.toInt())) },
            format = { "${it.toInt()} мс" }
        )
    }
    SwitchRow(
        title = stringResource(R.string.strategy_case_mix),
        checked = strategy.sniCaseMix,
        onCheckedChange = { v -> onChange(strategy.copy(sniCaseMix = v)) },
        subtitle = stringResource(R.string.strategy_case_mix_hint)
    )
}

/* ------------------------------------------------------------------ */

@Composable
private fun RuleRow(
    rule: StrategyRule,
    index: Int,
    total: Int,
    onToggle: () -> Unit,
    onEdit: () -> Unit,
    onMove: (Int) -> Unit,
    onDelete: () -> Unit
) {
    val scheme = MaterialTheme.colorScheme
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 5.dp),
        shape = MaterialTheme.shapes.medium,
        colors = CardDefaults.cardColors(
            containerColor = if (rule.enabled) scheme.surfaceContainerHigh else scheme.surfaceContainerLow
        ),
        elevation = CardDefaults.cardElevation(0.dp)
    ) {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(9.dp)
                        .clip(CircleShape)
                        .background(if (rule.enabled) scheme.primary else scheme.outlineVariant)
                )
                Spacer(Modifier.width(10.dp))
                Text(
                    rule.name.ifBlank { stringResource(R.string.rule_index, index + 1) },
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Switch(checked = rule.enabled, onCheckedChange = { onToggle() })
            }
            Spacer(Modifier.height(6.dp))
            Text(
                buildString {
                    if (rule.tcpPorts.isNotBlank()) append("tcp=").append(rule.tcpPorts).append("  ")
                    if (rule.udpPorts.isNotBlank()) append("udp=").append(rule.udpPorts).append("  ")
                    append(hostSourceLabel(rule.hostSource))
                },
                style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                color = scheme.onSurfaceVariant
            )
            Text(
                rule.strategy.describe(),
                style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                color = if (rule.enabled) scheme.primary else scheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
            Spacer(Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = { onMove(-1) }, enabled = index > 0) {
                    Icon(Icons.Rounded.ArrowUpward, contentDescription = null, modifier = Modifier.size(17.dp))
                }
                IconButton(onClick = { onMove(1) }, enabled = index < total - 1) {
                    Icon(Icons.Rounded.ArrowDownward, contentDescription = null, modifier = Modifier.size(17.dp))
                }
                Spacer(Modifier.weight(1f))
                IconButton(onClick = onDelete) {
                    Icon(
                        Icons.Rounded.Delete, contentDescription = stringResource(R.string.action_delete),
                        tint = scheme.error, modifier = Modifier.size(18.dp)
                    )
                }
                FilledTonalButton(onClick = onEdit) {
                    Icon(Icons.Rounded.Edit, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(R.string.action_edit))
                }
            }
        }
    }
}

@Composable
private fun hostSourceLabel(source: HostSource): String = stringResource(
    when (source) {
        HostSource.ANY -> R.string.hostsrc_any
        HostSource.HOSTLIST -> R.string.hostsrc_hostlist
        HostSource.GENERAL -> R.string.hostsrc_general
        HostSource.GOOGLE -> R.string.hostsrc_google
        HostSource.DISCORD -> R.string.hostsrc_discord
        HostSource.INLINE -> R.string.hostsrc_inline
    }
)

/* ------------------------------------------------------------------ */

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RuleEditor(
    rule: StrategyRule,
    onSave: (StrategyRule) -> Unit,
    onDelete: () -> Unit,
    onCancel: () -> Unit
) {
    var draft by remember(rule.id) { mutableStateOf(rule) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.rule_editor_title)) },
                navigationIcon = {
                    IconButton(onClick = onCancel) {
                        Icon(Icons.Rounded.ArrowBack, contentDescription = stringResource(R.string.action_cancel))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent),
                actions = {
                    IconButton(onClick = { onSave(draft) }) {
                        Icon(
                            Icons.Rounded.Save, contentDescription = stringResource(R.string.action_save),
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 32.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            item {
                SectionCard(title = stringResource(R.string.rule_filter_title), icon = Icons.Rounded.FilterAlt) {
                    LabeledTextField(
                        label = stringResource(R.string.rule_name_label),
                        value = draft.name,
                        onValueChange = { draft = draft.copy(name = it) }
                    )
                    Spacer(Modifier.height(10.dp))
                    LabeledTextField(
                        label = stringResource(R.string.strategy_tcp_ports),
                        value = draft.tcpPorts,
                        onValueChange = { draft = draft.copy(tcpPorts = it) },
                        monospace = true,
                        supportingText = stringResource(R.string.rule_tcp_hint)
                    )
                    Spacer(Modifier.height(10.dp))
                    LabeledTextField(
                        label = stringResource(R.string.strategy_udp_ports),
                        value = draft.udpPorts,
                        onValueChange = { draft = draft.copy(udpPorts = it) },
                        monospace = true,
                        supportingText = stringResource(R.string.rule_udp_hint)
                    )
                }
            }

            item {
                SectionCard(title = stringResource(R.string.rule_hosts_title), icon = Icons.Rounded.FilterAlt) {
                    ChipSelector(
                        options = HostSource.values().map { hostSourceLabel(it) },
                        selectedIndex = HostSource.values().indexOf(draft.hostSource),
                        onSelect = { i -> draft = draft.copy(hostSource = HostSource.values()[i]) }
                    )
                    if (draft.hostSource == HostSource.INLINE) {
                        Spacer(Modifier.height(12.dp))
                        LabeledTextField(
                            label = stringResource(R.string.rule_domains_label),
                            value = draft.inlineDomains,
                            onValueChange = { draft = draft.copy(inlineDomains = it) },
                            singleLine = false,
                            minLines = 4,
                            monospace = true
                        )
                    }
                    Spacer(Modifier.height(12.dp))
                    LabeledTextField(
                        label = stringResource(R.string.lists_exclude_title),
                        value = draft.excludeDomains,
                        onValueChange = { draft = draft.copy(excludeDomains = it) },
                        singleLine = false,
                        minLines = 2,
                        monospace = true
                    )
                }
            }

            item {
                SectionCard(
                    title = stringResource(R.string.strategy_group_desync),
                    icon = Icons.Rounded.Speed,
                    subtitle = stringResource(R.string.strategy_desync_hint)
                ) {
                    StrategyControls(
                        strategy = draft.strategy,
                        onChange = { draft = draft.copy(strategy = it) }
                    )
                }
            }

            item {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f)) {
                        Text(stringResource(R.string.action_cancel))
                    }
                    Button(onClick = { onSave(draft) }, modifier = Modifier.weight(1f)) {
                        Icon(Icons.Rounded.Save, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.action_save))
                    }
                }
            }

            item {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(MaterialTheme.colorScheme.surfaceContainerHigh)
                        .clickable(onClick = onDelete)
                        .padding(14.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        stringResource(R.string.action_delete),
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.SemiBold,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
    }
}
