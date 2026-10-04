package dev.rubcut.zapret.ui.screens

import android.content.Intent
import androidx.compose.foundation.background
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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Pause
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavHostController
import dev.rubcut.zapret.R
import dev.rubcut.zapret.core.LogEntry
import dev.rubcut.zapret.core.LogManager
import dev.rubcut.zapret.core.LogTag
import dev.rubcut.zapret.ui.AppViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import dev.rubcut.zapret.ui.back

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogsScreen(vm: AppViewModel, navController: NavHostController) {
    val entries by LogManager.entries.collectAsStateWithLifecycle()
    var filter by remember { mutableStateOf<LogTag?>(null) }
    var errorsOnly by remember { mutableStateOf(false) }
    var autoscroll by remember { mutableStateOf(true) }
    var paused by remember { mutableStateOf(false) }
    var frozen by remember { mutableStateOf<List<LogEntry>>(emptyList()) }
    val listState = rememberLazyListState()
    val context = LocalContext.current
    val scheme = MaterialTheme.colorScheme

    val visible = remember(entries, filter, errorsOnly, paused, frozen) {
        val source = if (paused) frozen else entries
        source.filter { entry ->
            (filter == null || entry.tag == filter) &&
                (!errorsOnly || entry.tag == LogTag.WARN || entry.tag == LogTag.ERR)
        }
    }

    LaunchedEffect(visible.size, autoscroll) {
        if (autoscroll && visible.isNotEmpty()) {
            listState.animateScrollToItem(visible.size - 1)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.logs_title)) },
                navigationIcon = {
                    IconButton(onClick = { navController.back() }) {
                        Icon(Icons.Rounded.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent),
                actions = {
                    IconButton(onClick = {
                        if (!paused) frozen = entries
                        paused = !paused
                    }) {
                        Icon(
                            if (paused) Icons.Rounded.PlayArrow else Icons.Rounded.Pause,
                            contentDescription = stringResource(R.string.logs_paused),
                            tint = if (paused) scheme.primary else scheme.onSurfaceVariant
                        )
                    }
                    IconButton(onClick = {
                        val text = visible.joinToString("\n") { "${stamp(it.time)} [${it.tag.label}] ${it.message}" }
                        runCatching {
                            context.startActivity(
                                Intent.createChooser(
                                    Intent(Intent.ACTION_SEND).apply {
                                        type = "text/plain"
                                        putExtra(Intent.EXTRA_SUBJECT, "ZapretForAndroid log")
                                        putExtra(Intent.EXTRA_TEXT, text)
                                    },
                                    null
                                )
                            )
                        }
                    }) {
                        Icon(Icons.Rounded.Share, contentDescription = stringResource(R.string.action_share))
                    }
                    IconButton(onClick = { vm.clearLogs() }) {
                        Icon(
                            Icons.Rounded.Delete, contentDescription = stringResource(R.string.action_clear),
                            tint = scheme.error
                        )
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // Фильтров десять (все + ошибки + восемь подсистем), в обычный Row они не
            // помещаются: последние чипы измеряются на нулевой ширине и
            // становятся ненажимаемыми. LazyRow прокручивает их по горизонтали.
            LazyRow(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                contentPadding = PaddingValues(end = 16.dp)
            ) {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        FilterChip(
                            selected = filter == null && !errorsOnly,
                            onClick = { filter = null; errorsOnly = false },
                            label = { Text(stringResource(R.string.logs_filter_all)) }
                        )
                        FilterChip(
                            selected = errorsOnly,
                            onClick = { errorsOnly = !errorsOnly; filter = null },
                            label = { Text(stringResource(R.string.logs_filter_err)) }
                        )
                        LogTag.values().forEach { tag ->
                            FilterChip(
                                selected = filter == tag,
                                onClick = { filter = if (filter == tag) null else tag; errorsOnly = false },
                                label = { Text(tag.name) }
                            )
                        }
                    }
                }
            }

            Spacer(Modifier.height(4.dp))
            Box(Modifier.fillMaxSize()) {
                if (visible.isEmpty()) {
                    Text(
                        stringResource(R.string.logs_empty),
                        style = MaterialTheme.typography.bodyMedium,
                        color = scheme.onSurfaceVariant,
                        modifier = Modifier
                            .align(Alignment.Center)
                            .padding(24.dp)
                    )
                } else {
                    LazyColumn(
                        state = listState,
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                    ) {
                        items(visible.size) { index ->
                            LogRow(visible[index])
                        }
                    }
                }
            }
        }
    }
}

private val timeFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

private fun stamp(millis: Long): String = timeFormat.format(Date(millis))

@Composable
private fun LogRow(entry: LogEntry) {
    val scheme = MaterialTheme.colorScheme
    val levelColor = when (entry.tag) {
        LogTag.ERR -> scheme.error
        LogTag.WARN -> scheme.tertiary
        LogTag.DPI, LogTag.VPN -> scheme.primary
        LogTag.DNS -> scheme.tertiary
        LogTag.TCP, LogTag.UDP -> scheme.secondary
        LogTag.APP -> scheme.outline
    }
    val tagColor = levelColor

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(scheme.surfaceContainerLow.copy(alpha = 0.6f))
            .padding(horizontal = 10.dp, vertical = 6.dp),
        verticalAlignment = Alignment.Top
    ) {
        Box(
            modifier = Modifier
                .padding(top = 5.dp)
                .size(7.dp)
                .clip(RoundedCornerShape(2.dp))
                .background(levelColor)
        )
        Spacer(Modifier.width(9.dp))
        Column(Modifier.weight(1f)) {
            Row {
                Text(
                    stamp(entry.time),
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                    color = scheme.outline
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    entry.tag.name,
                    style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
                    color = tagColor
                )
            }
            Text(
                entry.message,
                style = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.5.sp,
                    lineHeight = 15.sp
                ),
                color = scheme.onSurfaceVariant
            )
        }
    }
}
