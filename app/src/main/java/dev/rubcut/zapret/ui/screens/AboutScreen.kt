package dev.rubcut.zapret.ui.screens

import android.content.Intent
import android.net.Uri
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
import androidx.compose.material.icons.rounded.ArrowBack
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Favorite
import androidx.compose.material.icons.rounded.Gavel
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.RemoveCircle
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import dev.rubcut.zapret.BuildConfig
import dev.rubcut.zapret.R
import dev.rubcut.zapret.ui.back
import dev.rubcut.zapret.ui.components.SectionCard
import androidx.navigation.NavHostController

private enum class Capability { YES, PARTIAL, ROOT }

private val capabilityMatrix = listOf(
    Triple("split / multisplit", Capability.YES, "--dpi-desync-split-pos=1,midsld,sniend"),
    Triple("tlsrec", Capability.YES, "--dpi-desync-tlsrec=N"),
    Triple("hostfakesplit (HTTP)", Capability.YES, "--dpi-desync=hostfakesplit"),
    Triple("wssize", Capability.YES, "--wssize=6:1"),
    Triple("hostlist / exclude", Capability.YES, "--hostlist --hostlist-exclude"),
    Triple("hostlist-domains", Capability.YES, "--hostlist-domains=…"),
    Triple("ipset / ipset-exclude", Capability.YES, "--ipset --ipset-exclude"),
    Triple("цепочки правил", Capability.YES, "--new"),
    Triple("--wf-tcp / --wf-udp", Capability.YES, "--filter-tcp --filter-udp"),
    Triple("блокировка QUIC", Capability.YES, "--filter-udp=443 с дропом"),
    Triple("fake (TTL)", Capability.PARTIAL, "только подставным соединением"),
    Triple("disorder / multidisorder", Capability.ROOT, "нужен raw-сокет"),
    Triple("syndata / synack", Capability.ROOT, "нужен raw-сокет"),
    Triple("seqovl / fakedsplit", Capability.ROOT, "нужен raw-сокет"),
    Triple("rst / rstack", Capability.ROOT, "нужен raw-сокет"),
    Triple("ipfrag / hopbyhop / destopt", Capability.ROOT, "нужен raw-сокет"),
    Triple("fooling (ts, md5sig, badseq)", Capability.ROOT, "нужен raw-сокет"),
    Triple("autottl / --dpi-desync-ttl", Capability.ROOT, "нужен raw-сокет"),
    Triple("--ip-id", Capability.ROOT, "задаётся ядром")
)

private val credits = listOf(
    "zapret — bol-van (GPL-3.0)",
    "zapret-discord-youtube — Flowseal",
    "zapret-discord-youtube-linux — Sergeydigl3"
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AboutScreen(navController: NavHostController) {
    val context = LocalContext.current

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.about_title)) },
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
                Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                    Box(
                        modifier = Modifier
                            .size(72.dp)
                            .clip(RoundedCornerShape(22.dp))
                            .background(MaterialTheme.colorScheme.primaryContainer),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            Icons.Rounded.Lock, contentDescription = null,
                            tint = MaterialTheme.colorScheme.onPrimaryContainer,
                            modifier = Modifier.size(34.dp)
                        )
                    }
                    Spacer(Modifier.height(12.dp))
                    Text(stringResource(R.string.app_full_name), style = MaterialTheme.typography.headlineSmall)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        stringResource(R.string.about_version, BuildConfig.VERSION_NAME, BuildConfig.VERSION_CODE),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            item {
                SectionCard(title = stringResource(R.string.about_what), icon = Icons.Rounded.Favorite) {
                    Text(stringResource(R.string.about_what_text), style = MaterialTheme.typography.bodyMedium)
                }
            }

            item {
                SectionCard(
                    title = stringResource(R.string.about_matrix),
                    subtitle = stringResource(R.string.home_no_root_note),
                    icon = Icons.Rounded.Warning
                ) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        CapabilityLegend(Icons.Rounded.CheckCircle, stringResource(R.string.cap_supported), MaterialTheme.colorScheme.primary)
                        CapabilityLegend(Icons.Rounded.Warning, stringResource(R.string.cap_partial), MaterialTheme.colorScheme.tertiary)
                        CapabilityLegend(Icons.Rounded.RemoveCircle, stringResource(R.string.cap_root), MaterialTheme.colorScheme.error)
                    }
                    Spacer(Modifier.height(12.dp))
                    capabilityMatrix.forEach { (name, cap, note) ->
                        CapabilityRow(name, cap, note)
                    }
                }
            }

            item {
                SectionCard(title = stringResource(R.string.about_credits), icon = Icons.Rounded.Favorite) {
                    credits.forEach {
                        Text(
                            it,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    runCatching {
                                        context.startActivity(
                                            Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/flowseal/zapret-discord-youtube"))
                                        )
                                    }
                                }
                                .padding(vertical = 4.dp)
                        )
                    }
                }
            }

            item {
                SectionCard(title = stringResource(R.string.about_license), icon = Icons.Rounded.Gavel) {
                    Text(stringResource(R.string.about_license_text), style = MaterialTheme.typography.bodyMedium)
                }
            }

            item {
                SectionCard(
                    title = stringResource(R.string.about_disclaimer),
                    icon = Icons.Rounded.Warning,
                    containerColor = MaterialTheme.colorScheme.errorContainer
                ) {
                    Text(
                        stringResource(R.string.about_disclaimer_text),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                }
            }
        }
    }
}

@Composable
private fun CapabilityLegend(icon: ImageVector, text: String, tint: Color) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(14.dp))
        Spacer(Modifier.width(4.dp))
        Text(text, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun CapabilityRow(name: String, cap: Capability, note: String) {
    val scheme = MaterialTheme.colorScheme
    val (icon, tint) = when (cap) {
        Capability.YES -> Icons.Rounded.CheckCircle to scheme.primary
        Capability.PARTIAL -> Icons.Rounded.Warning to scheme.tertiary
        Capability.ROOT -> Icons.Rounded.RemoveCircle to scheme.error
    }
    Column(Modifier.padding(vertical = 5.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(15.dp))
            Spacer(Modifier.width(9.dp))
            Text(name, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        }
        Text(
            note,
            style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
            color = scheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 24.dp)
        )
    }
}
