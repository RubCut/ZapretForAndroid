package dev.rubcut.zapret.ui.screens

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavHostController
import dev.rubcut.zapret.R
import dev.rubcut.zapret.data.DnsMode
import dev.rubcut.zapret.data.HostListStore
import dev.rubcut.zapret.ui.Routes
import dev.rubcut.zapret.ui.AppViewModel
import dev.rubcut.zapret.ui.back
import dev.rubcut.zapret.ui.components.ChipSelector
import dev.rubcut.zapret.ui.components.InfoBanner
import dev.rubcut.zapret.ui.components.LabeledTextField
import dev.rubcut.zapret.ui.components.SectionCard
import dev.rubcut.zapret.ui.components.SliderRow
import dev.rubcut.zapret.ui.components.SwitchRow

private val dohProviders = listOf(
    "Google" to "https://dns.google/resolve",
    "Cloudflare" to "https://cloudflare-dns.com/dns-query",
    "Quad9" to "https://dns.quad9.net:5053/dns-query",
    "AdGuard" to "https://dns.adguard-dns.com/dns-query",
    "Yandex" to "https://dns.yandex.ru/dns-query",
    "Comss" to "https://dns.comss.one/dns-query",
    "NextDNS" to "https://dns.nextdns.io/dns-query"
)

private val dotProviders = listOf(
    "Google", "Cloudflare", "Quad9", "AdGuard"
)

private val dotHosts = listOf(
    "dns.google", "one.one.one.one", "dns.quad9.net", "dns.adguard-dns.com"
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DnsScreen(vm: AppViewModel, navController: NavHostController) {
    val cfg by vm.config.collectAsStateWithLifecycle()
    val snapshot by vm.listSnapshot.collectAsStateWithLifecycle()
    var testing by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<String?>(null) }
    val unitSec = stringResource(R.string.unit_sec_short)
    val hostsCount = remember(snapshot) {
        (snapshot.texts[HostListStore.Kind.HOSTS] ?: "").lineSequence()
            .count { it.isNotBlank() && !it.trimStart().startsWith("#") && !it.trimStart().startsWith(";") }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.dns_title)) },
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
                    stringResource(R.string.dns_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            item {
                SectionCard(title = stringResource(R.string.dns_mode), icon = Icons.Rounded.Dns) {
                    ChipSelector(
                        options = DnsMode.values().map {
                            stringResource(
                                when (it) {
                                    DnsMode.SYSTEM -> R.string.dns_mode_system
                                    DnsMode.CUSTOM -> R.string.dns_mode_custom
                                    DnsMode.DOH -> R.string.dns_mode_doh
                                    DnsMode.DOT -> R.string.dns_mode_dot
                                }
                            )
                        },
                        selectedIndex = DnsMode.values().indexOf(cfg.dnsMode),
                        onSelect = { i -> vm.update { c -> c.copy(dnsMode = DnsMode.values()[i]) } }
                    )

                    when (cfg.dnsMode) {
                        DnsMode.CUSTOM -> {
                            Spacer(Modifier.height(14.dp))
                            LabeledTextField(
                                label = stringResource(R.string.dns_servers),
                                value = cfg.dnsServers,
                                onValueChange = { v -> vm.update { it.copy(dnsServers = v) } },
                                singleLine = false,
                                minLines = 3,
                                monospace = true,
                                placeholder = "1.1.1.1\n8.8.8.8:5353",
                                supportingText = stringResource(R.string.dns_servers_hint)
                            )
                        }

                        DnsMode.DOH -> {
                            Spacer(Modifier.height(14.dp))
                            Text(stringResource(R.string.dns_doh_provider), style = MaterialTheme.typography.titleSmall)
                            Spacer(Modifier.height(8.dp))
                            ChipSelector(
                                options = dohProviders.map { it.first },
                                selectedIndex = dohProviders.indexOfFirst { it.second == cfg.dohUrl },
                                onSelect = { i -> vm.update { c -> c.copy(dohUrl = dohProviders[i].second) } }
                            )
                            Spacer(Modifier.height(12.dp))
                            LabeledTextField(
                                label = stringResource(R.string.dns_doh_url),
                                value = cfg.dohUrl,
                                onValueChange = { v -> vm.update { it.copy(dohUrl = v) } },
                                monospace = true
                            )
                        }

                        DnsMode.DOT -> {
                            Spacer(Modifier.height(14.dp))
                            ChipSelector(
                                options = dotProviders,
                                selectedIndex = dotHosts.indexOf(cfg.dotHost),
                                onSelect = { i -> vm.update { c -> c.copy(dotHost = dotHosts[i]) } }
                            )
                            Spacer(Modifier.height(12.dp))
                            LabeledTextField(
                                label = stringResource(R.string.dns_dot_host),
                                value = cfg.dotHost,
                                onValueChange = { v -> vm.update { it.copy(dotHost = v) } },
                                monospace = true
                            )
                        }

                        DnsMode.SYSTEM -> {
                            Spacer(Modifier.height(12.dp))
                            InfoBanner(
                                text = stringResource(R.string.dns_mode_system_hint),
                                icon = Icons.Rounded.Public
                            )
                        }
                    }
                }
            }

            item {
                SectionCard(title = stringResource(R.string.lists_hosts_title), icon = Icons.Rounded.Shield) {
                    Text(
                        stringResource(R.string.lists_hosts_hint),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.height(10.dp))
                    Text(
                        stringResource(R.string.lists_count, hostsCount),
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Spacer(Modifier.height(12.dp))
                    Button(onClick = { navController.navigate(Routes.LISTS) }) {
                        Text(stringResource(R.string.action_edit))
                    }
                }
            }

            item {
                SectionCard(title = stringResource(R.string.dns_protection_group), icon = Icons.Rounded.Shield) {
                    SwitchRow(
                        title = stringResource(R.string.dns_fake_protection),
                        subtitle = stringResource(R.string.dns_fake_protection_hint),
                        checked = cfg.dnsFakeProtection,
                        onCheckedChange = { v -> vm.update { it.copy(dnsFakeProtection = v) } }
                    )
                    SwitchRow(
                        title = stringResource(R.string.dns_hijack),
                        subtitle = stringResource(R.string.dns_hijack_hint),
                        checked = cfg.dnsHijack,
                        onCheckedChange = { v -> vm.update { it.copy(dnsHijack = v) } }
                    )
                    SwitchRow(
                        title = stringResource(R.string.dns_cache),
                        checked = cfg.dnsCache,
                        onCheckedChange = { v -> vm.update { it.copy(dnsCache = v) } }
                    )
                    if (cfg.dnsCache) {
                        SliderRow(
                            title = stringResource(R.string.dns_cache_ttl),
                            value = cfg.dnsCacheTtlSec.toFloat(),
                            valueRange = 30f..3600f,
                            onValueChange = { v -> vm.update { it.copy(dnsCacheTtlSec = v.toInt()) } },
                            format = { "${it.toInt()} $unitSec" }
                        )
                    }
                    SwitchRow(
                        title = stringResource(R.string.dns_block_ads),
                        subtitle = stringResource(R.string.dns_block_ads_hint),
                        checked = cfg.dnsBlockAds,
                        onCheckedChange = { v -> vm.update { it.copy(dnsBlockAds = v) } }
                    )
                }
            }

            item {
                SectionCard(title = stringResource(R.string.dns_test), icon = Icons.Rounded.PlayArrow) {
                    Button(
                        onClick = {
                            testing = true
                            result = null
                            vm.testDns("www.google.com") { text ->
                                testing = false
                                result = text
                            }
                        },
                        enabled = !testing,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (testing) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(18.dp),
                                strokeWidth = 2.dp,
                                color = MaterialTheme.colorScheme.onPrimary
                            )
                        } else {
                            Icon(Icons.Rounded.PlayArrow, contentDescription = null, modifier = Modifier.size(18.dp))
                        }
                        Spacer(Modifier.width(10.dp))
                        Text(stringResource(if (testing) R.string.dns_test_running else R.string.dns_test))
                    }
                    result?.let { text ->
                        Spacer(Modifier.height(12.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text,
                                style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.weight(1f)
                            )
                        }
                    }
                }
            }
        }
    }
}
