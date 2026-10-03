package dev.rubcut.zapret.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Lan
import androidx.compose.material.icons.rounded.ListAlt
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.Article
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.navigation.NavHostController
import dev.rubcut.zapret.R
import dev.rubcut.zapret.ui.Routes
import dev.rubcut.zapret.ui.components.ClickableRow
import dev.rubcut.zapret.ui.components.SectionCard

private data class HubEntry(val route: String, val titleRes: Int, val subtitleRes: Int, val icon: ImageVector)

private val hubEntries = listOf(
    HubEntry(Routes.LISTS, R.string.lists_title, R.string.lists_subtitle, Icons.Rounded.ListAlt),
    HubEntry(Routes.DNS, R.string.dns_title, R.string.dns_subtitle, Icons.Rounded.Dns),
    HubEntry(Routes.NETWORK, R.string.net_title, R.string.net_subtitle, Icons.Rounded.Lan),
    HubEntry(Routes.ARGS, R.string.args_title, R.string.args_subtitle, Icons.Rounded.Terminal),
    HubEntry(Routes.LOGS, R.string.logs_title, R.string.logs_title, Icons.Rounded.Article),
    HubEntry(Routes.SETTINGS, R.string.settings_title, R.string.settings_title, Icons.Rounded.Settings),
    HubEntry(Routes.ABOUT, R.string.about_title, R.string.about_matrix, Icons.Rounded.Info)
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MoreScreen(navController: NavHostController) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.nav_settings)) },
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
                SectionCard(
                    title = stringResource(R.string.nav_tuning),
                    subtitle = stringResource(R.string.strategy_subtitle),
                    icon = Icons.Rounded.Tune
                ) {
                    hubEntries.forEach { entry ->
                        ClickableRow(
                            title = stringResource(entry.titleRes),
                            subtitle = stringResource(entry.subtitleRes),
                            icon = entry.icon,
                            onClick = { navController.navigate(entry.route) }
                        )
                    }
                }
            }
            item {
                Text(
                    stringResource(R.string.home_no_root_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
