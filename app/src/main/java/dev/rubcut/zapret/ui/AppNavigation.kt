package dev.rubcut.zapret.ui

import android.content.Intent
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Bolt
import androidx.compose.material.icons.rounded.Home
import androidx.compose.material.icons.rounded.MoreHoriz
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import dev.rubcut.zapret.R
import dev.rubcut.zapret.ui.screens.AboutScreen
import dev.rubcut.zapret.ui.screens.ArgsScreen
import dev.rubcut.zapret.ui.screens.DnsScreen
import dev.rubcut.zapret.ui.screens.HomeScreen
import dev.rubcut.zapret.ui.screens.ListsScreen
import dev.rubcut.zapret.ui.screens.LogsScreen
import dev.rubcut.zapret.ui.screens.MoreScreen
import dev.rubcut.zapret.ui.screens.NetworkScreen
import dev.rubcut.zapret.ui.screens.ProfilesScreen
import dev.rubcut.zapret.ui.screens.SettingsScreen
import dev.rubcut.zapret.ui.screens.StrategyScreen

object Routes {
    const val HOME = "home"
    const val PROFILES = "profiles"
    const val STRATEGY = "strategy"
    const val MORE = "more"
    const val LISTS = "lists"
    const val DNS = "dns"
    const val NETWORK = "network"
    const val ARGS = "args"
    const val LOGS = "logs"
    const val SETTINGS = "settings"
    const val ABOUT = "about"

    val BOTTOM = setOf(HOME, PROFILES, STRATEGY, MORE)
}

private class BottomItem(
    val route: String,
    val icon: ImageVector,
    val labelRes: Int
)

private val bottomItems = listOf(
    BottomItem(Routes.HOME, Icons.Rounded.Home, R.string.nav_home),
    BottomItem(Routes.PROFILES, Icons.Rounded.Bolt, R.string.nav_profiles),
    BottomItem(Routes.STRATEGY, Icons.Rounded.Tune, R.string.nav_tuning),
    BottomItem(Routes.MORE, Icons.Rounded.MoreHoriz, R.string.nav_settings)
)

@Composable
fun ZapretApp(
    viewModel: AppViewModel,
    onVpnPermission: (Intent) -> Unit,
    onRequestNotificationPermission: () -> Unit
) {
    val navController = rememberNavController()
    val backStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = backStackEntry?.destination?.route
    val showBottomBar = currentRoute in Routes.BOTTOM

    val snackbarHostState = remember { SnackbarHostState() }
    val message by viewModel.snackbar.collectAsStateWithLifecycle()
    LaunchedEffect(message) {
        val text = message
        if (!text.isNullOrEmpty()) {
            snackbarHostState.showSnackbar(text)
            viewModel.snackbarShown()
        }
    }

    Surface(color = MaterialTheme.colorScheme.background) {
        Scaffold(
            snackbarHost = { SnackbarHost(snackbarHostState) },
            contentWindowInsets = WindowInsets(0, 0, 0, 0),
            bottomBar = {
                if (showBottomBar) {
                    NavigationBar {
                        bottomItems.forEach { item ->
                            NavigationBarItem(
                                selected = currentRoute == item.route,
                                onClick = {
                                    if (currentRoute != item.route) {
                                        navController.navigate(item.route) {
                                            popUpTo(Routes.HOME) { saveState = true }
                                            launchSingleTop = true
                                            restoreState = true
                                        }
                                    }
                                },
                                icon = {
                                    Icon(item.icon, contentDescription = stringResource(item.labelRes))
                                },
                                label = { Text(stringResource(item.labelRes)) }
                            )
                        }
                    }
                }
            }
        ) { padding ->
            NavHost(
                navController = navController,
                startDestination = Routes.HOME,
                modifier = Modifier.padding(bottom = padding.calculateBottomPadding())
            ) {
                composable(Routes.HOME) {
                    HomeScreen(viewModel, navController, onVpnPermission, onRequestNotificationPermission)
                }
                composable(Routes.PROFILES) { ProfilesScreen(viewModel) }
                composable(Routes.STRATEGY) { StrategyScreen(viewModel, navController) }
                composable(Routes.MORE) { MoreScreen(navController) }
                composable(Routes.LISTS) { ListsScreen(viewModel, navController) }
                composable(Routes.DNS) { DnsScreen(viewModel, navController) }
                composable(Routes.NETWORK) { NetworkScreen(viewModel, navController) }
                composable(Routes.ARGS) { ArgsScreen(viewModel, navController) }
                composable(Routes.LOGS) { LogsScreen(viewModel, navController) }
                composable(Routes.SETTINGS) { SettingsScreen(viewModel, navController) }
                composable(Routes.ABOUT) { AboutScreen(navController) }
            }
        }
    }
}

internal fun NavHostController.back() {
    if (!popBackStack()) navigate(Routes.HOME)
}
