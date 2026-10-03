package dev.rubcut.zapret.ui.screens

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.ContentPaste
import androidx.compose.material.icons.rounded.Download
import androidx.compose.material.icons.rounded.Save
import androidx.compose.material.icons.rounded.Share
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavHostController
import dev.rubcut.zapret.R
import dev.rubcut.zapret.data.BuiltinLists
import dev.rubcut.zapret.data.HostListStore
import dev.rubcut.zapret.ui.AppViewModel
import dev.rubcut.zapret.ui.back
import dev.rubcut.zapret.ui.components.InfoBanner
import dev.rubcut.zapret.ui.components.SectionCard

private val kinds = listOf(
    HostListStore.Kind.HOSTLIST to R.string.lists_tab_hostlist,
    HostListStore.Kind.EXCLUDE to R.string.lists_tab_exclude,
    HostListStore.Kind.IPSET to R.string.lists_tab_ipset,
    HostListStore.Kind.IPSET_EXCLUDE to R.string.lists_tab_ipset_ex,
    HostListStore.Kind.HOSTS to R.string.lists_tab_hosts
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ListsScreen(vm: AppViewModel, navController: NavHostController) {
    val snapshot by vm.listSnapshot.collectAsStateWithLifecycle()
    var tab by remember { mutableIntStateOf(0) }
    var editing by remember { mutableStateOf(false) }

    val kind = kinds[tab].first

    if (editing) {
        ListEditor(
            kind = kind,
            initial = snapshot.texts[kind] ?: "",
            onSave = { vm.saveList(kind, it); editing = false },
            onCancel = { editing = false }
        )
        return
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.lists_title)) },
                navigationIcon = {
                    IconButton(onClick = { navController.back() }) {
                        Icon(Icons.Rounded.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent)
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            ScrollableTabRow(
                selectedTabIndex = tab,
                edgePadding = 16.dp,
                containerColor = Color.Transparent
            ) {
                kinds.forEachIndexed { index, (_, labelRes) ->
                    Tab(
                        selected = index == tab,
                        onClick = { tab = index },
                        text = { Text(stringResource(labelRes), style = MaterialTheme.typography.labelLarge) }
                    )
                }
            }

            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 14.dp, bottom = 24.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                item {
                    InfoBanner(
                        text = stringResource(
                            when (kind) {
                                HostListStore.Kind.HOSTLIST -> R.string.lists_hostlist_hint
                                HostListStore.Kind.EXCLUDE -> R.string.lists_exclude_hint
                                HostListStore.Kind.IPSET -> R.string.lists_ipset_hint
                                HostListStore.Kind.IPSET_EXCLUDE -> R.string.lists_ipset_hint
                                HostListStore.Kind.HOSTS -> R.string.lists_hosts_hint
                            }
                        )
                    )
                }

                item {
                    SectionCard(
                        title = stringResource(
                            when (kind) {
                                HostListStore.Kind.HOSTLIST -> R.string.lists_hostlist_title
                                HostListStore.Kind.EXCLUDE -> R.string.lists_exclude_title
                                HostListStore.Kind.IPSET -> R.string.lists_ipset_title
                                HostListStore.Kind.IPSET_EXCLUDE -> R.string.lists_ipset_exclude_title
                                HostListStore.Kind.HOSTS -> R.string.lists_hosts_title
                            }
                        ),
                        subtitle = stringResource(R.string.lists_count, snapshot.count(kind))
                    ) {
                        val preview = (snapshot.texts[kind] ?: "").lineSequence()
                            .filter { it.isNotBlank() && !it.trimStart().startsWith("#") }
                            .take(14)
                            .joinToString("\n")
                        Text(
                            preview.ifBlank { "—" },
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 12.sp,
                                lineHeight = 18.sp
                            ),
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.height(14.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            Button(onClick = { editing = true }, modifier = Modifier.weight(1f)) {
                                Icon(Icons.Rounded.Save, contentDescription = null, modifier = Modifier.height(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Text(stringResource(R.string.action_edit))
                            }
                            OutlinedButton(onClick = { vm.resetLists() }, modifier = Modifier.weight(1f)) {
                                Icon(Icons.Rounded.Download, contentDescription = null, modifier = Modifier.height(18.dp))
                                Spacer(Modifier.width(8.dp))
                                Text(stringResource(R.string.lists_reset_builtin))
                            }
                        }
                    }
                }

                if (kind == HostListStore.Kind.HOSTLIST) {
                    item {
                        SectionCard(title = stringResource(R.string.lists_load_builtin), icon = null) {
                            BuiltinRow(R.string.lists_builtin_google) {
                                vm.appendToList(kind, BuiltinLists.GOOGLE.lines())
                            }
                            BuiltinRow(R.string.lists_builtin_discord) {
                                vm.appendToList(kind, BuiltinLists.DISCORD.lines())
                            }
                            BuiltinRow(R.string.lists_builtin_general) {
                                vm.appendToList(kind, BuiltinLists.GENERAL.lines())
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun BuiltinRow(labelRes: Int, onClick: () -> Unit) {
    FilledTonalButton(onClick = onClick, modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(stringResource(labelRes))
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ListEditor(
    kind: HostListStore.Kind,
    initial: String,
    onSave: (String) -> Unit,
    onCancel: () -> Unit
) {
    var text by remember(kind) { mutableStateOf(initial) }
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.lists_editor_title)) },
                navigationIcon = {
                    IconButton(onClick = onCancel) {
                        Icon(Icons.Rounded.Close, contentDescription = stringResource(R.string.action_cancel))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent),
                actions = {
                    IconButton(onClick = {
                        val shared = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_SUBJECT, kind.fileName)
                            putExtra(Intent.EXTRA_TEXT, text)
                        }
                        runCatching { context.startActivity(Intent.createChooser(shared, kind.fileName)) }
                    }) {
                        Icon(Icons.Rounded.Share, contentDescription = stringResource(R.string.action_share))
                    }
                    IconButton(onClick = {
                        clipboard.getText()?.text?.let { pasted ->
                            text = if (text.isBlank()) pasted else text.trimEnd() + "\n" + pasted
                        }
                    }) {
                        Icon(Icons.Rounded.ContentPaste, contentDescription = stringResource(R.string.lists_paste))
                    }
                    IconButton(onClick = { onSave(text) }) {
                        Icon(
                            Icons.Rounded.Check, contentDescription = stringResource(R.string.action_save),
                            tint = MaterialTheme.colorScheme.primary
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
                .padding(horizontal = 16.dp)
        ) {
            Text(
                "${kind.fileName} · ${text.lines().count { it.isNotBlank() }}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                modifier = Modifier.fillMaxSize(),
                textStyle = MaterialTheme.typography.bodySmall.copy(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    lineHeight = 18.sp
                ),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLow,
                    unfocusedContainerColor = MaterialTheme.colorScheme.surfaceContainerLow
                ),
                shape = MaterialTheme.shapes.medium
            )
            Spacer(Modifier.height(12.dp))
        }
    }
}
