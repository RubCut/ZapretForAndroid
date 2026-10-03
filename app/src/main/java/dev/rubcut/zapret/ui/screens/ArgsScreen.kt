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
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowBack
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Error
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavHostController
import dev.rubcut.zapret.R
import dev.rubcut.zapret.config.ParseResult
import dev.rubcut.zapret.config.ZapretArgsParser
import dev.rubcut.zapret.ui.AppViewModel
import dev.rubcut.zapret.ui.back
import dev.rubcut.zapret.ui.components.InfoBanner
import dev.rubcut.zapret.ui.components.SectionCard

private const val EXAMPLE_ARGS = "--filter-tcp=443 --hostlist=list-google.txt --dpi-desync=multisplit " +
    "--dpi-desync-split-pos=midsld --dpi-desync-split-seqovl=681 --dpi-desync-repeats=8 --wssize=6:1"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ArgsScreen(vm: AppViewModel, navController: NavHostController) {
    val cfg by vm.config.collectAsStateWithLifecycle()
    var text by remember { mutableStateOf(vm.generatedArgs()) }
    var parsed by remember { mutableStateOf<ParseResult?>(null) }
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.args_title)) },
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
                InfoBanner(
                    text = stringResource(R.string.args_hint),
                    icon = Icons.Rounded.Terminal
                )
            }

            item {
                SectionCard(title = stringResource(R.string.args_input), icon = Icons.Rounded.Terminal) {
                    OutlinedTextField(
                        value = text,
                        onValueChange = { text = it },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(190.dp),
                        textStyle = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = FontFamily.Monospace,
                            fontSize = 12.sp,
                            lineHeight = 18.sp
                        ),
                        placeholder = {
                            Text(
                                EXAMPLE_ARGS,
                                style = MaterialTheme.typography.bodySmall.copy(
                                    fontFamily = FontFamily.Monospace, fontSize = 12.sp
                                ),
                                color = MaterialTheme.colorScheme.outline
                            )
                        },
                        shape = MaterialTheme.shapes.medium
                    )
                    Spacer(Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        FilledTonalButton(onClick = { parsed = ZapretArgsParser.parse(text, cfg) }, modifier = Modifier.weight(1f)) {
                            Icon(Icons.Rounded.PlayArrow, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text(stringResource(R.string.args_parse))
                        }
                        Button(
                            onClick = {
                                val result = ZapretArgsParser.parse(text, cfg)
                                parsed = result
                                vm.applyArgs(text)
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Rounded.CheckCircle, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text(stringResource(R.string.args_apply))
                        }
                    }
                }
            }

            val result = parsed
            if (result != null) {
                if (result.supported.isNotEmpty()) {
                    item {
                        SectionCard(
                            title = stringResource(R.string.args_supported),
                            subtitle = result.supported.joinToString("\n"),
                            icon = Icons.Rounded.CheckCircle
                        ) {}
                    }
                }
                if (result.ignored.isNotEmpty()) {
                    item {
                        SectionCard(
                            title = stringResource(R.string.args_ignored),
                            icon = Icons.Rounded.Warning
                        ) {
                            result.ignored.forEach {
                                Text(
                                    it,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    modifier = Modifier.padding(vertical = 2.dp)
                                )
                            }
                        }
                    }
                }
                if (result.unknown.isNotEmpty()) {
                    item {
                        SectionCard(
                            title = stringResource(R.string.args_unknown),
                            subtitle = result.unknown.joinToString(" "),
                            icon = Icons.Rounded.Info
                        ) {}
                    }
                }
                if (result.errors.isNotEmpty()) {
                    item {
                        SectionCard(
                            title = stringResource(R.string.args_errors),
                            icon = Icons.Rounded.Error
                        ) {
                            result.errors.forEach {
                                Text(
                                    it,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.error,
                                    modifier = Modifier.padding(vertical = 2.dp)
                                )
                            }
                        }
                    }
                }
            }

            item {
                SectionCard(
                    title = stringResource(R.string.args_generated),
                    icon = Icons.Rounded.Terminal,
                    containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
                ) {
                    SelectionContainer {
                        Text(
                            vm.generatedArgs(),
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = FontFamily.Monospace,
                                fontSize = 12.sp,
                                lineHeight = 18.sp
                            ),
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Spacer(Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        FilledTonalButton(
                            onClick = {
                                clipboard.setText(AnnotatedString(vm.generatedArgs()))
                                vm.toast(context.getString(R.string.action_copied))
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Icon(Icons.Rounded.ContentCopy, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(8.dp))
                            Text(stringResource(R.string.action_copy))
                        }
                        FilledTonalButton(
                            onClick = {
                                text = vm.generatedArgs()
                                parsed = null
                            },
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(stringResource(R.string.action_reset))
                        }
                    }
                }
            }
        }
    }
}
