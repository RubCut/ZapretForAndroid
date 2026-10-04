package dev.rubcut.zapret.ui.screens

import androidx.compose.animation.animateColorAsState
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Bolt
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.Forum
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.SmartToy
import androidx.compose.material.icons.rounded.Slideshow
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
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.rubcut.zapret.R
import dev.rubcut.zapret.data.ProfileId
import dev.rubcut.zapret.ui.AppViewModel
import dev.rubcut.zapret.ui.components.SectionCard

private data class ProfileEntry(
    val id: ProfileId,
    val titleRes: Int,
    val descRes: Int,
    val icon: ImageVector
)

private val profileEntries = listOf(
    ProfileEntry(ProfileId.COMBINED, R.string.profile_combined, R.string.profile_combined_desc, Icons.Rounded.Bolt),
    ProfileEntry(ProfileId.YOUTUBE, R.string.profile_youtube, R.string.profile_youtube_desc, Icons.Rounded.Slideshow),
    ProfileEntry(ProfileId.DISCORD, R.string.profile_discord, R.string.profile_discord_desc, Icons.Rounded.Forum),
    ProfileEntry(ProfileId.MAX, R.string.profile_max, R.string.profile_max_desc, Icons.Rounded.SmartToy),
    ProfileEntry(ProfileId.CUSTOM, R.string.profile_custom, R.string.profile_custom_desc, Icons.Rounded.Bolt),
    ProfileEntry(ProfileId.OFF, R.string.profile_off, R.string.profile_off_desc, Icons.Rounded.PowerSettingsNew)
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfilesScreen(vm: AppViewModel) {
    val cfg by vm.config.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.profiles_title)) },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent)
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                Text(
                    stringResource(R.string.profiles_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            items(profileEntries.size) { index ->
                val entry = profileEntries[index]
                ProfileCard(
                    title = stringResource(entry.titleRes),
                    description = stringResource(entry.descRes),
                    icon = entry.icon,
                    active = cfg.profile == entry.id,
                    onClick = { vm.setProfile(entry.id) }
                )
            }

            item {
                SectionCard(
                    title = stringResource(R.string.args_generated),
                    icon = Icons.Rounded.Bolt,
                    containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
                ) {
                    Text(
                        vm.generatedArgs(),
                        style = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

@Composable
private fun ProfileCard(
    title: String,
    description: String,
    icon: ImageVector,
    active: Boolean,
    onClick: () -> Unit
) {
    val scheme = MaterialTheme.colorScheme
    val container by animateColorAsState(
        targetValue = if (active) scheme.primaryContainer else scheme.surfaceContainer,
        label = "profile-bg"
    )
    val content by animateColorAsState(
        targetValue = if (active) scheme.onPrimaryContainer else scheme.onSurface,
        label = "profile-fg"
    )

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.large)
            .clickable(onClick = onClick),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(containerColor = container),
        elevation = CardDefaults.cardElevation(0.dp)
    ) {
        Row(
            modifier = Modifier.padding(18.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(46.dp)
                    .clip(CircleShape)
                    .background(
                        if (active) scheme.primary.copy(alpha = 0.22f) else scheme.surfaceContainerHighest
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    icon, contentDescription = null,
                    tint = if (active) scheme.primary else scheme.onSurfaceVariant,
                    modifier = Modifier.size(24.dp)
                )
            }
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium, color = content)
                Spacer(Modifier.height(4.dp))
                Text(
                    description,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (active) scheme.onPrimaryContainer.copy(alpha = 0.8f) else scheme.onSurfaceVariant
                )
            }
            Spacer(Modifier.width(12.dp))
            if (active) {
                Box(
                    modifier = Modifier
                        .size(28.dp)
                        .clip(CircleShape)
                        .background(scheme.primary),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        Icons.Rounded.Check, contentDescription = stringResource(R.string.profile_active),
                        tint = scheme.onPrimary, modifier = Modifier.size(17.dp)
                    )
                }
            } else {
                Icon(
                    Icons.Rounded.PlayArrow, contentDescription = null,
                    tint = scheme.outline, modifier = Modifier.size(22.dp)
                )
            }
        }
    }
}
