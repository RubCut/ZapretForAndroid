package dev.rubcut.zapret.ui.theme

import android.graphics.Color as AndroidColor
import android.os.Build
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.rubcut.zapret.data.AccentPalette

private fun hsv(h: Float, s: Float, v: Float): Color =
    Color(AndroidColor.HSVToColor(floatArrayOf(((h % 360f) + 360f) % 360f, s.coerceIn(0f, 1f), v.coerceIn(0f, 1f))))

fun accentHue(accent: AccentPalette): Float = when (accent) {
    AccentPalette.EMERALD -> 158f
    AccentPalette.SKY -> 205f
    AccentPalette.VIOLET -> 268f
    AccentPalette.AMBER -> 34f
    AccentPalette.ROSE -> 344f
    AccentPalette.TEAL -> 186f
}

private fun lightScheme(h: Float) = lightColorScheme(
    primary = hsv(h, 0.72f, 0.58f),
    onPrimary = Color.White,
    primaryContainer = hsv(h, 0.34f, 0.96f),
    onPrimaryContainer = hsv(h, 0.80f, 0.28f),
    inversePrimary = hsv(h, 0.52f, 0.86f),
    secondary = hsv(h, 0.34f, 0.52f),
    onSecondary = Color.White,
    secondaryContainer = hsv(h, 0.24f, 0.94f),
    onSecondaryContainer = hsv(h, 0.55f, 0.26f),
    tertiary = hsv(h + 34f, 0.52f, 0.56f),
    onTertiary = Color.White,
    tertiaryContainer = hsv(h + 34f, 0.32f, 0.95f),
    onTertiaryContainer = hsv(h + 34f, 0.62f, 0.26f),
    background = hsv(h, 0.05f, 0.99f),
    onBackground = hsv(h, 0.12f, 0.12f),
    surface = hsv(h, 0.05f, 0.99f),
    onSurface = hsv(h, 0.12f, 0.12f),
    surfaceVariant = hsv(h, 0.14f, 0.93f),
    onSurfaceVariant = hsv(h, 0.16f, 0.32f),
    surfaceTint = hsv(h, 0.72f, 0.58f),
    inverseSurface = hsv(h, 0.12f, 0.20f),
    inverseOnSurface = hsv(h, 0.06f, 0.96f),
    error = hsv(25f, 0.82f, 0.70f),
    onError = Color.White,
    errorContainer = hsv(25f, 0.42f, 0.96f),
    onErrorContainer = hsv(25f, 0.90f, 0.32f),
    outline = hsv(h, 0.14f, 0.54f),
    outlineVariant = hsv(h, 0.14f, 0.85f),
    scrim = Color.Black,
    surfaceBright = hsv(h, 0.05f, 0.99f),
    surfaceDim = hsv(h, 0.08f, 0.90f),
    surfaceContainer = hsv(h, 0.08f, 0.96f),
    surfaceContainerHigh = hsv(h, 0.08f, 0.94f),
    surfaceContainerHighest = hsv(h, 0.09f, 0.92f),
    surfaceContainerLow = hsv(h, 0.06f, 0.98f),
    surfaceContainerLowest = Color.White
)

private fun darkScheme(h: Float) = darkColorScheme(
    primary = hsv(h, 0.56f, 0.86f),
    onPrimary = hsv(h, 0.78f, 0.24f),
    primaryContainer = hsv(h, 0.56f, 0.40f),
    onPrimaryContainer = hsv(h, 0.32f, 0.94f),
    inversePrimary = hsv(h, 0.72f, 0.54f),
    secondary = hsv(h, 0.30f, 0.84f),
    onSecondary = hsv(h, 0.50f, 0.20f),
    secondaryContainer = hsv(h, 0.34f, 0.34f),
    onSecondaryContainer = hsv(h, 0.22f, 0.94f),
    tertiary = hsv(h + 34f, 0.40f, 0.84f),
    onTertiary = hsv(h + 34f, 0.60f, 0.20f),
    tertiaryContainer = hsv(h + 34f, 0.42f, 0.36f),
    onTertiaryContainer = hsv(h + 34f, 0.24f, 0.94f),
    background = hsv(h, 0.12f, 0.09f),
    onBackground = hsv(h, 0.07f, 0.93f),
    surface = hsv(h, 0.12f, 0.09f),
    onSurface = hsv(h, 0.07f, 0.93f),
    surfaceVariant = hsv(h, 0.16f, 0.28f),
    onSurfaceVariant = hsv(h, 0.11f, 0.79f),
    surfaceTint = hsv(h, 0.56f, 0.86f),
    inverseSurface = hsv(h, 0.07f, 0.93f),
    inverseOnSurface = hsv(h, 0.12f, 0.11f),
    error = hsv(25f, 0.66f, 0.88f),
    onError = hsv(25f, 0.80f, 0.20f),
    errorContainer = hsv(25f, 0.60f, 0.42f),
    onErrorContainer = hsv(25f, 0.30f, 0.94f),
    outline = hsv(h, 0.11f, 0.56f),
    outlineVariant = hsv(h, 0.16f, 0.28f),
    scrim = Color.Black,
    surfaceBright = hsv(h, 0.11f, 0.22f),
    surfaceDim = hsv(h, 0.12f, 0.09f),
    surfaceContainer = hsv(h, 0.12f, 0.13f),
    surfaceContainerHigh = hsv(h, 0.12f, 0.17f),
    surfaceContainerHighest = hsv(h, 0.12f, 0.21f),
    surfaceContainerLow = hsv(h, 0.12f, 0.11f),
    surfaceContainerLowest = hsv(h, 0.13f, 0.06f)
)

val ZapretTypography = Typography(
    displaySmall = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold,
        fontSize = 34.sp, lineHeight = 42.sp, letterSpacing = 0.sp
    ),
    headlineMedium = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold,
        fontSize = 27.sp, lineHeight = 34.sp, letterSpacing = 0.sp
    ),
    headlineSmall = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold,
        fontSize = 23.sp, lineHeight = 30.sp
    ),
    titleLarge = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold,
        fontSize = 21.sp, lineHeight = 27.sp
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp, lineHeight = 22.sp, letterSpacing = 0.1.sp
    ),
    titleSmall = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Medium,
        fontSize = 14.sp, lineHeight = 20.sp, letterSpacing = 0.1.sp
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Normal,
        fontSize = 16.sp, lineHeight = 24.sp, letterSpacing = 0.2.sp
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Normal,
        fontSize = 14.sp, lineHeight = 21.sp, letterSpacing = 0.15.sp
    ),
    bodySmall = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Normal,
        fontSize = 12.sp, lineHeight = 17.sp, letterSpacing = 0.2.sp
    ),
    labelLarge = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Medium,
        fontSize = 14.sp, lineHeight = 19.sp, letterSpacing = 0.1.sp
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.Default, fontWeight = FontWeight.Medium,
        fontSize = 11.sp, lineHeight = 15.sp, letterSpacing = 0.4.sp
    )
)

val ZapretShapes = Shapes(
    extraSmall = RoundedCornerShape(6.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(22.dp),
    extraLarge = RoundedCornerShape(30.dp)
)

@Composable
fun ZapretTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    accent: AccentPalette = AccentPalette.EMERALD,
    content: @Composable () -> Unit
) {
    val context = LocalContext.current
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        darkTheme -> darkScheme(accentHue(accent))
        else -> lightScheme(accentHue(accent))
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = ZapretTypography,
        shapes = ZapretShapes,
        content = content
    )
}

/** Цвет-превью акцента для выбора палитры в настройках. */
fun accentPreviewColor(accent: AccentPalette): Color = hsv(accentHue(accent), 0.68f, 0.62f)
