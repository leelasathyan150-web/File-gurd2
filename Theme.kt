package com.fileguard.forensics.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

object ForensicColors {
    val DeepNavy = Color(0xFF0A0E17)
    val CharcoalSurface = Color(0xFF111827)
    val ElevatedCard = Color(0xFF1A2332)
    val BorderSlate = Color(0xFF283548)
    val CyanAccent = Color(0xFF00E5FF)
    val ElectricBlue = Color(0xFF2979FF)
    val TextPrimary = Color(0xFFF1F5F9)
    val TextSecondary = Color(0xFF94A3B8)
    val EmeraldSafe = Color(0xFF00E676)
    val AmberWarn = Color(0xFFFFB300)
    val OrangeHigh = Color(0xFFFF6D00)
    val CrimsonCritical = Color(0xFFFF3D57)
    val PurpleUnknown = Color(0xFFB388FF)
}

private val ForensicDarkScheme = darkColorScheme(
    primary = ForensicColors.CyanAccent,
    onPrimary = ForensicColors.DeepNavy,
    secondary = ForensicColors.ElectricBlue,
    onSecondary = Color.White,
    background = ForensicColors.DeepNavy,
    onBackground = ForensicColors.TextPrimary,
    surface = ForensicColors.CharcoalSurface,
    onSurface = ForensicColors.TextPrimary,
    surfaceVariant = ForensicColors.ElevatedCard,
    onSurfaceVariant = ForensicColors.TextSecondary,
    error = ForensicColors.CrimsonCritical,
    onError = Color.White,
    outline = ForensicColors.BorderSlate
)

private val ForensicTypography = Typography(
    headlineSmall = TextStyle(
        fontWeight = FontWeight.Bold,
        fontSize = 20.sp,
        letterSpacing = 0.2.sp,
        color = ForensicColors.TextPrimary
    ),
    titleMedium = TextStyle(
        fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp,
        color = ForensicColors.TextPrimary
    ),
    bodyMedium = TextStyle(
        fontSize = 14.sp,
        lineHeight = 20.sp,
        color = ForensicColors.TextPrimary
    ),
    bodySmall = TextStyle(
        fontSize = 12.sp,
        lineHeight = 17.sp,
        color = ForensicColors.TextSecondary
    ),
    labelMedium = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontSize = 11.sp,
        color = ForensicColors.CyanAccent
    )
)

@Composable
fun FileGuardTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = ForensicDarkScheme,
        typography = ForensicTypography,
        content = content
    )
}
