package com.fileguard.forensics.ui.components

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.fileguard.forensics.domain.model.RiskClassification
import com.fileguard.forensics.ui.theme.ForensicColors

fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024) return String.format("%.1f KB", kb)
    val mb = kb / 1024.0
    if (mb < 1024) return String.format("%.1f MB", mb)
    val gb = mb / 1024.0
    return String.format("%.2f GB", gb)
}

fun riskColor(risk: RiskClassification): Color = when (risk) {
    RiskClassification.SAFE_INDICATORS_FOUND -> ForensicColors.EmeraldSafe
    RiskClassification.LOW_RISK -> ForensicColors.CyanAccent
    RiskClassification.MEDIUM_RISK -> ForensicColors.AmberWarn
    RiskClassification.HIGH_RISK -> ForensicColors.OrangeHigh
    RiskClassification.CRITICAL_INDICATORS -> ForensicColors.CrimsonCritical
    RiskClassification.UNKNOWN_INSUFFICIENT_EVIDENCE -> ForensicColors.PurpleUnknown
}

@Composable
fun ForensicCard(
    modifier: Modifier = Modifier,
    borderColor: Color = ForensicColors.BorderSlate,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = ForensicColors.ElevatedCard),
        border = BorderStroke(1.dp, borderColor)
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            content = content
        )
    }
}

@Composable
fun RiskBadge(risk: RiskClassification) {
    val color = riskColor(risk)
    val text = if (risk == RiskClassification.SAFE_INDICATORS_FOUND) {
        "No known suspicious indicators detected"
    } else {
        risk.label
    }
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(color.copy(alpha = 0.16f))
            .padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        Text(
            text = text,
            color = color,
            fontSize = 11.sp,
            fontWeight = FontWeight.Bold
        )
    }
}

@Composable
fun MetricTile(
    label: String,
    value: String,
    accent: Color = ForensicColors.CyanAccent,
    modifier: Modifier = Modifier
) {
    ForensicCard(modifier = modifier) {
        Text(text = label, style = MaterialTheme.typography.bodySmall)
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = value,
            color = accent,
            fontSize = 20.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = FontFamily.Monospace
        )
    }
}

@Composable
fun ExpandableTechnicalSection(
    title: String,
    initiallyExpanded: Boolean = false,
    content: @Composable ColumnScope.() -> Unit
) {
    var expanded by remember { mutableStateOf(initiallyExpanded) }
    ForensicCard {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { expanded = !expanded },
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(text = title, style = MaterialTheme.typography.titleMedium)
            Icon(
                imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                contentDescription = null,
                tint = ForensicColors.CyanAccent
            )
        }
        AnimatedVisibility(visible = expanded) {
            Column(modifier = Modifier.padding(top = 10.dp), content = content)
        }
    }
}

@Composable
fun RiskDistributionChart(
    safeCount: Int,
    lowMedCount: Int,
    highCritCount: Int,
    unknownCount: Int
) {
    val total = (safeCount + lowMedCount + highCritCount + unknownCount).coerceAtLeast(1)
    val slices = listOf(
        Triple("No Suspicious Indicators", safeCount, ForensicColors.EmeraldSafe),
        Triple("Low / Medium Risk", lowMedCount, ForensicColors.AmberWarn),
        Triple("High / Critical", highCritCount, ForensicColors.CrimsonCritical),
        Triple("Unknown Evidence", unknownCount, ForensicColors.PurpleUnknown)
    )

    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Canvas(modifier = Modifier.size(104.dp)) {
            var startAngle = -90f
            val strokeWidth = 18.dp.toPx()
            val arcSize = Size(size.width - strokeWidth, size.height - strokeWidth)
            val topLeft = androidx.compose.ui.geometry.Offset(strokeWidth / 2f, strokeWidth / 2f)

            if (safeCount + lowMedCount + highCritCount + unknownCount == 0) {
                drawArc(
                    color = ForensicColors.BorderSlate,
                    startAngle = 0f,
                    sweepAngle = 360f,
                    useCenter = false,
                    topLeft = topLeft,
                    size = arcSize,
                    style = Stroke(width = strokeWidth, cap = StrokeCap.Butt)
                )
            } else {
                for ((_, count, color) in slices) {
                    if (count <= 0) continue
                    val sweep = (count.toFloat() / total.toFloat()) * 360f
                    drawArc(
                        color = color,
                        startAngle = startAngle,
                        sweepAngle = sweep,
                        useCenter = false,
                        topLeft = topLeft,
                        size = arcSize,
                        style = Stroke(width = strokeWidth, cap = StrokeCap.Butt)
                    )
                    startAngle += sweep
                }
            }
        }
        Spacer(modifier = Modifier.width(16.dp))
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            for ((label, count, color) in slices) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(10.dp)
                            .clip(CircleShape)
                            .background(color)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "$label: $count",
                        style = MaterialTheme.typography.bodySmall,
                        color = ForensicColors.TextPrimary
                    )
                }
            }
        }
    }
}
