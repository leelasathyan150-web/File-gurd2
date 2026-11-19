package com.fileguard.forensics.ui.screens

import android.net.Uri
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fileguard.forensics.domain.model.ScanProgressState
import com.fileguard.forensics.domain.model.ScannedFileSummary
import com.fileguard.forensics.ui.components.ForensicCard
import com.fileguard.forensics.ui.components.MetricTile
import com.fileguard.forensics.ui.components.RiskBadge
import com.fileguard.forensics.ui.components.formatBytes
import com.fileguard.forensics.ui.theme.ForensicColors

@Composable
fun DeepScanScreen(
    progress: ScanProgressState,
    onStartNewScan: () -> Unit,
    onPause: () -> Unit,
    onResume: () -> Unit,
    onCancel: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            ForensicCard {
                Text(
                    text = when {
                        progress.isScanning && progress.isPaused -> "Scan Paused"
                        progress.isScanning -> "Deep Forensic Scan Running..."
                        progress.isCancelled -> "Scan Cancelled"
                        progress.totalFilesExamined > 0 -> "Last Scan Complete"
                        else -> "Ready to Scan"
                    },
                    style = MaterialTheme.typography.titleMedium
                )
                Spacer(Modifier.height(8.dp))
                if (progress.isScanning && !progress.isPaused) {
                    LinearProgressIndicator(
                        modifier = Modifier.fillMaxWidth(),
                        color = ForensicColors.CyanAccent
                    )
                    Spacer(Modifier.height(8.dp))
                }
                Text(
                    text = if (progress.currentFile.isNotBlank()) "Current: ${progress.currentFile}" else "Select a storage folder or USB drive to begin.",
                    style = MaterialTheme.typography.bodySmall
                )
                Spacer(Modifier.height(10.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (!progress.isScanning) {
                        Button(
                            onClick = onStartNewScan,
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(containerColor = ForensicColors.CyanAccent, contentColor = ForensicColors.DeepNavy)
                        ) {
                            Text("Select Folder & Scan", fontWeight = FontWeight.Bold)
                        }
                    } else {
                        if (progress.isPaused) {
                            Button(onClick = onResume, modifier = Modifier.weight(1f)) { Text("Resume") }
                        } else {
                            OutlinedButton(onClick = onPause, modifier = Modifier.weight(1f)) { Text("Pause") }
                        }
                        OutlinedButton(onClick = onCancel, modifier = Modifier.weight(1f)) {
                            Text("Cancel", color = ForensicColors.CrimsonCritical)
                        }
                    }
                }
            }
        }

        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                MetricTile("Files Examined", progress.totalFilesExamined.toString(), ForensicColors.CyanAccent, Modifier.weight(1f))
                MetricTile("Folders Examined", progress.totalFoldersExamined.toString(), ForensicColors.ElectricBlue, Modifier.weight(1f))
            }
        }
        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                MetricTile("Storage Examined", formatBytes(progress.totalBytesExamined), ForensicColors.CyanAccent, Modifier.weight(1f))
                MetricTile("Hidden Files", progress.hiddenFilesCount.toString(), ForensicColors.AmberWarn, Modifier.weight(1f))
            }
        }
        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                MetricTile("Unknown Formats", progress.unknownFormatsCount.toString(), ForensicColors.PurpleUnknown, Modifier.weight(1f))
                MetricTile("Suspicious Files", progress.suspiciousFilesCount.toString(), ForensicColors.CrimsonCritical, Modifier.weight(1f))
            }
        }
        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                MetricTile("Duplicates (SHA-256)", progress.duplicateFilesCount.toString(), ForensicColors.TextPrimary, Modifier.weight(1f))
                MetricTile("Zero-Byte / Corrupt", "${progress.zeroByteFilesCount} / ${progress.corruptedFilesCount}", ForensicColors.OrangeHigh, Modifier.weight(1f))
            }
        }

        if (progress.errors.isNotEmpty()) {
            item {
                Text("Scan Errors & Skipped Locations (${progress.errors.size})", style = MaterialTheme.typography.titleMedium)
            }
            items(progress.errors.take(30)) { err ->
                ForensicCard(borderColor = ForensicColors.AmberWarn.copy(alpha = 0.5f)) {
                    Text(err.location, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                    Text(err.reason, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@Composable
fun HiddenFilesLabScreen(
    hiddenFiles: List<ScannedFileSummary>,
    onInspectFile: (Uri) -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            ForensicCard {
                Text("Hidden Files Laboratory", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(4.dp))
                Text(
                    "Detects dot-prefixed files/folders, extensionless files, double extensions, .nomedia markers, and hidden executables without bypassing Android's private app sandboxes.",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
        if (hiddenFiles.isEmpty()) {
            item {
                ForensicCard {
                    Text("No hidden or unusually named files discovered in scanned locations yet.", style = MaterialTheme.typography.bodySmall)
                }
            }
        } else {
            items(hiddenFiles) { file ->
                ForensicCard(modifier = Modifier.clickable { onInspectFile(Uri.parse(file.fileUri)) }) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Column(Modifier.weight(1f)) {
                            Text(file.fileName, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                            Text(file.filePathDisplay, style = MaterialTheme.typography.bodySmall)
                            Text("Format: ${file.detectedFormat} • ${file.findingsSummary}", style = MaterialTheme.typography.bodySmall, color = ForensicColors.AmberWarn)
                        }
                        RiskBadge(file.riskClassification)
                    }
                }
            }
        }
    }
}
