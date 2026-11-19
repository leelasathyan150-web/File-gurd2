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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.SdStorage
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Usb
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fileguard.forensics.domain.model.RiskClassification
import com.fileguard.forensics.domain.model.ScanSessionSummary
import com.fileguard.forensics.domain.model.ScannedFileSummary
import com.fileguard.forensics.ui.StorageVolumeInfo
import com.fileguard.forensics.ui.components.ForensicCard
import com.fileguard.forensics.ui.components.MetricTile
import com.fileguard.forensics.ui.components.RiskBadge
import com.fileguard.forensics.ui.components.RiskDistributionChart
import com.fileguard.forensics.ui.components.formatBytes
import com.fileguard.forensics.ui.navigation.ForensicRoute
import com.fileguard.forensics.ui.theme.ForensicColors

@Composable
fun DashboardScreen(
    volumes: List<StorageVolumeInfo>,
    recentSessions: List<ScanSessionSummary>,
    recentFiles: List<ScannedFileSummary>,
    offlineMode: Boolean,
    onNavigate: (ForensicRoute) -> Unit,
    onPickFolderToScan: () -> Unit,
    onPickSingleFile: () -> Unit,
    onInspectFile: (Uri) -> Unit
) {
    val safeCount = recentFiles.count { it.riskClassification == RiskClassification.SAFE_INDICATORS_FOUND }
    val lowMedCount = recentFiles.count {
        it.riskClassification == RiskClassification.LOW_RISK || it.riskClassification == RiskClassification.MEDIUM_RISK
    }
    val highCritCount = recentFiles.count {
        it.riskClassification == RiskClassification.HIGH_RISK || it.riskClassification == RiskClassification.CRITICAL_INDICATORS
    }
    val unknownCount = recentFiles.count {
        it.riskClassification == RiskClassification.UNKNOWN_INSUFFICIENT_EVIDENCE
    }
    val hiddenCount = recentFiles.count { it.isHidden }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            ForensicCard(borderColor = if (offlineMode) ForensicColors.EmeraldSafe.copy(0.5f) else ForensicColors.AmberWarn) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            tint = if (offlineMode) ForensicColors.EmeraldSafe else ForensicColors.AmberWarn
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text(
                                text = if (offlineMode) "OFFLINE FORENSIC MODE ACTIVE" else "OPTIONAL HASH LOOKUP ENABLED",
                                style = MaterialTheme.typography.labelMedium,
                                color = if (offlineMode) ForensicColors.EmeraldSafe else ForensicColors.AmberWarn
                            )
                            Text(
                                text = "All scanning & decoding run locally on-device.",
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                }
            }
        }

        item {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button(
                    onClick = onPickFolderToScan,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = ForensicColors.CyanAccent, contentColor = ForensicColors.DeepNavy)
                ) {
                    Icon(Icons.Default.Search, contentDescription = null)
                    Spacer(Modifier.width(6.dp))
                    Text("Scan Folder / USB", fontWeight = FontWeight.Bold)
                }
                OutlinedButton(
                    onClick = onPickSingleFile,
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Default.InsertDriveFile, contentDescription = null, tint = ForensicColors.CyanAccent)
                    Spacer(Modifier.width(6.dp))
                    Text("Inspect File", color = ForensicColors.CyanAccent)
                }
            }
        }

        item {
            ForensicCard {
                Text("Storage Overview", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(8.dp))
                for (vol in volumes) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = when {
                                vol.isUsb -> Icons.Default.Usb
                                vol.isRemovable -> Icons.Default.SdStorage
                                else -> Icons.Default.FolderOpen
                            },
                            contentDescription = null,
                            tint = ForensicColors.CyanAccent
                        )
                        Spacer(Modifier.width(10.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(vol.name, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                            val subtitle = if (vol.totalBytes > 0) {
                                "${formatBytes(vol.availableBytes)} free of ${formatBytes(vol.totalBytes)}"
                            } else {
                                "Removable volume — authorize via Storage Explorer"
                            }
                            Text(subtitle, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }

        item {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                MetricTile("Files Indexed", recentFiles.size.toString(), ForensicColors.CyanAccent, Modifier.weight(1f))
                MetricTile("Hidden Files", hiddenCount.toString(), ForensicColors.AmberWarn, Modifier.weight(1f))
            }
        }
        item {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                MetricTile("Unknown Formats", unknownCount.toString(), ForensicColors.PurpleUnknown, Modifier.weight(1f))
                MetricTile("High/Critical", highCritCount.toString(), ForensicColors.CrimsonCritical, Modifier.weight(1f))
            }
        }

        item {
            ForensicCard {
                Text("Risk Summary", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(10.dp))
                RiskDistributionChart(safeCount, lowMedCount, highCritCount, unknownCount)
            }
        }

        item {
            Text("Recent Investigations", style = MaterialTheme.typography.titleMedium)
        }

        if (recentSessions.isEmpty()) {
            item {
                ForensicCard {
                    Text(
                        "No scan sessions recorded yet. Tap 'Scan Folder / USB' or 'Inspect File' to begin an evidence-based investigation.",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        } else {
            items(recentSessions.take(5)) { session ->
                ForensicCard {
                    Text(session.sourceLabel, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                    Text(
                        "Files: ${session.totalFiles} • Hidden: ${session.hiddenCount} • Flagged: ${session.suspiciousCount} • ${session.status}",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }

        if (recentFiles.isNotEmpty()) {
            item {
                Text("Recent Flagged & Inspected Files", style = MaterialTheme.typography.titleMedium)
            }
            items(recentFiles.take(8)) { file ->
                ForensicCard(
                    modifier = Modifier.clickable {
                        onInspectFile(Uri.parse(file.fileUri))
                        onNavigate(ForensicRoute.UNKNOWN_DECODER)
                    }
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(file.fileName, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                            Text("${file.detectedFormat} • ${formatBytes(file.fileSize)}", style = MaterialTheme.typography.bodySmall)
                        }
                        RiskBadge(file.riskClassification)
                    }
                }
            }
        }
    }
}

@Composable
fun StorageExplorerScreen(
    volumes: List<StorageVolumeInfo>,
    onRefreshVolumes: () -> Unit,
    onPickFolderTree: () -> Unit,
    onPickSingleFile: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            ForensicCard {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Detected Storage Volumes", style = MaterialTheme.typography.titleMedium)
                    IconButton(onClick = onRefreshVolumes) {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh", tint = ForensicColors.CyanAccent)
                    }
                }
                for (vol in volumes) {
                    Text(
                        "• ${vol.name} (${if (vol.isUsb) "USB OTG" else if (vol.isRemovable) "SD / Removable" else "Internal"})",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(vertical = 3.dp)
                    )
                }
            }
        }

        item {
            ForensicCard {
                Text("User-Authorized Storage Access (SAF)", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(6.dp))
                Text(
                    "FileGuard uses Android's Storage Access Framework (ACTION_OPEN_DOCUMENT_TREE) to inspect internal folders, SD cards, and USB OTG drives without bypassing Android security or requesting invasive all-files privileges.",
                    style = MaterialTheme.typography.bodySmall
                )
                Spacer(Modifier.height(12.dp))
                Button(
                    onClick = onPickFolderTree,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = ForensicColors.CyanAccent, contentColor = ForensicColors.DeepNavy)
                ) {
                    Text("Select Folder / SD Card / USB Drive to Scan", fontWeight = FontWeight.Bold)
                }
                Spacer(Modifier.height(8.dp))
                OutlinedButton(
                    onClick = onPickSingleFile,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Select Individual File to Inspect", color = ForensicColors.CyanAccent)
                }
            }
        }

        item {
            ForensicCard {
                Text("Android Scoped Storage Boundaries", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(4.dp))
                Text(
                    "Protected OS partitions (/system, /data/data of other apps, and /Android/data on Android 11+) cannot be read by third-party apps without root. FileGuard respects these boundaries and logs inaccessible locations transparently.",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}
