package com.fileguard.forensics.ui.screens

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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fileguard.forensics.domain.model.PrivacyDashboardState
import com.fileguard.forensics.domain.model.QuarantineRecord
import com.fileguard.forensics.domain.model.ScanSessionSummary
import com.fileguard.forensics.ui.ActiveFileInvestigation
import com.fileguard.forensics.ui.components.ForensicCard
import com.fileguard.forensics.ui.components.RiskBadge
import com.fileguard.forensics.ui.components.formatBytes
import com.fileguard.forensics.ui.theme.ForensicColors
import java.io.File

@Composable
fun RecoveryLabScreen(
    active: ActiveFileInvestigation?,
    onPickFile: () -> Unit,
    onAttemptRecovery: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        if (active == null) {
            item {
                ForensicCard {
                    Text("File Recovery & Repair Laboratory", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(6.dp))
                    Text("Select a damaged ZIP archive, truncated JPEG, or mismatched file to assess safe non-destructive repair options.", style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(10.dp))
                    Button(onClick = onPickFile) { Text("Select Damaged File") }
                }
            }
            return@LazyColumn
        }

        val rec = active.recoveryAssessment
        item {
            ForensicCard {
                Text(rec.fileName, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(6.dp))
                Text("Issue Detected: ${rec.issueDetected}", style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(4.dp))
                Text("Suggested Action: ${rec.suggestedAction}", style = MaterialTheme.typography.bodySmall, color = ForensicColors.CyanAccent)
                if (rec.isRecoverableOrRepairable) {
                    Spacer(Modifier.height(10.dp))
                    Button(
                        onClick = onAttemptRecovery,
                        colors = ButtonDefaults.buttonColors(containerColor = ForensicColors.CyanAccent, contentColor = ForensicColors.DeepNavy)
                    ) {
                        Text("Create Safe Repaired / Extracted Copy", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        item {
            ForensicCard(borderColor = ForensicColors.AmberWarn.copy(0.5f)) {
                Text("Android Storage Recovery Limitations", style = MaterialTheme.typography.titleMedium, color = ForensicColors.AmberWarn)
                Spacer(Modifier.height(4.dp))
                Text(rec.androidLimitationNote, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
fun QuarantineScreen(
    records: List<QuarantineRecord>,
    onRestoreRecord: (QuarantineRecord) -> Unit,
    onDeleteRecord: (QuarantineRecord) -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            ForensicCard(borderColor = ForensicColors.AmberWarn.copy(0.5f)) {
                Text("Safe Quarantine Vault", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(4.dp))
                Text(
                    "Quarantined files are stored as non-executable copies in app-private storage with their SHA-256 preserved. Copying a file to Quarantine does not automatically delete or neutralize the original file on external storage.",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
        if (records.isEmpty()) {
            item {
                ForensicCard { Text("Quarantine vault is empty.", style = MaterialTheme.typography.bodySmall) }
            }
        } else {
            items(records) { rec ->
                ForensicCard {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(rec.originalName, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold)
                        RiskBadge(rec.riskClassification)
                    }
                    Spacer(Modifier.height(4.dp))
                    Text("Size: ${formatBytes(rec.fileSize)}", style = MaterialTheme.typography.bodySmall)
                    Text("Original SHA-256: ${rec.originalSha256}", style = MaterialTheme.typography.labelMedium)
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { onRestoreRecord(rec) }) { Text("Restore Copy") }
                        OutlinedButton(onClick = { onDeleteRecord(rec) }) {
                            Text("Remove", color = ForensicColors.CrimsonCritical)
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ForensicReportsScreen(
    sessions: List<ScanSessionSummary>,
    generatedFile: File?,
    onExportPdf: (ScanSessionSummary) -> Unit,
    onExportJson: (ScanSessionSummary) -> Unit,
    onShareFile: (File) -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        if (generatedFile != null) {
            item {
                ForensicCard(borderColor = ForensicColors.EmeraldSafe) {
                    Text("Report Ready: ${generatedFile.name}", style = MaterialTheme.typography.titleMedium, color = ForensicColors.EmeraldSafe)
                    Spacer(Modifier.height(6.dp))
                    Button(onClick = { onShareFile(generatedFile) }) {
                        Text("Share / Open Report")
                    }
                }
            }
        }

        if (sessions.isEmpty()) {
            item {
                ForensicCard {
                    Text("Complete a folder or storage scan first to generate PDF or JSON forensic investigation reports.", style = MaterialTheme.typography.bodySmall)
                }
            }
        } else {
            items(sessions) { session ->
                ForensicCard {
                    Text(session.sourceLabel, style = MaterialTheme.typography.titleMedium)
                    Text("ID: ${session.sessionId.take(12)} • Files: ${session.totalFiles} • Flagged: ${session.suspiciousCount}", style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { onExportPdf(session) }) { Text("Export PDF") }
                        OutlinedButton(onClick = { onExportJson(session) }) { Text("Export JSON") }
                    }
                }
            }
        }
    }
}

@Composable
fun SettingsPrivacyScreen(
    privacyState: PrivacyDashboardState,
    currentLanguage: String,
    onToggleOfflineMode: (Boolean) -> Unit,
    onSelectLanguage: (String) -> Unit,
    onClearHistory: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            ForensicCard(borderColor = if (privacyState.offlineModeEnabled) ForensicColors.EmeraldSafe else ForensicColors.AmberWarn) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Text("Offline Mode (Default)", style = MaterialTheme.typography.titleMedium)
                        Text(
                            "When enabled, FileGuard makes zero network requests. Disable only if you want optional SHA-256 hash-only lookups.",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                    Switch(
                        checked = privacyState.offlineModeEnabled,
                        onCheckedChange = onToggleOfflineMode
                    )
                }
            }
        }

        item {
            ForensicCard {
                Text("Privacy Dashboard", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(6.dp))
                Text("Data Sharing Status: ${privacyState.dataSharingStatus}", style = MaterialTheme.typography.bodySmall, color = ForensicColors.CyanAccent)
                Text("Device Network Available: ${if (privacyState.networkAvailable) "Yes" else "No"}", style = MaterialTheme.typography.bodySmall)
                Text("Last Online Lookup: ${privacyState.lastOnlineLookupTimestamp}", style = MaterialTheme.typography.bodySmall)
                Text("Local Scan Sessions Stored: ${privacyState.localScanHistoryCount}", style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(6.dp))
                Text("Granted Permissions:", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                for (p in privacyState.grantedPermissions) {
                    Text("• $p", style = MaterialTheme.typography.bodySmall)
                }
                if (privacyState.selectedStorageSources.isNotEmpty()) {
                    Spacer(Modifier.height(6.dp))
                    Text("Authorized Storage Sources:", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                    for (s in privacyState.selectedStorageSources) {
                        Text("• $s", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }

        item {
            ForensicCard {
                Text("Interface Language / ഭാഷ", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (currentLanguage == "en") {
                        Button(onClick = { onSelectLanguage("en") }) { Text("English") }
                        OutlinedButton(onClick = { onSelectLanguage("ml") }) { Text("മലയാളം (Malayalam)") }
                    } else {
                        OutlinedButton(onClick = { onSelectLanguage("en") }) { Text("English") }
                        Button(onClick = { onSelectLanguage("ml") }) { Text("മലയാളം (Malayalam)") }
                    }
                }
            }
        }

        item {
            OutlinedButton(
                onClick = onClearHistory,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Clear Local Scan History", color = ForensicColors.CrimsonCritical)
            }
        }
    }
}
