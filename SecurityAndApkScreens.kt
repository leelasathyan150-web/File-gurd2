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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fileguard.forensics.domain.engine.HashLookupResult
import com.fileguard.forensics.domain.model.IndicatorSeverity
import com.fileguard.forensics.ui.ActiveFileInvestigation
import com.fileguard.forensics.ui.components.ExpandableTechnicalSection
import com.fileguard.forensics.ui.components.ForensicCard
import com.fileguard.forensics.ui.components.RiskBadge
import com.fileguard.forensics.ui.theme.ForensicColors

@Composable
fun MalwareAnalysisScreen(
    active: ActiveFileInvestigation?,
    offlineMode: Boolean,
    lastLookup: HashLookupResult?,
    onPickFile: () -> Unit,
    onQuarantineActive: () -> Unit,
    onRequestHashLookup: (String) -> Unit
) {
    var showConsentDialog by remember { mutableStateOf(false) }

    if (showConsentDialog && active != null) {
        AlertDialog(
            onDismissRequest = { showConsentDialog = false },
            title = { Text("Confirm Optional Hash-Only Lookup") },
            text = {
                Text(
                    "Only the SHA-256 hash (${active.decoderResult.signature.sha256}) will be sent to abuse.ch MalwareBazaar. No file contents, filename, or personal data will be uploaded."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showConsentDialog = false
                    onRequestHashLookup(active.decoderResult.signature.sha256)
                }) { Text("Send Hash Only") }
            },
            dismissButton = {
                TextButton(onClick = { showConsentDialog = false }) { Text("Cancel") }
            }
        )
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        if (active == null) {
            item {
                ForensicCard {
                    Text("Offline Threat & Malware Analysis", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(6.dp))
                    Text("Select a file to run static signature, script, entropy, and binary indicator analysis.", style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(10.dp))
                    Button(onClick = onPickFile) { Text("Select File") }
                }
            }
            return@LazyColumn
        }

        val threat = active.threatResult
        val sig = active.decoderResult.signature

        item {
            ForensicCard {
                Text(active.fileName, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(6.dp))
                RiskBadge(threat.riskClassification)
                Spacer(Modifier.height(8.dp))
                Text(threat.explanation, style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(4.dp))
                Text("Recommended Action: ${threat.recommendedAction}", style = MaterialTheme.typography.bodySmall, color = ForensicColors.CyanAccent)
                Spacer(Modifier.height(6.dp))
                Text("SHA-256: ${sig.sha256}", style = MaterialTheme.typography.labelMedium)
            }
        }

        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = onQuarantineActive,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = ForensicColors.AmberWarn, contentColor = ForensicColors.DeepNavy)
                ) {
                    Text("Quarantine Copy", fontWeight = FontWeight.Bold)
                }
                OutlinedButton(
                    onClick = { showConsentDialog = true },
                    enabled = !offlineMode,
                    modifier = Modifier.weight(1f)
                ) {
                    Text(if (offlineMode) "Offline Mode On" else "Hash Lookup")
                }
            }
        }

        if (lastLookup != null) {
            item {
                ForensicCard(borderColor = ForensicColors.CyanAccent) {
                    Text("Optional Threat Intel Result (${lastLookup.source})", style = MaterialTheme.typography.titleMedium)
                    Text(lastLookup.summary, style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        items(threat.indicators) { ind ->
            val color = when (ind.severity) {
                IndicatorSeverity.CONFIRMED_MALICIOUS_INDICATOR -> ForensicColors.CrimsonCritical
                IndicatorSeverity.SUSPICIOUS_INDICATOR -> ForensicColors.AmberWarn
                IndicatorSeverity.UNUSUAL_POTENTIALLY_LEGITIMATE -> ForensicColors.CyanAccent
                IndicatorSeverity.UNKNOWN_UNVERIFIED -> ForensicColors.PurpleUnknown
            }
            ForensicCard(borderColor = color.copy(alpha = 0.6f)) {
                Text(ind.title, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold, color = color)
                Text("Category: ${ind.severity.name.replace('_', ' ')}", style = MaterialTheme.typography.labelMedium)
                Spacer(Modifier.height(4.dp))
                Text(ind.detail, style = MaterialTheme.typography.bodySmall)
                Text("Evidence: ${ind.evidence}", style = MaterialTheme.typography.bodySmall, color = ForensicColors.TextPrimary)
            }
        }

        item {
            ForensicCard {
                Text(threat.staticAnalysisDisclaimer, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
fun ApkInspectorScreen(
    active: ActiveFileInvestigation?,
    onPickApk: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        val apk = active?.apkResult
        if (apk == null) {
            item {
                ForensicCard {
                    Text("APK Static Inspector", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(6.dp))
                    Text("Select an .apk file to inspect package metadata, permissions, exported components, and signing certificates without installing or executing it.", style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(10.dp))
                    Button(onClick = onPickApk) { Text("Select APK File") }
                }
            }
            return@LazyColumn
        }

        if (apk.parseError != null) {
            item {
                ForensicCard(borderColor = ForensicColors.CrimsonCritical) {
                    Text("APK Parse Error", style = MaterialTheme.typography.titleMedium, color = ForensicColors.CrimsonCritical)
                    Text(apk.parseError, style = MaterialTheme.typography.bodySmall)
                }
            }
            return@LazyColumn
        }

        item {
            ForensicCard {
                Text("${apk.appName} (${apk.packageName})", style = MaterialTheme.typography.titleMedium)
                Text("Version: ${apk.versionName} (${apk.versionCode}) • minSdk: ${apk.minSdk ?: "?"} / targetSdk: ${apk.targetSdk ?: "?"}", style = MaterialTheme.typography.bodySmall)
                Text("Exported Components: ${apk.exportedComponentsCount}", style = MaterialTheme.typography.bodySmall)
                apk.signingCertSha256?.let {
                    Spacer(Modifier.height(4.dp))
                    Text("Signing Cert SHA-256: $it", style = MaterialTheme.typography.labelMedium)
                }
            }
        }

        if (apk.staticWarnings.isNotEmpty()) {
            item {
                ForensicCard(borderColor = ForensicColors.AmberWarn) {
                    Text("Static Security Warnings", style = MaterialTheme.typography.titleMedium, color = ForensicColors.AmberWarn)
                    for (w in apk.staticWarnings) {
                        Text("• $w", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }

        item {
            ExpandableTechnicalSection("Dangerous Permissions (${apk.dangerousPermissions.size})", initiallyExpanded = true) {
                if (apk.dangerousPermissions.isEmpty()) {
                    Text("None flagged.", style = MaterialTheme.typography.bodySmall)
                } else {
                    for (p in apk.dangerousPermissions) {
                        Text("• $p", style = MaterialTheme.typography.bodySmall, color = ForensicColors.AmberWarn)
                    }
                }
            }
        }

        item {
            ExpandableTechnicalSection("All Requested Permissions (${apk.requestedPermissions.size})") {
                for (p in apk.requestedPermissions) {
                    Text("• $p", style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        item {
            ExpandableTechnicalSection("Components (Activities: ${apk.activities.size}, Services: ${apk.services.size}, Receivers: ${apk.receivers.size})") {
                Text("Activities: ${apk.activities.joinToString()}", style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(4.dp))
                Text("Services: ${apk.services.joinToString()}", style = MaterialTheme.typography.bodySmall)
                Spacer(Modifier.height(4.dp))
                Text("Receivers: ${apk.receivers.joinToString()}", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}
