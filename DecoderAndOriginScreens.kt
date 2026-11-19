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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.fileguard.forensics.domain.model.ProvenanceCategory
import com.fileguard.forensics.domain.model.ScannedFileSummary
import com.fileguard.forensics.ui.ActiveFileInvestigation
import com.fileguard.forensics.ui.components.ExpandableTechnicalSection
import com.fileguard.forensics.ui.components.ForensicCard
import com.fileguard.forensics.ui.components.formatBytes
import com.fileguard.forensics.ui.theme.ForensicColors

@Composable
fun UnknownFileDecoderScreen(
    active: ActiveFileInvestigation?,
    isInspecting: Boolean,
    unknownFiles: List<ScannedFileSummary>,
    onPickFile: () -> Unit,
    onInspectFile: (Uri) -> Unit,
    onQuarantineActive: () -> Unit
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = onPickFile,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = ForensicColors.CyanAccent, contentColor = ForensicColors.DeepNavy)
                ) {
                    Text("Select File to Decode", fontWeight = FontWeight.Bold)
                }
                if (active != null) {
                    OutlinedButton(onClick = onQuarantineActive, modifier = Modifier.weight(1f)) {
                        Text("Copy to Quarantine", color = ForensicColors.AmberWarn)
                    }
                }
            }
        }

        if (isInspecting) {
            item {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = ForensicColors.CyanAccent)
            }
        }

        if (active != null) {
            val dec = active.decoderResult
            val sig = dec.signature
            item {
                ForensicCard(borderColor = if (sig.isExtensionMismatch) ForensicColors.CrimsonCritical else ForensicColors.CyanAccent.copy(0.5f)) {
                    Text(sig.fileName, style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(6.dp))
                    Text("Declared Extension: .${sig.declaredExtension.ifBlank { "(none)" }}", style = MaterialTheme.typography.bodySmall)
                    Text("Detected True Format: ${sig.detectedFormat}", style = MaterialTheme.typography.bodyMedium, color = ForensicColors.CyanAccent)
                    Text("Size: ${formatBytes(sig.fileSize)} | Entropy: ${String.format("%.2f", sig.entropyBitsPerByte)} bits/byte", style = MaterialTheme.typography.bodySmall)
                    Text("SHA-256: ${sig.sha256}", style = MaterialTheme.typography.labelMedium)
                    if (sig.isExtensionMismatch) {
                        Spacer(Modifier.height(6.dp))
                        Text(
                            "MISLEADING EXTENSION DETECTED: File pretends to be .${sig.declaredExtension} but is ${sig.detectedFormat}.",
                            color = ForensicColors.CrimsonCritical,
                            fontWeight = FontWeight.Bold,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }

            item {
                ForensicCard {
                    Text("Why Android Fails to Open It", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(4.dp))
                    Text(dec.androidOpenFailureReason, style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.height(6.dp))
                    Text("Recommended Safe Viewer: ${dec.recommendedViewerType}", style = MaterialTheme.typography.bodySmall, color = ForensicColors.CyanAccent)
                }
            }

            if (dec.encryptionIndicators.isNotEmpty()) {
                item {
                    ForensicCard(borderColor = ForensicColors.AmberWarn) {
                        Text("Encryption / Packing Indicators", style = MaterialTheme.typography.titleMedium, color = ForensicColors.AmberWarn)
                        for (ind in dec.encryptionIndicators) {
                            Text("• $ind", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }

            if (dec.safeTextPreview != null) {
                item {
                    ExpandableTechnicalSection("Safe Text Preview (Read-Only)", initiallyExpanded = true) {
                        Text(
                            text = dec.safeTextPreview.take(3000),
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            color = ForensicColors.TextPrimary
                        )
                    }
                }
            }

            if (dec.metadataMap.isNotEmpty()) {
                item {
                    ExpandableTechnicalSection("Embedded Metadata (${dec.metadataMap.size})") {
                        for ((k, v) in dec.metadataMap) {
                            Text("$k: $v", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }

            if (dec.archiveEntries.isNotEmpty()) {
                item {
                    ExpandableTechnicalSection("Archive Contents (${dec.archiveEntries.size}${if (dec.archiveLimitReached) "+" else ""})") {
                        for (entry in dec.archiveEntries.take(60)) {
                            Text(
                                "${if (entry.isHiddenOrSuspicious) "[!] " else "• "}${entry.name} (${formatBytes(entry.uncompressedSize.coerceAtLeast(0))})",
                                style = MaterialTheme.typography.bodySmall,
                                color = if (entry.isHiddenOrSuspicious) ForensicColors.AmberWarn else ForensicColors.TextPrimary
                            )
                        }
                    }
                }
            }

            item {
                ExpandableTechnicalSection("Hexadecimal Header Inspection (First 512 Bytes)") {
                    for (line in dec.hexLines) {
                        Text(line, fontFamily = FontFamily.Monospace, fontSize = 10.sp, color = ForensicColors.CyanAccent)
                    }
                }
            }

            item {
                ExpandableTechnicalSection("Extracted Readable Strings (${dec.extractedStrings.size})") {
                    for (s in dec.extractedStrings.take(60)) {
                        Text(s, fontFamily = FontFamily.Monospace, fontSize = 11.sp, color = ForensicColors.TextPrimary)
                    }
                }
            }

            item {
                ForensicCard {
                    Text(dec.decoderLimitations, style = MaterialTheme.typography.bodySmall)
                }
            }
        } else if (unknownFiles.isNotEmpty()) {
            item { Text("Unknown / Damaged / Mismatched Files from Scans", style = MaterialTheme.typography.titleMedium) }
            items(unknownFiles) { file ->
                ForensicCard(modifier = Modifier.clickable { onInspectFile(Uri.parse(file.fileUri)) }) {
                    Text(file.fileName, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                    Text("${file.detectedFormat} • ${file.findingsSummary}", style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@Composable
fun FileOriginScreen(
    active: ActiveFileInvestigation?,
    onPickFile: () -> Unit
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
                    Text("File Origin & Digital Forensics", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(6.dp))
                    Text("Select a file to investigate timestamps, EXIF/device identifiers, embedded URLs, and probable provenance.", style = MaterialTheme.typography.bodySmall)
                    Spacer(Modifier.height(10.dp))
                    Button(onClick = onPickFile) { Text("Select File") }
                }
            }
            return@LazyColumn
        }

        val origin = active.originResult
        item {
            ForensicCard(
                borderColor = if (origin.category == ProvenanceCategory.UNKNOWN_ORIGIN) {
                    ForensicColors.PurpleUnknown
                } else {
                    ForensicColors.CyanAccent
                }
            ) {
                Text(active.fileName, style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(6.dp))
                Text(
                    text = origin.summaryStatement,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Bold,
                    color = if (origin.category == ProvenanceCategory.UNKNOWN_ORIGIN) ForensicColors.PurpleUnknown else ForensicColors.CyanAccent
                )
                Spacer(Modifier.height(4.dp))
                Text("Confidence: ${origin.confidence.label}", style = MaterialTheme.typography.bodySmall)
            }
        }

        item {
            ForensicCard {
                Text("Supporting Forensic Evidence", style = MaterialTheme.typography.titleMedium)
                Spacer(Modifier.height(4.dp))
                if (origin.supportingEvidence.isEmpty()) {
                    Text("No provenance artifacts (EXIF, download path, USB volume, or embedded origin tags) were found.", style = MaterialTheme.typography.bodySmall)
                } else {
                    for (ev in origin.supportingEvidence) {
                        Text("• $ev", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }

        if (origin.timestamps.isNotEmpty()) {
            item {
                ForensicCard {
                    Text("Observed Timestamps", style = MaterialTheme.typography.titleMedium)
                    for ((k, v) in origin.timestamps) {
                        Text("$k: $v", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }

        if (origin.embeddedUrls.isNotEmpty()) {
            item {
                ForensicCard {
                    Text("Embedded URLs (${origin.embeddedUrls.size})", style = MaterialTheme.typography.titleMedium)
                    for (u in origin.embeddedUrls) {
                        Text("• $u", style = MaterialTheme.typography.labelMedium)
                    }
                }
            }
        }
    }
}
