package com.fileguard.forensics.domain.engine

import com.fileguard.forensics.domain.model.ApkAnalysisResult
import com.fileguard.forensics.domain.model.DecoderInspectionResult
import com.fileguard.forensics.domain.model.EvidenceConfidence
import com.fileguard.forensics.domain.model.ForensicIndicator
import com.fileguard.forensics.domain.model.IndicatorSeverity
import com.fileguard.forensics.domain.model.RiskClassification
import com.fileguard.forensics.domain.model.ThreatAnalysisResult

class ThreatAnalysisEngine {

    private val dangerousScriptPatterns = listOf(
        "curl " to "Shell download command (curl)",
        "wget " to "Shell download command (wget)",
        "chmod +x" to "Executable permission grant (chmod +x)",
        "/system/bin/su" to "Root binary reference (su)",
        "Runtime.getRuntime().exec" to "Dynamic OS command execution API",
        "DexClassLoader" to "Dynamic DEX code loading API",
        "Cipher.getInstance" to "Cryptographic cipher invocation",
        "powershell" to "PowerShell invocation",
        "<script>" to "Embedded HTML/JS script block",
        "eval(" to "Dynamic script evaluation (eval)"
    )

    private val ipUrlRegex = Regex("""https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:/]""")

    fun analyze(
        inspection: DecoderInspectionResult,
        apkResult: ApkAnalysisResult? = null
    ): ThreatAnalysisResult {
        val sig = inspection.signature
        val indicators = mutableListOf<ForensicIndicator>()

        // 1. Disguised executable or severe extension mismatch
        val isExecutableFormat = sig.detectedFormat.contains("ELF") ||
            sig.detectedFormat.contains("DEX") ||
            sig.detectedFormat.contains("PE / EXE") ||
            sig.detectedFormat.contains("APK") ||
            sig.detectedFormat.contains("Shell / Script")

        if (sig.isExtensionMismatch && isExecutableFormat) {
            indicators += ForensicIndicator(
                title = "Disguised Executable / Binary",
                detail = "File claims to be .${sig.declaredExtension} but internal magic bytes identify it as ${sig.detectedFormat}.",
                severity = IndicatorSeverity.CONFIRMED_MALICIOUS_INDICATOR,
                evidence = "Header bytes: ${sig.headerHexPreview}"
            )
        } else if (sig.isExtensionMismatch) {
            indicators += ForensicIndicator(
                title = "Extension Mismatch",
                detail = "Declared extension .${sig.declaredExtension} does not match detected format (${sig.detectedFormat}).",
                severity = IndicatorSeverity.SUSPICIOUS_INDICATOR,
                evidence = "Expected: ${sig.expectedExtensions.joinToString(", ")}"
            )
        }

        // 2. Double extension check (e.g. invoice.pdf.apk or photo.jpg.exe)
        val parts = sig.fileName.split('.')
        if (parts.size >= 3) {
            val lastExt = parts.last().lowercase()
            if (lastExt in listOf("apk", "exe", "sh", "bat", "vbs", "js", "scr", "dex")) {
                indicators += ForensicIndicator(
                    title = "Double-Extension Naming Pattern",
                    detail = "Filename uses multiple extensions ending in executable type .$lastExt.",
                    severity = IndicatorSeverity.SUSPICIOUS_INDICATOR,
                    evidence = "Filename: ${sig.fileName}"
                )
            }
        }

        // 3. Suspicious script / payload strings
        val joinedStrings = inspection.extractedStrings.joinToString("\n")
        for ((pattern, desc) in dangerousScriptPatterns) {
            if (joinedStrings.contains(pattern, ignoreCase = true)) {
                indicators += ForensicIndicator(
                    title = "Suspicious Code/Script Pattern",
                    detail = desc,
                    severity = IndicatorSeverity.SUSPICIOUS_INDICATOR,
                    evidence = "Matched token: '$pattern'"
                )
            }
        }

        // 4. Raw IP URL endpoints
        val ipUrls = inspection.extractedStrings.filter { ipUrlRegex.containsMatchIn(it) }
        if (ipUrls.isNotEmpty()) {
            indicators += ForensicIndicator(
                title = "Hardcoded IP Network Endpoint",
                detail = "Embedded HTTP(S) URL pointing directly to an IPv4 address.",
                severity = IndicatorSeverity.SUSPICIOUS_INDICATOR,
                evidence = ipUrls.take(3).joinToString("; ")
            )
        }

        // 5. High entropy / potential packing or ransomware encryption
        if (sig.isLikelyEncryptedOrPacked && !sig.detectedFormat.contains("ZIP") &&
            !sig.detectedFormat.contains("JPEG") && !sig.detectedFormat.contains("PNG") &&
            !sig.detectedFormat.contains("MP4") && !sig.detectedFormat.contains("MP3") &&
            !sig.detectedFormat.contains("7-Zip") && !sig.detectedFormat.contains("RAR")
        ) {
            indicators += ForensicIndicator(
                title = "High-Entropy Obfuscated/Encrypted Payload",
                detail = "Shannon entropy is ${String.format("%.2f", sig.entropyBitsPerByte)} bits/byte in a non-standard container.",
                severity = IndicatorSeverity.UNUSUAL_POTENTIALLY_LEGITIMATE,
                evidence = "Entropy: ${String.format("%.2f", sig.entropyBitsPerByte)} / 8.00"
            )
        }

        // 6. Archive macro or hidden executable entries
        val suspiciousArchiveEntries = inspection.archiveEntries.filter { it.isHiddenOrSuspicious }
        if (suspiciousArchiveEntries.isNotEmpty()) {
            indicators += ForensicIndicator(
                title = "Suspicious Archive Entries",
                detail = "Archive contains hidden, macro (vbaProject.bin), or executable entries.",
                severity = IndicatorSeverity.SUSPICIOUS_INDICATOR,
                evidence = suspiciousArchiveEntries.take(5).joinToString(", ") { it.name }
            )
        }

        // 7. APK static analysis findings
        if (apkResult != null && apkResult.parseError == null) {
            if (apkResult.dangerousPermissions.size >= 4) {
                indicators += ForensicIndicator(
                    title = "High-Privilege APK Permission Footprint",
                    detail = "APK requests ${apkResult.dangerousPermissions.size} sensitive permissions.",
                    severity = IndicatorSeverity.SUSPICIOUS_INDICATOR,
                    evidence = apkResult.dangerousPermissions.joinToString(", ")
                )
            }
            for (warn in apkResult.staticWarnings) {
                indicators += ForensicIndicator(
                    title = "APK Static Warning",
                    detail = warn,
                    severity = IndicatorSeverity.SUSPICIOUS_INDICATOR,
                    evidence = "Package: ${apkResult.packageName}"
                )
            }
        }

        // 8. Unknown format (never label malware just for being unknown!)
        if (sig.isUnknownFormat && indicators.isEmpty()) {
            indicators += ForensicIndicator(
                title = "Unrecognized Binary Structure",
                detail = "File format did not match known offline signatures. Unknown does not imply malicious.",
                severity = IndicatorSeverity.UNKNOWN_UNVERIFIED,
                evidence = "Header: ${sig.headerHexPreview}"
            )
            return ThreatAnalysisResult(
                riskClassification = RiskClassification.UNKNOWN_INSUFFICIENT_EVIDENCE,
                confidence = EvidenceConfidence.LOW,
                indicators = indicators,
                explanation = "No known malicious indicators were found, but the file format could not be verified.",
                recommendedAction = "Inspect hex/strings in the Unknown File Decoder before opening in any external app."
            )
        }

        val confirmedCount = indicators.count { it.severity == IndicatorSeverity.CONFIRMED_MALICIOUS_INDICATOR }
        val suspiciousCount = indicators.count { it.severity == IndicatorSeverity.SUSPICIOUS_INDICATOR }
        val unusualCount = indicators.count { it.severity == IndicatorSeverity.UNUSUAL_POTENTIALLY_LEGITIMATE }

        val (classification, confidence, action) = when {
            confirmedCount >= 1 && suspiciousCount >= 1 -> Triple(
                RiskClassification.CRITICAL_INDICATORS,
                EvidenceConfidence.HIGH,
                "Do not execute or install. Copy to Quarantine for safe preservation and review forensic evidence."
            )
            confirmedCount >= 1 || suspiciousCount >= 3 -> Triple(
                RiskClassification.HIGH_RISK,
                EvidenceConfidence.HIGH,
                "Avoid opening directly. Quarantine a copy and verify the file source."
            )
            suspiciousCount in 1..2 -> Triple(
                RiskClassification.MEDIUM_RISK,
                EvidenceConfidence.MEDIUM,
                "Review the flagged indicators and provenance before trusting this file."
            )
            unusualCount >= 1 || sig.isCorruptedOrTruncated -> Triple(
                RiskClassification.LOW_RISK,
                EvidenceConfidence.MEDIUM,
                "Minor structural or entropy anomalies noted; verify integrity if unexpected."
            )
            else -> Triple(
                RiskClassification.SAFE_INDICATORS_FOUND,
                EvidenceConfidence.MEDIUM,
                "No known suspicious indicators detected by offline static analysis."
            )
        }

        val explanation = if (indicators.isEmpty()) {
            "No known suspicious indicators detected. Note: absence of static indicators does not guarantee absolute safety."
        } else {
            "Identified ${indicators.size} technical indicator(s) (${confirmedCount} confirmed high-severity, ${suspiciousCount} suspicious, ${unusualCount} unusual)."
        }

        return ThreatAnalysisResult(
            riskClassification = classification,
            confidence = confidence,
            indicators = indicators,
            explanation = explanation,
            recommendedAction = action
        )
    }
}
