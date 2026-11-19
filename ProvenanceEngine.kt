package com.fileguard.forensics.domain.engine

import com.fileguard.forensics.domain.model.DecoderInspectionResult
import com.fileguard.forensics.domain.model.EvidenceConfidence
import com.fileguard.forensics.domain.model.OriginAnalysisResult
import com.fileguard.forensics.domain.model.ProvenanceCategory
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ProvenanceEngine {

    private val urlRegex = Regex("""https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+""")

    fun investigateOrigin(
        inspection: DecoderInspectionResult,
        lastModifiedMillis: Long,
        createdMillis: Long? = null,
        lastAccessedMillis: Long? = null
    ): OriginAnalysisResult {
        val evidence = mutableListOf<String>()
        val timestamps = mutableMapOf<String, String>()
        val softwareIds = mutableListOf<String>()

        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US)
        if (lastModifiedMillis > 0L) {
            timestamps["Last Modified"] = fmt.format(Date(lastModifiedMillis))
        }
        createdMillis?.takeIf { it > 0L }?.let {
            timestamps["Created"] = fmt.format(Date(it))
        }
        lastAccessedMillis?.takeIf { it > 0L }?.let {
            timestamps["Last Accessed"] = fmt.format(Date(it))
        }

        val pathLower = inspection.signature.filePathDisplay.lowercase(Locale.US)
        val uriLower = inspection.signature.fileUri.lowercase(Locale.US)
        val embeddedUrls = inspection.extractedStrings
            .flatMap { line -> urlRegex.findAll(line).map { it.value } }
            .distinct()
            .take(15)

        inspection.metadataMap["Camera Make"]?.let { make ->
            val model = inspection.metadataMap["Camera Model"] ?: ""
            softwareIds += "Device: $make $model".trim()
            evidence += "EXIF device identifier present: $make $model".trim()
        }
        inspection.metadataMap["Software"]?.let { sw ->
            softwareIds += "Software: $sw"
            evidence += "EXIF/embedded software tag: $sw"
        }
        inspection.metadataMap["Original DateTime"]?.let { dt ->
            timestamps["EXIF Original DateTime"] = dt
            evidence += "EXIF original capture timestamp: $dt"
        }
        if (embeddedUrls.isNotEmpty()) {
            evidence += "Embedded URL(s) detected in file strings (${embeddedUrls.size} found)."
        }

        val (category, confidence) = when {
            pathLower.contains("usb") || uriLower.contains("usb") || pathLower.contains("otg") -> {
                evidence += "Storage path/provider indicates removable USB/OTG volume: ${inspection.signature.filePathDisplay}"
                ProvenanceCategory.TRANSFERRED_THROUGH_USB to EvidenceConfidence.MEDIUM
            }
            pathLower.contains("/download") || pathLower.contains("downloads") || pathLower.contains("browser") -> {
                evidence += "File resides in a Download directory (${inspection.signature.filePathDisplay})."
                if (embeddedUrls.isNotEmpty()) {
                    ProvenanceCategory.DOWNLOADED_FROM_INTERNET to EvidenceConfidence.HIGH
                } else {
                    ProvenanceCategory.DOWNLOADED_FROM_INTERNET to EvidenceConfidence.MEDIUM
                }
            }
            pathLower.contains("whatsapp") || pathLower.contains("telegram") || pathLower.contains("signal") ||
                pathLower.contains("share") -> {
                evidence += "Path references a messaging or sharing application folder."
                ProvenanceCategory.SHARED_THROUGH_APP to EvidenceConfidence.MEDIUM
            }
            pathLower.contains("dcim") || pathLower.contains("pictures") || pathLower.contains("android/data") -> {
                evidence += "Located in app-associated media or Android data directory."
                ProvenanceCategory.CREATED_BY_ANDROID_APP to EvidenceConfidence.MEDIUM
            }
            pathLower.contains("/unzipped") || pathLower.contains("/extracted") -> {
                evidence += "Directory naming suggests archive extraction."
                ProvenanceCategory.EXTRACTED_FROM_ARCHIVE to EvidenceConfidence.LOW
            }
            pathLower.startsWith("/system") || pathLower.startsWith("/vendor") || pathLower.startsWith("/proc") -> {
                evidence += "Located in a system-managed partition."
                ProvenanceCategory.GENERATED_BY_SYSTEM to EvidenceConfidence.MEDIUM
            }
            else -> {
                ProvenanceCategory.UNKNOWN_ORIGIN to EvidenceConfidence.NONE
            }
        }

        val summary = if (category == ProvenanceCategory.UNKNOWN_ORIGIN) {
            ProvenanceCategory.UNKNOWN_ORIGIN.label
        } else {
            "Probable origin: ${category.label} (${confidence.label}) based on ${evidence.size} observable artifact(s)."
        }

        return OriginAnalysisResult(
            category = category,
            confidence = confidence,
            supportingEvidence = evidence,
            timestamps = timestamps,
            embeddedUrls = embeddedUrls,
            softwareOrDeviceIdentifiers = softwareIds,
            summaryStatement = summary
        )
    }
}
