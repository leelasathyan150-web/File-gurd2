package com.fileguard.forensics.domain.engine

import android.content.Context
import android.net.Uri
import androidx.exifinterface.media.ExifInterface
import com.fileguard.forensics.domain.model.ArchiveEntryInfo
import com.fileguard.forensics.domain.model.DecoderInspectionResult
import com.fileguard.forensics.domain.model.FileSignatureResult
import java.util.zip.ZipInputStream

class FileDecoderEngine(
    private val context: Context,
    private val signatureEngine: FileSignatureEngine
) {
    companion object {
        private const val MAX_HEX_BYTES = 512
        private const val MAX_TEXT_PREVIEW_BYTES = 16 * 1024
        private const val MAX_STRING_SCAN_BYTES = 256 * 1024
        private const val MAX_ARCHIVE_ENTRIES = 500
        private const val MAX_ARCHIVE_UNCOMPRESSED_BYTES = 50L * 1024L * 1024L
    }

    fun inspectFile(
        uri: Uri,
        fileName: String,
        fileSize: Long,
        pathDisplay: String
    ): DecoderInspectionResult {
        val signature = signatureEngine.analyzeUri(uri, fileName, fileSize, pathDisplay)
        val hexLines = readHexDump(uri, MAX_HEX_BYTES)
        val strings = extractReadableStrings(uri, minLen = 5, maxStrings = 120)
        val metadata = mutableMapOf<String, String>()
        val archiveEntries = mutableListOf<ArchiveEntryInfo>()
        var archiveLimitReached = false
        val encryptionIndicators = mutableListOf<String>()

        if (signature.isLikelyEncryptedOrPacked) {
            encryptionIndicators += "High Shannon entropy (${String.format("%.2f", signature.entropyBitsPerByte)} bits/byte) suggests encrypted, compressed, or packed data."
        }

        // Format-specific safe local metadata extraction
        when {
            signature.detectedFormat.contains("JPEG") || signature.detectedFormat.contains("PNG") || signature.detectedFormat.contains("WEBP") -> {
                extractExifMetadata(uri, metadata)
            }
            signature.detectedFormat.contains("SQLite") -> {
                extractSqliteHeader(uri, metadata)
            }
            signature.detectedFormat.contains("PDF") -> {
                if (strings.any { it.contains("/Encrypt") }) {
                    encryptionIndicators += "PDF /Encrypt dictionary marker detected; document may be password-protected."
                }
                strings.firstOrNull { it.startsWith("%PDF-") }?.let { metadata["PDF Version"] = it }
            }
            signature.detectedFormat.contains("ZIP") || signature.detectedFormat.contains("APK") ||
                signature.detectedFormat.contains("DOCX") || signature.detectedFormat.contains("XLSX") ||
                signature.detectedFormat.contains("PPTX") -> {
                archiveLimitReached = inspectArchiveSafely(uri, archiveEntries, encryptionIndicators)
                metadata["Archive Entries Inspected"] = archiveEntries.size.toString()
            }
        }

        val safeTextPreview = if (signature.detectedMimeType.startsWith("text/") ||
            signature.detectedMimeType == "application/json" ||
            signature.detectedMimeType == "application/xml"
        ) {
            readSafeTextPreview(uri)
        } else null

        val failureReason = explainAndroidOpenFailure(signature)
        val viewerType = recommendViewer(signature)

        return DecoderInspectionResult(
            signature = signature,
            hexLines = hexLines,
            extractedStrings = strings,
            safeTextPreview = safeTextPreview,
            metadataMap = metadata,
            archiveEntries = archiveEntries,
            archiveLimitReached = archiveLimitReached,
            encryptionIndicators = encryptionIndicators,
            androidOpenFailureReason = failureReason,
            recommendedViewerType = viewerType,
            decoderLimitations = "FileGuard inspects headers, metadata, and readable strings locally without executing content. Encrypted or proprietary binary payloads cannot be decrypted without the original key or specification."
        )
    }

    private fun readHexDump(uri: Uri, maxBytes: Int): List<String> {
        val bytes = ByteArray(maxBytes)
        var readCount = 0
        try {
            context.contentResolver.openInputStream(uri)?.use { stream ->
                readCount = stream.read(bytes, 0, maxBytes).coerceAtLeast(0)
            }
        } catch (_: Exception) {
            return listOf("Unable to read bytes from URI.")
        }
        val lines = mutableListOf<String>()
        for (offset in 0 until readCount step 16) {
            val end = minOf(offset + 16, readCount)
            val hexPart = (offset until offset + 16).joinToString(" ") { idx ->
                if (idx < end) "%02X".format(bytes[idx]) else "  "
            }
            val asciiPart = (offset until end).map { idx ->
                val c = bytes[idx].toInt() and 0xFF
                if (c in 0x20..0x7E) c.toChar() else '.'
            }.joinToString("")
            lines += "%04X: %-47s  |%s|".format(offset, hexPart, asciiPart)
        }
        return lines
    }

    private fun extractReadableStrings(uri: Uri, minLen: Int, maxStrings: Int): List<String> {
        val results = mutableListOf<String>()
        val current = StringBuilder()
        try {
            context.contentResolver.openInputStream(uri)?.use { stream ->
                val buf = ByteArray(4096)
                var total = 0
                while (total < MAX_STRING_SCAN_BYTES && results.size < maxStrings) {
                    val n = stream.read(buf)
                    if (n <= 0) break
                    total += n
                    for (i in 0 until n) {
                        val c = buf[i].toInt() and 0xFF
                        if (c in 0x20..0x7E) {
                            current.append(c.toChar())
                        } else {
                            if (current.length >= minLen) {
                                results += current.toString()
                                if (results.size >= maxStrings) break
                            }
                            current.clear()
                        }
                    }
                }
            }
        } catch (_: Exception) {
            // ignore partial read failure
        }
        if (current.length >= minLen && results.size < maxStrings) {
            results += current.toString()
        }
        return results
    }

    private fun readSafeTextPreview(uri: Uri): String? {
        return try {
            context.contentResolver.openInputStream(uri)?.use { stream ->
                val buf = ByteArray(MAX_TEXT_PREVIEW_BYTES)
                val n = stream.read(buf)
                if (n > 0) String(buf, 0, n, Charsets.UTF_8) else ""
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun extractExifMetadata(uri: Uri, out: MutableMap<String, String>) {
        try {
            context.contentResolver.openInputStream(uri)?.use { stream ->
                val exif = ExifInterface(stream)
                exif.getAttribute(ExifInterface.TAG_MAKE)?.let { out["Camera Make"] = it }
                exif.getAttribute(ExifInterface.TAG_MODEL)?.let { out["Camera Model"] = it }
                exif.getAttribute(ExifInterface.TAG_SOFTWARE)?.let { out["Software"] = it }
                exif.getAttribute(ExifInterface.TAG_DATETIME_ORIGINAL)?.let { out["Original DateTime"] = it }
                exif.getAttribute(ExifInterface.TAG_IMAGE_WIDTH)?.let { out["Width"] = it }
                exif.getAttribute(ExifInterface.TAG_IMAGE_LENGTH)?.let { out["Height"] = it }
                if (exif.latLong != null) {
                    out["GPS Coordinates"] = "Present in EXIF metadata"
                }
            }
        } catch (_: Exception) {
            // EXIF absent or unreadable
        }
    }

    private fun extractSqliteHeader(uri: Uri, out: MutableMap<String, String>) {
        try {
            context.contentResolver.openInputStream(uri)?.use { stream ->
                val hdr = ByteArray(100)
                if (stream.read(hdr) >= 24) {
                    val pageSize = ((hdr[16].toInt() and 0xFF) shl 8) or (hdr[17].toInt() and 0xFF)
                    out["SQLite Page Size"] = if (pageSize == 1) "65536 bytes" else "$pageSize bytes"
                    out["SQLite Format Write/Read"] = "${hdr[18].toInt() and 0xFF} / ${hdr[19].toInt() and 0xFF}"
                }
            }
        } catch (_: Exception) {
            // ignore
        }
    }

    private fun inspectArchiveSafely(
        uri: Uri,
        entries: MutableList<ArchiveEntryInfo>,
        encryptionIndicators: MutableList<String>
    ): Boolean {
        var limitHit = false
        var totalUncompressed = 0L
        try {
            context.contentResolver.openInputStream(uri)?.use { stream ->
                ZipInputStream(stream).use { zis ->
                    while (true) {
                        if (entries.size >= MAX_ARCHIVE_ENTRIES || totalUncompressed >= MAX_ARCHIVE_UNCOMPRESSED_BYTES) {
                            limitHit = true
                            break
                        }
                        val entry = zis.nextEntry ?: break
                        val size = entry.size.coerceAtLeast(0L)
                        totalUncompressed += size
                        val isHiddenOrSuspicious = entry.name.startsWith(".") ||
                            entry.name.contains("/.") ||
                            entry.name.endsWith(".exe", true) ||
                            entry.name.endsWith(".sh", true) ||
                            entry.name.endsWith(".apk", true) ||
                            entry.name.endsWith("vbaProject.bin", true)
                        entries += ArchiveEntryInfo(
                            name = entry.name,
                            compressedSize = entry.compressedSize,
                            uncompressedSize = entry.size,
                            isDirectory = entry.isDirectory,
                            isEncrypted = false,
                            isHiddenOrSuspicious = isHiddenOrSuspicious
                        )
                    }
                }
            }
        } catch (e: Exception) {
            if (e.message?.contains("encrypted", ignoreCase = true) == true) {
                encryptionIndicators += "Archive contains password-encrypted entries."
            }
        }
        return limitHit
    }

    private fun explainAndroidOpenFailure(sig: FileSignatureResult): String {
        return when {
            sig.isZeroByte -> "Android cannot open a 0-byte file because it contains no header or data payload."
            sig.isExtensionMismatch -> "Filename extension (.${sig.declaredExtension}) does not match actual internal format (${sig.detectedFormat}). Android's MIME resolver routes the file to the wrong app."
            sig.isCorruptedOrTruncated -> sig.corruptionReason ?: "File structure appears truncated or damaged."
            sig.isUnknownFormat -> "No recognized file signature or plain-text structure was found. Android has no registered MIME handler for unknown binary data."
            sig.detectedFormat.contains("ELF") || sig.detectedFormat.contains("DEX") || sig.detectedFormat.contains("PE") ->
                "Compiled binary/executable formats cannot be opened directly by standard Android document viewers."
            sig.detectedFormat.contains("SQLite") ->
                "SQLite databases require a database inspector rather than a standard file viewer."
            else -> "File signature (${sig.detectedFormat}) is valid. If Android still fails to open it, no compatible viewer app may be installed or the file may be encrypted."
        }
    }

    private fun recommendViewer(sig: FileSignatureResult): String {
        return when {
            sig.detectedFormat.contains("SQLite") -> "Local SQLite Database Viewer"
            sig.detectedFormat.contains("PDF") -> "PDF Reader"
            sig.detectedFormat.contains("ZIP") || sig.detectedFormat.contains("RAR") || sig.detectedFormat.contains("7-Zip") -> "Archive Extractor"
            sig.detectedMimeType.startsWith("text/") || sig.detectedMimeType == "application/json" -> "Plain Text / Code Viewer"
            sig.detectedFormat.contains("APK") -> "FileGuard APK Inspector (Static Only — Do Not Install Unknown APKs)"
            sig.isUnknownFormat -> "Hexadecimal & String Inspector Only"
            else -> "Standard ${sig.detectedFormat} Viewer"
        }
    }
}
