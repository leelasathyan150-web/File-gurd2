package com.fileguard.forensics.domain.engine

import android.content.Context
import android.net.Uri
import com.fileguard.forensics.domain.model.FileSignatureResult
import java.io.InputStream
import java.security.MessageDigest
import java.util.zip.ZipInputStream

class FileSignatureEngine(private val context: Context) {

    companion object {
        private const val HEADER_SAMPLE_SIZE = 4096
        private const val FOOTER_SAMPLE_SIZE = 512
        private const val STREAM_BUFFER_SIZE = 8192
    }

    fun analyzeUri(
        uri: Uri,
        fileName: String,
        fileSize: Long,
        pathDisplay: String
    ): FileSignatureResult {
        val ext = fileName.substringAfterLast('.', "").lowercase()
        if (fileSize == 0L) {
            return FileSignatureResult(
                fileName = fileName,
                fileUri = uri.toString(),
                filePathDisplay = pathDisplay,
                fileSize = 0L,
                sha256 = sha256Empty(),
                declaredExtension = ext,
                detectedFormat = "Zero-Byte Empty File",
                detectedMimeType = "application/x-empty",
                expectedExtensions = emptyList(),
                isExtensionMismatch = false,
                isZeroByte = true,
                isUnknownFormat = false,
                isCorruptedOrTruncated = true,
                corruptionReason = "File contains 0 bytes; header and payload are completely absent.",
                headerHexPreview = "(empty)",
                footerHexPreview = "(empty)",
                entropyBitsPerByte = 0.0,
                isLikelyEncryptedOrPacked = false
            )
        }

        var headerBytes = ByteArray(0)
        val tailRing = ArrayDeque<Byte>(FOOTER_SAMPLE_SIZE)
        val digest = MessageDigest.getInstance("SHA-256")

        context.contentResolver.openInputStream(uri)?.use { raw ->
            val buf = ByteArray(STREAM_BUFFER_SIZE)
            var totalRead = 0L
            while (true) {
                val read = raw.read(buf)
                if (read <= 0) break
                digest.update(buf, 0, read)
                if (totalRead < HEADER_SAMPLE_SIZE) {
                    val needed = minOf(read, (HEADER_SAMPLE_SIZE - totalRead).toInt())
                    headerBytes = headerBytes + buf.copyOfRange(0, needed)
                }
                for (i in 0 until read) {
                    if (tailRing.size == FOOTER_SAMPLE_SIZE) {
                        tailRing.removeFirst()
                    }
                    tailRing.addLast(buf[i])
                }
                totalRead += read
            }
        }

        val footerBytes = tailRing.toByteArray()
        val sha256 = digest.digest().joinToString("") { "%02x".format(it) }
        val entropy = MagicByteDatabase.calculateShannonEntropy(headerBytes)
        val likelyEncrypted = entropy >= 7.5

        var sig = MagicByteDatabase.matchHeader(headerBytes)
        var detectedFormat = sig?.formatName ?: "Unknown Binary Format"
        var detectedMime = sig?.mimeType ?: "application/octet-stream"
        var expectedExts = sig?.expectedExtensions ?: emptyList()
        var isUnknown = sig == null

        // Disambiguate ZIP-based formats (APK, DOCX, XLSX, PPTX, JAR) safely with bounded entries
        if (sig != null && sig.mimeType == "application/zip") {
            val zipSubType = disambiguateZipFormat(uri)
            if (zipSubType != null) {
                detectedFormat = zipSubType.first
                detectedMime = zipSubType.second
                expectedExts = zipSubType.third
            }
        }

        // If no binary magic matched, check if it is structured text
        if (sig == null) {
            val (isText, textType) = MagicByteDatabase.looksLikePlainText(headerBytes)
            if (isText) {
                isUnknown = false
                detectedFormat = textType
                detectedMime = when {
                    textType.startsWith("JSON") -> "application/json"
                    textType.startsWith("XML") -> "application/xml"
                    textType.startsWith("HTML") -> "text/html"
                    textType.startsWith("CSV") -> "text/csv"
                    else -> "text/plain"
                }
                expectedExts = when {
                    textType.startsWith("JSON") -> listOf("json")
                    textType.startsWith("XML") -> listOf("xml")
                    textType.startsWith("HTML") -> listOf("html", "htm")
                    textType.startsWith("CSV") -> listOf("csv", "tsv")
                    else -> listOf("txt", "log", "md", "cfg", "ini", "json", "xml", "csv")
                }
            }
        }

        val mismatch = !isUnknown && ext.isNotEmpty() && expectedExts.isNotEmpty() && !expectedExts.contains(ext)
        val (corrupted, corruptionReason) = checkStructuralIntegrity(detectedFormat, headerBytes, footerBytes)

        return FileSignatureResult(
            fileName = fileName,
            fileUri = uri.toString(),
            filePathDisplay = pathDisplay,
            fileSize = fileSize,
            sha256 = sha256,
            declaredExtension = ext,
            detectedFormat = detectedFormat,
            detectedMimeType = detectedMime,
            expectedExtensions = expectedExts,
            isExtensionMismatch = mismatch,
            isZeroByte = false,
            isUnknownFormat = isUnknown,
            isCorruptedOrTruncated = corrupted,
            corruptionReason = corruptionReason,
            headerHexPreview = formatHexInline(headerBytes.take(32).toByteArray()),
            footerHexPreview = formatHexInline(footerBytes.takeLast(32).toByteArray()),
            entropyBitsPerByte = entropy,
            isLikelyEncryptedOrPacked = likelyEncrypted
        )
    }

    private fun disambiguateZipFormat(uri: Uri): Triple<String, String, List<String>>? {
        return try {
            context.contentResolver.openInputStream(uri)?.use { stream ->
                ZipInputStream(stream).use { zis ->
                    var count = 0
                    var hasManifest = false
                    var hasDex = false
                    var hasWordDoc = false
                    var hasExcel = false
                    var hasPpt = false
                    while (count < 80) {
                        val entry = zis.nextEntry ?: break
                        val name = entry.name
                        when {
                            name == "AndroidManifest.xml" -> hasManifest = true
                            name.endsWith(".dex") -> hasDex = true
                            name.startsWith("word/") -> hasWordDoc = true
                            name.startsWith("xl/") -> hasExcel = true
                            name.startsWith("ppt/") -> hasPpt = true
                        }
                        count++
                    }
                    when {
                        hasManifest && hasDex -> Triple("Android Package (APK)", "application/vnd.android.package-archive", listOf("apk"))
                        hasManifest -> Triple("Android Archive (APK/AAB)", "application/vnd.android.package-archive", listOf("apk", "aab"))
                        hasWordDoc -> Triple("Microsoft Word Document (DOCX)", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", listOf("docx"))
                        hasExcel -> Triple("Microsoft Excel Workbook (XLSX)", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", listOf("xlsx"))
                        hasPpt -> Triple("Microsoft PowerPoint (PPTX)", "application/vnd.openxmlformats-officedocument.presentationml.presentation", listOf("pptx"))
                        else -> null
                    }
                }
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun checkStructuralIntegrity(
        detectedFormat: String,
        header: ByteArray,
        footer: ByteArray
    ): Pair<Boolean, String?> {
        if (footer.isEmpty()) return true to "File footer could not be read."
        return when {
            detectedFormat.contains("JPEG") -> {
                val hasEoi = footer.size >= 2 &&
                    footer[footer.size - 2] == 0xFF.toByte() &&
                    footer[footer.size - 1] == 0xD9.toByte()
                if (!hasEoi) true to "Missing JPEG End-Of-Image (FF D9) marker; image may be truncated." else false to null
            }
            detectedFormat.contains("PNG") -> {
                val tailStr = String(footer, Charsets.ISO_8859_1)
                if (!tailStr.contains("IEND")) true to "Missing PNG IEND chunk; file may be incomplete or truncated." else false to null
            }
            detectedFormat.contains("PDF") -> {
                val tailStr = String(footer, Charsets.ISO_8859_1)
                if (!tailStr.contains("%%EOF")) true to "Missing PDF %%EOF trailer; document may be truncated or corrupted." else false to null
            }
            detectedFormat.contains("ZIP") || detectedFormat.contains("APK") || detectedFormat.contains("DOCX") || detectedFormat.contains("XLSX") -> {
                val eocd = byteArrayOf(0x50, 0x4B, 0x05, 0x06)
                if (!containsSequence(footer, eocd) && header.size >= 4) {
                    true to "Missing ZIP End-Of-Central-Directory (PK 05 06) record; archive may be truncated."
                } else false to null
            }
            else -> false to null
        }
    }

    private fun containsSequence(haystack: ByteArray, needle: ByteArray): Boolean {
        if (haystack.size < needle.size) return false
        for (i in 0..haystack.size - needle.size) {
            var match = true
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) {
                    match = false
                    break
                }
            }
            if (match) return true
        }
        return false
    }

    private fun sha256Empty(): String =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    private fun formatHexInline(bytes: ByteArray): String =
        bytes.joinToString(" ") { "%02X".format(it) }
}
