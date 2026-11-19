package com.fileguard.forensics.domain.engine

import android.content.Context
import android.net.Uri
import com.fileguard.forensics.domain.model.DecoderInspectionResult
import com.fileguard.forensics.domain.model.RecoveryAssessment
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipInputStream

class RecoveryEngine(private val context: Context) {

    companion object {
        private const val ANDROID_LIMITATION =
            "Modern Android devices use File-Based Encryption (FBE), TRIM, and Scoped Storage. Raw deleted blocks cannot be recovered without root access. Any repair saves a separate copy and never modifies the original file."
    }

    fun assess(inspection: DecoderInspectionResult): RecoveryAssessment {
        val sig = inspection.signature
        return when {
            sig.isZeroByte -> RecoveryAssessment(
                fileName = sig.fileName,
                fileUri = sig.fileUri,
                isRecoverableOrRepairable = false,
                issueDetected = "0-byte file contains no payload data.",
                suggestedAction = "Check original download source or backups; 0-byte files cannot be reconstructed locally.",
                recoverableEntriesCount = 0,
                androidLimitationNote = ANDROID_LIMITATION
            )
            sig.isCorruptedOrTruncated && (sig.detectedFormat.contains("ZIP") || sig.detectedFormat.contains("DOCX") || sig.detectedFormat.contains("XLSX")) -> {
                RecoveryAssessment(
                    fileName = sig.fileName,
                    fileUri = sig.fileUri,
                    isRecoverableOrRepairable = true,
                    issueDetected = sig.corruptionReason ?: "Damaged ZIP container structure.",
                    suggestedAction = "Extract intact local entries into a separate safe recovery folder.",
                    recoverableEntriesCount = inspection.archiveEntries.size,
                    androidLimitationNote = ANDROID_LIMITATION
                )
            }
            sig.isCorruptedOrTruncated && sig.detectedFormat.contains("JPEG") -> {
                RecoveryAssessment(
                    fileName = sig.fileName,
                    fileUri = sig.fileUri,
                    isRecoverableOrRepairable = true,
                    issueDetected = sig.corruptionReason ?: "Missing JPEG End-of-Image marker.",
                    suggestedAction = "Create a repaired copy with a reconstructed JPEG EOI (FF D9) trailer.",
                    recoverableEntriesCount = 1,
                    androidLimitationNote = ANDROID_LIMITATION
                )
            }
            sig.isExtensionMismatch -> {
                RecoveryAssessment(
                    fileName = sig.fileName,
                    fileUri = sig.fileUri,
                    isRecoverableOrRepairable = true,
                    issueDetected = "File is intact but misnamed as .${sig.declaredExtension} instead of ${sig.expectedExtensions.firstOrNull() ?: "true format"}.",
                    suggestedAction = "Save a separate copy with the corrected extension (.${sig.expectedExtensions.firstOrNull() ?: "bin"}).",
                    recoverableEntriesCount = 1,
                    androidLimitationNote = ANDROID_LIMITATION
                )
            }
            else -> RecoveryAssessment(
                fileName = sig.fileName,
                fileUri = sig.fileUri,
                isRecoverableOrRepairable = false,
                issueDetected = if (sig.isCorruptedOrTruncated) sig.corruptionReason ?: "Truncated file." else "No structural corruption detected.",
                suggestedAction = if (sig.isCorruptedOrTruncated) "Extract readable strings via Unknown File Decoder." else "No repair required.",
                recoverableEntriesCount = 0,
                androidLimitationNote = ANDROID_LIMITATION
            )
        }
    }

    /**
     * Repairs a truncated JPEG or extracts intact ZIP entries into app-private filesDir/recovered/<folder>
     * Never modifies the original file.
     */
    fun performSafeRecoveryCopy(uri: Uri, inspection: DecoderInspectionResult): Result<File> {
        return try {
            val outRoot = File(context.filesDir, "recovered").apply { mkdirs() }
            val sig = inspection.signature
            val safeBase = sig.fileName.replace(Regex("[^a-zA-Z0-9._-]"), "_")

            when {
                sig.detectedFormat.contains("JPEG") && sig.isCorruptedOrTruncated -> {
                    val outFile = File(outRoot, "repaired_${System.currentTimeMillis()}_$safeBase.jpg")
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        FileOutputStream(outFile).use { out ->
                            input.copyTo(out)
                            out.write(byteArrayOf(0xFF.toByte(), 0xD9.toByte()))
                        }
                    }
                    Result.success(outFile)
                }
                sig.detectedFormat.contains("ZIP") -> {
                    val folder = File(outRoot, "zip_${System.currentTimeMillis()}_$safeBase").apply { mkdirs() }
                    var extracted = 0
                    var totalBytes = 0L
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        ZipInputStream(input).use { zis ->
                            while (extracted < 100 && totalBytes < 25L * 1024L * 1024L) {
                                val entry = zis.nextEntry ?: break
                                if (entry.isDirectory) continue
                                val cleanName = entry.name.replace("..", "_").replace('/', '_')
                                val target = File(folder, cleanName)
                                FileOutputStream(target).use { out ->
                                    val buf = ByteArray(4096)
                                    while (true) {
                                        val n = zis.read(buf)
                                        if (n <= 0) break
                                        totalBytes += n
                                        if (totalBytes > 25L * 1024L * 1024L) break
                                        out.write(buf, 0, n)
                                    }
                                }
                                extracted++
                            }
                        }
                    }
                    Result.success(folder)
                }
                sig.isExtensionMismatch -> {
                    val trueExt = sig.expectedExtensions.firstOrNull() ?: "bin"
                    val outFile = File(outRoot, "${safeBase.substringBeforeLast('.')}.$trueExt")
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        FileOutputStream(outFile).use { out -> input.copyTo(out) }
                    }
                    Result.success(outFile)
                }
                else -> Result.failure(IllegalStateException("No automated repair strategy available for ${sig.detectedFormat}."))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
