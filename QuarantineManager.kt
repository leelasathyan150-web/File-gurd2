package com.fileguard.forensics.domain.engine

import android.content.Context
import android.net.Uri
import com.fileguard.forensics.data.db.QuarantineDao
import com.fileguard.forensics.data.db.QuarantineEntity
import com.fileguard.forensics.domain.model.QuarantineRecord
import com.fileguard.forensics.domain.model.RiskClassification
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.UUID

class QuarantineManager(
    private val context: Context,
    private val quarantineDao: QuarantineDao
) {
    private val quarantineDir: File
        get() = File(context.filesDir, "quarantine").apply { mkdirs() }

    /**
     * Copies a suspicious file to an app-controlled private directory with a non-executable extension.
     * Never modifies or deletes the original file.
     */
    suspend fun quarantineCopy(
        sourceUri: Uri,
        fileName: String,
        fileSize: Long,
        expectedSha256: String,
        risk: RiskClassification,
        notes: String
    ): Result<QuarantineRecord> {
        return try {
            val id = UUID.randomUUID().toString()
            val safeName = fileName.replace(Regex("[^a-zA-Z0-9._-]"), "_")
            val destFile = File(quarantineDir, "${id}_${safeName}.quarantined")

            val digest = MessageDigest.getInstance("SHA-256")
            context.contentResolver.openInputStream(sourceUri)?.use { input ->
                FileOutputStream(destFile).use { output ->
                    val buf = ByteArray(8192)
                    while (true) {
                        val n = input.read(buf)
                        if (n <= 0) break
                        digest.update(buf, 0, n)
                        output.write(buf, 0, n)
                    }
                }
            } ?: return Result.failure(IllegalStateException("Unable to read source file."))

            val actualHash = digest.digest().joinToString("") { "%02x".format(it) }
            val now = System.currentTimeMillis()
            val entity = QuarantineEntity(
                id = id,
                originalName = fileName,
                originalUri = sourceUri.toString(),
                originalSha256 = if (expectedSha256.isNotBlank()) expectedSha256 else actualHash,
                quarantinedPath = destFile.absolutePath,
                fileSize = fileSize,
                riskClassification = risk.name,
                quarantinedAtMillis = now,
                notes = notes
            )
            quarantineDao.insert(entity)

            Result.success(entity.toDomain())
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun restoreToUri(record: QuarantineRecord, targetUri: Uri): Result<Unit> {
        return try {
            val src = File(record.quarantinedPath)
            if (!src.exists()) {
                return Result.failure(IllegalStateException("Quarantined file no longer exists on disk."))
            }
            context.contentResolver.openOutputStream(targetUri)?.use { out ->
                FileInputStream(src).use { input ->
                    input.copyTo(out)
                }
            } ?: return Result.failure(IllegalStateException("Unable to write to destination URI."))
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun removeFromQuarantine(record: QuarantineRecord) {
        File(record.quarantinedPath).delete()
        quarantineDao.deleteById(record.id)
    }

    private fun QuarantineEntity.toDomain() = QuarantineRecord(
        id = id,
        originalName = originalName,
        originalUri = originalUri,
        originalSha256 = originalSha256,
        quarantinedPath = quarantinedPath,
        fileSize = fileSize,
        riskClassification = RiskClassification.entries.firstOrNull { it.name == riskClassification }
            ?: RiskClassification.UNKNOWN_INSUFFICIENT_EVIDENCE,
        quarantinedAtMillis = quarantinedAtMillis,
        notes = notes
    )
}
