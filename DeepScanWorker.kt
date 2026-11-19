package com.fileguard.forensics.worker

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.ForegroundInfo
import androidx.work.WorkerParameters
import com.fileguard.forensics.FileGuardApp
import com.fileguard.forensics.data.db.ScanSessionEntity
import com.fileguard.forensics.data.db.ScannedFileEntity

class DeepScanWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    companion object {
        const val KEY_TREE_URI = "tree_uri"
        const val KEY_SOURCE_LABEL = "source_label"
        private const val CHANNEL_ID = "fileguard_scan_channel"
        private const val NOTIFICATION_ID = 4041
    }

    override suspend fun doWork(): Result {
        val uriString = inputData.getString(KEY_TREE_URI) ?: return Result.failure()
        val sourceLabel = inputData.getString(KEY_SOURCE_LABEL) ?: "Selected Folder"
        val app = applicationContext as FileGuardApp
        val container = app.container

        setForeground(createForegroundInfo("Scanning $sourceLabel..."))

        val startedAt = System.currentTimeMillis()
        val finalProgress = container.storageScanner.scanDocumentTree(Uri.parse(uriString)) { item ->
            container.database.scannedFileDao().insert(
                ScannedFileEntity(
                    sessionId = item.sessionId,
                    fileName = item.fileName,
                    fileUri = item.fileUri,
                    filePathDisplay = item.filePathDisplay,
                    fileSize = item.fileSize,
                    sha256 = item.sha256,
                    declaredExtension = item.declaredExtension,
                    detectedFormat = item.detectedFormat,
                    isHidden = item.isHidden,
                    isExtensionMismatch = item.isExtensionMismatch,
                    isUnknownFormat = item.isUnknownFormat,
                    isCorrupted = item.isCorrupted,
                    isZeroByte = item.isZeroByte,
                    isDuplicate = item.isDuplicate,
                    riskClassification = item.riskClassification.name,
                    provenanceCategory = item.provenanceCategory.name,
                    lastModifiedMillis = item.lastModifiedMillis,
                    findingsSummary = item.findingsSummary
                )
            )
        }

        container.database.scanSessionDao().insert(
            ScanSessionEntity(
                sessionId = finalProgress.sessionId,
                sourceLabel = sourceLabel,
                startedAtMillis = startedAt,
                completedAtMillis = System.currentTimeMillis(),
                totalFiles = finalProgress.totalFilesExamined,
                totalFolders = finalProgress.totalFoldersExamined,
                totalBytes = finalProgress.totalBytesExamined,
                hiddenCount = finalProgress.hiddenFilesCount,
                unknownCount = finalProgress.unknownFormatsCount,
                suspiciousCount = finalProgress.suspiciousFilesCount,
                status = if (finalProgress.isCancelled) "CANCELLED" else "COMPLETED"
            )
        )

        return Result.success()
    }

    private fun createForegroundInfo(text: String): ForegroundInfo {
        val manager = applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "FileGuard Forensic Scans",
                NotificationManager.IMPORTANCE_LOW
            )
            manager.createNotificationChannel(channel)
        }
        val notification = NotificationCompat.Builder(applicationContext, CHANNEL_ID)
            .setContentTitle("FileGuard Forensics")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_search)
            .setOngoing(true)
            .build()
        return ForegroundInfo(NOTIFICATION_ID, notification)
    }
}
