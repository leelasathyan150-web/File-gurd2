package com.fileguard.forensics.data.storage

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import com.fileguard.forensics.domain.engine.FileDecoderEngine
import com.fileguard.forensics.domain.engine.FileSignatureEngine
import com.fileguard.forensics.domain.engine.HiddenFileDetector
import com.fileguard.forensics.domain.engine.ProvenanceEngine
import com.fileguard.forensics.domain.engine.ThreatAnalysisEngine
import com.fileguard.forensics.domain.model.RiskClassification
import com.fileguard.forensics.domain.model.ScanErrorEntry
import com.fileguard.forensics.domain.model.ScanProgressState
import com.fileguard.forensics.domain.model.ScannedFileSummary
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.UUID

class StorageScanner(
    private val context: Context,
    private val signatureEngine: FileSignatureEngine,
    private val decoderEngine: FileDecoderEngine,
    private val provenanceEngine: ProvenanceEngine,
    private val threatEngine: ThreatAnalysisEngine,
    private val hiddenDetector: HiddenFileDetector
) {
    private val _progress = MutableStateFlow(ScanProgressState())
    val progress: StateFlow<ScanProgressState> = _progress.asStateFlow()

    @Volatile
    private var paused = false

    @Volatile
    private var cancelled = false

    fun pause() {
        paused = true
        _progress.value = _progress.value.copy(isPaused = true)
    }

    fun resume() {
        paused = false
        _progress.value = _progress.value.copy(isPaused = false)
    }

    fun cancel() {
        cancelled = true
        paused = false
        _progress.value = _progress.value.copy(isCancelled = true, isPaused = false, isScanning = false)
    }

    suspend fun scanDocumentTree(
        rootUri: Uri,
        onFileScanned: suspend (ScannedFileSummary) -> Unit
    ): ScanProgressState {
        val sessionId = UUID.randomUUID().toString()
        paused = false
        cancelled = false

        val errors = mutableListOf<ScanErrorEntry>()
        val seenHashes = mutableMapOf<String, String>()

        var totalFiles = 0
        var totalFolders = 0
        var totalBytes = 0L
        var hiddenCount = 0
        var unknownCount = 0
        var suspiciousCount = 0
        var duplicateCount = 0
        var zeroByteCount = 0
        var corruptedCount = 0

        _progress.value = ScanProgressState(sessionId = sessionId, isScanning = true)

        val rootDoc = try {
            DocumentFile.fromTreeUri(context, rootUri)
        } catch (e: Exception) {
            errors += ScanErrorEntry(rootUri.toString(), "Unable to open selected storage tree: ${e.message}")
            null
        }

        if (rootDoc == null || !rootDoc.canRead()) {
            errors += ScanErrorEntry(rootUri.toString(), "Storage location is unreadable or disconnected.")
            val finalErr = _progress.value.copy(isScanning = false, errors = errors)
            _progress.value = finalErr
            return finalErr
        }

        val queue = ArrayDeque<Pair<DocumentFile, String>>()
        queue.add(rootDoc to (rootDoc.name ?: "Selected Storage"))

        while (queue.isNotEmpty()) {
            if (cancelled) break
            while (paused && !cancelled) {
                delay(200)
            }
            if (cancelled) break

            val (dir, relPath) = queue.removeFirst()
            totalFolders++

            val children = try {
                dir.listFiles()
            } catch (e: SecurityException) {
                errors += ScanErrorEntry(relPath, "Permission denied by Android Scoped Storage.")
                emptyArray()
            } catch (e: Exception) {
                errors += ScanErrorEntry(relPath, "Device/storage read error (possibly disconnected): ${e.message}")
                emptyArray()
            }

            for (child in children) {
                if (cancelled) break
                while (paused && !cancelled) {
                    delay(200)
                }
                if (cancelled) break

                val name = child.name ?: "unnamed"
                val childPath = "$relPath/$name"

                if (child.isDirectory) {
                    queue.add(child to childPath)
                } else if (child.isFile) {
                    if (!child.canRead()) {
                        errors += ScanErrorEntry(childPath, "File is unreadable under current permissions.")
                        continue
                    }
                    try {
                        val size = child.length()
                        val inspection = decoderEngine.inspectFile(child.uri, name, size, childPath)
                        val sig = inspection.signature
                        val hiddenFinding = hiddenDetector.evaluate(name, childPath, sig.detectedFormat)
                        val provenance = provenanceEngine.investigateOrigin(inspection, child.lastModified())
                        val threat = threatEngine.analyze(inspection)

                        val isDup = !sig.isZeroByte && seenHashes.containsKey(sig.sha256)
                        if (!sig.isZeroByte && !isDup) {
                            seenHashes[sig.sha256] = childPath
                        }

                        totalFiles++
                        totalBytes += size
                        if (hiddenFinding.isHidden) hiddenCount++
                        if (sig.isUnknownFormat) unknownCount++
                        if (sig.isZeroByte) zeroByteCount++
                        if (sig.isCorruptedOrTruncated) corruptedCount++
                        if (isDup) duplicateCount++
                        if (threat.riskClassification in setOf(
                                RiskClassification.MEDIUM_RISK,
                                RiskClassification.HIGH_RISK,
                                RiskClassification.CRITICAL_INDICATORS
                            )
                        ) {
                            suspiciousCount++
                        }

                        val summary = ScannedFileSummary(
                            sessionId = sessionId,
                            fileName = name,
                            fileUri = child.uri.toString(),
                            filePathDisplay = childPath,
                            fileSize = size,
                            sha256 = sig.sha256,
                            declaredExtension = sig.declaredExtension,
                            detectedFormat = sig.detectedFormat,
                            isHidden = hiddenFinding.isHidden,
                            isExtensionMismatch = sig.isExtensionMismatch,
                            isUnknownFormat = sig.isUnknownFormat,
                            isCorrupted = sig.isCorruptedOrTruncated,
                            isZeroByte = sig.isZeroByte,
                            isDuplicate = isDup,
                            riskClassification = threat.riskClassification,
                            provenanceCategory = provenance.category,
                            lastModifiedMillis = child.lastModified(),
                            findingsSummary = buildString {
                                if (sig.isExtensionMismatch) append("Extension mismatch. ")
                                if (hiddenFinding.isHidden) append(hiddenFinding.reasons.firstOrNull() ?: "Hidden. ").append(". ")
                                if (threat.indicators.isNotEmpty()) append(threat.indicators.first().title)
                            }.trim()
                        )
                        onFileScanned(summary)

                        _progress.value = ScanProgressState(
                            sessionId = sessionId,
                            isScanning = true,
                            isPaused = paused,
                            isCancelled = cancelled,
                            currentFile = childPath,
                            totalFilesExamined = totalFiles,
                            totalFoldersExamined = totalFolders,
                            totalBytesExamined = totalBytes,
                            hiddenFilesCount = hiddenCount,
                            unknownFormatsCount = unknownCount,
                            suspiciousFilesCount = suspiciousCount,
                            duplicateFilesCount = duplicateCount,
                            zeroByteFilesCount = zeroByteCount,
                            corruptedFilesCount = corruptedCount,
                            errors = errors.toList()
                        )
                    } catch (e: Exception) {
                        errors += ScanErrorEntry(childPath, "Skipped due to read error: ${e.message}")
                    }
                }
            }
        }

        val finalState = _progress.value.copy(
            isScanning = false,
            isPaused = false,
            errors = errors.toList()
        )
        _progress.value = finalState
        return finalState
    }
}
