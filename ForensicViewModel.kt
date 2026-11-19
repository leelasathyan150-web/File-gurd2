package com.fileguard.forensics.ui

import android.app.Application
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.Environment
import android.os.StatFs
import android.os.storage.StorageManager
import androidx.core.content.ContextCompat
import androidx.documentfile.provider.DocumentFile
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.workDataOf
import com.fileguard.forensics.FileGuardApp
import com.fileguard.forensics.data.db.QuarantineEntity
import com.fileguard.forensics.data.db.ScanSessionEntity
import com.fileguard.forensics.data.db.ScannedFileEntity
import com.fileguard.forensics.domain.engine.HashLookupResult
import com.fileguard.forensics.domain.model.ApkAnalysisResult
import com.fileguard.forensics.domain.model.DecoderInspectionResult
import com.fileguard.forensics.domain.model.OriginAnalysisResult
import com.fileguard.forensics.domain.model.PrivacyDashboardState
import com.fileguard.forensics.domain.model.ProvenanceCategory
import com.fileguard.forensics.domain.model.QuarantineRecord
import com.fileguard.forensics.domain.model.RecoveryAssessment
import com.fileguard.forensics.domain.model.RiskClassification
import com.fileguard.forensics.domain.model.ScanProgressState
import com.fileguard.forensics.domain.model.ScanSessionSummary
import com.fileguard.forensics.domain.model.ScannedFileSummary
import com.fileguard.forensics.domain.model.ThreatAnalysisResult
import com.fileguard.forensics.worker.DeepScanWorker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class StorageVolumeInfo(
    val name: String,
    val isRemovable: Boolean,
    val isUsb: Boolean,
    val totalBytes: Long,
    val availableBytes: Long
)

data class ActiveFileInvestigation(
    val fileName: String,
    val fileUri: Uri,
    val decoderResult: DecoderInspectionResult,
    val originResult: OriginAnalysisResult,
    val threatResult: ThreatAnalysisResult,
    val apkResult: ApkAnalysisResult?,
    val recoveryAssessment: RecoveryAssessment
)

class ForensicViewModel(application: Application) : AndroidViewModel(application) {

    private val app = application as FileGuardApp
    private val container = app.container

    val scanProgress: StateFlow<ScanProgressState> = container.storageScanner.progress
    val offlineMode: StateFlow<Boolean> = container.privacyPreferences.offlineMode
    val language: StateFlow<String> = container.privacyPreferences.language

    val recentSessions: StateFlow<List<ScanSessionSummary>> =
        container.database.scanSessionDao().observeAll()
            .map { list -> list.map { it.toDomain() } }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val recentFiles: StateFlow<List<ScannedFileSummary>> =
        container.database.scannedFileDao().observeRecent()
            .map { list -> list.map { it.toDomain() } }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val hiddenFiles: StateFlow<List<ScannedFileSummary>> =
        container.database.scannedFileDao().observeHidden()
            .map { list -> list.map { it.toDomain() } }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val unknownOrDamagedFiles: StateFlow<List<ScannedFileSummary>> =
        container.database.scannedFileDao().observeUnknownOrDamaged()
            .map { list -> list.map { it.toDomain() } }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val flaggedFiles: StateFlow<List<ScannedFileSummary>> =
        container.database.scannedFileDao().observeFlagged()
            .map { list -> list.map { it.toDomain() } }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val quarantineRecords: StateFlow<List<QuarantineRecord>> =
        container.database.quarantineDao().observeAll()
            .map { list -> list.map { it.toDomain() } }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val _activeInvestigation = MutableStateFlow<ActiveFileInvestigation?>(null)
    val activeInvestigation: StateFlow<ActiveFileInvestigation?> = _activeInvestigation.asStateFlow()

    private val _isInspecting = MutableStateFlow(false)
    val isInspecting: StateFlow<Boolean> = _isInspecting.asStateFlow()

    private val _statusMessage = MutableStateFlow<String?>(null)
    val statusMessage: StateFlow<String?> = _statusMessage.asStateFlow()

    private val _lastLookupResult = MutableStateFlow<HashLookupResult?>(null)
    val lastLookupResult: StateFlow<HashLookupResult?> = _lastLookupResult.asStateFlow()

    private val _storageVolumes = MutableStateFlow<List<StorageVolumeInfo>>(emptyList())
    val storageVolumes: StateFlow<List<StorageVolumeInfo>> = _storageVolumes.asStateFlow()

    private val _generatedReportFile = MutableStateFlow<File?>(null)
    val generatedReportFile: StateFlow<File?> = _generatedReportFile.asStateFlow()

    init {
        refreshStorageVolumes()
    }

    fun clearStatusMessage() {
        _statusMessage.value = null
    }

    fun refreshStorageVolumes() {
        viewModelScope.launch(Dispatchers.IO) {
            val list = mutableListOf<StorageVolumeInfo>()
            try {
                val stat = StatFs(Environment.getDataDirectory().path)
                list += StorageVolumeInfo(
                    name = "Internal Shared Storage",
                    isRemovable = false,
                    isUsb = false,
                    totalBytes = stat.totalBytes,
                    availableBytes = stat.availableBytes
                )
                val sm = app.getSystemService(Context.STORAGE_SERVICE) as StorageManager
                for (vol in sm.storageVolumes) {
                    if (vol.isRemovable) {
                        val desc = vol.getDescription(app) ?: "Removable Storage"
                        val isUsb = desc.contains("USB", ignoreCase = true)
                        list += StorageVolumeInfo(
                            name = desc,
                            isRemovable = true,
                            isUsb = isUsb,
                            totalBytes = 0L,
                            availableBytes = 0L
                        )
                    }
                }
            } catch (_: Exception) {
                // ignore
            }
            _storageVolumes.value = list
        }
    }

    fun startFolderScan(treeUri: Uri, label: String) {
        try {
            app.contentResolver.takePersistableUriPermission(
                treeUri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        } catch (_: Exception) {
            // Some providers don't support persistable permissions
        }
        container.privacyPreferences.addStorageSource("$label ($treeUri)")
        val req = OneTimeWorkRequestBuilder<DeepScanWorker>()
            .setInputData(
                workDataOf(
                    DeepScanWorker.KEY_TREE_URI to treeUri.toString(),
                    DeepScanWorker.KEY_SOURCE_LABEL to label
                )
            )
            .build()
        WorkManager.getInstance(app).enqueue(req)
        _statusMessage.value = "Deep scan queued for $label."
    }

    fun pauseScan() = container.storageScanner.pause()
    fun resumeScan() = container.storageScanner.resume()
    fun cancelScan() = container.storageScanner.cancel()

    fun inspectSingleUri(uri: Uri) {
        viewModelScope.launch(Dispatchers.IO) {
            _isInspecting.value = true
            try {
                val doc = DocumentFile.fromSingleUri(app, uri)
                val name = doc?.name ?: uri.lastPathSegment ?: "unknown_file"
                val size = doc?.length()?.takeIf { it >= 0 } ?: 0L
                val lastMod = doc?.lastModified() ?: 0L
                val pathDisplay = uri.path ?: name

                val decoder = container.decoderEngine.inspectFile(uri, name, size, pathDisplay)
                val apkResult = if (
                    decoder.signature.detectedFormat.contains("APK") ||
                    name.endsWith(".apk", ignoreCase = true)
                ) {
                    container.apkInspectorEngine.inspectApkUri(uri, name)
                } else null
                val origin = container.provenanceEngine.investigateOrigin(decoder, lastMod)
                val threat = container.threatAnalysisEngine.analyze(decoder, apkResult)
                val recovery = container.recoveryEngine.assess(decoder)

                _activeInvestigation.value = ActiveFileInvestigation(
                    fileName = name,
                    fileUri = uri,
                    decoderResult = decoder,
                    originResult = origin,
                    threatResult = threat,
                    apkResult = apkResult,
                    recoveryAssessment = recovery
                )
            } catch (e: Exception) {
                _statusMessage.value = "Inspection error: ${e.message}"
            } finally {
                _isInspecting.value = false
            }
        }
    }

    fun quarantineActiveFile() {
        val active = _activeInvestigation.value ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val res = container.quarantineManager.quarantineCopy(
                sourceUri = active.fileUri,
                fileName = active.fileName,
                fileSize = active.decoderResult.signature.fileSize,
                expectedSha256 = active.decoderResult.signature.sha256,
                risk = active.threatResult.riskClassification,
                notes = active.threatResult.explanation
            )
            _statusMessage.value = res.fold(
                onSuccess = { "Copied ${active.fileName} to private Quarantine. Original file was not modified." },
                onFailure = { "Quarantine failed: ${it.message}" }
            )
        }
    }

    fun restoreQuarantineRecord(record: QuarantineRecord, targetUri: Uri) {
        viewModelScope.launch(Dispatchers.IO) {
            val res = container.quarantineManager.restoreToUri(record, targetUri)
            _statusMessage.value = res.fold(
                onSuccess = { "Restored ${record.originalName} to selected location." },
                onFailure = { "Restore failed: ${it.message}" }
            )
        }
    }

    fun deleteQuarantineRecord(record: QuarantineRecord) {
        viewModelScope.launch(Dispatchers.IO) {
            container.quarantineManager.removeFromQuarantine(record)
            _statusMessage.value = "Removed ${record.originalName} from Quarantine."
        }
    }

    fun attemptSafeRecovery() {
        val active = _activeInvestigation.value ?: return
        viewModelScope.launch(Dispatchers.IO) {
            val res = container.recoveryEngine.performSafeRecoveryCopy(active.fileUri, active.decoderResult)
            _statusMessage.value = res.fold(
                onSuccess = { "Saved recovered/repaired copy to app recovery folder: ${it.name}" },
                onFailure = { "Recovery failed: ${it.message}" }
            )
        }
    }

    fun exportReport(session: ScanSessionSummary, asPdf: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val files = container.database.scannedFileDao().getBySession(session.sessionId).map { it.toDomain() }
                val out = if (asPdf) {
                    container.reportGenerator.generatePdfReport(session, files)
                } else {
                    container.reportGenerator.generateJsonReport(session, files)
                }
                _generatedReportFile.value = out
                _statusMessage.value = "Generated ${out.name}"
            } catch (e: Exception) {
                _statusMessage.value = "Report generation failed: ${e.message}"
            }
        }
    }

    fun performHashLookup(sha256: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val res = container.threatIntelClient.lookupSha256(sha256, offlineMode.value)
            res.fold(
                onSuccess = {
                    _lastLookupResult.value = it
                    val now = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
                    container.privacyPreferences.recordOnlineLookup(now)
                    _statusMessage.value = "Hash lookup complete: ${it.summary}"
                },
                onFailure = {
                    _statusMessage.value = "Lookup blocked/failed: ${it.message}"
                }
            )
        }
    }

    fun setOfflineMode(enabled: Boolean) = container.privacyPreferences.setOfflineMode(enabled)
    fun setLanguage(langCode: String) = container.privacyPreferences.setLanguage(langCode)

    fun clearLocalHistory() {
        viewModelScope.launch(Dispatchers.IO) {
            container.database.scannedFileDao().clearAll()
            container.database.scanSessionDao().clearAll()
            _statusMessage.value = "Local scan history cleared."
        }
    }

    fun buildPrivacyDashboardState(): PrivacyDashboardState {
        val cm = app.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val netCap = cm.getNetworkCapabilities(cm.activeNetwork)
        val hasNet = netCap?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true

        val permsToCheck = listOf(
            android.Manifest.permission.READ_EXTERNAL_STORAGE,
            android.Manifest.permission.READ_MEDIA_IMAGES,
            android.Manifest.permission.READ_MEDIA_VIDEO,
            android.Manifest.permission.READ_MEDIA_AUDIO,
            android.Manifest.permission.POST_NOTIFICATIONS
        )
        val granted = permsToCheck.filter {
            ContextCompat.checkSelfPermission(app, it) == PackageManager.PERMISSION_GRANTED
        }.map { it.substringAfterLast('.') }

        return PrivacyDashboardState(
            offlineModeEnabled = offlineMode.value,
            networkAvailable = hasNet,
            lastOnlineLookupTimestamp = container.privacyPreferences.lastLookup.value,
            grantedPermissions = granted.ifEmpty { listOf("Scoped Storage (SAF User Grants Only)") },
            selectedStorageSources = container.privacyPreferences.selectedSources.value,
            localScanHistoryCount = recentSessions.value.size,
            dataSharingStatus = if (offlineMode.value) {
                "100% Local Processing — Zero External Network Calls"
            } else {
                "Hash-Only Lookup Permitted (Explicit Per-Query Consent Required)"
            }
        )
    }

    private fun ScanSessionEntity.toDomain() = ScanSessionSummary(
        sessionId = sessionId,
        sourceLabel = sourceLabel,
        startedAtMillis = startedAtMillis,
        completedAtMillis = completedAtMillis,
        totalFiles = totalFiles,
        totalFolders = totalFolders,
        totalBytes = totalBytes,
        hiddenCount = hiddenCount,
        unknownCount = unknownCount,
        suspiciousCount = suspiciousCount,
        status = status
    )

    private fun ScannedFileEntity.toDomain() = ScannedFileSummary(
        id = id,
        sessionId = sessionId,
        fileName = fileName,
        fileUri = fileUri,
        filePathDisplay = filePathDisplay,
        fileSize = fileSize,
        sha256 = sha256,
        declaredExtension = declaredExtension,
        detectedFormat = detectedFormat,
        isHidden = isHidden,
        isExtensionMismatch = isExtensionMismatch,
        isUnknownFormat = isUnknownFormat,
        isCorrupted = isCorrupted,
        isZeroByte = isZeroByte,
        isDuplicate = isDuplicate,
        riskClassification = RiskClassification.entries.firstOrNull { it.name == riskClassification }
            ?: RiskClassification.UNKNOWN_INSUFFICIENT_EVIDENCE,
        provenanceCategory = ProvenanceCategory.entries.firstOrNull { it.name == provenanceCategory }
            ?: ProvenanceCategory.UNKNOWN_ORIGIN,
        lastModifiedMillis = lastModifiedMillis,
        findingsSummary = findingsSummary
    )

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
