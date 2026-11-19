package com.fileguard.forensics.di

import android.content.Context
import com.fileguard.forensics.data.db.ForensicDatabase
import com.fileguard.forensics.data.preferences.PrivacyPreferences
import com.fileguard.forensics.data.storage.StorageScanner
import com.fileguard.forensics.domain.engine.ApkInspectorEngine
import com.fileguard.forensics.domain.engine.FileDecoderEngine
import com.fileguard.forensics.domain.engine.FileSignatureEngine
import com.fileguard.forensics.domain.engine.ForensicReportGenerator
import com.fileguard.forensics.domain.engine.HiddenFileDetector
import com.fileguard.forensics.domain.engine.OptionalThreatIntelClient
import com.fileguard.forensics.domain.engine.ProvenanceEngine
import com.fileguard.forensics.domain.engine.QuarantineManager
import com.fileguard.forensics.domain.engine.RecoveryEngine
import com.fileguard.forensics.domain.engine.ThreatAnalysisEngine

class AppContainer(context: Context) {
    val database: ForensicDatabase = ForensicDatabase.getInstance(context)
    val privacyPreferences: PrivacyPreferences = PrivacyPreferences(context)
    val signatureEngine: FileSignatureEngine = FileSignatureEngine(context)
    val decoderEngine: FileDecoderEngine = FileDecoderEngine(context, signatureEngine)
    val provenanceEngine: ProvenanceEngine = ProvenanceEngine()
    val threatAnalysisEngine: ThreatAnalysisEngine = ThreatAnalysisEngine()
    val apkInspectorEngine: ApkInspectorEngine = ApkInspectorEngine(context)
    val hiddenFileDetector: HiddenFileDetector = HiddenFileDetector()
    val recoveryEngine: RecoveryEngine = RecoveryEngine(context)
    val quarantineManager: QuarantineManager = QuarantineManager(context, database.quarantineDao())
    val reportGenerator: ForensicReportGenerator = ForensicReportGenerator(context)
    val threatIntelClient: OptionalThreatIntelClient = OptionalThreatIntelClient()
    val storageScanner: StorageScanner = StorageScanner(
        context = context,
        signatureEngine = signatureEngine,
        decoderEngine = decoderEngine,
        provenanceEngine = provenanceEngine,
        threatEngine = threatAnalysisEngine,
        hiddenDetector = hiddenFileDetector
    )
}
