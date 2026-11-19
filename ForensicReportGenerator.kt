package com.fileguard.forensics.domain.engine

import android.content.Context
import android.graphics.Color
import android.graphics.Paint
import android.graphics.pdf.PdfDocument
import com.fileguard.forensics.domain.model.ScanSessionSummary
import com.fileguard.forensics.domain.model.ScannedFileSummary
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ForensicReportGenerator(private val context: Context) {

    private val reportsDir: File
        get() = File(context.filesDir, "reports").apply { mkdirs() }

    fun generateJsonReport(
        session: ScanSessionSummary,
        files: List<ScannedFileSummary>
    ): File {
        val root = JSONObject().apply {
            put("investigationId", session.sessionId)
            put("generatedAt", SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US).format(Date()))
            put("storageSource", session.sourceLabel)
            put("scanStatistics", JSONObject().apply {
                put("status", session.status)
                put("totalFilesExamined", session.totalFiles)
                put("totalFoldersExamined", session.totalFolders)
                put("totalBytesExamined", session.totalBytes)
                put("hiddenFilesDiscovered", session.hiddenCount)
                put("unknownFormatsDiscovered", session.unknownCount)
                put("suspiciousFilesDiscovered", session.suspiciousCount)
            })
            put("epistemicNotice", JSONObject().apply {
                put("verifiedFacts", "SHA-256 hashes, file sizes, and exact byte headers observed during local read.")
                put("technicalIndicators", "Magic-byte format matches, entropy scores, and static string/permission flags.")
                put("assumptionsAndLimitations", "Static analysis cannot guarantee detection of unknown malware families. Absence of indicators does not prove absolute safety. Android scoped storage may restrict access to protected system/app sandboxes.")
            })
            put("files", JSONArray().apply {
                for (f in files) {
                    put(JSONObject().apply {
                        put("fileName", f.fileName)
                        put("pathDisplay", f.filePathDisplay)
                        put("fileSizeBytes", f.fileSize)
                        put("sha256", f.sha256)
                        put("declaredExtension", f.declaredExtension)
                        put("detectedFormat", f.detectedFormat)
                        put("isHidden", f.isHidden)
                        put("isExtensionMismatch", f.isExtensionMismatch)
                        put("isUnknownFormat", f.isUnknownFormat)
                        put("isCorrupted", f.isCorrupted)
                        put("riskClassification", f.riskClassification.label)
                        put("provenance", f.provenanceCategory.label)
                        put("findingsSummary", f.findingsSummary)
                    })
                }
            })
            put("recommendedNextSteps", JSONArray().apply {
                put("Review any HIGH RISK or CRITICAL INDICATORS files in the Malware Analysis or Unknown File Decoder screen.")
                put("Copy suspicious executables or disguised binaries to Quarantine; never install or execute unknown APKs.")
                put("Use Recovery Lab for damaged ZIP/JPEG copies without overwriting originals.")
            })
        }

        val outFile = File(reportsDir, "FileGuard_Report_${session.sessionId.take(8)}.json")
        outFile.writeText(root.toString(2), Charsets.UTF_8)
        return outFile
    }

    fun generatePdfReport(
        session: ScanSessionSummary,
        files: List<ScannedFileSummary>
    ): File {
        val doc = PdfDocument()
        val pageWidth = 595
        val pageHeight = 842
        val margin = 40f

        val titlePaint = Paint().apply {
            color = Color.rgb(0, 150, 199)
            textSize = 18f
            isFakeBoldText = true
        }
        val headingPaint = Paint().apply {
            color = Color.rgb(20, 33, 61)
            textSize = 13f
            isFakeBoldText = true
        }
        val bodyPaint = Paint().apply {
            color = Color.DKGRAY
            textSize = 10f
        }
        val monoPaint = Paint().apply {
            color = Color.rgb(55, 65, 81)
            textSize = 8.5f
        }

        var pageNum = 1
        var page = doc.startPage(PdfDocument.PageInfo.Builder(pageWidth, pageHeight, pageNum).create())
        var canvas = page.canvas
        var y = 48f

        fun newPageIfNeeded(neededHeight: Float) {
            if (y + neededHeight > pageHeight - 40f) {
                doc.finishPage(page)
                pageNum++
                page = doc.startPage(PdfDocument.PageInfo.Builder(pageWidth, pageHeight, pageNum).create())
                canvas = page.canvas
                y = 48f
            }
        }

        fun drawLine(text: String, paint: Paint, lineHeight: Float = 15f) {
            newPageIfNeeded(lineHeight)
            canvas.drawText(text, margin, y, paint)
            y += lineHeight
        }

        drawLine("FILEGUARD FORENSICS — DIGITAL INVESTIGATION REPORT", titlePaint, 24f)
        drawLine("Investigation ID: ${session.sessionId}", bodyPaint)
        drawLine("Generated: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US).format(Date())}", bodyPaint)
        drawLine("Storage Source: ${session.sourceLabel}", bodyPaint, 20f)

        drawLine("1. SCAN STATISTICS", headingPaint, 18f)
        drawLine("Status: ${session.status} | Files: ${session.totalFiles} | Folders: ${session.totalFolders}", bodyPaint)
        drawLine("Total Examined: ${session.totalBytes} bytes", bodyPaint)
        drawLine("Hidden: ${session.hiddenCount} | Unknown Formats: ${session.unknownCount} | Flagged: ${session.suspiciousCount}", bodyPaint, 20f)

        drawLine("2. TECHNICAL LIMITATIONS & EVIDENCE DISTINCTION", headingPaint, 18f)
        drawLine("Verified Facts: SHA-256 hashes, byte sizes, and observed file headers.", bodyPaint)
        drawLine("Technical Indicators: Signature matches, entropy, and static permission/string heuristics.", bodyPaint)
        drawLine("Limitations: Static analysis cannot detect all malware. Scoped storage restricts protected paths.", bodyPaint, 20f)

        drawLine("3. FILE FINDINGS (TOP ${minOf(files.size, 60)} ITEMS)", headingPaint, 18f)
        for (f in files.take(60)) {
            newPageIfNeeded(56f)
            drawLine("• ${f.fileName} [${f.riskClassification.label}]", headingPaint, 14f)
            drawLine("  Format: ${f.detectedFormat} (Ext: .${f.declaredExtension}) | Size: ${f.fileSize} B", bodyPaint, 13f)
            drawLine("  SHA-256: ${f.sha256}", monoPaint, 12f)
            drawLine("  Provenance: ${f.provenanceCategory.label}", bodyPaint, 13f)
            if (f.findingsSummary.isNotBlank()) {
                drawLine("  Notes: ${f.findingsSummary.take(88)}", bodyPaint, 15f)
            }
        }

        newPageIfNeeded(60f)
        y += 8f
        drawLine("4. RECOMMENDED NEXT STEPS", headingPaint, 18f)
        drawLine("- Inspect unknown or mismatched files in Unknown File Decoder before opening.", bodyPaint)
        drawLine("- Copy high-risk files to Quarantine; never install unverified APKs.", bodyPaint)
        drawLine("- Keep original files untouched when attempting Recovery Lab repairs.", bodyPaint)

        doc.finishPage(page)
        val outFile = File(reportsDir, "FileGuard_Report_${session.sessionId.take(8)}.pdf")
        FileOutputStream(outFile).use { doc.writeTo(it) }
        doc.close()
        return outFile
    }
}
