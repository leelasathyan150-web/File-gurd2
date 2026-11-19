package com.fileguard.forensics.domain.engine

data class HiddenFileFinding(
    val isHidden: Boolean,
    val reasons: List<String>
)

class HiddenFileDetector {

    private val suspiciousExtensions = setOf(
        "exe", "dll", "bat", "cmd", "ps1", "vbs", "sh", "elf", "dex", "so", "apk", "scr", "jar"
    )

    fun evaluate(fileName: String, relativePath: String, detectedFormat: String): HiddenFileFinding {
        val reasons = mutableListOf<String>()

        if (fileName.startsWith(".")) {
            reasons += if (fileName.equals(".nomedia", ignoreCase = true)) {
                "Media-hiding marker (.nomedia) prevents gallery indexing"
            } else {
                "Dot-prefixed hidden filename"
            }
        }

        if (relativePath.split('/').any { it.startsWith(".") && it.length > 1 }) {
            reasons += "Resides inside a dot-prefixed hidden directory"
        }

        if (!fileName.contains('.')) {
            reasons += "Extensionless file (hidden from extension-based filters)"
        }

        val parts = fileName.split('.')
        if (parts.size >= 3) {
            reasons += "Multiple extensions detected (${parts.drop(1).joinToString(".")})"
        }

        val ext = fileName.substringAfterLast('.', "").lowercase()
        if (ext in suspiciousExtensions) {
            reasons += "Potentially executable/script extension (.$ext)"
        }

        if (detectedFormat.contains("ELF") || detectedFormat.contains("DEX") || detectedFormat.contains("PE")) {
            reasons += "Contains compiled executable binary format ($detectedFormat)"
        }

        return HiddenFileFinding(
            isHidden = reasons.isNotEmpty(),
            reasons = reasons
        )
    }
}
