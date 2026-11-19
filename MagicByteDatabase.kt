package com.fileguard.forensics.domain.engine

import kotlin.math.log2

data class MagicSignature(
    val formatName: String,
    val mimeType: String,
    val expectedExtensions: List<String>,
    val magicBytes: ByteArray,
    val offset: Int = 0,
    val footerBytes: ByteArray? = null
)

object MagicByteDatabase {

    val signatures: List<MagicSignature> = listOf(
        MagicSignature("PDF Document", "application/pdf", listOf("pdf"), byteArrayOf(0x25, 0x50, 0x44, 0x46, 0x2D)), // %PDF-
        MagicSignature("PNG Image", "image/png", listOf("png"), byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)),
        MagicSignature("JPEG Image", "image/jpeg", listOf("jpg", "jpeg"), byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte())),
        MagicSignature("GIF Image", "image/gif", listOf("gif"), byteArrayOf(0x47, 0x49, 0x46, 0x38)), // GIF8
        MagicSignature("BMP Image", "image/bmp", listOf("bmp"), byteArrayOf(0x42, 0x4D)), // BM
        MagicSignature("RIFF Container (WAV/WEBP/AVI)", "application/octet-stream", listOf("wav", "webp", "avi"), byteArrayOf(0x52, 0x49, 0x46, 0x46)),
        MagicSignature("ZIP / Office / APK Archive", "application/zip", listOf("zip", "apk", "docx", "xlsx", "pptx", "jar"), byteArrayOf(0x50, 0x4B, 0x03, 0x04)),
        MagicSignature("ZIP Empty Archive", "application/zip", listOf("zip"), byteArrayOf(0x50, 0x4B, 0x05, 0x06)),
        MagicSignature("RAR Archive (v5+)", "application/vnd.rar", listOf("rar"), byteArrayOf(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00)),
        MagicSignature("RAR Archive (v4)", "application/vnd.rar", listOf("rar"), byteArrayOf(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00)),
        MagicSignature("7-Zip Archive", "application/x-7z-compressed", listOf("7z"), byteArrayOf(0x37, 0x7A, 0xBC.toByte(), 0xAF.toByte(), 0x27, 0x1C)),
        MagicSignature("GZIP Compressed", "application/gzip", listOf("gz", "tgz"), byteArrayOf(0x1F, 0x8B.toByte())),
        MagicSignature("ELF Executable / Shared Library", "application/x-elf", listOf("so", "elf", "bin", ""), byteArrayOf(0x7F, 0x45, 0x4C, 0x46)),
        MagicSignature("Android DEX Bytecode", "application/x-dex", listOf("dex"), byteArrayOf(0x64, 0x65, 0x78, 0x0A, 0x30, 0x33)),
        MagicSignature("SQLite 3 Database", "application/vnd.sqlite3", listOf("db", "sqlite", "sqlite3"), "SQLite format 3\u0000".toByteArray(Charsets.US_ASCII)),
        MagicSignature("Windows PE / EXE / DLL", "application/x-msdownload", listOf("exe", "dll", "sys"), byteArrayOf(0x4D, 0x5A)),
        MagicSignature("Java Class / Mach-O Fat", "application/java-vm", listOf("class"), byteArrayOf(0xCA.toByte(), 0xFE.toByte(), 0xBA.toByte(), 0xBE.toByte())),
        MagicSignature("MP3 Audio (ID3v2)", "audio/mpeg", listOf("mp3"), byteArrayOf(0x49, 0x44, 0x33)),
        MagicSignature("MP3 Audio (Frame Sync)", "audio/mpeg", listOf("mp3"), byteArrayOf(0xFF.toByte(), 0xFB.toByte())),
        MagicSignature("OGG Media", "audio/ogg", listOf("ogg", "oga", "ogv"), byteArrayOf(0x4F, 0x67, 0x67, 0x53)),
        MagicSignature("FLAC Audio", "audio/flac", listOf("flac"), byteArrayOf(0x66, 0x4C, 0x61, 0x43)),
        MagicSignature("Matroska / WebM Video", "video/x-matroska", listOf("mkv", "webm"), byteArrayOf(0x1A, 0x45, 0xDF.toByte(), 0xA3.toByte())),
        MagicSignature("Shell / Script Shebang", "text/x-shellscript", listOf("sh", "py", "pl", "rb"), byteArrayOf(0x23, 0x21))
    )

    fun matchHeader(header: ByteArray): MagicSignature? {
        if (header.isEmpty()) return null

        // Check MP4/M4A ftyp box at offset 4
        if (header.size >= 12 &&
            header[4] == 0x66.toByte() && header[5] == 0x74.toByte() &&
            header[6] == 0x79.toByte() && header[7] == 0x70.toByte()
        ) {
            val brand = String(header.copyOfRange(8, 12), Charsets.US_ASCII)
            return if (brand.startsWith("M4A")) {
                MagicSignature("M4A Audio (ISO Media)", "audio/mp4", listOf("m4a", "mp4"), byteArrayOf(), 4)
            } else {
                MagicSignature("MP4 / ISO Base Media", "video/mp4", listOf("mp4", "m4v", "mov", "3gp"), byteArrayOf(), 4)
            }
        }

        // Check RIFF sub-type
        if (header.size >= 12 &&
            header[0] == 0x52.toByte() && header[1] == 0x49.toByte() &&
            header[2] == 0x46.toByte() && header[3] == 0x46.toByte()
        ) {
            val sub = String(header.copyOfRange(8, 12), Charsets.US_ASCII)
            return when (sub) {
                "WEBP" -> MagicSignature("WEBP Image", "image/webp", listOf("webp"), byteArrayOf(0x52, 0x49, 0x46, 0x46))
                "WAVE" -> MagicSignature("WAV Audio", "audio/wav", listOf("wav"), byteArrayOf(0x52, 0x49, 0x46, 0x46))
                "AVI " -> MagicSignature("AVI Video", "video/x-msvideo", listOf("avi"), byteArrayOf(0x52, 0x49, 0x46, 0x46))
                else -> MagicSignature("RIFF Container ($sub)", "application/octet-stream", listOf("riff"), byteArrayOf(0x52, 0x49, 0x46, 0x46))
            }
        }

        for (sig in signatures) {
            if (header.size >= sig.offset + sig.magicBytes.size && sig.magicBytes.isNotEmpty()) {
                var matched = true
                for (i in sig.magicBytes.indices) {
                    if (header[sig.offset + i] != sig.magicBytes[i]) {
                        matched = false
                        break
                    }
                }
                if (matched) return sig
            }
        }
        return null
    }

    fun looksLikePlainText(sample: ByteArray): Pair<Boolean, String> {
        if (sample.isEmpty()) return false to "Empty"
        var printable = 0
        var control = 0
        for (b in sample) {
            val v = b.toInt() and 0xFF
            when {
                v == 0x09 || v == 0x0A || v == 0x0D -> printable++
                v in 0x20..0x7E -> printable++
                v >= 0x80 -> printable++ // potential UTF-8 multibyte
                else -> control++
            }
        }
        val ratio = printable.toDouble() / sample.size
        if (ratio < 0.90 || control > sample.size * 0.05) {
            return false to "Binary"
        }
        val text = String(sample, Charsets.UTF_8).trimStart()
        return when {
            text.startsWith("{") || text.startsWith("[") -> true to "JSON Data"
            text.startsWith("<?xml", ignoreCase = true) || text.startsWith("<manifest", ignoreCase = true) -> true to "XML Document"
            text.startsWith("<!DOCTYPE html", ignoreCase = true) || text.startsWith("<html", ignoreCase = true) -> true to "HTML Document"
            text.contains(",") && text.lines().take(5).count { it.contains(",") } >= 2 -> true to "CSV / Delimited Text"
            else -> true to "Plain Text (UTF-8)"
        }
    }

    fun calculateShannonEntropy(bytes: ByteArray): Double {
        if (bytes.isEmpty()) return 0.0
        val counts = IntArray(256)
        for (b in bytes) {
            counts[b.toInt() and 0xFF]++
        }
        var entropy = 0.0
        val total = bytes.size.toDouble()
        for (count in counts) {
            if (count > 0) {
                val p = count / total
                entropy -= p * log2(p)
            }
        }
        return entropy
    }
}
