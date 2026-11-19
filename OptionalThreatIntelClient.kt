package com.fileguard.forensics.domain.engine

import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

data class HashLookupResult(
    val sha256: String,
    val status: String,
    val summary: String,
    val source: String
)

/**
 * Strictly optional, hash-only threat intelligence lookup.
 * Never uploads file contents, filenames, or personal metadata.
 * Only executes when Offline Mode is explicitly disabled AND user confirms the lookup dialog.
 */
class OptionalThreatIntelClient {

    suspend fun lookupSha256(sha256: String, offlineModeEnabled: Boolean): Result<HashLookupResult> =
        withContext(Dispatchers.IO) {
            if (offlineModeEnabled) {
                return@withContext Result.failure(
                    IllegalStateException("Offline Mode is enabled. Disable Offline Mode in Privacy Settings to perform a hash-only lookup.")
                )
            }
            if (!sha256.matches(Regex("^[a-fA-F0-9]{64}$"))) {
                return@withContext Result.failure(IllegalArgumentException("Invalid SHA-256 hash format."))
            }
            try {
                val url = URL("https://mb-api.abuse.ch/api/v1/")
                val conn = (url.openConnection() as HttpURLConnection).apply {
                    requestMethod = "POST"
                    connectTimeout = 8000
                    readTimeout = 8000
                    doOutput = true
                    setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
                }
                OutputStreamWriter(conn.outputStream).use { writer ->
                    writer.write("query=get_info&hash=$sha256")
                    writer.flush()
                }
                val code = conn.responseCode
                val body = (if (code in 200..299) conn.inputStream else conn.errorStream)
                    ?.bufferedReader()?.readText() ?: ""
                conn.disconnect()

                val json = JSONObject(body)
                val queryStatus = json.optString("query_status", "unknown")
                val summary = when (queryStatus) {
                    "ok" -> "Known malware sample match found in public MalwareBazaar feed."
                    "hash_not_found" -> "Hash not found in MalwareBazaar public database (not a guarantee of safety)."
                    else -> "Lookup returned status: $queryStatus"
                }
                Result.success(
                    HashLookupResult(
                        sha256 = sha256,
                        status = queryStatus,
                        summary = summary,
                        source = "abuse.ch MalwareBazaar (Hash-Only)"
                    )
                )
            } catch (e: Exception) {
                Result.failure(e)
            }
        }
}
