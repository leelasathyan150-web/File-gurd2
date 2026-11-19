package com.fileguard.forensics.domain.engine

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import com.fileguard.forensics.domain.model.ApkAnalysisResult
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest

class ApkInspectorEngine(private val context: Context) {

    private val highRiskPermissions = setOf(
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_CONTACTS"
    )

    @Suppress("DEPRECATION")
    fun inspectApkUri(uri: Uri, displayName: String): ApkAnalysisResult {
        val tempDir = File(context.cacheDir, "inspect").apply { mkdirs() }
        val tempApk = File(tempDir, "inspect_${System.currentTimeMillis()}.apk")
        try {
            // Copy safely to app-private cache for PackageManager static archive parsing (never executed/installed)
            context.contentResolver.openInputStream(uri)?.use { input ->
                FileOutputStream(tempApk).use { output ->
                    val buf = ByteArray(8192)
                    var total = 0L
                    val maxBytes = 150L * 1024L * 1024L // 150MB safety cap
                    while (true) {
                        val n = input.read(buf)
                        if (n <= 0) break
                        total += n
                        if (total > maxBytes) {
                            return emptyErrorResult("APK exceeds 150 MB static inspection cap.")
                        }
                        output.write(buf, 0, n)
                    }
                }
            } ?: return emptyErrorResult("Unable to open APK stream.")

            val pm = context.packageManager
            val flags = PackageManager.GET_ACTIVITIES or
                PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS or
                PackageManager.GET_PROVIDERS or
                PackageManager.GET_PERMISSIONS or
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    PackageManager.GET_SIGNING_CERTIFICATES
                } else {
                    PackageManager.GET_SIGNATURES
                }

            val pkgInfo: PackageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageArchiveInfo(tempApk.absolutePath, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                pm.getPackageArchiveInfo(tempApk.absolutePath, flags)
            } ?: return emptyErrorResult("Android PackageManager could not parse $displayName as a valid APK.")

            pkgInfo.applicationInfo?.let { appInfo ->
                appInfo.sourceDir = tempApk.absolutePath
                appInfo.publicSourceDir = tempApk.absolutePath
            }

            val appName = pkgInfo.applicationInfo?.loadLabel(pm)?.toString() ?: displayName
            val perms = pkgInfo.requestedPermissions?.toList() ?: emptyList()
            val dangerous = perms.filter { it in highRiskPermissions }

            val activities = pkgInfo.activities?.map { it.name } ?: emptyList()
            val services = pkgInfo.services?.map { it.name } ?: emptyList()
            val receivers = pkgInfo.receivers?.map { it.name } ?: emptyList()
            val providers = pkgInfo.providers?.map { it.name } ?: emptyList()

            val exportedCount = (pkgInfo.activities?.count { it.exported } ?: 0) +
                (pkgInfo.services?.count { it.exported } ?: 0) +
                (pkgInfo.receivers?.count { it.exported } ?: 0) +
                (pkgInfo.providers?.count { it.exported } ?: 0)

            val certSha256 = extractCertSha256(pkgInfo)
            val warnings = mutableListOf<String>()
            if (perms.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")) {
                warnings += "Requests Accessibility Service binding (frequently abused for UI overlay/keylogging)."
            }
            if (perms.contains("android.permission.REQUEST_INSTALL_PACKAGES")) {
                warnings += "Can request installation of additional APKs (dropper capability)."
            }
            if (perms.contains("android.permission.READ_SMS") && perms.contains("android.permission.RECEIVE_BOOT_COMPLETED")) {
                warnings += "Combines SMS read access with boot persistence."
            }
            if (exportedCount > 5) {
                warnings += "Exposes $exportedCount exported components to other apps."
            }

            val verCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkgInfo.longVersionCode
            } else {
                pkgInfo.versionCode.toLong()
            }

            return ApkAnalysisResult(
                packageName = pkgInfo.packageName ?: "Unknown",
                appName = appName,
                versionName = pkgInfo.versionName ?: "Unknown",
                versionCode = verCode,
                minSdk = pkgInfo.applicationInfo?.minSdkVersion,
                targetSdk = pkgInfo.applicationInfo?.targetSdkVersion,
                requestedPermissions = perms,
                dangerousPermissions = dangerous,
                activities = activities,
                services = services,
                receivers = receivers,
                providers = providers,
                exportedComponentsCount = exportedCount,
                signingCertSha256 = certSha256,
                signingSubject = if (certSha256 != null) "X.509 APK Signature Present" else "No Signature Found",
                staticWarnings = warnings,
                parseError = null
            )
        } catch (e: Exception) {
            return emptyErrorResult("APK inspection error: ${e.message ?: "Unknown error"}")
        } finally {
            tempApk.delete()
        }
    }

    @Suppress("DEPRECATION")
    private fun extractCertSha256(pkgInfo: PackageInfo): String? {
        val sigBytes: ByteArray? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pkgInfo.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
                ?: pkgInfo.signingInfo?.signingCertificateHistory?.firstOrNull()?.toByteArray()
        } else {
            pkgInfo.signatures?.firstOrNull()?.toByteArray()
        }
        return sigBytes?.let {
            MessageDigest.getInstance("SHA-256").digest(it).joinToString("") { b -> "%02X".format(b) }
        }
    }

    private fun emptyErrorResult(err: String) = ApkAnalysisResult(
        packageName = "N/A",
        appName = "N/A",
        versionName = "N/A",
        versionCode = 0L,
        minSdk = null,
        targetSdk = null,
        requestedPermissions = emptyList(),
        dangerousPermissions = emptyList(),
        activities = emptyList(),
        services = emptyList(),
        receivers = emptyList(),
        providers = emptyList(),
        exportedComponentsCount = 0,
        signingCertSha256 = null,
        signingSubject = null,
        staticWarnings = emptyList(),
        parseError = err
    )
}
