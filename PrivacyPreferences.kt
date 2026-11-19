package com.fileguard.forensics.data.preferences

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.security.KeyStore
import javax.crypto.KeyGenerator

class PrivacyPreferences(context: Context) {

    private val prefs = context.getSharedPreferences("fileguard_privacy_prefs", Context.MODE_PRIVATE)

    companion object {
        private const val KEY_OFFLINE_MODE = "offline_mode"
        private const val KEY_LANGUAGE = "app_language"
        private const val KEY_LAST_LOOKUP = "last_online_lookup"
        private const val KEY_STORAGE_SOURCES = "selected_storage_sources"
        private const val KEYSTORE_ALIAS = "fileguard_local_integrity_key"
    }

    private val _offlineMode = MutableStateFlow(prefs.getBoolean(KEY_OFFLINE_MODE, true))
    val offlineMode: StateFlow<Boolean> = _offlineMode.asStateFlow()

    private val _language = MutableStateFlow(prefs.getString(KEY_LANGUAGE, "en") ?: "en")
    val language: StateFlow<String> = _language.asStateFlow()

    private val _lastLookup = MutableStateFlow(prefs.getString(KEY_LAST_LOOKUP, "Never (100% Offline)") ?: "Never (100% Offline)")
    val lastLookup: StateFlow<String> = _lastLookup.asStateFlow()

    private val _selectedSources = MutableStateFlow(
        prefs.getStringSet(KEY_STORAGE_SOURCES, emptySet())?.toList() ?: emptyList()
    )
    val selectedSources: StateFlow<List<String>> = _selectedSources.asStateFlow()

    fun setOfflineMode(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_OFFLINE_MODE, enabled).apply()
        _offlineMode.value = enabled
    }

    fun setLanguage(langCode: String) {
        prefs.edit().putString(KEY_LANGUAGE, langCode).apply()
        _language.value = langCode
    }

    fun recordOnlineLookup(timestampText: String) {
        prefs.edit().putString(KEY_LAST_LOOKUP, timestampText).apply()
        _lastLookup.value = timestampText
    }

    fun addStorageSource(uriAndLabel: String) {
        val current = _selectedSources.value.toMutableSet()
        current.add(uriAndLabel)
        prefs.edit().putStringSet(KEY_STORAGE_SOURCES, current).apply()
        _selectedSources.value = current.toList()
    }

    fun ensureKeystoreKeyExists(): Boolean {
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (!ks.containsAlias(KEYSTORE_ALIAS)) {
                val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                generator.init(
                    KeyGenParameterSpec.Builder(
                        KEYSTORE_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                    )
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .build()
                )
                generator.generateKey()
            }
            true
        } catch (_: Exception) {
            false
        }
    }
}
