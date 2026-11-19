package com.fileguard.forensics

import android.app.Application
import com.fileguard.forensics.di.AppContainer

class FileGuardApp : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
        container.privacyPreferences.ensureKeystoreKeyExists()
    }
}
