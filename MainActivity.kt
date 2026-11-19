package com.fileguard.forensics

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import androidx.core.os.LocaleListCompat
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.fileguard.forensics.domain.model.QuarantineRecord
import com.fileguard.forensics.ui.ForensicViewModel
import com.fileguard.forensics.ui.navigation.ForensicRoute
import com.fileguard.forensics.ui.screens.ApkInspectorScreen
import com.fileguard.forensics.ui.screens.DashboardScreen
import com.fileguard.forensics.ui.screens.DeepScanScreen
import com.fileguard.forensics.ui.screens.FileOriginScreen
import com.fileguard.forensics.ui.screens.ForensicReportsScreen
import com.fileguard.forensics.ui.screens.HiddenFilesLabScreen
import com.fileguard.forensics.ui.screens.MalwareAnalysisScreen
import com.fileguard.forensics.ui.screens.QuarantineScreen
import com.fileguard.forensics.ui.screens.RecoveryLabScreen
import com.fileguard.forensics.ui.screens.SettingsPrivacyScreen
import com.fileguard.forensics.ui.screens.StorageExplorerScreen
import com.fileguard.forensics.ui.screens.UnknownFileDecoderScreen
import com.fileguard.forensics.ui.theme.FileGuardTheme
import com.fileguard.forensics.ui.theme.ForensicColors
import kotlinx.coroutines.launch
import java.io.File

class MainActivity : AppCompatActivity() {

    private val viewModel: ForensicViewModel by viewModels()

    @OptIn(ExperimentalMaterial3Api::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            FileGuardTheme {
                val navController = rememberNavController()
                val drawerState = rememberDrawerState(DrawerValue.Closed)
                val scope = rememberCoroutineScope()
                val snackbarHostState = remember { SnackbarHostState() }

                val scanProgress by viewModel.scanProgress.collectAsState()
                val offlineMode by viewModel.offlineMode.collectAsState()
                val language by viewModel.language.collectAsState()
                val recentSessions by viewModel.recentSessions.collectAsState()
                val recentFiles by viewModel.recentFiles.collectAsState()
                val hiddenFiles by viewModel.hiddenFiles.collectAsState()
                val unknownFiles by viewModel.unknownOrDamagedFiles.collectAsState()
                val quarantineRecords by viewModel.quarantineRecords.collectAsState()
                val activeInvestigation by viewModel.activeInvestigation.collectAsState()
                val isInspecting by viewModel.isInspecting.collectAsState()
                val statusMessage by viewModel.statusMessage.collectAsState()
                val lastLookup by viewModel.lastLookupResult.collectAsState()
                val volumes by viewModel.storageVolumes.collectAsState()
                val generatedReportFile by viewModel.generatedReportFile.collectAsState()

                var pendingRestoreRecord by remember { mutableStateOf<QuarantineRecord?>(null) }

                val folderPickerLauncher = rememberLauncherForActivityResult(
                    ActivityResultContracts.OpenDocumentTree()
                ) { uri ->
                    if (uri != null) {
                        val label = uri.lastPathSegment ?: "Authorized Folder"
                        viewModel.startFolderScan(uri, label)
                        navController.navigate(ForensicRoute.DEEP_SCAN.route)
                    }
                }

                val singleFilePickerLauncher = rememberLauncherForActivityResult(
                    ActivityResultContracts.OpenDocument()
                ) { uri ->
                    if (uri != null) {
                        viewModel.inspectSingleUri(uri)
                        navController.navigate(ForensicRoute.UNKNOWN_DECODER.route)
                    }
                }

                val restoreFileLauncher = rememberLauncherForActivityResult(
                    ActivityResultContracts.CreateDocument("*/*")
                ) { targetUri ->
                    val rec = pendingRestoreRecord
                    if (targetUri != null && rec != null) {
                        viewModel.restoreQuarantineRecord(rec, targetUri)
                    }
                    pendingRestoreRecord = null
                }

                LaunchedEffect(statusMessage) {
                    val msg = statusMessage
                    if (msg != null) {
                        snackbarHostState.showSnackbar(msg)
                        viewModel.clearStatusMessage()
                    }
                }

                val navItems = listOf(
                    ForensicRoute.DASHBOARD to stringResource(R.string.nav_dashboard),
                    ForensicRoute.STORAGE_EXPLORER to stringResource(R.string.nav_explorer),
                    ForensicRoute.DEEP_SCAN to stringResource(R.string.nav_scan),
                    ForensicRoute.HIDDEN_FILES to stringResource(R.string.nav_hidden),
                    ForensicRoute.UNKNOWN_DECODER to stringResource(R.string.nav_decoder),
                    ForensicRoute.FILE_ORIGIN to stringResource(R.string.nav_origin),
                    ForensicRoute.MALWARE_ANALYSIS to stringResource(R.string.nav_malware),
                    ForensicRoute.APK_INSPECTOR to stringResource(R.string.nav_apk),
                    ForensicRoute.RECOVERY_LAB to stringResource(R.string.nav_recovery),
                    ForensicRoute.QUARANTINE to stringResource(R.string.nav_quarantine),
                    ForensicRoute.FORENSIC_REPORTS to stringResource(R.string.nav_reports),
                    ForensicRoute.SETTINGS_PRIVACY to stringResource(R.string.nav_settings)
                )

                val backStack by navController.currentBackStackEntryAsState()
                val currentRoute = backStack?.destination?.route ?: ForensicRoute.DASHBOARD.route
                val currentTitle = navItems.firstOrNull { it.first.route == currentRoute }?.second
                    ?: stringResource(R.string.app_name)

                ModalNavigationDrawer(
                    drawerState = drawerState,
                    drawerContent = {
                        ModalDrawerSheet(drawerContainerColor = ForensicColors.CharcoalSurface) {
                            Text(
                                text = stringResource(R.string.app_name),
                                color = ForensicColors.CyanAccent,
                                modifier = Modifier.padding(16.dp)
                            )
                            for ((route, title) in navItems) {
                                NavigationDrawerItem(
                                    label = { Text(title) },
                                    selected = currentRoute == route.route,
                                    onClick = {
                                        scope.launch { drawerState.close() }
                                        navController.navigate(route.route) {
                                            launchSingleTop = true
                                        }
                                    }
                                )
                            }
                        }
                    }
                ) {
                    Scaffold(
                        topBar = {
                            TopAppBar(
                                title = { Text(currentTitle) },
                                navigationIcon = {
                                    IconButton(onClick = { scope.launch { drawerState.open() } }) {
                                        Icon(Icons.Default.Menu, contentDescription = "Menu", tint = ForensicColors.CyanAccent)
                                    }
                                },
                                colors = TopAppBarDefaults.topAppBarColors(
                                    containerColor = ForensicColors.CharcoalSurface,
                                    titleContentColor = ForensicColors.TextPrimary
                                )
                            )
                        },
                        snackbarHost = { SnackbarHost(snackbarHostState) },
                        containerColor = ForensicColors.DeepNavy
                    ) { innerPadding ->
                        NavHost(
                            navController = navController,
                            startDestination = ForensicRoute.DASHBOARD.route,
                            modifier = Modifier.padding(innerPadding)
                        ) {
                            composable(ForensicRoute.DASHBOARD.route) {
                                DashboardScreen(
                                    volumes = volumes,
                                    recentSessions = recentSessions,
                                    recentFiles = recentFiles,
                                    offlineMode = offlineMode,
                                    onNavigate = { navController.navigate(it.route) },
                                    onPickFolderToScan = { folderPickerLauncher.launch(null) },
                                    onPickSingleFile = { singleFilePickerLauncher.launch(arrayOf("*/*")) },
                                    onInspectFile = { viewModel.inspectSingleUri(it) }
                                )
                            }
                            composable(ForensicRoute.STORAGE_EXPLORER.route) {
                                StorageExplorerScreen(
                                    volumes = volumes,
                                    onRefreshVolumes = { viewModel.refreshStorageVolumes() },
                                    onPickFolderTree = { folderPickerLauncher.launch(null) },
                                    onPickSingleFile = { singleFilePickerLauncher.launch(arrayOf("*/*")) }
                                )
                            }
                            composable(ForensicRoute.DEEP_SCAN.route) {
                                DeepScanScreen(
                                    progress = scanProgress,
                                    onStartNewScan = { folderPickerLauncher.launch(null) },
                                    onPause = { viewModel.pauseScan() },
                                    onResume = { viewModel.resumeScan() },
                                    onCancel = { viewModel.cancelScan() }
                                )
                            }
                            composable(ForensicRoute.HIDDEN_FILES.route) {
                                HiddenFilesLabScreen(
                                    hiddenFiles = hiddenFiles,
                                    onInspectFile = { uri ->
                                        viewModel.inspectSingleUri(uri)
                                        navController.navigate(ForensicRoute.UNKNOWN_DECODER.route)
                                    }
                                )
                            }
                            composable(ForensicRoute.UNKNOWN_DECODER.route) {
                                UnknownFileDecoderScreen(
                                    active = activeInvestigation,
                                    isInspecting = isInspecting,
                                    unknownFiles = unknownFiles,
                                    onPickFile = { singleFilePickerLauncher.launch(arrayOf("*/*")) },
                                    onInspectFile = { viewModel.inspectSingleUri(it) },
                                    onQuarantineActive = { viewModel.quarantineActiveFile() }
                                )
                            }
                            composable(ForensicRoute.FILE_ORIGIN.route) {
                                FileOriginScreen(
                                    active = activeInvestigation,
                                    onPickFile = { singleFilePickerLauncher.launch(arrayOf("*/*")) }
                                )
                            }
                            composable(ForensicRoute.MALWARE_ANALYSIS.route) {
                                MalwareAnalysisScreen(
                                    active = activeInvestigation,
                                    offlineMode = offlineMode,
                                    lastLookup = lastLookup,
                                    onPickFile = { singleFilePickerLauncher.launch(arrayOf("*/*")) },
                                    onQuarantineActive = { viewModel.quarantineActiveFile() },
                                    onRequestHashLookup = { viewModel.performHashLookup(it) }
                                )
                            }
                            composable(ForensicRoute.APK_INSPECTOR.route) {
                                ApkInspectorScreen(
                                    active = activeInvestigation,
                                    onPickApk = { singleFilePickerLauncher.launch(arrayOf("*/*")) }
                                )
                            }
                            composable(ForensicRoute.RECOVERY_LAB.route) {
                                RecoveryLabScreen(
                                    active = activeInvestigation,
                                    onPickFile = { singleFilePickerLauncher.launch(arrayOf("*/*")) },
                                    onAttemptRecovery = { viewModel.attemptSafeRecovery() }
                                )
                            }
                            composable(ForensicRoute.QUARANTINE.route) {
                                QuarantineScreen(
                                    records = quarantineRecords,
                                    onRestoreRecord = { rec ->
                                        pendingRestoreRecord = rec
                                        restoreFileLauncher.launch(rec.originalName)
                                    },
                                    onDeleteRecord = { viewModel.deleteQuarantineRecord(it) }
                                )
                            }
                            composable(ForensicRoute.FORENSIC_REPORTS.route) {
                                ForensicReportsScreen(
                                    sessions = recentSessions,
                                    generatedFile = generatedReportFile,
                                    onExportPdf = { viewModel.exportReport(it, asPdf = true) },
                                    onExportJson = { viewModel.exportReport(it, asPdf = false) },
                                    onShareFile = { shareReportFile(it) }
                                )
                            }
                            composable(ForensicRoute.SETTINGS_PRIVACY.route) {
                                SettingsPrivacyScreen(
                                    privacyState = viewModel.buildPrivacyDashboardState(),
                                    currentLanguage = language,
                                    onToggleOfflineMode = { viewModel.setOfflineMode(it) },
                                    onSelectLanguage = { lang ->
                                        viewModel.setLanguage(lang)
                                        AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(lang))
                                    },
                                    onClearHistory = { viewModel.clearLocalHistory() }
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    private fun shareReportFile(file: File) {
        val uri = FileProvider.getUriForFile(this, "${packageName}.fileprovider", file)
        val mime = if (file.extension == "pdf") "application/pdf" else "application/json"
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = mime
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivity(Intent.createChooser(intent, "Share Forensic Report"))
    }
}
