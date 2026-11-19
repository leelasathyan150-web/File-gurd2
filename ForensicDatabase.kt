package com.fileguard.forensics.data.db

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "scan_sessions")
data class ScanSessionEntity(
    @PrimaryKey val sessionId: String,
    val sourceLabel: String,
    val startedAtMillis: Long,
    val completedAtMillis: Long?,
    val totalFiles: Int,
    val totalFolders: Int,
    val totalBytes: Long,
    val hiddenCount: Int,
    val unknownCount: Int,
    val suspiciousCount: Int,
    val status: String
)

@Entity(tableName = "scanned_files")
data class ScannedFileEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val sessionId: String,
    val fileName: String,
    val fileUri: String,
    val filePathDisplay: String,
    val fileSize: Long,
    val sha256: String,
    val declaredExtension: String,
    val detectedFormat: String,
    val isHidden: Boolean,
    val isExtensionMismatch: Boolean,
    val isUnknownFormat: Boolean,
    val isCorrupted: Boolean,
    val isZeroByte: Boolean,
    val isDuplicate: Boolean,
    val riskClassification: String,
    val provenanceCategory: String,
    val lastModifiedMillis: Long,
    val findingsSummary: String
)

@Entity(tableName = "quarantine_records")
data class QuarantineEntity(
    @PrimaryKey val id: String,
    val originalName: String,
    val originalUri: String,
    val originalSha256: String,
    val quarantinedPath: String,
    val fileSize: Long,
    val riskClassification: String,
    val quarantinedAtMillis: Long,
    val notes: String
)

@Dao
interface ScanSessionDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(session: ScanSessionEntity)

    @Query("SELECT * FROM scan_sessions ORDER BY startedAtMillis DESC")
    fun observeAll(): Flow<List<ScanSessionEntity>>

    @Query("SELECT COUNT(*) FROM scan_sessions")
    fun observeCount(): Flow<Int>

    @Query("DELETE FROM scan_sessions")
    suspend fun clearAll()
}

@Dao
interface ScannedFileDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(file: ScannedFileEntity)

    @Query("SELECT * FROM scanned_files ORDER BY id DESC LIMIT 500")
    fun observeRecent(): Flow<List<ScannedFileEntity>>

    @Query("SELECT * FROM scanned_files WHERE sessionId = :sessionId ORDER BY id DESC")
    suspend fun getBySession(sessionId: String): List<ScannedFileEntity>

    @Query("SELECT * FROM scanned_files WHERE isHidden = 1 ORDER BY id DESC")
    fun observeHidden(): Flow<List<ScannedFileEntity>>

    @Query("SELECT * FROM scanned_files WHERE isUnknownFormat = 1 OR isCorrupted = 1 OR isExtensionMismatch = 1 ORDER BY id DESC")
    fun observeUnknownOrDamaged(): Flow<List<ScannedFileEntity>>

    @Query("SELECT * FROM scanned_files WHERE riskClassification IN ('MEDIUM_RISK', 'HIGH_RISK', 'CRITICAL_INDICATORS') ORDER BY id DESC")
    fun observeFlagged(): Flow<List<ScannedFileEntity>>

    @Query("DELETE FROM scanned_files")
    suspend fun clearAll()
}

@Dao
interface QuarantineDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(record: QuarantineEntity)

    @Query("SELECT * FROM quarantine_records ORDER BY quarantinedAtMillis DESC")
    fun observeAll(): Flow<List<QuarantineEntity>>

    @Query("DELETE FROM quarantine_records WHERE id = :id")
    suspend fun deleteById(id: String)
}

@Database(
    entities = [ScanSessionEntity::class, ScannedFileEntity::class, QuarantineEntity::class],
    version = 1,
    exportSchema = true
)
abstract class ForensicDatabase : RoomDatabase() {
    abstract fun scanSessionDao(): ScanSessionDao
    abstract fun scannedFileDao(): ScannedFileDao
    abstract fun quarantineDao(): QuarantineDao

    companion object {
        @Volatile
        private var INSTANCE: ForensicDatabase? = null

        fun getInstance(context: Context): ForensicDatabase {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    ForensicDatabase::class.java,
                    "fileguard_forensics.db"
                ).build().also { INSTANCE = it }
            }
        }
    }
}
