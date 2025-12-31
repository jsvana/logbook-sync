pub mod integrations;
pub mod users;

use crate::adif::Qso;
use crate::{Error, Result};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

pub use integrations::*;
pub use users::*;

/// State database for tracking sync status
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Get a reference to the database connection
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

#[derive(Debug, Clone)]
pub struct StoredQso {
    pub id: i64,
    pub call: String,
    pub qso_date: String,
    pub time_on: String,
    pub band: String,
    pub mode: String,
    pub source_file: Option<String>,
    pub source_hash: String,
    pub qrz_logid: Option<i64>,
    pub qrz_synced_at: Option<String>,
    pub lotw_qsl_rcvd: Option<String>,
    pub lotw_qsl_sent: Option<String>,
    pub qsl_rcvd: Option<String>,
    pub qsl_sent: Option<String>,
    pub pota_synced: bool,
    pub created_at: String,
    pub updated_at: String,
    pub adif_record: String,
    /// Source of this QSO: 'local', 'qrz', 'wavelog', 'lotw', etc.
    pub source: Option<String>,
    /// External system's ID for this QSO (e.g., QRZ logid, Wavelog ID)
    pub source_id: Option<String>,
}

/// Known QSO sources
pub mod qso_source {
    pub const LOCAL: &str = "local";
    pub const QRZ: &str = "qrz";
    pub const WAVELOG: &str = "wavelog";
    pub const LOTW: &str = "lotw";
    pub const EQSL: &str = "eqsl";
    pub const CLUBLOG: &str = "clublog";
    pub const HRDLOG: &str = "hrdlog";
    pub const LOFI: &str = "lofi";
    pub const POTA: &str = "pota";
}

#[derive(Debug, Clone)]
pub struct ProcessedFile {
    pub id: i64,
    pub path: String,
    pub checksum: String,
    pub processed_at: String,
    pub qso_count: i64,
}

impl Database {
    /// Open or create the database at the given path
    pub fn open(path: &Path) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        let db = Database { conn };
        db.initialize()?;
        db.migrate()?;
        Ok(db)
    }

    /// Open an in-memory database (for testing)
    #[cfg(test)]
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Database { conn };
        db.initialize()?;
        db.migrate()?;
        Ok(db)
    }

    /// Initialize database schema
    fn initialize(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS qsos (
                id INTEGER PRIMARY KEY,
                call TEXT NOT NULL,
                qso_date TEXT NOT NULL,
                time_on TEXT NOT NULL,
                band TEXT NOT NULL,
                mode TEXT NOT NULL,
                source_file TEXT,
                source_hash TEXT NOT NULL,
                qrz_logid INTEGER,
                qrz_synced_at TEXT,
                lotw_qsl_rcvd TEXT,
                lotw_qsl_sent TEXT,
                qsl_rcvd TEXT,
                qsl_sent TEXT,
                pota_synced INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                adif_record TEXT NOT NULL,
                UNIQUE(call, qso_date, time_on, band, mode)
            );

            CREATE TABLE IF NOT EXISTS processed_files (
                id INTEGER PRIMARY KEY,
                path TEXT NOT NULL UNIQUE,
                checksum TEXT NOT NULL,
                processed_at TEXT NOT NULL,
                qso_count INTEGER
            );

            CREATE TABLE IF NOT EXISTS sync_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_qsos_qrz_synced ON qsos(qrz_synced_at);
            CREATE INDEX IF NOT EXISTS idx_qsos_source_file ON qsos(source_file);

            -- LoFi Operations (collections of QSOs, often POTA activations)
            CREATE TABLE IF NOT EXISTS lofi_operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                -- LoFi identifiers
                lofi_uuid TEXT NOT NULL UNIQUE,
                account_uuid TEXT NOT NULL,

                -- Timestamps (stored as milliseconds since epoch)
                created_at_millis REAL NOT NULL,
                updated_at_millis REAL NOT NULL,
                synced_at_millis REAL,

                -- Device tracking
                created_on_device_id TEXT,
                updated_on_device_id TEXT,

                -- Operation metadata
                station_call TEXT NOT NULL,
                title TEXT,
                subtitle TEXT,
                grid TEXT,

                -- QSO stats
                qso_count INTEGER DEFAULT 0,
                start_at_millis_min REAL,
                start_at_millis_max REAL,

                -- Status flags
                deleted INTEGER DEFAULT 0,
                synced INTEGER DEFAULT 0,

                -- Sync tracking
                first_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                last_updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

                -- Store full JSON for complete data preservation
                raw_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_lofi_operations_updated ON lofi_operations(updated_at_millis);
            CREATE INDEX IF NOT EXISTS idx_lofi_operations_station ON lofi_operations(station_call);
            CREATE INDEX IF NOT EXISTS idx_lofi_operations_deleted ON lofi_operations(deleted);

            -- LoFi Operation References (POTA parks, SOTA summits, etc.)
            CREATE TABLE IF NOT EXISTS lofi_operation_refs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_uuid TEXT NOT NULL,

                -- Reference info
                ref_type TEXT NOT NULL,
                reference TEXT NOT NULL,
                program TEXT,
                name TEXT,
                location TEXT,
                label TEXT,
                short_label TEXT,

                FOREIGN KEY (operation_uuid) REFERENCES lofi_operations(lofi_uuid) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_lofi_op_refs_operation ON lofi_operation_refs(operation_uuid);
            CREATE INDEX IF NOT EXISTS idx_lofi_op_refs_type ON lofi_operation_refs(ref_type);
            CREATE INDEX IF NOT EXISTS idx_lofi_op_refs_reference ON lofi_operation_refs(reference);

            -- LoFi QSOs
            CREATE TABLE IF NOT EXISTS lofi_qsos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                -- LoFi identifiers
                lofi_uuid TEXT NOT NULL UNIQUE,
                account_uuid TEXT NOT NULL,

                -- Link to operation (nullable)
                operation_uuid TEXT,

                -- Timestamps (stored as milliseconds since epoch)
                created_at_millis REAL NOT NULL,
                updated_at_millis REAL NOT NULL,
                synced_at_millis REAL,
                start_at_millis REAL NOT NULL,

                -- Core QSO fields
                their_call TEXT NOT NULL,
                our_call TEXT,
                band TEXT,
                freq REAL,
                mode TEXT,
                rst_sent TEXT,
                rst_rcvd TEXT,

                -- Grid squares
                our_grid TEXT,
                their_grid TEXT,

                -- Their info
                their_name TEXT,
                their_qth TEXT,
                their_state TEXT,
                their_country TEXT,
                their_cq_zone INTEGER,
                their_itu_zone INTEGER,

                -- Additional fields
                tx_pwr TEXT,
                notes TEXT,

                -- Status flags
                deleted INTEGER DEFAULT 0,

                -- Sync tracking
                first_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                last_updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                is_new INTEGER DEFAULT 1,

                -- Store full JSON for complete data preservation
                raw_json TEXT NOT NULL,

                FOREIGN KEY (operation_uuid) REFERENCES lofi_operations(lofi_uuid)
            );

            CREATE INDEX IF NOT EXISTS idx_lofi_qsos_updated ON lofi_qsos(updated_at_millis);
            CREATE INDEX IF NOT EXISTS idx_lofi_qsos_their_call ON lofi_qsos(their_call);
            CREATE INDEX IF NOT EXISTS idx_lofi_qsos_start_at ON lofi_qsos(start_at_millis);
            CREATE INDEX IF NOT EXISTS idx_lofi_qsos_operation ON lofi_qsos(operation_uuid);
            CREATE INDEX IF NOT EXISTS idx_lofi_qsos_is_new ON lofi_qsos(is_new);
            CREATE INDEX IF NOT EXISTS idx_lofi_qsos_deleted ON lofi_qsos(deleted);

            -- LoFi QSO References (their POTA park, SOTA summit, etc.)
            CREATE TABLE IF NOT EXISTS lofi_qso_refs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                qso_uuid TEXT NOT NULL,

                -- Reference info
                ref_type TEXT NOT NULL,
                reference TEXT NOT NULL,
                program TEXT,

                FOREIGN KEY (qso_uuid) REFERENCES lofi_qsos(lofi_uuid) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_lofi_qso_refs_qso ON lofi_qso_refs(qso_uuid);
            CREATE INDEX IF NOT EXISTS idx_lofi_qso_refs_reference ON lofi_qso_refs(reference);

            -- Multitenancy: Users table
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                encryption_salt BLOB NOT NULL,  -- 32 bytes, for per-user key derivation
                callsign TEXT,
                is_admin INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                theme TEXT NOT NULL DEFAULT 'light',  -- 'light' or 'dark'
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                last_login_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

            -- User integration configurations (encrypted)
            CREATE TABLE IF NOT EXISTS user_integrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                integration_type TEXT NOT NULL,  -- 'qrz', 'lofi', 'lotw', 'clublog', etc.
                enabled INTEGER NOT NULL DEFAULT 1,
                encrypted_config TEXT NOT NULL,  -- JSON encrypted with user's derived key
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                UNIQUE(user_id, integration_type)
            );

            CREATE INDEX IF NOT EXISTS idx_user_integrations_user ON user_integrations(user_id);

            -- User-specific watch directories
            CREATE TABLE IF NOT EXISTS user_watch_paths (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                watch_path TEXT NOT NULL,
                patterns TEXT NOT NULL DEFAULT '["*.adi", "*.adif", "*.ADI", "*.ADIF"]',  -- JSON array
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            );

            CREATE INDEX IF NOT EXISTS idx_user_watch_paths_user ON user_watch_paths(user_id);

            -- Sessions table for web auth
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY NOT NULL,
                data BLOB NOT NULL,
                expiry_date INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expiry_date);

            -- User sync state tracking (per user/integration/direction)
            CREATE TABLE IF NOT EXISTS user_sync_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                integration_type TEXT NOT NULL,  -- 'qrz', 'lofi', 'lotw', etc.
                direction TEXT NOT NULL,         -- 'upload' or 'download'
                last_sync_at TEXT,               -- ISO timestamp of last successful sync
                last_sync_result TEXT,           -- 'success', 'error', or null if never synced
                last_sync_message TEXT,          -- Details or error message
                items_synced INTEGER DEFAULT 0,  -- Count of items synced in last sync
                UNIQUE(user_id, integration_type, direction)
            );

            CREATE INDEX IF NOT EXISTS idx_user_sync_state_user ON user_sync_state(user_id);

            -- POTA Activations (downloaded from POTA.app)
            CREATE TABLE IF NOT EXISTS pota_activations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                callsign TEXT NOT NULL,
                date TEXT NOT NULL,              -- YYYY-MM-DD format
                reference TEXT NOT NULL,         -- Park reference (e.g., "US-0189")
                name TEXT,                       -- Park name
                parktype_desc TEXT,              -- Park type description
                location_desc TEXT,              -- Location (e.g., "US-CA")
                first_qso TEXT,                  -- ISO datetime of first QSO
                last_qso TEXT,                   -- ISO datetime of last QSO
                total INTEGER NOT NULL DEFAULT 0,
                cw INTEGER NOT NULL DEFAULT 0,
                data INTEGER NOT NULL DEFAULT 0,
                phone INTEGER NOT NULL DEFAULT 0,
                first_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                last_updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                UNIQUE(callsign, date, reference)
            );

            CREATE INDEX IF NOT EXISTS idx_pota_activations_callsign ON pota_activations(callsign);
            CREATE INDEX IF NOT EXISTS idx_pota_activations_date ON pota_activations(date);
            CREATE INDEX IF NOT EXISTS idx_pota_activations_reference ON pota_activations(reference);

            -- POTA QSOs (downloaded from POTA.app)
            CREATE TABLE IF NOT EXISTS pota_qsos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                qso_id INTEGER NOT NULL UNIQUE,  -- POTA's qsoId
                user_id INTEGER,                 -- POTA's userId
                qso_datetime TEXT NOT NULL,      -- ISO datetime
                station_callsign TEXT NOT NULL,
                operator_callsign TEXT,
                worked_callsign TEXT NOT NULL,
                band TEXT,
                mode TEXT,
                rst_sent TEXT,
                rst_rcvd TEXT,
                my_sig TEXT,
                my_sig_info TEXT,
                p2p_match TEXT,                  -- Park-to-park match info
                job_id INTEGER,
                park_id INTEGER,
                reference TEXT,                  -- Park reference
                park_name TEXT,
                parktype_desc TEXT,
                location_id INTEGER,
                location_desc TEXT,
                location_name TEXT,
                sig TEXT,                        -- Their SIG (e.g., POTA if they were at a park)
                sig_info TEXT,                   -- Their SIG_INFO (their park ref)
                logged_mode TEXT,
                first_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                last_updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            );

            CREATE INDEX IF NOT EXISTS idx_pota_qsos_qso_id ON pota_qsos(qso_id);
            CREATE INDEX IF NOT EXISTS idx_pota_qsos_datetime ON pota_qsos(qso_datetime);
            CREATE INDEX IF NOT EXISTS idx_pota_qsos_worked_callsign ON pota_qsos(worked_callsign);
            CREATE INDEX IF NOT EXISTS idx_pota_qsos_reference ON pota_qsos(reference);
            CREATE INDEX IF NOT EXISTS idx_pota_qsos_station_callsign ON pota_qsos(station_callsign);

            -- POTA upload status tracking (prevents duplicate uploads)
            CREATE TABLE IF NOT EXISTS pota_upload_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                park_ref TEXT NOT NULL,           -- Park reference (e.g., "US-0189")
                date TEXT NOT NULL,               -- YYYY-MM-DD format
                status TEXT NOT NULL DEFAULT 'uploading',  -- 'uploading', 'uploaded', 'failed'
                qso_count INTEGER NOT NULL DEFAULT 0,      -- Number of QSOs in this upload
                started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                completed_at TEXT,
                error_message TEXT,
                UNIQUE(user_id, park_ref, date)
            );

            CREATE INDEX IF NOT EXISTS idx_pota_upload_status_user ON pota_upload_status(user_id);
            CREATE INDEX IF NOT EXISTS idx_pota_upload_status_status ON pota_upload_status(status);
            "#,
        )?;
        Ok(())
    }

    /// Run database migrations for schema updates
    fn migrate(&self) -> Result<()> {
        // Check if confirmation columns exist, add them if not
        let columns: Vec<String> = self
            .conn
            .prepare("PRAGMA table_info(qsos)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        if !columns.contains(&"lotw_qsl_rcvd".to_string()) {
            self.conn.execute_batch(
                r#"
                ALTER TABLE qsos ADD COLUMN lotw_qsl_rcvd TEXT;
                ALTER TABLE qsos ADD COLUMN lotw_qsl_sent TEXT;
                ALTER TABLE qsos ADD COLUMN qsl_rcvd TEXT;
                ALTER TABLE qsos ADD COLUMN qsl_sent TEXT;
                "#,
            )?;
        }

        // Add source tracking columns (migration v2)
        if !columns.contains(&"source".to_string()) {
            self.conn.execute_batch(
                r#"
                ALTER TABLE qsos ADD COLUMN source TEXT DEFAULT 'local';
                ALTER TABLE qsos ADD COLUMN source_id TEXT;
                "#,
            )?;
        }

        // Add user_id column for multi-user isolation (migration v5)
        if !columns.contains(&"user_id".to_string()) {
            self.conn.execute_batch(
                r#"
                ALTER TABLE qsos ADD COLUMN user_id INTEGER REFERENCES users(id);
                "#,
            )?;
            // Create index for user-scoped queries
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_qsos_user ON qsos(user_id)",
                [],
            )?;
        }

        // Create index on lotw_qsl_rcvd (after migration ensures column exists)
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_qsos_lotw ON qsos(lotw_qsl_rcvd)",
            [],
        )?;

        // Create index on source for filtering by origin
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_qsos_source ON qsos(source)",
            [],
        )?;

        // Deduplicate QSOs and normalize time_on to HHMMSS (migration v4)
        // This removes duplicate QSOs that differ only in time precision (HHMM vs HHMMSS)
        self.deduplicate_qsos()?;

        // Add theme column to users table (migration v3)
        let user_columns: Vec<String> = self
            .conn
            .prepare("PRAGMA table_info(users)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        if !user_columns.is_empty() && !user_columns.contains(&"theme".to_string()) {
            self.conn.execute(
                "ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT 'light'",
                [],
            )?;
        }

        // Create pota_upload_status table if it doesn't exist (migration v6)
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS pota_upload_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                park_ref TEXT NOT NULL,
                date TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'uploading',
                qso_count INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                completed_at TEXT,
                error_message TEXT,
                UNIQUE(user_id, park_ref, date)
            );

            CREATE INDEX IF NOT EXISTS idx_pota_upload_status_user ON pota_upload_status(user_id);
            CREATE INDEX IF NOT EXISTS idx_pota_upload_status_status ON pota_upload_status(status);
            "#,
        )?;

        // Add job verification columns to pota_upload_status (migration v7)
        let pota_columns: Vec<String> = self
            .conn
            .prepare("PRAGMA table_info(pota_upload_status)")?
            .query_map([], |row| row.get(1))?
            .collect::<std::result::Result<_, _>>()?;

        if !pota_columns.is_empty() && !pota_columns.contains(&"job_id".to_string()) {
            self.conn.execute_batch(
                r#"
                ALTER TABLE pota_upload_status ADD COLUMN job_id INTEGER;
                ALTER TABLE pota_upload_status ADD COLUMN verified_inserted INTEGER;
                ALTER TABLE pota_upload_status ADD COLUMN callsign TEXT;
                "#,
            )?;
        }

        Ok(())
    }

    /// Insert or update a QSO record
    pub fn upsert_qso(&self, qso: &Qso, source_file: Option<&str>) -> Result<i64> {
        self.upsert_qso_with_source(qso, source_file, qso_source::LOCAL, None)
    }

    /// Insert or update a QSO record with source tracking
    pub fn upsert_qso_with_source(
        &self,
        qso: &Qso,
        source_file: Option<&str>,
        source: &str,
        source_id: Option<&str>,
    ) -> Result<i64> {
        let (id, _is_new) =
            self.upsert_qso_with_source_ext(qso, source_file, source, source_id, None)?;
        Ok(id)
    }

    /// Insert or update a QSO record with source tracking and user_id
    pub fn upsert_qso_with_source_for_user(
        &self,
        qso: &Qso,
        source_file: Option<&str>,
        source: &str,
        source_id: Option<&str>,
        user_id: i64,
    ) -> Result<i64> {
        let (id, _is_new) =
            self.upsert_qso_with_source_ext(qso, source_file, source, source_id, Some(user_id))?;
        Ok(id)
    }

    /// Upsert a QSO and return (row_id, is_new)
    pub fn upsert_qso_with_source_ext(
        &self,
        qso: &Qso,
        source_file: Option<&str>,
        source: &str,
        source_id: Option<&str>,
        user_id: Option<i64>,
    ) -> Result<(i64, bool)> {
        let now = Utc::now().to_rfc3339();
        let adif_json = serde_json::to_string(qso).map_err(|e| Error::Other(e.to_string()))?;
        let source_hash = compute_hash(&adif_json);

        // Check if QSO already exists
        let is_new = !self.qso_exists(qso)?;

        // Try to insert, on conflict update
        self.conn.execute(
            r#"
            INSERT INTO qsos (call, qso_date, time_on, band, mode, source_file, source_hash,
                              created_at, updated_at, adif_record, source, source_id, user_id)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10, ?11, ?12)
            ON CONFLICT(call, qso_date, time_on, band, mode) DO UPDATE SET
                source_file = COALESCE(excluded.source_file, source_file),
                source_hash = excluded.source_hash,
                updated_at = excluded.updated_at,
                adif_record = excluded.adif_record,
                source = COALESCE(excluded.source, source),
                source_id = COALESCE(excluded.source_id, source_id),
                user_id = COALESCE(excluded.user_id, user_id)
            "#,
            params![
                qso.call.to_uppercase(),
                qso.qso_date,
                qso.normalized_time(),
                qso.band.to_lowercase(),
                qso.mode.to_uppercase(),
                source_file,
                source_hash,
                now,
                adif_json,
                source,
                source_id,
                user_id,
            ],
        )?;

        Ok((self.conn.last_insert_rowid(), is_new))
    }

    /// Check if a QSO already exists
    pub fn qso_exists(&self, qso: &Qso) -> Result<bool> {
        let count: i64 = self.conn.query_row(
            r#"
            SELECT COUNT(*) FROM qsos
            WHERE call = ?1 AND qso_date = ?2 AND time_on = ?3 AND band = ?4 AND mode = ?5
            "#,
            params![
                qso.call.to_uppercase(),
                qso.qso_date,
                qso.normalized_time(),
                qso.band.to_lowercase(),
                qso.mode.to_uppercase(),
            ],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Get QSOs that haven't been synced to QRZ
    pub fn get_unsynced_qrz(&self) -> Result<Vec<StoredQso>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, call, qso_date, time_on, band, mode, source_file, source_hash,
                   qrz_logid, qrz_synced_at, lotw_qsl_rcvd, lotw_qsl_sent, qsl_rcvd, qsl_sent,
                   pota_synced, created_at, updated_at, adif_record, source, source_id
            FROM qsos
            WHERE qrz_synced_at IS NULL
            ORDER BY qso_date, time_on
            "#,
        )?;

        let qsos = stmt
            .query_map([], |row| {
                Ok(StoredQso {
                    id: row.get(0)?,
                    call: row.get(1)?,
                    qso_date: row.get(2)?,
                    time_on: row.get(3)?,
                    band: row.get(4)?,
                    mode: row.get(5)?,
                    source_file: row.get(6)?,
                    source_hash: row.get(7)?,
                    qrz_logid: row.get(8)?,
                    qrz_synced_at: row.get(9)?,
                    lotw_qsl_rcvd: row.get(10)?,
                    lotw_qsl_sent: row.get(11)?,
                    qsl_rcvd: row.get(12)?,
                    qsl_sent: row.get(13)?,
                    pota_synced: row.get::<_, i64>(14)? != 0,
                    created_at: row.get(15)?,
                    updated_at: row.get(16)?,
                    adif_record: row.get(17)?,
                    source: row.get(18)?,
                    source_id: row.get(19)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(qsos)
    }

    /// Mark a QSO as synced to QRZ
    pub fn mark_qrz_synced(&self, qso_id: i64, qrz_logid: i64) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE qsos SET qrz_logid = ?1, qrz_synced_at = ?2, updated_at = ?2 WHERE id = ?3",
            params![qrz_logid, now, qso_id],
        )?;
        Ok(())
    }

    /// Update confirmation status for a QSO (matched by call, date, time, band, mode)
    #[allow(clippy::too_many_arguments)]
    pub fn update_confirmation(
        &self,
        call: &str,
        qso_date: &str,
        time_on: &str,
        band: &str,
        mode: &str,
        lotw_qsl_rcvd: Option<&str>,
        lotw_qsl_sent: Option<&str>,
        qsl_rcvd: Option<&str>,
        qsl_sent: Option<&str>,
    ) -> Result<bool> {
        let now = Utc::now().to_rfc3339();

        // Extract just HHMM (first 4 chars) for matching
        // QRZ returns 4-digit times but local DB may have 6-digit with seconds
        let time_hhmm = &time_on[..4.min(time_on.len())];

        let rows = self.conn.execute(
            r#"
            UPDATE qsos SET
                lotw_qsl_rcvd = COALESCE(?1, lotw_qsl_rcvd),
                lotw_qsl_sent = COALESCE(?2, lotw_qsl_sent),
                qsl_rcvd = COALESCE(?3, qsl_rcvd),
                qsl_sent = COALESCE(?4, qsl_sent),
                updated_at = ?5
            WHERE call = ?6 AND qso_date = ?7
              AND SUBSTR(time_on, 1, 4) = ?8
              AND band = ?9 AND mode = ?10
            "#,
            params![
                lotw_qsl_rcvd,
                lotw_qsl_sent,
                qsl_rcvd,
                qsl_sent,
                now,
                call.to_uppercase(),
                qso_date,
                time_hhmm,
                band.to_lowercase(),
                mode.to_uppercase(),
            ],
        )?;

        Ok(rows > 0)
    }

    /// Get QSOs that have been confirmed via LotW
    pub fn get_lotw_confirmed(&self) -> Result<Vec<StoredQso>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, call, qso_date, time_on, band, mode, source_file, source_hash,
                   qrz_logid, qrz_synced_at, lotw_qsl_rcvd, lotw_qsl_sent, qsl_rcvd, qsl_sent,
                   pota_synced, created_at, updated_at, adif_record, source, source_id
            FROM qsos
            WHERE lotw_qsl_rcvd = 'Y'
            ORDER BY qso_date DESC, time_on DESC
            "#,
        )?;

        let qsos = stmt
            .query_map([], |row| {
                Ok(StoredQso {
                    id: row.get(0)?,
                    call: row.get(1)?,
                    qso_date: row.get(2)?,
                    time_on: row.get(3)?,
                    band: row.get(4)?,
                    mode: row.get(5)?,
                    source_file: row.get(6)?,
                    source_hash: row.get(7)?,
                    qrz_logid: row.get(8)?,
                    qrz_synced_at: row.get(9)?,
                    lotw_qsl_rcvd: row.get(10)?,
                    lotw_qsl_sent: row.get(11)?,
                    qsl_rcvd: row.get(12)?,
                    qsl_sent: row.get(13)?,
                    pota_synced: row.get::<_, i64>(14)? != 0,
                    created_at: row.get(15)?,
                    updated_at: row.get(16)?,
                    adif_record: row.get(17)?,
                    source: row.get(18)?,
                    source_id: row.get(19)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(qsos)
    }

    /// Record a processed file
    pub fn record_processed_file(&self, path: &str, checksum: &str, qso_count: i64) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            r#"
            INSERT INTO processed_files (path, checksum, processed_at, qso_count)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(path) DO UPDATE SET
                checksum = excluded.checksum,
                processed_at = excluded.processed_at,
                qso_count = excluded.qso_count
            "#,
            params![path, checksum, now, qso_count],
        )?;
        Ok(())
    }

    /// Get the checksum of a previously processed file
    pub fn get_file_checksum(&self, path: &str) -> Result<Option<String>> {
        let checksum = self
            .conn
            .query_row(
                "SELECT checksum FROM processed_files WHERE path = ?1",
                params![path],
                |row| row.get(0),
            )
            .optional()?;
        Ok(checksum)
    }

    /// Get sync state value
    pub fn get_sync_state(&self, key: &str) -> Result<Option<String>> {
        let value = self
            .conn
            .query_row(
                "SELECT value FROM sync_state WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(value)
    }

    /// Set sync state value
    pub fn set_sync_state(&self, key: &str, value: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            r#"
            INSERT INTO sync_state (key, value, updated_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            "#,
            params![key, value, now],
        )?;
        Ok(())
    }

    /// Get Wavelog last fetched ID for incremental sync
    pub fn get_wavelog_last_fetched_id(&self) -> Result<i64> {
        Ok(self
            .get_sync_state("wavelog_last_fetched_id")?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0))
    }

    /// Set Wavelog last fetched ID for incremental sync
    pub fn set_wavelog_last_fetched_id(&self, id: i64) -> Result<()> {
        self.set_sync_state("wavelog_last_fetched_id", &id.to_string())
    }

    /// Get LoFi bearer token
    pub fn get_lofi_bearer_token(&self) -> Result<Option<String>> {
        self.get_sync_state("lofi_bearer_token")
    }

    /// Set LoFi bearer token
    pub fn set_lofi_bearer_token(&self, token: &str) -> Result<()> {
        self.set_sync_state("lofi_bearer_token", token)
    }

    /// Check if LoFi bearer token exists
    pub fn has_lofi_bearer_token(&self) -> Result<bool> {
        Ok(self.get_lofi_bearer_token()?.is_some())
    }

    /// Get LoFi last sync timestamp (unix epoch milliseconds)
    pub fn get_lofi_last_sync_millis(&self) -> Result<i64> {
        Ok(self
            .get_sync_state("lofi_last_sync_millis")?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0))
    }

    /// Set LoFi last sync timestamp (unix epoch milliseconds)
    pub fn set_lofi_last_sync_millis(&self, millis: i64) -> Result<()> {
        self.set_sync_state("lofi_last_sync_millis", &millis.to_string())
    }

    /// Get QSOs by source (for filtering/querying)
    pub fn get_qsos_by_source(&self, source: &str) -> Result<Vec<Qso>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT adif_record FROM qsos
            WHERE source = ?1
            ORDER BY qso_date, time_on
            "#,
        )?;

        let qsos = stmt
            .query_map([source], |row| {
                let json: String = row.get(0)?;
                Ok(json)
            })?
            .filter_map(|r| r.ok())
            .filter_map(|json| serde_json::from_str::<Qso>(&json).ok())
            .collect();

        Ok(qsos)
    }

    /// Count QSOs by source
    pub fn count_qsos_by_source(&self, source: &str) -> Result<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM qsos WHERE source = ?1",
            [source],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Get statistics grouped by source
    pub fn get_source_statistics(&self) -> Result<Vec<(String, i64)>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT COALESCE(source, 'unknown') as src, COUNT(*) as count
            FROM qsos
            GROUP BY src
            ORDER BY count DESC
            "#,
        )?;

        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Get QSO counts for the most recent dates
    pub fn get_recent_date_statistics(&self, limit: usize) -> Result<Vec<(String, i64)>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT qso_date, COUNT(*) as count
            FROM qsos
            GROUP BY qso_date
            ORDER BY qso_date DESC
            LIMIT ?1
            "#,
        )?;

        let rows = stmt.query_map([limit as i64], |row| Ok((row.get(0)?, row.get(1)?)))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Get QSO counts for the most recent dates, grouped by source
    pub fn get_recent_date_statistics_by_source(
        &self,
        source: &str,
        limit: usize,
    ) -> Result<Vec<(String, i64)>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT qso_date, COUNT(*) as count
            FROM qsos
            WHERE source = ?1
            GROUP BY qso_date
            ORDER BY qso_date DESC
            LIMIT ?2
            "#,
        )?;

        let rows = stmt.query_map(params![source, limit as i64], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    /// Get total QSO count
    pub fn get_total_qso_count(&self) -> Result<i64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM qsos", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Insert a new QSO (convenience method)
    pub fn insert_qso(&self, qso: &Qso) -> Result<i64> {
        self.upsert_qso(qso, None)
    }

    /// Insert a new QSO with source tracking (convenience method)
    pub fn insert_qso_with_source(
        &self,
        qso: &Qso,
        source: &str,
        source_id: Option<&str>,
    ) -> Result<i64> {
        self.upsert_qso_with_source(qso, None, source, source_id)
    }

    /// Get all QSOs from the database
    pub fn get_all_qsos(&self) -> Result<Vec<Qso>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT adif_record FROM qsos
            ORDER BY qso_date, time_on
            "#,
        )?;

        let qsos = stmt
            .query_map([], |row| {
                let json: String = row.get(0)?;
                Ok(json)
            })?
            .filter_map(|r| r.ok())
            .filter_map(|json| serde_json::from_str::<Qso>(&json).ok())
            .collect();

        Ok(qsos)
    }

    /// Get POTA-tagged QSOs for a specific station callsign (legacy, no user filtering)
    ///
    /// DEPRECATED: Use get_pota_qsos_for_user instead to ensure proper user isolation.
    pub fn get_pota_qsos_for_callsign(&self, station_callsign: &str) -> Result<Vec<Qso>> {
        let callsign_upper = station_callsign.to_uppercase();
        let mut stmt = self.conn.prepare(
            r#"
            SELECT adif_record FROM qsos
            WHERE (
                UPPER(json_extract(adif_record, '$.MY_SIG')) = 'POTA'
                OR UPPER(json_extract(adif_record, '$.my_sig')) = 'POTA'
            )
            AND COALESCE(
                json_extract(adif_record, '$.MY_SIG_INFO'),
                json_extract(adif_record, '$.my_sig_info')
            ) IS NOT NULL
            AND (
                UPPER(json_extract(adif_record, '$.STATION_CALLSIGN')) = ?1
                OR UPPER(json_extract(adif_record, '$.station_callsign')) = ?1
            )
            ORDER BY qso_date, time_on
            "#,
        )?;

        let qsos = stmt
            .query_map([&callsign_upper], |row| {
                let json: String = row.get(0)?;
                Ok(json)
            })?
            .filter_map(|r| r.ok())
            .filter_map(|json| serde_json::from_str::<Qso>(&json).ok())
            .collect();

        Ok(qsos)
    }

    /// Get POTA-tagged QSOs for a specific user
    ///
    /// This is an optimized query for POTA sync that:
    /// 1. Only loads QSOs where MY_SIG='POTA' (activator QSOs)
    /// 2. Filters by user_id to ensure proper data isolation
    /// 3. Filters by station_callsign as additional verification
    /// 4. Requires valid MY_SIG_INFO (park reference)
    ///
    /// This ensures only the specified user's QSOs are returned.
    pub fn get_pota_qsos_for_user(&self, user_id: i64, station_callsign: &str) -> Result<Vec<Qso>> {
        let callsign_upper = station_callsign.to_uppercase();
        let mut stmt = self.conn.prepare(
            r#"
            SELECT adif_record FROM qsos
            WHERE user_id = ?1
            AND (
                UPPER(json_extract(adif_record, '$.MY_SIG')) = 'POTA'
                OR UPPER(json_extract(adif_record, '$.my_sig')) = 'POTA'
            )
            AND COALESCE(
                json_extract(adif_record, '$.MY_SIG_INFO'),
                json_extract(adif_record, '$.my_sig_info')
            ) IS NOT NULL
            AND (
                UPPER(json_extract(adif_record, '$.STATION_CALLSIGN')) = ?2
                OR UPPER(json_extract(adif_record, '$.station_callsign')) = ?2
            )
            ORDER BY qso_date, time_on
            "#,
        )?;

        let qsos = stmt
            .query_map(params![user_id, &callsign_upper], |row| {
                let json: String = row.get(0)?;
                Ok(json)
            })?
            .filter_map(|r| r.ok())
            .filter_map(|json| serde_json::from_str::<Qso>(&json).ok())
            .collect();

        Ok(qsos)
    }

    /// Get recent QSOs with sync status info
    pub fn get_recent_qsos(&self, limit: usize) -> Result<Vec<StoredQso>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT id, call, qso_date, time_on, band, mode, source_file, source_hash,
                   qrz_logid, qrz_synced_at, lotw_qsl_rcvd, lotw_qsl_sent, qsl_rcvd, qsl_sent,
                   pota_synced, created_at, updated_at, adif_record, source, source_id
            FROM qsos
            ORDER BY qso_date DESC, time_on DESC
            LIMIT ?1
            "#,
        )?;

        let qsos = stmt
            .query_map([limit as i64], |row| {
                Ok(StoredQso {
                    id: row.get(0)?,
                    call: row.get(1)?,
                    qso_date: row.get(2)?,
                    time_on: row.get(3)?,
                    band: row.get(4)?,
                    mode: row.get(5)?,
                    source_file: row.get(6)?,
                    source_hash: row.get(7)?,
                    qrz_logid: row.get(8)?,
                    qrz_synced_at: row.get(9)?,
                    lotw_qsl_rcvd: row.get(10)?,
                    lotw_qsl_sent: row.get(11)?,
                    qsl_rcvd: row.get(12)?,
                    qsl_sent: row.get(13)?,
                    pota_synced: row.get::<_, i64>(14)? != 0,
                    created_at: row.get(15)?,
                    updated_at: row.get(16)?,
                    adif_record: row.get(17)?,
                    source: row.get(18)?,
                    source_id: row.get(19)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(qsos)
    }

    /// Get statistics for status display
    pub fn get_stats(&self) -> Result<DbStats> {
        // Count unique QSOs by dedup key (call + date + HHMM + band + mode)
        // This prevents counting the same QSO from different sources as duplicates
        let total_qsos: i64 = self.conn.query_row(
            r#"
            SELECT COUNT(*) FROM (
                SELECT DISTINCT
                    UPPER(call),
                    qso_date,
                    SUBSTR(time_on, 1, 4),
                    LOWER(band),
                    UPPER(mode)
                FROM qsos
            )
            "#,
            [],
            |row| row.get(0),
        )?;

        let synced_qrz: i64 = self.conn.query_row(
            r#"
            SELECT COUNT(*) FROM (
                SELECT DISTINCT
                    UPPER(call),
                    qso_date,
                    SUBSTR(time_on, 1, 4),
                    LOWER(band),
                    UPPER(mode)
                FROM qsos
                WHERE qrz_synced_at IS NOT NULL
            )
            "#,
            [],
            |row| row.get(0),
        )?;

        let pending_qrz: i64 = self.conn.query_row(
            r#"
            SELECT COUNT(*) FROM (
                SELECT DISTINCT
                    UPPER(call),
                    qso_date,
                    SUBSTR(time_on, 1, 4),
                    LOWER(band),
                    UPPER(mode)
                FROM qsos
                WHERE qrz_synced_at IS NULL
            )
            "#,
            [],
            |row| row.get(0),
        )?;

        let lotw_confirmed: i64 = self.conn.query_row(
            r#"
            SELECT COUNT(*) FROM (
                SELECT DISTINCT
                    UPPER(call),
                    qso_date,
                    SUBSTR(time_on, 1, 4),
                    LOWER(band),
                    UPPER(mode)
                FROM qsos
                WHERE lotw_qsl_rcvd = 'Y'
            )
            "#,
            [],
            |row| row.get(0),
        )?;

        let qsl_confirmed: i64 = self.conn.query_row(
            r#"
            SELECT COUNT(*) FROM (
                SELECT DISTINCT
                    UPPER(call),
                    qso_date,
                    SUBSTR(time_on, 1, 4),
                    LOWER(band),
                    UPPER(mode)
                FROM qsos
                WHERE qsl_rcvd = 'Y'
            )
            "#,
            [],
            |row| row.get(0),
        )?;

        let processed_files: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM processed_files", [], |row| row.get(0))?;

        Ok(DbStats {
            total_qsos,
            synced_qrz,
            pending_qrz,
            lotw_confirmed,
            qsl_confirmed,
            processed_files,
        })
    }

    // === Database Maintenance Methods ===

    /// Deduplicate QSOs by normalizing time_on to HHMMSS and removing duplicates
    /// Keeps the row with the most information (preferring qrz_synced, then most recent)
    fn deduplicate_qsos(&self) -> Result<()> {
        // First, normalize all time_on values to HHMMSS format
        self.conn.execute(
            r#"
            UPDATE qsos
            SET time_on = time_on || '00'
            WHERE LENGTH(time_on) = 4
            "#,
            [],
        )?;

        // Find and remove duplicates, keeping the "best" row:
        // - Prefer rows with qrz_synced_at (already synced to QRZ)
        // - Then prefer rows with lotw_qsl_rcvd = 'Y' (LotW confirmed)
        // - Then prefer the most recently updated row
        let deleted = self.conn.execute(
            r#"
            DELETE FROM qsos WHERE id IN (
                SELECT id FROM (
                    SELECT
                        id,
                        ROW_NUMBER() OVER (
                            PARTITION BY UPPER(call), qso_date, SUBSTR(time_on, 1, 4), LOWER(band), UPPER(mode)
                            ORDER BY
                                (CASE WHEN qrz_synced_at IS NOT NULL THEN 1 ELSE 0 END) DESC,
                                (CASE WHEN lotw_qsl_rcvd = 'Y' THEN 1 ELSE 0 END) DESC,
                                updated_at DESC
                        ) as rn
                    FROM qsos
                ) WHERE rn > 1
            )
            "#,
            [],
        )?;

        if deleted > 0 {
            tracing::info!(deleted_count = deleted, "Deduplicated QSOs in database");
        }

        Ok(())
    }

    /// Compact the database (VACUUM)
    pub fn vacuum(&self) -> Result<()> {
        self.conn.execute("VACUUM", [])?;
        Ok(())
    }

    /// Analyze and optimize query performance
    pub fn analyze(&self) -> Result<()> {
        self.conn.execute("ANALYZE", [])?;
        Ok(())
    }

    /// Get database file size in bytes
    pub fn file_size(&self) -> Result<u64> {
        let size: i64 = self.conn.query_row(
            "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()",
            [],
            |row| row.get(0),
        )?;
        Ok(size as u64)
    }

    /// Get database integrity check result
    pub fn integrity_check(&self) -> Result<String> {
        let result: String = self
            .conn
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        Ok(result)
    }

    /// Get freelist count (unused pages)
    pub fn freelist_count(&self) -> Result<i64> {
        let count: i64 = self
            .conn
            .query_row("PRAGMA freelist_count", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Get detailed database info
    pub fn detailed_info(&self) -> Result<DbInfo> {
        let page_count: i64 = self
            .conn
            .query_row("PRAGMA page_count", [], |row| row.get(0))?;
        let page_size: i64 = self
            .conn
            .query_row("PRAGMA page_size", [], |row| row.get(0))?;
        let freelist_count: i64 = self
            .conn
            .query_row("PRAGMA freelist_count", [], |row| row.get(0))?;
        let schema_version: i64 = self
            .conn
            .query_row("PRAGMA schema_version", [], |row| row.get(0))?;
        let user_version: i64 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let journal_mode: String = self
            .conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))?;

        let total_size = page_count * page_size;
        let wasted_space = freelist_count * page_size;

        Ok(DbInfo {
            page_count,
            page_size,
            freelist_count,
            total_size,
            wasted_space,
            schema_version,
            user_version,
            journal_mode,
        })
    }

    // === POTA Database Operations ===

    /// Insert or update a POTA activation
    /// Returns true if this is a new activation (not previously seen)
    pub fn upsert_pota_activation(
        &self,
        activation: &crate::pota::PotaRemoteActivation,
    ) -> Result<bool> {
        let existing: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM pota_activations WHERE callsign = ?1 AND date = ?2 AND reference = ?3",
            params![&activation.callsign, &activation.date, &activation.reference],
            |row| row.get(0),
        )?;

        let is_new = existing == 0;

        self.conn.execute(
            r#"
            INSERT INTO pota_activations (
                callsign, date, reference, name, parktype_desc, location_desc,
                first_qso, last_qso, total, cw, data, phone
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            ON CONFLICT(callsign, date, reference) DO UPDATE SET
                name = excluded.name,
                parktype_desc = excluded.parktype_desc,
                location_desc = excluded.location_desc,
                first_qso = excluded.first_qso,
                last_qso = excluded.last_qso,
                total = excluded.total,
                cw = excluded.cw,
                data = excluded.data,
                phone = excluded.phone,
                last_updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            "#,
            params![
                &activation.callsign,
                &activation.date,
                &activation.reference,
                &activation.name,
                &activation.parktype_desc,
                &activation.location_desc,
                &activation.first_qso,
                &activation.last_qso,
                activation.total,
                activation.cw,
                activation.data,
                activation.phone,
            ],
        )?;

        Ok(is_new)
    }

    /// Insert or update a POTA QSO from the remote API
    /// Returns true if this is a new QSO (not previously seen)
    pub fn upsert_pota_qso(&self, qso: &crate::pota::PotaRemoteQso) -> Result<bool> {
        let existing: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM pota_qsos WHERE qso_id = ?1",
            params![qso.qso_id],
            |row| row.get(0),
        )?;

        let is_new = existing == 0;

        self.conn.execute(
            r#"
            INSERT INTO pota_qsos (
                qso_id, user_id, qso_datetime, station_callsign, operator_callsign,
                worked_callsign, band, mode, rst_sent, rst_rcvd, my_sig, my_sig_info,
                p2p_match, job_id, park_id, reference, park_name, parktype_desc,
                location_id, location_desc, location_name, sig, sig_info, logged_mode
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)
            ON CONFLICT(qso_id) DO UPDATE SET
                qso_datetime = excluded.qso_datetime,
                station_callsign = excluded.station_callsign,
                operator_callsign = excluded.operator_callsign,
                worked_callsign = excluded.worked_callsign,
                band = excluded.band,
                mode = excluded.mode,
                rst_sent = excluded.rst_sent,
                rst_rcvd = excluded.rst_rcvd,
                my_sig = excluded.my_sig,
                my_sig_info = excluded.my_sig_info,
                p2p_match = excluded.p2p_match,
                job_id = excluded.job_id,
                park_id = excluded.park_id,
                reference = excluded.reference,
                park_name = excluded.park_name,
                parktype_desc = excluded.parktype_desc,
                location_id = excluded.location_id,
                location_desc = excluded.location_desc,
                location_name = excluded.location_name,
                sig = excluded.sig,
                sig_info = excluded.sig_info,
                logged_mode = excluded.logged_mode,
                last_updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            "#,
            params![
                qso.qso_id,
                qso.user_id,
                &qso.qso_date_time,
                &qso.station_callsign,
                &qso.operator_callsign,
                &qso.worked_callsign,
                &qso.band,
                &qso.mode,
                &qso.rst_sent,
                &qso.rst_rcvd,
                &qso.my_sig,
                &qso.my_sig_info,
                &qso.p2p_match,
                qso.job_id,
                qso.park_id,
                &qso.reference,
                &qso.name,
                &qso.parktype_desc,
                qso.location_id,
                &qso.location_desc,
                &qso.location_name,
                &qso.sig,
                &qso.sig_info,
                &qso.logged_mode,
            ],
        )?;

        // Also insert into the main qsos table for unified QSO handling
        if let Some(adif_qso) = qso.to_qso() {
            let _ = self.upsert_qso_with_source(
                &adif_qso,
                None,
                qso_source::POTA,
                Some(&qso.qso_id.to_string()),
            );
        }

        Ok(is_new)
    }

    /// Get total count of POTA activations
    pub fn get_pota_activation_count(&self) -> Result<i64> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM pota_activations", [], |row| {
                    row.get(0)
                })?;
        Ok(count)
    }

    /// Get total count of POTA QSOs
    pub fn get_pota_qso_count(&self) -> Result<i64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM pota_qsos", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Get POTA statistics with download/upload/pending breakdown
    pub fn get_pota_stats(&self) -> Result<PotaStats> {
        // === Download stats (from POTA.app - stored in pota_activations/pota_qsos tables) ===
        let download_parks: i64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT reference) FROM pota_activations",
            [],
            |row| row.get(0),
        )?;

        let download_activations: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM pota_activations WHERE total >= 10",
            [],
            |row| row.get(0),
        )?;

        let download_partial_activations: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM pota_activations WHERE total < 10",
            [],
            |row| row.get(0),
        )?;

        let download_qsos: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM pota_qsos", [], |row| row.get(0))?;

        tracing::debug!(
            download_parks,
            download_activations,
            download_partial_activations,
            download_qsos,
            "POTA download stats from database"
        );

        // === Local POTA activations (from qsos table with MY_SIG=POTA) ===
        // Get unique (park_ref, date) combinations from local POTA QSOs
        // Note: my_sig and my_sig_info are stored in adif_record JSON, not as columns
        let local_activations: Vec<(String, String, i64)> = {
            let mut stmt = self.conn.prepare(
                r#"
                SELECT
                    UPPER(COALESCE(
                        json_extract(adif_record, '$.MY_SIG_INFO'),
                        json_extract(adif_record, '$.my_sig_info')
                    )) as park_ref,
                    qso_date,
                    COUNT(*) as qso_count
                FROM qsos
                WHERE (
                    UPPER(json_extract(adif_record, '$.MY_SIG')) = 'POTA'
                    OR UPPER(json_extract(adif_record, '$.my_sig')) = 'POTA'
                )
                AND COALESCE(
                    json_extract(adif_record, '$.MY_SIG_INFO'),
                    json_extract(adif_record, '$.my_sig_info')
                ) IS NOT NULL
                GROUP BY park_ref, qso_date
                "#,
            )?;

            stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect()
        };

        // For each local activation, count how many QSOs are already on POTA.app
        let mut uploaded_parks_set = std::collections::HashSet::new();
        let mut pending_parks_set = std::collections::HashSet::new();
        let mut uploaded_activations: i64 = 0;
        let mut uploaded_partial_activations: i64 = 0;
        let mut pending_activations: i64 = 0;
        let mut pending_partial_activations: i64 = 0;
        let mut uploaded_qsos: i64 = 0;
        let mut pending_qsos: i64 = 0;

        for (park_ref, date, local_qso_count) in &local_activations {
            let uploaded_count = self.count_pota_uploaded_qsos(park_ref, date).unwrap_or(0);
            // Ensure pending_count is never negative (can happen if POTA.app has more QSOs
            // than local, e.g., if QSOs were deleted locally or added directly on POTA.app)
            let pending_count = (*local_qso_count - uploaded_count).max(0);
            // Use the minimum of local_qso_count and uploaded_count for uploaded stats
            // to avoid over-counting if remote has more than local
            let actual_uploaded = uploaded_count.min(*local_qso_count);

            // Track uploaded QSOs
            uploaded_qsos += actual_uploaded;
            pending_qsos += pending_count;

            // Track parks
            if uploaded_count > 0 {
                uploaded_parks_set.insert(park_ref.clone());
            }
            if pending_count > 0 {
                pending_parks_set.insert(park_ref.clone());
            }

            // Track activations
            // An activation is considered uploaded if ALL its QSOs are on POTA.app
            // An activation is pending if it has ANY QSOs not yet on POTA.app
            let is_valid = *local_qso_count >= 10;

            if pending_count == 0 && uploaded_count > 0 {
                // All QSOs uploaded
                if is_valid {
                    uploaded_activations += 1;
                } else {
                    uploaded_partial_activations += 1;
                }
            } else if pending_count > 0 {
                // Has pending QSOs
                if is_valid {
                    pending_activations += 1;
                } else {
                    pending_partial_activations += 1;
                }
            }
        }

        Ok(PotaStats {
            download_parks,
            download_activations,
            download_partial_activations,
            download_qsos,
            uploaded_parks: uploaded_parks_set.len() as i64,
            uploaded_activations,
            uploaded_partial_activations,
            uploaded_qsos,
            pending_parks: pending_parks_set.len() as i64,
            pending_activations,
            pending_partial_activations,
            pending_qsos,
        })
    }

    /// Get POTA last sync timestamp
    pub fn get_pota_last_sync(&self) -> Result<Option<String>> {
        self.get_sync_state("pota_last_sync")
    }

    /// Set POTA last sync timestamp
    pub fn set_pota_last_sync(&self, timestamp: &str) -> Result<()> {
        self.set_sync_state("pota_last_sync", timestamp)
    }

    /// Get comprehensive sync statistics showing downloaded/uploaded/pending counts
    pub fn get_sync_stats(&self) -> Result<SyncStats> {
        // Total unique QSOs (deduplicated by call, date, time HHMM, band, mode)
        let total_unique_qsos: i64 = self.conn.query_row(
            r#"
            SELECT COUNT(*) FROM (
                SELECT DISTINCT
                    UPPER(call),
                    qso_date,
                    SUBSTR(time_on, 1, 4),
                    LOWER(band),
                    UPPER(mode)
                FROM qsos
            )
            "#,
            [],
            |row| row.get(0),
        )?;

        // Count QSOs by source (these are unique QSOs per source, not total rows)
        let count_by_source = |source: &str| -> Result<i64> {
            Ok(self.conn.query_row(
                r#"
                SELECT COUNT(*) FROM (
                    SELECT DISTINCT
                        UPPER(call),
                        qso_date,
                        SUBSTR(time_on, 1, 4),
                        LOWER(band),
                        UPPER(mode)
                    FROM qsos
                    WHERE source = ?1
                )
                "#,
                [source],
                |row| row.get(0),
            )?)
        };

        // For POTA, count directly from pota_qsos table since those may not be in the main qsos table
        let pota_downloaded: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM pota_qsos", [], |row| row.get(0))?;

        // For LoFi, count directly from lofi_qsos table
        let lofi_downloaded: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM lofi_qsos WHERE deleted = 0",
            [],
            |row| row.get(0),
        )?;

        let downloaded = SourceCounts {
            local: count_by_source(qso_source::LOCAL)?,
            qrz: count_by_source(qso_source::QRZ)?,
            lofi: lofi_downloaded,
            pota: pota_downloaded,
            wavelog: count_by_source(qso_source::WAVELOG)?,
            lotw: count_by_source(qso_source::LOTW)?,
        };

        // Uploaded to QRZ (has qrz_synced_at)
        let uploaded_qrz: i64 = self.conn.query_row(
            r#"
            SELECT COUNT(*) FROM (
                SELECT DISTINCT
                    UPPER(call),
                    qso_date,
                    SUBSTR(time_on, 1, 4),
                    LOWER(band),
                    UPPER(mode)
                FROM qsos
                WHERE qrz_synced_at IS NOT NULL
            )
            "#,
            [],
            |row| row.get(0),
        )?;

        // Uploaded to POTA (has pota_synced = 1)
        let uploaded_pota: i64 = self.conn.query_row(
            r#"
            SELECT COUNT(*) FROM (
                SELECT DISTINCT
                    UPPER(call),
                    qso_date,
                    SUBSTR(time_on, 1, 4),
                    LOWER(band),
                    UPPER(mode)
                FROM qsos
                WHERE pota_synced = 1
            )
            "#,
            [],
            |row| row.get(0),
        )?;

        let uploaded = UploadCounts {
            qrz: uploaded_qrz,
            pota: uploaded_pota,
        };

        // Pending = total - uploaded
        let pending = PendingCounts {
            qrz: total_unique_qsos - uploaded_qrz,
            pota: self.count_pending_pota_qsos()?,
        };

        Ok(SyncStats {
            total_unique_qsos,
            downloaded,
            uploaded,
            pending,
        })
    }

    /// Count POTA QSOs that are pending upload (have my_sig=POTA but not in pota_qsos table)
    fn count_pending_pota_qsos(&self) -> Result<i64> {
        // Count QSOs that:
        // 1. Have my_sig='POTA' (they're POTA activations)
        // 2. Are NOT already in pota_qsos table (not yet on POTA.app)
        let count: i64 = self.conn.query_row(
            r#"
            SELECT COUNT(*) FROM qsos q
            WHERE (
                json_extract(q.adif_record, '$.my_sig') = 'POTA'
                OR json_extract(q.adif_record, '$.MY_SIG') = 'POTA'
            )
            AND NOT EXISTS (
                SELECT 1 FROM pota_qsos p
                WHERE UPPER(q.call) = UPPER(p.worked_callsign)
                  AND q.qso_date = REPLACE(SUBSTR(p.qso_datetime, 1, 10), '-', '')
                  AND SUBSTR(q.time_on, 1, 4) = REPLACE(SUBSTR(p.qso_datetime, 12, 5), ':', '')
            )
            "#,
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Check if a specific activation (park_ref + date) has QSOs already on POTA.app
    /// Returns the count of QSOs already uploaded for this activation
    pub fn count_pota_uploaded_qsos(&self, park_ref: &str, date: &str) -> Result<i64> {
        // Date in qsos table is YYYYMMDD, in pota_qsos it's YYYY-MM-DD
        let formatted_date = if date.len() == 8 && !date.contains('-') {
            format!("{}-{}-{}", &date[0..4], &date[4..6], &date[6..8])
        } else {
            date.to_string()
        };

        let count: i64 = self.conn.query_row(
            r#"
            SELECT COUNT(*) FROM pota_qsos
            WHERE reference = ?1
              AND DATE(qso_datetime) = ?2
            "#,
            params![park_ref, formatted_date],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Check which QSOs in an activation are already on POTA.app
    /// Returns a set of (call, time_hhmm) pairs that are already uploaded
    pub fn get_pota_uploaded_qso_keys(
        &self,
        park_ref: &str,
        date: &str,
    ) -> Result<std::collections::HashSet<(String, String)>> {
        use std::collections::HashSet;

        // Date in qsos table is YYYYMMDD, in pota_qsos it's YYYY-MM-DD
        let formatted_date = if date.len() == 8 && !date.contains('-') {
            format!("{}-{}-{}", &date[0..4], &date[4..6], &date[6..8])
        } else {
            date.to_string()
        };

        let mut stmt = self.conn.prepare(
            r#"
            SELECT UPPER(worked_callsign), REPLACE(SUBSTR(qso_datetime, 12, 5), ':', '')
            FROM pota_qsos
            WHERE reference = ?1
              AND DATE(qso_datetime) = ?2
            "#,
        )?;

        let rows = stmt.query_map(params![park_ref, formatted_date], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut keys = HashSet::new();
        for (call, time) in rows.flatten() {
            keys.insert((call, time));
        }
        Ok(keys)
    }

    /// Get ALL uploaded QSO keys from POTA.app in a single query
    /// Returns a HashMap keyed by (park_ref, date) containing sets of (call, time_hhmm) pairs
    /// This avoids the N+1 query pattern when checking multiple activations
    #[allow(clippy::type_complexity)]
    pub fn get_all_pota_uploaded_qso_keys(
        &self,
    ) -> Result<HashMap<(String, String), Vec<(String, String)>>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT
                reference,
                DATE(qso_datetime) as qso_date,
                UPPER(worked_callsign),
                REPLACE(SUBSTR(qso_datetime, 12, 5), ':', '')
            FROM pota_qsos
            ORDER BY reference, qso_date
            "#,
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?, // reference
                row.get::<_, String>(1)?, // date (YYYY-MM-DD)
                row.get::<_, String>(2)?, // call (uppercased)
                row.get::<_, String>(3)?, // time (HHMM)
            ))
        })?;

        let mut result: HashMap<(String, String), Vec<(String, String)>> = HashMap::new();
        for row in rows.flatten() {
            let (reference, date_str, call, time) = row;
            // Convert date from YYYY-MM-DD to YYYYMMDD to match activation.date format
            let date_yyyymmdd = date_str.replace('-', "");
            let key = (reference, date_yyyymmdd);
            result.entry(key).or_default().push((call, time));
        }
        Ok(result)
    }

    // === POTA Upload Status Tracking ===

    /// Try to start a POTA upload for an activation.
    /// Returns Ok(true) if we successfully claimed the upload (no one else is uploading).
    /// Returns Ok(false) if another process is already uploading this activation.
    /// This uses INSERT OR IGNORE to atomically claim the upload.
    pub fn try_start_pota_upload(
        &self,
        user_id: i64,
        park_ref: &str,
        date: &str,
        qso_count: i64,
        callsign: &str,
    ) -> Result<bool> {
        // First, check if there's already an upload in progress or completed recently
        let existing: Option<(String, String)> = self
            .conn
            .query_row(
                r#"
                SELECT status, started_at FROM pota_upload_status
                WHERE user_id = ?1 AND park_ref = ?2 AND date = ?3
                "#,
                params![user_id, park_ref, date],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        if let Some((status, started_at)) = existing {
            match status.as_str() {
                "uploading" | "pending_verification" => {
                    // Check if it's stale (started more than 10 minutes ago)
                    if let Ok(started) = chrono::DateTime::parse_from_rfc3339(&started_at) {
                        let age = Utc::now().signed_duration_since(started.with_timezone(&Utc));
                        if age.num_minutes() < 10 {
                            // Recent upload in progress, don't start another
                            return Ok(false);
                        }
                        // Stale upload, we'll replace it below
                    }
                }
                "uploaded" => {
                    // Already uploaded, don't upload again
                    return Ok(false);
                }
                "failed" => {
                    // Previous attempt failed, we'll retry below
                }
                _ => {}
            }
        }

        // Insert or replace the status
        self.conn.execute(
            r#"
            INSERT INTO pota_upload_status (user_id, park_ref, date, status, qso_count, started_at, completed_at, error_message, callsign)
            VALUES (?1, ?2, ?3, 'uploading', ?4, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), NULL, NULL, ?5)
            ON CONFLICT(user_id, park_ref, date) DO UPDATE SET
                status = 'uploading',
                qso_count = excluded.qso_count,
                started_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                completed_at = NULL,
                error_message = NULL,
                callsign = excluded.callsign,
                job_id = NULL,
                verified_inserted = NULL
            "#,
            params![user_id, park_ref, date, qso_count, callsign],
        )?;

        Ok(true)
    }

    /// Mark a POTA upload as completed successfully
    pub fn mark_pota_upload_completed(
        &self,
        user_id: i64,
        park_ref: &str,
        date: &str,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            UPDATE pota_upload_status
            SET status = 'uploaded',
                completed_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            WHERE user_id = ?1 AND park_ref = ?2 AND date = ?3
            "#,
            params![user_id, park_ref, date],
        )?;
        Ok(())
    }

    /// Mark a POTA upload as failed
    pub fn mark_pota_upload_failed(
        &self,
        user_id: i64,
        park_ref: &str,
        date: &str,
        error: &str,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            UPDATE pota_upload_status
            SET status = 'failed',
                completed_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                error_message = ?4
            WHERE user_id = ?1 AND park_ref = ?2 AND date = ?3
            "#,
            params![user_id, park_ref, date, error],
        )?;
        Ok(())
    }

    /// Check if a POTA activation is currently being uploaded or was recently uploaded
    /// Returns the status if found: "uploading", "uploaded", or "failed"
    pub fn get_pota_upload_status(
        &self,
        user_id: i64,
        park_ref: &str,
        date: &str,
    ) -> Result<Option<String>> {
        let status: Option<String> = self
            .conn
            .query_row(
                "SELECT status FROM pota_upload_status WHERE user_id = ?1 AND park_ref = ?2 AND date = ?3",
                params![user_id, park_ref, date],
                |row| row.get(0),
            )
            .optional()?;
        Ok(status)
    }

    /// Clear stale "uploading" statuses (older than 10 minutes)
    /// This handles cases where an upload process crashed
    pub fn clear_stale_pota_uploads(&self) -> Result<i64> {
        let affected = self.conn.execute(
            r#"
            DELETE FROM pota_upload_status
            WHERE status = 'uploading'
              AND datetime(started_at) < datetime('now', '-10 minutes')
            "#,
            [],
        )?;
        Ok(affected as i64)
    }

    /// Mark a POTA upload as pending verification (file accepted, awaiting job completion)
    pub fn mark_pota_upload_pending_verification(
        &self,
        user_id: i64,
        park_ref: &str,
        date: &str,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            UPDATE pota_upload_status
            SET status = 'pending_verification'
            WHERE user_id = ?1 AND park_ref = ?2 AND date = ?3
            "#,
            params![user_id, park_ref, date],
        )?;
        Ok(())
    }

    /// Mark a POTA upload as verified with job details
    pub fn mark_pota_upload_verified(
        &self,
        user_id: i64,
        park_ref: &str,
        date: &str,
        job_id: u64,
        verified_inserted: u32,
    ) -> Result<()> {
        self.conn.execute(
            r#"
            UPDATE pota_upload_status
            SET status = 'uploaded',
                completed_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                job_id = ?4,
                verified_inserted = ?5
            WHERE user_id = ?1 AND park_ref = ?2 AND date = ?3
            "#,
            params![user_id, park_ref, date, job_id, verified_inserted],
        )?;
        Ok(())
    }

    /// Get pending POTA verifications for a user (uploads awaiting job confirmation)
    /// Returns list of (park_ref, date, callsign, started_at)
    pub fn get_pending_pota_verifications(
        &self,
        user_id: i64,
    ) -> Result<Vec<(String, String, String, String)>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT park_ref, date, callsign, started_at
            FROM pota_upload_status
            WHERE user_id = ?1
              AND status = 'pending_verification'
              AND datetime(started_at) > datetime('now', '-1 hour')
            ORDER BY started_at DESC
            "#,
        )?;

        let results = stmt
            .query_map(params![user_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(results)
    }

    /// Get all users with pending POTA verifications
    pub fn get_users_with_pending_pota_verifications(&self) -> Result<Vec<i64>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT DISTINCT user_id
            FROM pota_upload_status
            WHERE status = 'pending_verification'
              AND datetime(started_at) > datetime('now', '-1 hour')
            "#,
        )?;

        let results = stmt
            .query_map([], |row| row.get(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(results)
    }

    /// Mark stale pending verifications as failed (older than 1 hour)
    pub fn fail_stale_pota_verifications(&self) -> Result<i64> {
        let affected = self.conn.execute(
            r#"
            UPDATE pota_upload_status
            SET status = 'failed',
                completed_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                error_message = 'Verification timed out after 1 hour'
            WHERE status = 'pending_verification'
              AND datetime(started_at) < datetime('now', '-1 hour')
            "#,
            [],
        )?;
        Ok(affected as i64)
    }

    // === LoFi Database Operations ===

    /// Insert or update a LoFi operation
    /// Returns true if this is a new operation (not previously seen)
    pub fn upsert_lofi_operation(&self, op: &crate::lofi::LofiOperation) -> Result<bool> {
        let existing: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM lofi_operations WHERE lofi_uuid = ?1",
            params![&op.uuid],
            |row| row.get(0),
        )?;

        let is_new = existing == 0;
        let raw_json = serde_json::to_string(op).map_err(|e| Error::Other(e.to_string()))?;

        // Upsert the operation
        self.conn.execute(
            r#"
            INSERT INTO lofi_operations (
                lofi_uuid, account_uuid, created_at_millis, updated_at_millis,
                synced_at_millis, created_on_device_id, updated_on_device_id,
                station_call, title, subtitle, grid, qso_count,
                start_at_millis_min, start_at_millis_max, deleted, synced, raw_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
            ON CONFLICT(lofi_uuid) DO UPDATE SET
                updated_at_millis = excluded.updated_at_millis,
                synced_at_millis = excluded.synced_at_millis,
                updated_on_device_id = excluded.updated_on_device_id,
                title = excluded.title,
                subtitle = excluded.subtitle,
                grid = excluded.grid,
                qso_count = excluded.qso_count,
                start_at_millis_min = excluded.start_at_millis_min,
                start_at_millis_max = excluded.start_at_millis_max,
                deleted = excluded.deleted,
                synced = excluded.synced,
                raw_json = excluded.raw_json,
                last_updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            "#,
            params![
                &op.uuid,
                &op.account,
                op.created_at_millis,
                op.updated_at_millis,
                op.synced_at_millis,
                &op.created_on_device_id,
                &op.updated_on_device_id,
                &op.station_call,
                &op.title,
                &op.subtitle,
                &op.grid,
                op.qso_count,
                op.start_at_millis_min,
                op.start_at_millis_max,
                op.deleted,
                op.synced,
                &raw_json,
            ],
        )?;

        // Delete existing refs and insert new ones
        self.conn.execute(
            "DELETE FROM lofi_operation_refs WHERE operation_uuid = ?1",
            params![&op.uuid],
        )?;

        for ref_item in &op.refs {
            // Skip refs with empty or missing reference codes (e.g., placeholder refs from LoFi)
            let Some(reference) = ref_item.reference.as_ref().filter(|s| !s.is_empty()) else {
                continue;
            };
            self.conn.execute(
                r#"
                INSERT INTO lofi_operation_refs (
                    operation_uuid, ref_type, reference, program, name,
                    location, label, short_label
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
                params![
                    &op.uuid,
                    &ref_item.ref_type,
                    reference,
                    &ref_item.program,
                    &ref_item.name,
                    &ref_item.location,
                    &ref_item.label,
                    &ref_item.short_label,
                ],
            )?;
        }

        Ok(is_new)
    }

    /// Get all LoFi operations from the database
    pub fn get_lofi_operations(&self) -> Result<Vec<crate::lofi::LofiOperation>> {
        let mut stmt = self
            .conn
            .prepare("SELECT raw_json FROM lofi_operations ORDER BY updated_at_millis DESC")?;

        let operations = stmt
            .query_map([], |row| {
                let json: String = row.get(0)?;
                Ok(json)
            })?
            .filter_map(|r| r.ok())
            .filter_map(|json| serde_json::from_str(&json).ok())
            .collect();

        Ok(operations)
    }

    /// Get operation refs for a given operation UUID
    pub fn get_lofi_operation_refs(
        &self,
        operation_uuid: &str,
    ) -> Result<Vec<crate::lofi::OperationRef>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT ref_type, reference, program, name, location, label, short_label
            FROM lofi_operation_refs
            WHERE operation_uuid = ?1
            "#,
        )?;

        let refs = stmt
            .query_map(params![operation_uuid], |row| {
                Ok(crate::lofi::OperationRef {
                    ref_type: row.get(0)?,
                    reference: Some(row.get(1)?),
                    program: row.get(2)?,
                    name: row.get(3)?,
                    location: row.get(4)?,
                    label: row.get(5)?,
                    short_label: row.get(6)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(refs)
    }

    /// Insert or update a LoFi QSO
    /// Returns true if this is a new QSO (not previously seen)
    /// `account_override` can be used to provide the account UUID from the operation
    /// when the QSO itself doesn't include it (per-operation endpoint)
    /// `user_id` is used to associate the QSO with the correct user for data isolation
    pub fn upsert_lofi_qso(
        &self,
        qso: &crate::lofi::LofiQso,
        account_override: Option<&str>,
        user_id: i64,
    ) -> Result<bool> {
        let existing: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM lofi_qsos WHERE lofi_uuid = ?1",
            params![&qso.uuid],
            |row| row.get(0),
        )?;

        let is_new = existing == 0;
        let raw_json = serde_json::to_string(qso).map_err(|e| Error::Other(e.to_string()))?;

        // Use account from QSO if present, otherwise use override
        let account = qso
            .account
            .as_deref()
            .or(account_override)
            .unwrap_or("unknown");

        self.conn.execute(
            r#"
            INSERT INTO lofi_qsos (
                lofi_uuid, account_uuid, operation_uuid, created_at_millis,
                updated_at_millis, synced_at_millis, start_at_millis,
                their_call, our_call, band, freq, mode, rst_sent, rst_rcvd,
                our_grid, their_grid, their_name, their_qth, their_state,
                their_country, their_cq_zone, their_itu_zone, tx_pwr, notes,
                deleted, raw_json, is_new
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27)
            ON CONFLICT(lofi_uuid) DO UPDATE SET
                updated_at_millis = excluded.updated_at_millis,
                synced_at_millis = excluded.synced_at_millis,
                their_call = excluded.their_call,
                our_call = excluded.our_call,
                band = excluded.band,
                freq = excluded.freq,
                mode = excluded.mode,
                rst_sent = excluded.rst_sent,
                rst_rcvd = excluded.rst_rcvd,
                our_grid = excluded.our_grid,
                their_grid = excluded.their_grid,
                their_name = excluded.their_name,
                their_qth = excluded.their_qth,
                their_state = excluded.their_state,
                their_country = excluded.their_country,
                their_cq_zone = excluded.their_cq_zone,
                their_itu_zone = excluded.their_itu_zone,
                tx_pwr = excluded.tx_pwr,
                notes = excluded.notes,
                deleted = excluded.deleted,
                raw_json = excluded.raw_json,
                last_updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            "#,
            params![
                &qso.uuid,
                account,
                &qso.operation,
                qso.created_at_millis,
                qso.updated_at_millis,
                qso.synced_at_millis,
                qso.start_at_millis,
                qso.their_call(),
                qso.our_call(),
                &qso.band,
                qso.freq,
                &qso.mode,
                qso.rst_sent(),
                qso.rst_rcvd(),
                None::<String>, // our_grid - not in new API
                qso.their_grid(),
                qso.their_name(),
                None::<String>, // their_qth - not in new API
                qso.their_state(),
                qso.their_country(),
                qso.their
                    .as_ref()
                    .and_then(|t| t.guess.as_ref())
                    .and_then(|g| g.cq_zone),
                qso.their
                    .as_ref()
                    .and_then(|t| t.guess.as_ref())
                    .and_then(|g| g.itu_zone),
                &qso.tx_pwr,
                &qso.notes,
                qso.deleted,
                &raw_json,
                is_new,
            ],
        )?;

        // Delete existing refs and insert new ones
        self.conn.execute(
            "DELETE FROM lofi_qso_refs WHERE qso_uuid = ?1",
            params![&qso.uuid],
        )?;

        for ref_item in &qso.refs {
            // Only insert refs that have both type and reference
            if ref_item.ref_type.is_some() && ref_item.reference.is_some() {
                self.conn.execute(
                    r#"
                    INSERT INTO lofi_qso_refs (qso_uuid, ref_type, reference, program)
                    VALUES (?1, ?2, ?3, ?4)
                    "#,
                    params![
                        &qso.uuid,
                        &ref_item.ref_type,
                        &ref_item.reference,
                        &ref_item.program,
                    ],
                )?;
            }
        }

        // Also insert into the main qsos table for unified QSO handling
        // Get operation refs and grid to populate POTA fields
        let (operation_refs, operation_grid) = if let Some(op_uuid) = &qso.operation {
            let refs = self.get_lofi_operation_refs(op_uuid).unwrap_or_default();
            // Get operation grid from database
            let grid: Option<String> = self
                .conn
                .query_row(
                    "SELECT grid FROM lofi_operations WHERE lofi_uuid = ?1",
                    params![op_uuid],
                    |row| row.get(0),
                )
                .ok()
                .flatten();
            (refs, grid)
        } else {
            (vec![], None)
        };

        // Convert LoFi QSO to ADIF QSO and insert into main table
        if let Some(adif_qso) = qso.to_qso(&operation_refs, operation_grid.as_deref()) {
            // Use source="lofi" and source_id=uuid for tracking, with user_id for isolation
            let _ = self.upsert_qso_with_source_for_user(
                &adif_qso,
                None, // no source file
                qso_source::LOFI,
                Some(&qso.uuid),
                user_id,
            );
        }

        Ok(is_new)
    }

    /// Get new LoFi QSOs that haven't been notified yet, then mark them as notified
    pub fn get_and_mark_new_lofi_qsos(&self) -> Result<Vec<crate::lofi::LofiQso>> {
        // Fetch the raw JSON and parse it back
        let mut stmt = self.conn.prepare(
            "SELECT raw_json FROM lofi_qsos WHERE is_new = 1 AND deleted = 0 ORDER BY start_at_millis",
        )?;

        let qsos: Vec<crate::lofi::LofiQso> = stmt
            .query_map([], |row| {
                let json: String = row.get(0)?;
                Ok(json)
            })?
            .filter_map(|r| r.ok())
            .filter_map(|json| serde_json::from_str(&json).ok())
            .collect();

        self.conn
            .execute("UPDATE lofi_qsos SET is_new = 0 WHERE is_new = 1", [])?;

        Ok(qsos)
    }

    /// Get total count of LoFi operations
    pub fn get_lofi_operation_count(&self) -> Result<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM lofi_operations WHERE deleted = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Get total count of LoFi QSOs
    pub fn get_lofi_qso_count(&self) -> Result<i64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM lofi_qsos WHERE deleted = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Get LoFi statistics
    pub fn get_lofi_stats(&self) -> Result<LofiStats> {
        let operations: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM lofi_operations WHERE deleted = 0",
            [],
            |row| row.get(0),
        )?;

        let qsos: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM lofi_qsos WHERE deleted = 0",
            [],
            |row| row.get(0),
        )?;

        let pota_operations: i64 = self.conn.query_row(
            r#"
            SELECT COUNT(DISTINCT o.lofi_uuid)
            FROM lofi_operations o
            INNER JOIN lofi_operation_refs r ON o.lofi_uuid = r.operation_uuid
            WHERE r.program = 'POTA' AND o.deleted = 0
            "#,
            [],
            |row| row.get(0),
        )?;

        Ok(LofiStats {
            operations,
            qsos,
            pota_operations,
        })
    }
}

/// Detailed database information
#[derive(Debug)]
pub struct DbInfo {
    pub page_count: i64,
    pub page_size: i64,
    pub freelist_count: i64,
    pub total_size: i64,
    pub wasted_space: i64,
    pub schema_version: i64,
    pub user_version: i64,
    pub journal_mode: String,
}

#[derive(Debug)]
pub struct DbStats {
    pub total_qsos: i64,
    pub synced_qrz: i64,
    pub pending_qrz: i64,
    pub lotw_confirmed: i64,
    pub qsl_confirmed: i64,
    pub processed_files: i64,
}

/// LoFi-specific statistics
#[derive(Debug)]
pub struct LofiStats {
    pub operations: i64,
    pub qsos: i64,
    pub pota_operations: i64,
}

/// POTA-specific statistics with download/upload/pending breakdown
#[derive(Debug, Clone, serde::Serialize)]
pub struct PotaStats {
    // Download stats (from POTA.app)
    pub download_parks: i64,
    pub download_activations: i64,
    pub download_partial_activations: i64,
    pub download_qsos: i64,

    // Upload stats (to POTA.app) - QSOs that exist in both local and remote
    pub uploaded_parks: i64,
    pub uploaded_activations: i64,
    pub uploaded_partial_activations: i64,
    pub uploaded_qsos: i64,

    // Pending stats - local POTA QSOs not yet on POTA.app
    pub pending_parks: i64,
    pub pending_activations: i64,
    pub pending_partial_activations: i64,
    pub pending_qsos: i64,
}

/// Sync statistics showing downloaded/uploaded counts per integration
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncStats {
    /// Total unique QSOs across all sources (deduplicated)
    pub total_unique_qsos: i64,
    /// QSOs downloaded from each source
    pub downloaded: SourceCounts,
    /// QSOs uploaded/synced to each service
    pub uploaded: UploadCounts,
    /// Pending uploads to each service
    pub pending: PendingCounts,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SourceCounts {
    pub local: i64,
    pub qrz: i64,
    pub lofi: i64,
    pub pota: i64,
    pub wavelog: i64,
    pub lotw: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UploadCounts {
    pub qrz: i64,
    pub pota: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PendingCounts {
    pub qrz: i64,
    pub pota: i64,
}

/// Compute SHA256 hash of content
pub fn compute_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute file checksum
pub fn compute_file_checksum(path: &Path) -> Result<String> {
    let content = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&content);
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_test_qso(call: &str) -> Qso {
        Qso {
            call: call.to_string(),
            qso_date: "20241201".to_string(),
            time_on: "1430".to_string(),
            band: "20m".to_string(),
            mode: "CW".to_string(),
            station_callsign: None,
            freq: None,
            rst_sent: None,
            rst_rcvd: None,
            time_off: None,
            gridsquare: None,
            my_gridsquare: None,
            my_sig: None,
            my_sig_info: None,
            sig: None,
            sig_info: None,
            comment: None,
            my_state: None,
            my_cnty: None,
            state: None,
            cnty: None,
            other_fields: HashMap::new(),
        }
    }

    #[test]
    fn test_database_creation() {
        let db = Database::in_memory().unwrap();
        let stats = db.get_stats().unwrap();
        assert_eq!(stats.total_qsos, 0);
    }

    #[test]
    fn test_upsert_qso() {
        let db = Database::in_memory().unwrap();
        let qso = make_test_qso("W1AW");

        let id = db.upsert_qso(&qso, Some("test.adi")).unwrap();
        assert!(id > 0);

        assert!(db.qso_exists(&qso).unwrap());
    }

    #[test]
    fn test_unsynced_qsos() {
        let db = Database::in_memory().unwrap();
        let qso = make_test_qso("W1AW");
        let id = db.upsert_qso(&qso, None).unwrap();

        let unsynced = db.get_unsynced_qrz().unwrap();
        assert_eq!(unsynced.len(), 1);

        db.mark_qrz_synced(id, 12345).unwrap();

        let unsynced = db.get_unsynced_qrz().unwrap();
        assert_eq!(unsynced.len(), 0);
    }

    #[test]
    fn test_confirmation_update() {
        let db = Database::in_memory().unwrap();
        let qso = make_test_qso("W1AW");
        db.upsert_qso(&qso, None).unwrap();

        // Update confirmation
        let updated = db
            .update_confirmation(
                "W1AW",
                "20241201",
                "143000",
                "20m",
                "CW",
                Some("Y"),
                Some("Y"),
                None,
                None,
            )
            .unwrap();
        assert!(updated);

        // Check stats
        let stats = db.get_stats().unwrap();
        assert_eq!(stats.lotw_confirmed, 1);
    }

    #[test]
    fn test_file_tracking() {
        let db = Database::in_memory().unwrap();

        assert!(db.get_file_checksum("/path/to/file.adi").unwrap().is_none());

        db.record_processed_file("/path/to/file.adi", "abc123", 5)
            .unwrap();

        let checksum = db.get_file_checksum("/path/to/file.adi").unwrap();
        assert_eq!(checksum, Some("abc123".to_string()));
    }

    #[test]
    fn test_sync_state() {
        let db = Database::in_memory().unwrap();

        assert!(db.get_sync_state("last_qrz_download").unwrap().is_none());

        db.set_sync_state("last_qrz_download", "2024-12-01T14:30:00Z")
            .unwrap();

        let value = db.get_sync_state("last_qrz_download").unwrap();
        assert_eq!(value, Some("2024-12-01T14:30:00Z".to_string()));
    }
}
