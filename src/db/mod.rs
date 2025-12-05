pub mod integrations;
pub mod users;

use crate::adif::Qso;
use crate::{Error, Result};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
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
                first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_updated_at TEXT NOT NULL DEFAULT (datetime('now')),

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
                first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
                last_updated_at TEXT NOT NULL DEFAULT (datetime('now')),
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
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
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
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
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
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_user_watch_paths_user ON user_watch_paths(user_id);

            -- Sessions table for web auth
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY NOT NULL,
                data BLOB NOT NULL,
                expiry_date INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expiry_date);
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
        let now = Utc::now().to_rfc3339();
        let adif_json = serde_json::to_string(qso).map_err(|e| Error::Other(e.to_string()))?;
        let source_hash = compute_hash(&adif_json);

        // Try to insert, on conflict update
        self.conn.execute(
            r#"
            INSERT INTO qsos (call, qso_date, time_on, band, mode, source_file, source_hash,
                              created_at, updated_at, adif_record, source, source_id)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10, ?11)
            ON CONFLICT(call, qso_date, time_on, band, mode) DO UPDATE SET
                source_file = COALESCE(excluded.source_file, source_file),
                source_hash = excluded.source_hash,
                updated_at = excluded.updated_at,
                adif_record = excluded.adif_record,
                source = COALESCE(excluded.source, source),
                source_id = COALESCE(excluded.source_id, source_id)
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
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
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

    /// Get statistics for status display
    pub fn get_stats(&self) -> Result<DbStats> {
        let total_qsos: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM qsos", [], |row| row.get(0))?;

        let synced_qrz: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM qsos WHERE qrz_synced_at IS NOT NULL",
            [],
            |row| row.get(0),
        )?;

        let pending_qrz: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM qsos WHERE qrz_synced_at IS NULL",
            [],
            |row| row.get(0),
        )?;

        let lotw_confirmed: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM qsos WHERE lotw_qsl_rcvd = 'Y'",
            [],
            |row| row.get(0),
        )?;

        let qsl_confirmed: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM qsos WHERE qsl_rcvd = 'Y'",
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
                last_updated_at = datetime('now')
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
                    &ref_item.reference,
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

    /// Insert or update a LoFi QSO
    /// Returns true if this is a new QSO (not previously seen)
    pub fn upsert_lofi_qso(&self, qso: &crate::lofi::LofiQso) -> Result<bool> {
        let existing: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM lofi_qsos WHERE lofi_uuid = ?1",
            params![&qso.uuid],
            |row| row.get(0),
        )?;

        let is_new = existing == 0;
        let raw_json = serde_json::to_string(qso).map_err(|e| Error::Other(e.to_string()))?;

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
                last_updated_at = datetime('now')
            "#,
            params![
                &qso.uuid,
                &qso.account,
                &qso.operation,
                qso.created_at_millis,
                qso.updated_at_millis,
                qso.synced_at_millis,
                qso.start_at_millis,
                &qso.their_call,
                &qso.our_call,
                &qso.band,
                qso.freq,
                &qso.mode,
                &qso.rst_sent,
                &qso.rst_rcvd,
                &qso.our_grid,
                &qso.their_grid,
                &qso.their_name,
                &qso.their_qth,
                &qso.their_state,
                &qso.their_country,
                qso.their_cq_zone,
                qso.their_itu_zone,
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
