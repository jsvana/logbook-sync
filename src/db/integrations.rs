//! Integration configuration database operations.
//!
//! Stores encrypted user integration configs for QRZ, LoFi, LotW, etc.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::Result;
use crate::crypto::{CryptoError, MasterKey, UserCrypto};

/// QRZ.com integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrzIntegrationConfig {
    pub api_key: String,
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    #[serde(default = "default_true")]
    pub upload_enabled: bool,
    #[serde(default = "default_true")]
    pub download_enabled: bool,
    #[serde(default = "default_download_interval")]
    pub download_interval_secs: u64,
}

/// Ham2K LoFi integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LofiIntegrationConfig {
    pub client_key: String,
    pub client_secret: String,
    pub bearer_token: Option<String>,
    pub account_uuid: Option<String>,
    /// Callsign used for registration (needed for token refresh)
    pub callsign: Option<String>,
    pub device_linked: bool,
    #[serde(default = "default_sync_batch_size")]
    pub sync_batch_size: u32,
    #[serde(default = "default_sync_loop_delay")]
    pub sync_loop_delay_ms: u64,
}

/// LotW integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LotwIntegrationConfig {
    pub tqsl_path: Option<String>,
    pub station_callsign: String,
    pub cert_password: Option<String>,
    #[serde(default = "default_true")]
    pub auto_upload: bool,
}

/// Clublog integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClublogIntegrationConfig {
    pub email: String,
    pub password: String,
    pub callsign: String,
    #[serde(default = "default_true")]
    pub upload_enabled: bool,
}

/// eQSL integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EqslIntegrationConfig {
    pub username: String,
    pub password: String,
    #[serde(default = "default_true")]
    pub upload_enabled: bool,
    #[serde(default = "default_true")]
    pub download_enabled: bool,
}

/// HRDLog integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HrdlogIntegrationConfig {
    pub callsign: String,
    pub upload_code: String,
    #[serde(default = "default_true")]
    pub upload_enabled: bool,
}

/// Wavelog integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WavelogIntegrationConfig {
    pub base_url: String,
    pub api_key: String,
    pub station_id: Option<i64>,
    pub logbook_slug: Option<String>,
    #[serde(default = "default_true")]
    pub upload_enabled: bool,
    #[serde(default = "default_true")]
    pub download_enabled: bool,
}

/// ntfy.sh notification integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtfyIntegrationConfig {
    /// The ntfy server URL (default: https://ntfy.sh)
    #[serde(default = "default_ntfy_server")]
    pub server: String,
    /// The topic to publish to
    pub topic: String,
    /// Optional authentication token/password
    pub token: Option<String>,
    /// Priority level (1-5, default 3)
    #[serde(default = "default_ntfy_priority")]
    pub priority: u8,
    /// Notify on new QSOs synced
    #[serde(default = "default_true")]
    pub notify_on_sync: bool,
    /// Notify on sync errors
    #[serde(default = "default_true")]
    pub notify_on_error: bool,
}

fn default_ntfy_server() -> String {
    "https://ntfy.sh".to_string()
}

fn default_ntfy_priority() -> u8 {
    3
}

/// POTA.app integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PotaIntegrationConfig {
    /// POTA.app email address
    pub email: String,
    /// POTA.app password
    pub password: String,
}

/// Wrapper enum for all integration types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IntegrationConfig {
    Qrz(QrzIntegrationConfig),
    Lofi(LofiIntegrationConfig),
    Lotw(LotwIntegrationConfig),
    Clublog(ClublogIntegrationConfig),
    Eqsl(EqslIntegrationConfig),
    Hrdlog(HrdlogIntegrationConfig),
    Wavelog(WavelogIntegrationConfig),
    Ntfy(NtfyIntegrationConfig),
    Pota(PotaIntegrationConfig),
}

impl IntegrationConfig {
    /// Get the type name for this integration
    pub fn type_name(&self) -> &'static str {
        match self {
            IntegrationConfig::Qrz(_) => "qrz",
            IntegrationConfig::Lofi(_) => "lofi",
            IntegrationConfig::Lotw(_) => "lotw",
            IntegrationConfig::Clublog(_) => "clublog",
            IntegrationConfig::Eqsl(_) => "eqsl",
            IntegrationConfig::Hrdlog(_) => "hrdlog",
            IntegrationConfig::Wavelog(_) => "wavelog",
            IntegrationConfig::Ntfy(_) => "ntfy",
            IntegrationConfig::Pota(_) => "pota",
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_user_agent() -> String {
    "logbook-sync/0.2.0".to_string()
}
fn default_download_interval() -> u64 {
    3600
}
fn default_sync_batch_size() -> u32 {
    50
}
fn default_sync_loop_delay() -> u64 {
    10000
}

/// User integration record from database
#[derive(Debug)]
pub struct UserIntegration {
    pub id: i64,
    pub user_id: i64,
    pub integration_type: String,
    pub enabled: bool,
    pub config: IntegrationConfig,
    pub created_at: String,
    pub updated_at: String,
}

/// Raw integration row from database (before decryption)
#[derive(Debug)]
struct IntegrationRow {
    id: i64,
    user_id: i64,
    integration_type: String,
    enabled: bool,
    encrypted_config: String,
    created_at: String,
    updated_at: String,
}

/// Save or update an integration config (encrypts automatically)
pub fn save_integration(
    conn: &Connection,
    master_key: &MasterKey,
    user_id: i64,
    user_salt: &[u8; 32],
    integration_type: &str,
    config: &IntegrationConfig,
    enabled: bool,
) -> std::result::Result<(), CryptoError> {
    let crypto = UserCrypto::derive(master_key, user_id, user_salt)?;
    let encrypted = crypto.encrypt_json(config)?;

    conn.execute(
        r#"
        INSERT INTO user_integrations (user_id, integration_type, enabled, encrypted_config)
        VALUES (?1, ?2, ?3, ?4)
        ON CONFLICT(user_id, integration_type) DO UPDATE SET
            enabled = excluded.enabled,
            encrypted_config = excluded.encrypted_config,
            updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
        "#,
        params![user_id, integration_type, enabled, &encrypted],
    )
    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    Ok(())
}

/// Get a specific integration config (decrypts automatically)
pub fn get_integration(
    conn: &Connection,
    master_key: &MasterKey,
    user_id: i64,
    user_salt: &[u8; 32],
    integration_type: &str,
) -> std::result::Result<Option<UserIntegration>, CryptoError> {
    let row: Option<IntegrationRow> = conn
        .query_row(
            r#"
            SELECT id, user_id, integration_type, enabled, encrypted_config, created_at, updated_at
            FROM user_integrations WHERE user_id = ?1 AND integration_type = ?2
            "#,
            params![user_id, integration_type],
            |row| {
                Ok(IntegrationRow {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    integration_type: row.get(2)?,
                    enabled: row.get::<_, i64>(3)? != 0,
                    encrypted_config: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    match row {
        Some(r) => {
            let crypto = UserCrypto::derive(master_key, user_id, user_salt)?;
            let config: IntegrationConfig = crypto.decrypt_json(&r.encrypted_config)?;
            Ok(Some(UserIntegration {
                id: r.id,
                user_id: r.user_id,
                integration_type: r.integration_type,
                enabled: r.enabled,
                config,
                created_at: r.created_at,
                updated_at: r.updated_at,
            }))
        }
        None => Ok(None),
    }
}

/// Get all integrations for a user
pub fn get_user_integrations(
    conn: &Connection,
    master_key: &MasterKey,
    user_id: i64,
    user_salt: &[u8; 32],
) -> std::result::Result<Vec<UserIntegration>, CryptoError> {
    let mut stmt = conn
        .prepare(
            r#"
            SELECT id, user_id, integration_type, enabled, encrypted_config, created_at, updated_at
            FROM user_integrations WHERE user_id = ?1
            "#,
        )
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let rows: Vec<IntegrationRow> = stmt
        .query_map([user_id], |row| {
            Ok(IntegrationRow {
                id: row.get(0)?,
                user_id: row.get(1)?,
                integration_type: row.get(2)?,
                enabled: row.get::<_, i64>(3)? != 0,
                encrypted_config: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let crypto = UserCrypto::derive(master_key, user_id, user_salt)?;
    let mut integrations = Vec::with_capacity(rows.len());

    for row in rows {
        let config: IntegrationConfig = crypto.decrypt_json(&row.encrypted_config)?;
        integrations.push(UserIntegration {
            id: row.id,
            user_id: row.user_id,
            integration_type: row.integration_type,
            enabled: row.enabled,
            config,
            created_at: row.created_at,
            updated_at: row.updated_at,
        });
    }

    Ok(integrations)
}

/// Get list of integration types configured for a user (without decrypting)
pub fn get_integration_types(conn: &Connection, user_id: i64) -> Result<Vec<(String, bool)>> {
    let mut stmt =
        conn.prepare("SELECT integration_type, enabled FROM user_integrations WHERE user_id = ?1")?;

    let types = stmt
        .query_map([user_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? != 0))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(types)
}

/// Delete an integration
pub fn delete_integration(conn: &Connection, user_id: i64, integration_type: &str) -> Result<()> {
    conn.execute(
        "DELETE FROM user_integrations WHERE user_id = ?1 AND integration_type = ?2",
        params![user_id, integration_type],
    )?;
    Ok(())
}

/// Toggle integration enabled status
pub fn set_integration_enabled(
    conn: &Connection,
    user_id: i64,
    integration_type: &str,
    enabled: bool,
) -> Result<()> {
    conn.execute(
        r#"
        UPDATE user_integrations
        SET enabled = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
        WHERE user_id = ?2 AND integration_type = ?3
        "#,
        params![enabled, user_id, integration_type],
    )?;
    Ok(())
}

/// User watch path record
#[derive(Debug, Clone, Serialize)]
pub struct UserWatchPath {
    pub id: i64,
    pub user_id: i64,
    pub watch_path: String,
    pub patterns: Vec<String>,
    pub enabled: bool,
    pub created_at: String,
}

/// Add a watch path for a user
pub fn add_watch_path(
    conn: &Connection,
    user_id: i64,
    watch_path: &str,
    patterns: &[String],
) -> Result<i64> {
    let patterns_json =
        serde_json::to_string(patterns).map_err(|e| crate::Error::Other(e.to_string()))?;

    conn.execute(
        r#"
        INSERT INTO user_watch_paths (user_id, watch_path, patterns)
        VALUES (?1, ?2, ?3)
        "#,
        params![user_id, watch_path, patterns_json],
    )?;

    Ok(conn.last_insert_rowid())
}

/// Get watch paths for a user
pub fn get_user_watch_paths(conn: &Connection, user_id: i64) -> Result<Vec<UserWatchPath>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT id, user_id, watch_path, patterns, enabled, created_at
        FROM user_watch_paths WHERE user_id = ?1
        "#,
    )?;

    let paths = stmt
        .query_map([user_id], |row| {
            let patterns_json: String = row.get(3)?;
            let patterns: Vec<String> = serde_json::from_str(&patterns_json).unwrap_or_default();

            Ok(UserWatchPath {
                id: row.get(0)?,
                user_id: row.get(1)?,
                watch_path: row.get(2)?,
                patterns,
                enabled: row.get::<_, i64>(4)? != 0,
                created_at: row.get(5)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(paths)
}

/// Delete a watch path
pub fn delete_watch_path(conn: &Connection, watch_path_id: i64, user_id: i64) -> Result<bool> {
    let rows = conn.execute(
        "DELETE FROM user_watch_paths WHERE id = ?1 AND user_id = ?2",
        params![watch_path_id, user_id],
    )?;
    Ok(rows > 0)
}

/// Toggle watch path enabled status
pub fn set_watch_path_enabled(
    conn: &Connection,
    watch_path_id: i64,
    user_id: i64,
    enabled: bool,
) -> Result<()> {
    conn.execute(
        "UPDATE user_watch_paths SET enabled = ?1 WHERE id = ?2 AND user_id = ?3",
        params![enabled, watch_path_id, user_id],
    )?;
    Ok(())
}

// === Sync State Tracking ===

/// Sync state record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncState {
    pub integration_type: String,
    pub direction: String,
    pub last_sync_at: Option<String>,
    pub last_sync_result: Option<String>,
    pub last_sync_message: Option<String>,
    pub items_synced: i64,
}

/// Record a successful sync
pub fn record_sync_success(
    conn: &Connection,
    user_id: i64,
    integration_type: &str,
    direction: &str,
    items_synced: i64,
    message: Option<&str>,
) -> Result<()> {
    conn.execute(
        r#"
        INSERT INTO user_sync_state (user_id, integration_type, direction, last_sync_at, last_sync_result, last_sync_message, items_synced)
        VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), 'success', ?4, ?5)
        ON CONFLICT(user_id, integration_type, direction) DO UPDATE SET
            last_sync_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
            last_sync_result = 'success',
            last_sync_message = excluded.last_sync_message,
            items_synced = excluded.items_synced
        "#,
        params![user_id, integration_type, direction, message, items_synced],
    )?;
    Ok(())
}

/// Record a failed sync
pub fn record_sync_error(
    conn: &Connection,
    user_id: i64,
    integration_type: &str,
    direction: &str,
    error_message: &str,
) -> Result<()> {
    conn.execute(
        r#"
        INSERT INTO user_sync_state (user_id, integration_type, direction, last_sync_at, last_sync_result, last_sync_message, items_synced)
        VALUES (?1, ?2, ?3, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), 'error', ?4, 0)
        ON CONFLICT(user_id, integration_type, direction) DO UPDATE SET
            last_sync_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
            last_sync_result = 'error',
            last_sync_message = excluded.last_sync_message,
            items_synced = 0
        "#,
        params![user_id, integration_type, direction, error_message],
    )?;
    Ok(())
}

/// Get sync state for a user and integration
pub fn get_sync_state(
    conn: &Connection,
    user_id: i64,
    integration_type: &str,
) -> Result<Vec<SyncState>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT integration_type, direction, last_sync_at, last_sync_result, last_sync_message, items_synced
        FROM user_sync_state
        WHERE user_id = ?1 AND integration_type = ?2
        "#,
    )?;

    let states = stmt
        .query_map(params![user_id, integration_type], |row| {
            Ok(SyncState {
                integration_type: row.get(0)?,
                direction: row.get(1)?,
                last_sync_at: row.get(2)?,
                last_sync_result: row.get(3)?,
                last_sync_message: row.get(4)?,
                items_synced: row.get(5)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(states)
}

/// Get all sync states for a user
pub fn get_all_sync_states(conn: &Connection, user_id: i64) -> Result<Vec<SyncState>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT integration_type, direction, last_sync_at, last_sync_result, last_sync_message, items_synced
        FROM user_sync_state
        WHERE user_id = ?1
        ORDER BY integration_type, direction
        "#,
    )?;

    let states = stmt
        .query_map([user_id], |row| {
            Ok(SyncState {
                integration_type: row.get(0)?,
                direction: row.get(1)?,
                last_sync_at: row.get(2)?,
                last_sync_result: row.get(3)?,
                last_sync_message: row.get(4)?,
                items_synced: row.get(5)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(states)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntfy_config_deserialization() {
        // Test JSON that comes from frontend (with string priority)
        let json = r#"{"type":"ntfy","server":"https://ntfy.sh","topic":"test","priority":"3","notify_on_sync":true,"notify_on_error":true}"#;
        let result: std::result::Result<NtfyIntegrationConfig, _> = serde_json::from_str(json);
        println!("String priority result: {:?}", result);

        // Test JSON with number priority
        let json = r#"{"type":"ntfy","server":"https://ntfy.sh","topic":"test","priority":3,"notify_on_sync":true,"notify_on_error":true}"#;
        let result: std::result::Result<NtfyIntegrationConfig, _> = serde_json::from_str(json);
        println!("Number priority result: {:?}", result);
        assert!(result.is_ok());

        // Test without priority (should use default)
        let json = r#"{"server":"https://ntfy.sh","topic":"test"}"#;
        let result: std::result::Result<NtfyIntegrationConfig, _> = serde_json::from_str(json);
        println!("No priority result: {:?}", result);
        assert!(result.is_ok());
    }
}
