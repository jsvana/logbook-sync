//! Data structures for Ham2K LoFi API responses.

use serde::{Deserialize, Serialize};

// ============================================================================
// Client Registration
// ============================================================================

/// Response from POST /v1/client (registration)
#[derive(Debug, Clone, Deserialize)]
pub struct ClientRegistrationResponse {
    pub token: String,
    pub client: ClientInfo,
    pub account: AccountInfo,
    pub meta: MetaInfo,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientInfo {
    pub uuid: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountInfo {
    pub uuid: String,
    pub call: String,
    #[serde(default)]
    pub name: String,
    pub email: Option<String>,
    pub cutoff_date: Option<String>,
    pub cutoff_date_millis: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetaInfo {
    pub flags: SyncFlags,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncFlags {
    pub suggested_sync_batch_size: u32,
    pub suggested_sync_loop_delay: u64,
    pub suggested_sync_check_period: u64,
}

/// Request body for POST /v1/client
#[derive(Debug, Serialize)]
pub struct ClientRegistrationRequest {
    pub client: ClientCredentials,
    pub account: AccountRequest,
    pub meta: MetaRequest,
}

#[derive(Debug, Serialize)]
pub struct ClientCredentials {
    pub key: String,
    pub name: String,
    pub secret: String,
}

#[derive(Debug, Serialize)]
pub struct AccountRequest {
    pub call: String,
}

#[derive(Debug, Serialize)]
pub struct MetaRequest {
    pub app: String,
}

/// Request body for POST /v1/client/link
#[derive(Debug, Serialize)]
pub struct LinkDeviceRequest {
    pub email: String,
}

// ============================================================================
// Operations API
// ============================================================================

/// Response from GET /v1/operations
#[derive(Debug, Clone, Deserialize)]
pub struct OperationsResponse {
    pub operations: Vec<LofiOperation>,
    pub meta: OperationsMetaWrapper,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OperationsMetaWrapper {
    pub operations: OperationsMeta,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OperationsMeta {
    /// Total number of operations in the account
    pub total_records: u32,
    /// Cursor for pagination - milliseconds since epoch
    pub synced_until_millis: f64,
    /// Human-readable sync timestamp
    pub synced_until: String,
    /// Limit used in this request
    pub limit: u32,
    /// Number of records remaining after this page (0 = last page)
    pub records_left: u32,
}

/// A single operation from LoFi (e.g., a POTA activation)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LofiOperation {
    pub uuid: String,

    /// Callsign used for this operation
    pub station_call: String,

    /// Account UUID
    pub account: String,

    /// Creation timestamp in milliseconds since epoch
    pub created_at_millis: f64,

    /// Device that created this operation
    pub created_on_device_id: Option<String>,

    /// Last update timestamp in milliseconds since epoch
    pub updated_at_millis: f64,

    /// Device that last updated this operation
    pub updated_on_device_id: Option<String>,

    /// When synced to server (milliseconds since epoch)
    pub synced_at_millis: Option<f64>,

    /// Operation title (e.g., "at US-4571")
    #[serde(default)]
    pub title: Option<String>,

    /// Operation subtitle (e.g., park name)
    #[serde(default)]
    pub subtitle: Option<String>,

    /// Maidenhead grid square
    #[serde(default)]
    pub grid: Option<String>,

    /// Array of references (POTA parks, SOTA summits, etc.)
    #[serde(default)]
    pub refs: Vec<OperationRef>,

    /// Number of QSOs in this operation
    #[serde(default)]
    pub qso_count: u32,

    /// Earliest QSO timestamp (milliseconds since epoch)
    pub start_at_millis_min: Option<f64>,

    /// Latest QSO timestamp (milliseconds since epoch)
    pub start_at_millis_max: Option<f64>,

    /// Whether this is a new operation (from LoFi's perspective)
    #[serde(rename = "_isNew", default)]
    pub is_new: bool,

    /// Soft delete flag (0 = active, 1 = deleted)
    #[serde(default)]
    pub deleted: u8,

    /// Sync status flag
    #[serde(default)]
    pub synced: u8,
}

/// A reference to a special activity (POTA park, SOTA summit, etc.)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OperationRef {
    /// Reference type: "potaActivation", "sotaActivation", etc.
    #[serde(rename = "type")]
    pub ref_type: String,

    /// Reference code (e.g., "US-4571", "K-1234", "W6/NC-001")
    #[serde(rename = "ref")]
    pub reference: String,

    /// Full name (e.g., "Juan Bautista de Anza National Historic Trail")
    #[serde(default)]
    pub name: Option<String>,

    /// Location codes (e.g., "US-AZ,US-CA")
    #[serde(default)]
    pub location: Option<String>,

    /// Full display label
    #[serde(default)]
    pub label: Option<String>,

    /// Short display label (e.g., "POTA US-4571")
    #[serde(default)]
    pub short_label: Option<String>,

    /// Program name: "POTA", "SOTA", "WWFF", etc.
    #[serde(default)]
    pub program: Option<String>,
}

impl LofiOperation {
    /// Get the first POTA reference, if any
    pub fn pota_ref(&self) -> Option<&OperationRef> {
        self.refs
            .iter()
            .find(|r| r.ref_type == "potaActivation" || r.program.as_deref() == Some("POTA"))
    }

    /// Get the first SOTA reference, if any
    pub fn sota_ref(&self) -> Option<&OperationRef> {
        self.refs
            .iter()
            .find(|r| r.ref_type == "sotaActivation" || r.program.as_deref() == Some("SOTA"))
    }

    /// Convert updated_at_millis to ISO 8601 string
    pub fn updated_at_iso(&self) -> String {
        let secs = (self.updated_at_millis / 1000.0) as i64;
        let nanos = ((self.updated_at_millis % 1000.0) * 1_000_000.0) as u32;
        chrono::DateTime::from_timestamp(secs, nanos)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default()
    }

    /// Convert created_at_millis to ISO 8601 string
    pub fn created_at_iso(&self) -> String {
        let secs = (self.created_at_millis / 1000.0) as i64;
        let nanos = ((self.created_at_millis % 1000.0) * 1_000_000.0) as u32;
        chrono::DateTime::from_timestamp(secs, nanos)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default()
    }
}

// ============================================================================
// QSOs API
// ============================================================================

/// Response from GET /v1/qsos
#[derive(Debug, Clone, Deserialize)]
pub struct QsosResponse {
    pub qsos: Vec<LofiQso>,
    pub meta: QsosMetaWrapper,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QsosMetaWrapper {
    pub qsos: QsosMeta,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QsosMeta {
    /// Total number of QSOs in the account
    pub total_records: u32,
    /// Cursor for pagination - milliseconds since epoch
    pub synced_until_millis: f64,
    /// Human-readable sync timestamp
    pub synced_until: String,
    /// Limit used in this request
    pub limit: u32,
    /// Number of records remaining after this page (0 = last page)
    pub records_left: u32,
}

/// A single QSO from LoFi
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LofiQso {
    pub uuid: String,

    /// Parent operation UUID (if part of an operation)
    #[serde(default)]
    pub operation: Option<String>,

    /// Account UUID
    pub account: String,

    /// Creation timestamp in milliseconds since epoch
    pub created_at_millis: f64,

    /// Last update timestamp in milliseconds since epoch
    pub updated_at_millis: f64,

    /// When synced to server (milliseconds since epoch)
    pub synced_at_millis: Option<f64>,

    /// QSO start time in milliseconds since epoch
    pub start_at_millis: f64,

    /// Worked station's callsign
    pub their_call: String,

    /// Your callsign for this QSO
    #[serde(default)]
    pub our_call: Option<String>,

    /// Band (e.g., "20m", "40m")
    #[serde(default)]
    pub band: Option<String>,

    /// Frequency in kHz (note: kHz not MHz!)
    #[serde(default)]
    pub freq: Option<f64>,

    /// Mode (e.g., "CW", "SSB", "FT8")
    #[serde(default)]
    pub mode: Option<String>,

    /// Signal report sent
    #[serde(default)]
    pub rst_sent: Option<String>,

    /// Signal report received
    #[serde(default)]
    pub rst_rcvd: Option<String>,

    /// Your grid square
    #[serde(default)]
    pub our_grid: Option<String>,

    /// Their grid square
    #[serde(default)]
    pub their_grid: Option<String>,

    /// Their name
    #[serde(default)]
    pub their_name: Option<String>,

    /// Their QTH/location
    #[serde(default)]
    pub their_qth: Option<String>,

    /// Their state/province
    #[serde(default)]
    pub their_state: Option<String>,

    /// Their country
    #[serde(default)]
    pub their_country: Option<String>,

    /// Their CQ zone
    #[serde(default)]
    pub their_cq_zone: Option<u32>,

    /// Their ITU zone
    #[serde(default)]
    pub their_itu_zone: Option<u32>,

    /// Array of references for this QSO (POTA, SOTA, etc.)
    /// These represent THEIR references (for P2P, S2S, etc.)
    #[serde(default)]
    pub refs: Vec<QsoRef>,

    /// Transmit power
    #[serde(default)]
    pub tx_pwr: Option<String>,

    /// Comment/notes
    #[serde(default)]
    pub notes: Option<String>,

    /// Soft delete flag
    #[serde(default)]
    pub deleted: u8,
}

/// A reference attached to a QSO (their POTA park, SOTA summit, etc.)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QsoRef {
    /// Reference type: "pota", "sota", etc.
    #[serde(rename = "type")]
    pub ref_type: String,

    /// Reference code (e.g., "K-1234")
    #[serde(rename = "ref")]
    pub reference: String,

    /// Program name
    #[serde(default)]
    pub program: Option<String>,
}

impl LofiQso {
    /// Convert start_at_millis to QSO date (YYYYMMDD format)
    pub fn qso_date(&self) -> String {
        let secs = (self.start_at_millis / 1000.0) as i64;
        chrono::DateTime::from_timestamp(secs, 0)
            .map(|dt| dt.format("%Y%m%d").to_string())
            .unwrap_or_default()
    }

    /// Convert start_at_millis to time on (HHMM format)
    pub fn time_on(&self) -> String {
        let secs = (self.start_at_millis / 1000.0) as i64;
        chrono::DateTime::from_timestamp(secs, 0)
            .map(|dt| dt.format("%H%M").to_string())
            .unwrap_or_default()
    }

    /// Convert start_at_millis to ISO 8601 string
    pub fn start_at_iso(&self) -> String {
        let secs = (self.start_at_millis / 1000.0) as i64;
        let nanos = ((self.start_at_millis % 1000.0) * 1_000_000.0) as u32;
        chrono::DateTime::from_timestamp(secs, nanos)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default()
    }

    /// Get frequency in MHz (API returns kHz)
    pub fn freq_mhz(&self) -> Option<f64> {
        self.freq.map(|f| f / 1000.0)
    }

    /// Get their POTA reference from refs array
    pub fn their_pota_ref(&self) -> Option<&str> {
        self.refs
            .iter()
            .find(|r| r.ref_type == "pota" || r.program.as_deref() == Some("POTA"))
            .map(|r| r.reference.as_str())
    }

    /// Get their SOTA reference from refs array
    pub fn their_sota_ref(&self) -> Option<&str> {
        self.refs
            .iter()
            .find(|r| r.ref_type == "sota" || r.program.as_deref() == Some("SOTA"))
            .map(|r| r.reference.as_str())
    }
}

// ============================================================================
// Sync Statistics
// ============================================================================

/// Statistics from a sync operation
#[derive(Debug, Default, Clone)]
pub struct SyncStats {
    pub new_operations: u32,
    pub updated_operations: u32,
    pub total_operations: u32,
    pub new_qsos: u32,
    pub updated_qsos: u32,
    pub total_qsos: u32,
}
