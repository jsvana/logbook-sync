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
    /// Sync timestamp - milliseconds since epoch
    #[serde(default)]
    pub synced_until_millis: f64,
    /// Human-readable sync timestamp
    #[serde(default)]
    pub synced_until: String,
    /// The synced_since_millis value that was used for this request
    #[serde(default)]
    pub synced_since_millis: Option<f64>,
    /// Limit used in this request
    pub limit: u32,
    /// Number of records remaining after this page (0 = last page)
    pub records_left: u32,
    /// Timestamp to use for next page request (only present if records_left > 0)
    #[serde(default)]
    pub next_updated_at_millis: Option<f64>,
    /// Alternative timestamp for next page
    #[serde(default)]
    pub next_synced_at_millis: Option<f64>,
    /// Whether the page was extended to include all records with same timestamp
    #[serde(default)]
    pub extended_page: bool,
    /// Whether other_clients_only filter was applied
    #[serde(default)]
    pub other_clients_only: bool,
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
    /// Total number of QSOs in the account/operation
    pub total_records: u32,
    /// Sync timestamp - milliseconds since epoch
    #[serde(default)]
    pub synced_until_millis: f64,
    /// Human-readable sync timestamp
    #[serde(default)]
    pub synced_until: String,
    /// The synced_since_millis value that was used for this request
    #[serde(default)]
    pub synced_since_millis: Option<f64>,
    /// Limit used in this request
    pub limit: u32,
    /// Number of records remaining after this page (0 = last page)
    pub records_left: u32,
    /// Timestamp to use for next page request (only present if records_left > 0)
    #[serde(default)]
    pub next_updated_at_millis: Option<f64>,
    /// Alternative timestamp for next page
    #[serde(default)]
    pub next_synced_at_millis: Option<f64>,
    /// Whether the page was extended to include all records with same timestamp
    #[serde(default)]
    pub extended_page: bool,
    /// Whether other_clients_only filter was applied
    #[serde(default)]
    pub other_clients_only: bool,
}

/// A single QSO from LoFi
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LofiQso {
    pub uuid: String,

    /// Parent operation UUID (if part of an operation)
    #[serde(default)]
    pub operation: Option<String>,

    /// Account UUID (only present in some API responses)
    #[serde(default)]
    pub account: Option<String>,

    /// Creation timestamp in milliseconds since epoch
    #[serde(default)]
    pub created_at_millis: f64,

    /// Last update timestamp in milliseconds since epoch
    #[serde(default)]
    pub updated_at_millis: f64,

    /// When synced to server (milliseconds since epoch)
    #[serde(default)]
    pub synced_at_millis: Option<f64>,

    /// QSO start time in milliseconds since epoch
    #[serde(default)]
    pub start_at_millis: f64,

    /// Their station info (callsign, RST sent to them, lookup data)
    #[serde(default)]
    pub their: Option<QsoTheirInfo>,

    /// Our station info (callsign, RST sent)
    #[serde(default)]
    pub our: Option<QsoOurInfo>,

    /// Band (e.g., "20m", "40m")
    #[serde(default)]
    pub band: Option<String>,

    /// Frequency in kHz (note: kHz not MHz!)
    #[serde(default)]
    pub freq: Option<f64>,

    /// Mode (e.g., "CW", "SSB", "FT8")
    #[serde(default)]
    pub mode: Option<String>,

    /// Array of references for this QSO (POTA, SOTA, etc.)
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

/// Their station info in a QSO
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct QsoTheirInfo {
    /// Their callsign
    #[serde(default)]
    pub call: Option<String>,

    /// RST sent to them
    #[serde(default)]
    pub sent: Option<String>,

    /// Lookup/guess data
    #[serde(default)]
    pub guess: Option<QsoGuessInfo>,
}

/// Our station info in a QSO
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct QsoOurInfo {
    /// Our callsign
    #[serde(default)]
    pub call: Option<String>,

    /// RST we sent
    #[serde(default)]
    pub sent: Option<String>,
}

/// Lookup/guess information for a station
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct QsoGuessInfo {
    #[serde(default)]
    pub call: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub grid: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub entity_name: Option<String>,
    #[serde(default)]
    pub cq_zone: Option<u32>,
    #[serde(default)]
    pub itu_zone: Option<u32>,
    #[serde(default)]
    pub dxcc_code: Option<u32>,
    #[serde(default)]
    pub continent: Option<String>,
}

/// A reference attached to a QSO (their POTA park, SOTA summit, etc.)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QsoRef {
    /// Reference type: "pota", "sota", etc.
    #[serde(rename = "type", default)]
    pub ref_type: Option<String>,

    /// Reference code (e.g., "K-1234")
    #[serde(rename = "ref", default)]
    pub reference: Option<String>,

    /// Program name
    #[serde(default)]
    pub program: Option<String>,

    /// Our number (for contest exchanges)
    #[serde(default)]
    pub our_number: Option<String>,
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

    /// Get their callsign
    pub fn their_call(&self) -> Option<&str> {
        self.their.as_ref().and_then(|t| t.call.as_deref())
    }

    /// Get our callsign
    pub fn our_call(&self) -> Option<&str> {
        self.our.as_ref().and_then(|o| o.call.as_deref())
    }

    /// Get RST sent (to them)
    pub fn rst_sent(&self) -> Option<&str> {
        self.our.as_ref().and_then(|o| o.sent.as_deref())
    }

    /// Get RST received (from them)
    pub fn rst_rcvd(&self) -> Option<&str> {
        self.their.as_ref().and_then(|t| t.sent.as_deref())
    }

    /// Get their name from guess info
    pub fn their_name(&self) -> Option<&str> {
        self.their
            .as_ref()
            .and_then(|t| t.guess.as_ref())
            .and_then(|g| g.name.as_deref())
    }

    /// Get their state from guess info
    pub fn their_state(&self) -> Option<&str> {
        self.their
            .as_ref()
            .and_then(|t| t.guess.as_ref())
            .and_then(|g| g.state.as_deref())
    }

    /// Get their grid from guess info
    pub fn their_grid(&self) -> Option<&str> {
        self.their
            .as_ref()
            .and_then(|t| t.guess.as_ref())
            .and_then(|g| g.grid.as_deref())
    }

    /// Get their country from guess info
    pub fn their_country(&self) -> Option<&str> {
        self.their
            .as_ref()
            .and_then(|t| t.guess.as_ref())
            .and_then(|g| g.entity_name.as_deref())
    }

    /// Get their POTA reference from refs array
    pub fn their_pota_ref(&self) -> Option<&str> {
        self.refs
            .iter()
            .find(|r| r.ref_type.as_deref() == Some("pota") || r.program.as_deref() == Some("POTA"))
            .and_then(|r| r.reference.as_deref())
    }

    /// Get their SOTA reference from refs array
    pub fn their_sota_ref(&self) -> Option<&str> {
        self.refs
            .iter()
            .find(|r| r.ref_type.as_deref() == Some("sota") || r.program.as_deref() == Some("SOTA"))
            .and_then(|r| r.reference.as_deref())
    }

    /// Get our POTA reference from operation refs (potaActivation type)
    /// This requires looking up the operation, so we pass the ref info directly
    pub fn get_my_pota_ref_from_operation(
        &self,
        operation_refs: &[OperationRef],
    ) -> Option<String> {
        operation_refs
            .iter()
            .find(|r| r.ref_type == "potaActivation")
            .map(|r| r.reference.clone())
    }

    /// Convert this LoFi QSO to an ADIF Qso struct
    /// Requires operation refs to get MY_SIG_INFO (our POTA park)
    pub fn to_qso(&self, operation_refs: &[OperationRef]) -> Option<crate::adif::Qso> {
        use std::collections::HashMap;

        let their_call = self.their_call()?;
        let band = self.band.clone()?;
        let mode = self.mode.clone()?;

        let qso_date = self.qso_date();
        let time_on = self.time_on();

        if qso_date.is_empty() || time_on.is_empty() {
            return None;
        }

        let mut other_fields = HashMap::new();

        // Add frequency if available
        if let Some(freq_mhz) = self.freq_mhz() {
            other_fields.insert("FREQ".to_string(), format!("{:.6}", freq_mhz));
        }

        // Add POTA activation info (MY_SIG and MY_SIG_INFO)
        if let Some(my_pota_ref) = self.get_my_pota_ref_from_operation(operation_refs) {
            other_fields.insert("MY_SIG".to_string(), "POTA".to_string());
            other_fields.insert("MY_SIG_INFO".to_string(), my_pota_ref);
        }

        // Add their POTA ref if present (SIG/SIG_INFO for park-to-park)
        if let Some(their_pota) = self.their_pota_ref() {
            other_fields.insert("SIG".to_string(), "POTA".to_string());
            other_fields.insert("SIG_INFO".to_string(), their_pota.to_string());
        }

        // Add name, state, country if available
        if let Some(name) = self.their_name() {
            other_fields.insert("NAME".to_string(), name.to_string());
        }
        if let Some(country) = self.their_country() {
            other_fields.insert("COUNTRY".to_string(), country.to_string());
        }

        // Add CQ/ITU zones if available
        if let Some(cq) = self
            .their
            .as_ref()
            .and_then(|t| t.guess.as_ref())
            .and_then(|g| g.cq_zone)
        {
            other_fields.insert("CQZ".to_string(), cq.to_string());
        }
        if let Some(itu) = self
            .their
            .as_ref()
            .and_then(|t| t.guess.as_ref())
            .and_then(|g| g.itu_zone)
        {
            other_fields.insert("ITUZ".to_string(), itu.to_string());
        }

        // Add DXCC if available
        if let Some(dxcc) = self
            .their
            .as_ref()
            .and_then(|t| t.guess.as_ref())
            .and_then(|g| g.dxcc_code)
        {
            other_fields.insert("DXCC".to_string(), dxcc.to_string());
        }

        // Add TX power if available
        if let Some(pwr) = &self.tx_pwr {
            other_fields.insert("TX_PWR".to_string(), pwr.clone());
        }

        // Add notes/comment if available
        if let Some(notes) = &self.notes {
            other_fields.insert("COMMENT".to_string(), notes.clone());
        }

        Some(crate::adif::Qso {
            call: their_call.to_string(),
            qso_date,
            time_on,
            band,
            mode,
            station_callsign: self.our_call().map(|s| s.to_string()),
            freq: self.freq_mhz().map(|f| format!("{:.6}", f)),
            rst_sent: self.rst_sent().map(|s| s.to_string()),
            rst_rcvd: self.rst_rcvd().map(|s| s.to_string()),
            time_off: None,
            gridsquare: self.their_grid().map(|s| s.to_string()),
            my_gridsquare: None, // Could get from operation if needed
            my_sig: self
                .get_my_pota_ref_from_operation(operation_refs)
                .map(|_| "POTA".to_string()),
            my_sig_info: self.get_my_pota_ref_from_operation(operation_refs),
            sig: self.their_pota_ref().map(|_| "POTA".to_string()),
            sig_info: self.their_pota_ref().map(|s| s.to_string()),
            comment: self.notes.clone(),
            my_state: None,
            my_cnty: None,
            state: self.their_state().map(|s| s.to_string()),
            cnty: None,
            other_fields,
        })
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
