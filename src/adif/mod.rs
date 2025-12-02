mod parser;
mod writer;

pub use parser::{parse_adif, AdifHeader, AdifRecord};
pub use writer::write_adif;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a single QSO record from an ADIF file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Qso {
    /// Contacted station callsign (required)
    pub call: String,
    /// QSO date in YYYYMMDD format (required)
    pub qso_date: String,
    /// Time on in HHMMSS or HHMM format (required)
    pub time_on: String,
    /// Operating band (required)
    pub band: String,
    /// Operating mode (required)
    pub mode: String,

    // Common optional fields
    pub station_callsign: Option<String>,
    pub freq: Option<String>,
    pub rst_sent: Option<String>,
    pub rst_rcvd: Option<String>,
    pub time_off: Option<String>,
    pub gridsquare: Option<String>,
    pub my_gridsquare: Option<String>,
    pub my_sig: Option<String>,
    pub my_sig_info: Option<String>,
    pub sig: Option<String>,
    pub sig_info: Option<String>,
    pub comment: Option<String>,
    pub my_state: Option<String>,
    pub my_cnty: Option<String>,
    pub state: Option<String>,
    pub cnty: Option<String>,

    /// All other fields (including APP_* fields) for lossless round-trip
    #[serde(flatten)]
    pub other_fields: HashMap<String, String>,
}

impl Qso {
    /// Create a unique key for deduplication (call + date + time + band + mode)
    pub fn dedup_key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.call.to_uppercase(),
            self.qso_date,
            self.time_on,
            self.band.to_lowercase(),
            self.mode.to_uppercase()
        )
    }

    /// Normalize the time_on to 6 digits (HHMMSS)
    pub fn normalized_time(&self) -> String {
        if self.time_on.len() == 4 {
            format!("{}00", self.time_on)
        } else {
            self.time_on.clone()
        }
    }

    /// Check if this is a POTA activation QSO
    pub fn is_pota(&self) -> bool {
        self.my_sig
            .as_ref()
            .is_some_and(|s| s.eq_ignore_ascii_case("POTA"))
    }
}
