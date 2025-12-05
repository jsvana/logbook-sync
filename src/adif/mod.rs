mod parser;
mod writer;

pub use parser::{AdifHeader, AdifRecord, parse_adif};
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
    /// Uses only HHMM (first 4 digits) of time since seconds often differ between sources
    pub fn dedup_key(&self) -> String {
        // Use only first 4 characters of time (HHMM) for deduplication
        // This handles both HHMM and HHMMSS formats consistently
        let time_hhmm = if self.time_on.len() >= 4 {
            &self.time_on[..4]
        } else {
            &self.time_on
        };
        format!(
            "{}:{}:{}:{}:{}",
            self.call.to_uppercase(),
            self.qso_date,
            time_hhmm,
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
        // Check MY_SIG field
        if self
            .my_sig
            .as_ref()
            .is_some_and(|s| s.eq_ignore_ascii_case("POTA"))
        {
            return true;
        }

        // Also check QSLMSG field for "POTA" pattern (e.g., "POTA US-0189")
        if let Some(qslmsg) = self.other_fields.get("QSLMSG")
            && qslmsg.to_uppercase().contains("POTA")
        {
            return true;
        }

        false
    }

    /// Extract POTA park reference from this QSO
    pub fn get_pota_ref(&self) -> Option<&str> {
        // First check MY_SIG_INFO
        if let Some(ref info) = self.my_sig_info
            && !info.is_empty()
        {
            return Some(info.as_str());
        }

        // Fall back to extracting from QSLMSG (e.g., "POTA US-0189")
        if let Some(qslmsg) = self.other_fields.get("QSLMSG") {
            // Look for pattern like "POTA XX-NNNN"
            if let Some(pos) = qslmsg.to_uppercase().find("POTA") {
                let after_pota = &qslmsg[pos + 4..].trim_start();
                // Extract the park reference (first word after "POTA")
                let park_ref = after_pota.split_whitespace().next()?;
                if !park_ref.is_empty() {
                    // Return the original case from the qslmsg
                    let start = qslmsg.find(park_ref)?;
                    return Some(&qslmsg[start..start + park_ref.len()]);
                }
            }
        }

        None
    }
}
