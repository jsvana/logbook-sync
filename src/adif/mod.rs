mod parser;
mod writer;

pub use parser::{AdifHeader, AdifRecord, parse_adif};
pub use writer::{write_adif, write_pota_adif};

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

    /// Create a hash for deduplication without allocating strings
    /// Uses the same fields as dedup_key() but returns a u64 hash instead
    pub fn dedup_hash(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();

        // Hash call (case-insensitive)
        for c in self.call.chars() {
            c.to_ascii_uppercase().hash(&mut hasher);
        }
        ':'.hash(&mut hasher);

        // Hash date as-is
        self.qso_date.hash(&mut hasher);
        ':'.hash(&mut hasher);

        // Hash time (only HHMM)
        let time_hhmm = if self.time_on.len() >= 4 {
            &self.time_on[..4]
        } else {
            &self.time_on
        };
        time_hhmm.hash(&mut hasher);
        ':'.hash(&mut hasher);

        // Hash band (case-insensitive)
        for c in self.band.chars() {
            c.to_ascii_lowercase().hash(&mut hasher);
        }
        ':'.hash(&mut hasher);

        // Hash mode (case-insensitive)
        for c in self.mode.chars() {
            c.to_ascii_uppercase().hash(&mut hasher);
        }

        hasher.finish()
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
        // Use case-insensitive search without allocation
        if let Some(qslmsg) = self.other_fields.get("QSLMSG")
            && contains_ignore_ascii_case(qslmsg, "POTA")
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
            // Look for pattern like "POTA XX-NNNN" using case-insensitive search
            if let Some(pos) = find_ignore_ascii_case(qslmsg, "POTA") {
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

/// Case-insensitive substring search without allocation
/// Returns true if `haystack` contains `needle` (case-insensitive)
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    find_ignore_ascii_case(haystack, needle).is_some()
}

/// Case-insensitive substring search without allocation
/// Returns the starting position if `haystack` contains `needle` (case-insensitive)
fn find_ignore_ascii_case(haystack: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }

    let needle_bytes = needle.as_bytes();
    let haystack_bytes = haystack.as_bytes();

    'outer: for i in 0..=(haystack_bytes.len() - needle_bytes.len()) {
        for (j, &n) in needle_bytes.iter().enumerate() {
            if !haystack_bytes[i + j].eq_ignore_ascii_case(&n) {
                continue 'outer;
            }
        }
        return Some(i);
    }
    None
}
