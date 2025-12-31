//! POTA (Parks on the Air) ADIF export and upload functionality.
//!
//! Groups QSOs by UTC date and park reference, generating separate
//! ADIF files suitable for upload to pota.app.

pub mod auth_service;
pub mod browser;

pub use auth_service::PotaAuthServiceClient;
pub use browser::{
    BrowserProgress, PotaCachedTokens, PotaRemoteActivation, PotaRemoteQso, PotaUploadJob,
    PotaUploader, ProgressCallback, UploadResult, get_activation_qsos, get_activations,
    get_all_activation_qsos,
};

use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::{info, warn};

use crate::adif::{Qso, write_pota_adif};
use crate::{Error, Result};

/// Derive US state from Maidenhead grid square (4 or 6 character).
/// Returns the most likely state abbreviation for US grid squares.
/// This is approximate - grid squares can span state boundaries.
fn grid_to_us_state(grid: &str) -> Option<&'static str> {
    if grid.len() < 4 {
        return None;
    }
    let field = &grid[..2].to_uppercase();
    let square = &grid[2..4];

    // Map field + square to most likely US state
    // This covers the continental US - not exhaustive but handles common cases
    match (field.as_str(), square) {
        // California
        ("CM", "87") | ("CM", "88") | ("CM", "97") | ("CM", "98") => Some("CA"),
        ("DM", "03")
        | ("DM", "04")
        | ("DM", "05")
        | ("DM", "06")
        | ("DM", "07")
        | ("DM", "12")
        | ("DM", "13")
        | ("DM", "14") => Some("CA"),
        // Arizona
        ("DM", "31") | ("DM", "32") | ("DM", "33") | ("DM", "41") | ("DM", "42") | ("DM", "43") => {
            Some("AZ")
        }
        // Nevada
        ("DM", "08") | ("DM", "09") | ("DM", "18") | ("DM", "19") | ("DM", "26") | ("DM", "27") => {
            Some("NV")
        }
        // Oregon/Washington
        ("CN", "74")
        | ("CN", "75")
        | ("CN", "84")
        | ("CN", "85")
        | ("CN", "86")
        | ("CN", "87")
        | ("CN", "88") => Some("WA"),
        ("CN", "73") | ("CN", "82") | ("CN", "83") | ("CN", "93") | ("CN", "94") | ("CN", "95") => {
            Some("OR")
        }
        // Texas
        ("EM", "00")
        | ("EM", "01")
        | ("EM", "10")
        | ("EM", "11")
        | ("EM", "12")
        | ("EM", "13")
        | ("EM", "20")
        | ("EM", "21") => Some("TX"),
        // Florida
        ("EL", "87") | ("EL", "88") | ("EL", "96") | ("EL", "97") | ("EL", "98") => Some("FL"),
        // New York
        ("FN", "21") | ("FN", "30") | ("FN", "31") => Some("NY"),
        // Pennsylvania / New York border - default to NY
        ("FN", "10") | ("FN", "11") | ("FN", "20") => Some("NY"),
        // Colorado
        ("DM", "69") | ("DM", "79") | ("DM", "78") | ("DN", "60") | ("DN", "70") => Some("CO"),
        // Other common fields - return approximate state
        ("CM", _) => Some("CA"),
        ("DM", _) => Some("CA"), // Could be CA, AZ, NM, NV - default to CA for POTA
        ("CN", _) => Some("WA"), // Pacific Northwest
        ("DN", _) => Some("CO"), // Rocky Mountain area
        ("EM", _) => Some("TX"), // South central
        ("EN", _) => Some("WI"), // Upper Midwest
        ("EL", _) => Some("FL"), // Southeast
        ("FM", _) => Some("VA"), // Mid-Atlantic
        ("FN", _) => Some("NY"), // Northeast
        _ => None,
    }
}

/// Key for grouping QSOs: (UTC Date, Park Reference)
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct PotaGroupKey {
    pub date: NaiveDate,
    pub park_ref: String,
}

impl PotaGroupKey {
    /// Generate POTA-compliant filename
    /// Format: CALLSIGN@PARK-YYMMDD.adi
    pub fn to_filename(&self, callsign: &str) -> String {
        let date_str = self.date.format("%y%m%d").to_string();
        // Replace any characters that might be problematic in filenames
        let safe_park = self.park_ref.replace('/', "-");
        format!("{}@{}-{}.adi", callsign.to_uppercase(), safe_park, date_str)
    }
}

/// POTA export service
pub struct PotaExporter {
    output_dir: PathBuf,
    default_callsign: String,
}

impl PotaExporter {
    pub fn new(output_dir: PathBuf, default_callsign: String) -> Self {
        Self {
            output_dir,
            default_callsign,
        }
    }

    /// Check if a QSO is a POTA activation QSO
    pub fn is_pota_qso(qso: &Qso) -> bool {
        qso.is_pota() && qso.get_pota_ref().is_some()
    }

    /// Extract the park reference from a QSO
    pub fn get_park_ref(qso: &Qso) -> Option<&str> {
        qso.get_pota_ref()
    }

    /// Group QSOs by UTC date and park reference, deduplicating by call/date/time/band/mode
    pub fn group_qsos<'a>(
        &self,
        qsos: impl Iterator<Item = &'a Qso>,
    ) -> HashMap<PotaGroupKey, Vec<&'a Qso>> {
        use std::collections::HashSet;

        let mut groups: HashMap<PotaGroupKey, Vec<&Qso>> = HashMap::new();
        // Track seen QSOs globally to avoid duplicates across all groups
        let mut seen: HashSet<String> = HashSet::new();

        for qso in qsos {
            if !Self::is_pota_qso(qso) {
                continue;
            }

            let park_ref = match Self::get_park_ref(qso) {
                Some(r) => r.to_uppercase(),
                None => continue,
            };

            // Parse QSO date (YYYYMMDD format)
            let date = NaiveDate::parse_from_str(&qso.qso_date, "%Y%m%d")
                .or_else(|_| NaiveDate::parse_from_str(&qso.qso_date, "%Y-%m-%d"))
                .ok();

            let date = match date {
                Some(d) => d,
                None => continue,
            };

            // Deduplicate by call/date/time/band/mode within each park/date group
            let dedup_key = format!("{}:{}", park_ref, qso.dedup_key());
            if seen.contains(&dedup_key) {
                continue;
            }
            seen.insert(dedup_key);

            let key = PotaGroupKey { date, park_ref };
            groups.entry(key).or_default().push(qso);
        }

        groups
    }

    /// Export QSOs to POTA ADIF files
    ///
    /// Returns the list of files created
    pub fn export(&self, qsos: &[Qso]) -> Result<Vec<PathBuf>> {
        // Ensure output directory exists
        fs::create_dir_all(&self.output_dir)?;

        let groups = self.group_qsos(qsos.iter());
        let mut created_files = Vec::new();

        for (key, group_qsos) in groups {
            // Determine callsign for filename
            let callsign = group_qsos
                .first()
                .and_then(|q| q.station_callsign.as_deref())
                .unwrap_or(&self.default_callsign);

            let filename = key.to_filename(callsign);
            let filepath = self.output_dir.join(&filename);

            // Generate ADIF content
            let adif = self.generate_pota_adif(&group_qsos, callsign, &key.park_ref, &key.date);

            // Write to file
            fs::write(&filepath, adif)?;

            info!(
                qsos = group_qsos.len(),
                park = %key.park_ref,
                date = %key.date,
                file = %filepath.display(),
                "Exported POTA QSOs"
            );

            created_files.push(filepath);
        }

        Ok(created_files)
    }

    /// Generate POTA-compliant ADIF content
    fn generate_pota_adif(
        &self,
        qsos: &[&Qso],
        activator: &str,
        park: &str,
        date: &NaiveDate,
    ) -> String {
        // Pre-allocate string buffer: ~300 bytes header + ~500 bytes per QSO
        let estimated_size = 300 + (qsos.len() * 500);
        let mut output = String::with_capacity(estimated_size);

        // Header with activator, park, and date
        let date_str = date.format("%Y-%m-%d").to_string();
        output.push_str(&format!(
            "ADIF for {}: POTA {} on {}\n",
            activator, park, date_str
        ));
        output.push_str(&format_field("ADIF_VER", "3.1.5"));
        output.push_str(&format_field("PROGRAMID", "logbook-sync"));
        output.push_str(&format_field("PROGRAMVERSION", env!("CARGO_PKG_VERSION")));

        let timestamp = chrono::Utc::now().format("%Y%m%d %H%M%S").to_string();
        output.push_str(&format_field("CREATED_TIMESTAMP", &timestamp));
        output.push_str("<EOH>\n\n");

        // QSO records
        for qso in qsos {
            output.push_str(&self.format_qso_record(qso, park));
            output.push('\n');
        }

        output
    }

    /// Format a single QSO record for POTA ADIF
    /// Field order follows Ham2K Portable Logger format for compatibility
    /// The park parameter ensures MY_SIG, MY_SIG_INFO, MY_POTA_REF, and QSLMSG are always present
    fn format_qso_record(&self, qso: &Qso, park: &str) -> String {
        // Pre-allocate ~500 bytes for a typical QSO record
        let mut record = String::with_capacity(500);

        // Core QSO fields
        record.push_str(&format_field("CALL", &qso.call));
        record.push_str(&format_field("MODE", &qso.mode));
        record.push_str(&format_field("BAND", &qso.band));
        if let Some(ref v) = qso.freq {
            record.push_str(&format_field("FREQ", v));
        }
        record.push_str(&format_field("QSO_DATE", &qso.qso_date));
        record.push_str(&format_field("TIME_ON", &qso.time_on));

        // Signal reports
        if let Some(ref v) = qso.rst_rcvd {
            record.push_str(&format_field("RST_RCVD", v));
        }
        if let Some(ref v) = qso.rst_sent {
            record.push_str(&format_field("RST_SENT", v));
        }

        // Station info
        if let Some(ref v) = qso.station_callsign {
            record.push_str(&format_field("STATION_CALLSIGN", v));
        }
        if let Some(v) = qso.other_fields.get("OPERATOR") {
            record.push_str(&format_field("OPERATOR", v));
        }

        // Grid squares
        if let Some(ref v) = qso.gridsquare {
            record.push_str(&format_field("GRIDSQUARE", v));
        }
        if let Some(ref v) = qso.my_gridsquare {
            record.push_str(&format_field("MY_GRIDSQUARE", v));
        }

        // Contacted station info from other_fields
        if let Some(v) = qso.other_fields.get("NAME") {
            record.push_str(&format_field("NAME", v));
        }
        if let Some(v) = qso.other_fields.get("DXCC") {
            record.push_str(&format_field("DXCC", v));
        }
        if let Some(v) = qso.other_fields.get("QTH") {
            record.push_str(&format_field("QTH", v));
        }
        if let Some(ref v) = qso.state {
            record.push_str(&format_field("STATE", v));
        }
        if let Some(v) = qso.other_fields.get("CQZ") {
            record.push_str(&format_field("CQZ", v));
        }
        if let Some(v) = qso.other_fields.get("ITUZ") {
            record.push_str(&format_field("ITUZ", v));
        }

        // QSL message - use existing or generate from park reference
        let qslmsg = qso
            .other_fields
            .get("QSLMSG")
            .map(|s| s.as_str())
            .unwrap_or("");
        if !qslmsg.is_empty() {
            record.push_str(&format_field("QSLMSG", qslmsg));
        } else {
            record.push_str(&format_field("QSLMSG", &format!("POTA {}", park)));
        }

        // Hunter POTA info (contacted station at a park)
        if let Some(ref v) = qso.sig {
            record.push_str(&format_field("SIG", v));
        }
        if let Some(ref v) = qso.sig_info {
            record.push_str(&format_field("SIG_INFO", v));
        }
        if let Some(v) = qso.other_fields.get("POTA_REF") {
            record.push_str(&format_field("POTA_REF", v));
        }

        // Activator POTA info (my station at a park) - always include for POTA exports
        let my_sig = qso.my_sig.as_deref().unwrap_or("POTA");
        record.push_str(&format_field("MY_SIG", my_sig));

        let my_sig_info = qso.my_sig_info.as_deref().unwrap_or(park);
        record.push_str(&format_field("MY_SIG_INFO", my_sig_info));

        let my_pota_ref = qso
            .other_fields
            .get("MY_POTA_REF")
            .map(|s| s.as_str())
            .unwrap_or(park);
        record.push_str(&format_field("MY_POTA_REF", my_pota_ref));

        if let Some(v) = qso.other_fields.get("MY_WWFF_REF") {
            record.push_str(&format_field("MY_WWFF_REF", v));
        }

        // My location info
        if let Some(ref v) = qso.my_state {
            record.push_str(&format_field("MY_STATE", v));
        }
        if let Some(ref v) = qso.my_cnty {
            record.push_str(&format_field("MY_CNTY", v));
        }

        // Comment
        if let Some(ref v) = qso.comment {
            record.push_str(&format_field("COMMENT", v));
        }

        // End of record
        record.push_str("<EOR>\n");
        record
    }
}

/// Format a single ADIF field
fn format_field(name: &str, value: &str) -> String {
    format!("<{}:{}>{}", name.to_uppercase(), value.len(), value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_pota_qso(call: &str, date: &str, park: &str) -> Qso {
        Qso {
            call: call.to_string(),
            qso_date: date.to_string(),
            time_on: "143000".to_string(),
            band: "20m".to_string(),
            mode: "SSB".to_string(),
            station_callsign: Some("W6JSV".to_string()),
            freq: Some("14.250".to_string()),
            rst_sent: Some("59".to_string()),
            rst_rcvd: Some("59".to_string()),
            time_off: None,
            gridsquare: None,
            my_gridsquare: Some("CM87".to_string()),
            my_sig: Some("POTA".to_string()),
            my_sig_info: Some(park.to_string()),
            sig: None,
            sig_info: None,
            comment: None,
            my_state: Some("CA".to_string()),
            my_cnty: None,
            state: None,
            cnty: None,
            other_fields: HashMap::new(),
        }
    }

    #[test]
    fn test_is_pota_qso() {
        let mut qso = make_pota_qso("W1AW", "20240115", "US-3315");
        assert!(PotaExporter::is_pota_qso(&qso));

        // Not POTA without my_sig
        qso.my_sig = None;
        assert!(!PotaExporter::is_pota_qso(&qso));

        // Not POTA without my_sig_info
        qso.my_sig = Some("POTA".to_string());
        qso.my_sig_info = None;
        assert!(!PotaExporter::is_pota_qso(&qso));

        // Case insensitive
        qso.my_sig = Some("pota".to_string());
        qso.my_sig_info = Some("US-3315".to_string());
        assert!(PotaExporter::is_pota_qso(&qso));
    }

    #[test]
    fn test_group_key_filename() {
        let key = PotaGroupKey {
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            park_ref: "US-3315".to_string(),
        };

        assert_eq!(key.to_filename("W6JSV"), "W6JSV@US-3315-240115.adi");
        assert_eq!(key.to_filename("w6jsv"), "W6JSV@US-3315-240115.adi");
    }

    #[test]
    fn test_grouping() {
        let exporter = PotaExporter::new(PathBuf::from("/tmp"), "W6JSV".to_string());

        let qsos = [
            make_pota_qso("W1AW", "20240115", "US-3315"),
            make_pota_qso("N3VEM", "20240115", "US-3315"),
            make_pota_qso("K0ABC", "20240116", "US-3315"), // Different date
            make_pota_qso("W5XYZ", "20240115", "US-0001"), // Different park
        ];

        let groups = exporter.group_qsos(qsos.iter());

        // Should have 3 groups:
        // 1. US-3315 on 2024-01-15 (2 QSOs)
        // 2. US-3315 on 2024-01-16 (1 QSO)
        // 3. US-0001 on 2024-01-15 (1 QSO)
        assert_eq!(groups.len(), 3);

        let key1 = PotaGroupKey {
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            park_ref: "US-3315".to_string(),
        };
        assert_eq!(groups.get(&key1).unwrap().len(), 2);

        let key2 = PotaGroupKey {
            date: NaiveDate::from_ymd_opt(2024, 1, 16).unwrap(),
            park_ref: "US-3315".to_string(),
        };
        assert_eq!(groups.get(&key2).unwrap().len(), 1);

        let key3 = PotaGroupKey {
            date: NaiveDate::from_ymd_opt(2024, 1, 15).unwrap(),
            park_ref: "US-0001".to_string(),
        };
        assert_eq!(groups.get(&key3).unwrap().len(), 1);
    }

    #[test]
    fn test_non_pota_qsos_filtered() {
        let exporter = PotaExporter::new(PathBuf::from("/tmp"), "W6JSV".to_string());

        let mut non_pota = make_pota_qso("W1AW", "20240115", "US-3315");
        non_pota.my_sig = Some("SOTA".to_string()); // Not POTA

        let qsos = [non_pota];
        let groups = exporter.group_qsos(qsos.iter());

        assert!(groups.is_empty());
    }

    #[test]
    fn test_format_field() {
        assert_eq!(format_field("CALL", "W1AW"), "<CALL:4>W1AW");
        assert_eq!(format_field("qso_date", "20241201"), "<QSO_DATE:8>20241201");
    }

    #[test]
    fn test_valid_park_ref() {
        assert!(is_valid_park_ref("US-0001"));
        assert!(is_valid_park_ref("VE-1234"));
        assert!(is_valid_park_ref("JA-0001"));
        assert!(is_valid_park_ref("JAFF-0001")); // 4-letter entities
        assert!(!is_valid_park_ref("US0001")); // No hyphen
        assert!(!is_valid_park_ref("US-001")); // Only 3 digits
        assert!(!is_valid_park_ref("US-00001")); // 5 digits
        assert!(!is_valid_park_ref("1S-0001")); // Number in entity
        assert!(!is_valid_park_ref("us-0001")); // Lowercase entity
    }

    #[test]
    fn test_group_activations() {
        let qsos = vec![
            // First activation: US-0001 on day 1
            make_pota_qso("W1ABC", "20240101", "US-0001"),
            make_pota_qso("W2DEF", "20240101", "US-0001"),
            // Second activation: US-0002 on day 1
            make_pota_qso("W3GHI", "20240101", "US-0002"),
            // Third activation: US-0001 on day 2
            make_pota_qso("W4JKL", "20240102", "US-0001"),
        ];

        let (activations, skipped) = group_pota_activations(&qsos);

        assert_eq!(skipped, 0);
        assert_eq!(activations.len(), 3);
    }

    #[test]
    fn test_group_activations_deduplicates() {
        let qsos = vec![
            // Same QSO appearing twice (duplicate)
            make_pota_qso("W1ABC", "20240101", "US-0001"),
            make_pota_qso("W1ABC", "20240101", "US-0001"), // Duplicate - same call/date/time/band/mode
            // Different QSO
            make_pota_qso("W2DEF", "20240101", "US-0001"),
        ];

        let (activations, skipped) = group_pota_activations(&qsos);

        assert_eq!(skipped, 0);
        assert_eq!(activations.len(), 1);
        // Should only have 2 QSOs after deduplication, not 3
        assert_eq!(activations[0].qsos.len(), 2);
    }

    #[test]
    fn test_preview_upload() {
        // Create 12 QSOs for a valid activation
        let mut qsos: Vec<Qso> = (1..=12)
            .map(|i| {
                let mut qso = make_pota_qso(&format!("W{}ABC", i), "20240101", "US-0001");
                qso.time_on = format!("12{:02}00", i);
                qso
            })
            .collect();

        // Add 5 QSOs for an invalid activation
        for i in 1..=5 {
            let mut qso = make_pota_qso(&format!("W{}DEF", i), "20240101", "US-0002");
            qso.time_on = format!("14{:02}00", i);
            qsos.push(qso);
        }

        let preview = preview_upload(&qsos);

        assert_eq!(preview.valid_activations.len(), 1);
        assert_eq!(preview.invalid_activations.len(), 1);
        assert_eq!(preview.total_qsos, 12);
        assert_eq!(preview.skipped_qsos, 0);
    }
}

// =============================================================================
// POTA Upload functionality
// =============================================================================

/// Represents a single POTA activation (grouped by park + UTC date)
#[derive(Debug, Clone, Serialize)]
pub struct PotaActivation {
    /// Park reference (e.g., "US-0001")
    pub park_ref: String,
    /// UTC date in YYYYMMDD format
    pub date: String,
    /// QSOs in this activation
    pub qsos: Vec<Qso>,
}

impl PotaActivation {
    /// Check if this is a valid activation (10+ QSOs)
    pub fn is_valid_activation(&self) -> bool {
        self.qsos.len() >= 10
    }

    /// Get a summary of this activation
    pub fn summary(&self) -> String {
        format!(
            "{} on {} ({} QSOs{})",
            self.park_ref,
            format_date(&self.date),
            self.qsos.len(),
            if self.is_valid_activation() {
                ""
            } else {
                " - NOT A VALID ACTIVATION"
            }
        )
    }
}

/// Format YYYYMMDD date to YYYY-MM-DD
fn format_date(date: &str) -> String {
    if date.len() == 8 {
        format!("{}-{}-{}", &date[0..4], &date[4..6], &date[6..8])
    } else {
        date.to_string()
    }
}

/// Result of a POTA upload preview (dry run)
#[derive(Debug, Clone, Serialize)]
pub struct PotaUploadPreview {
    /// Valid activations (10+ QSOs)
    pub valid_activations: Vec<PotaActivation>,
    /// Invalid activations (less than 10 QSOs)
    pub invalid_activations: Vec<PotaActivation>,
    /// Total QSOs that would be uploaded
    pub total_qsos: usize,
    /// QSOs that were skipped (no POTA ref, invalid data, etc.)
    pub skipped_qsos: usize,
}

/// Result of an actual POTA upload
#[derive(Debug, Clone, Serialize)]
pub struct PotaUploadResult {
    /// Number of activations uploaded
    pub activations_uploaded: usize,
    /// Total QSOs uploaded
    pub qsos_uploaded: usize,
    /// Any errors encountered
    pub errors: Vec<String>,
}

/// Group QSOs into POTA activations by park reference and UTC date
/// Deduplicates QSOs by call/date/time/band/mode within each activation
///
/// Optimized to avoid cloning QSOs during grouping - only clones when building
/// the final PotaActivation structs.
pub fn group_pota_activations(qsos: &[Qso]) -> (Vec<PotaActivation>, usize) {
    use std::collections::HashSet;

    // Group by (park_ref, date), storing indices to avoid cloning during grouping
    let mut groups: HashMap<(String, String), Vec<usize>> = HashMap::new();
    let mut seen_keys: HashMap<(String, String), HashSet<u64>> = HashMap::new();
    let mut skipped = 0;

    // Special annotation callsigns from Ham2K PoLo that shouldn't be uploaded
    const ANNOTATION_CALLS: &[&str] = &["SOLAR", "WEATHER", "NOTE"];

    for (idx, qso) in qsos.iter().enumerate() {
        // Check if this is a POTA QSO with a valid park reference
        if !qso.is_pota() {
            skipped += 1;
            continue;
        }

        // Skip Ham2K PoLo annotation records (SOLAR, WEATHER, NOTE)
        // Use case-insensitive comparison without allocation
        if ANNOTATION_CALLS
            .iter()
            .any(|&ann| qso.call.eq_ignore_ascii_case(ann))
        {
            tracing::debug!(call = %qso.call, "Skipping Ham2K PoLo annotation record");
            skipped += 1;
            continue;
        }

        let park_ref = match qso.get_pota_ref() {
            Some(r) => r.to_uppercase(),
            None => {
                skipped += 1;
                continue;
            }
        };

        // Validate park reference format (XX-NNNN or similar)
        if !is_valid_park_ref(&park_ref) {
            tracing::debug!(park_ref = %park_ref, "Skipping QSO with invalid park reference");
            skipped += 1;
            continue;
        }

        let group_key = (park_ref, qso.qso_date.clone());

        // Use hash-based deduplication to avoid String allocation
        let dedup_hash = qso.dedup_hash();

        // Check for duplicates within this activation
        let seen = seen_keys.entry(group_key.clone()).or_default();
        if seen.contains(&dedup_hash) {
            tracing::debug!(
                call = %qso.call,
                date = %qso.qso_date,
                time = %qso.time_on,
                "Skipping duplicate QSO in POTA activation"
            );
            continue;
        }
        seen.insert(dedup_hash);

        // Store index instead of cloning
        groups.entry(group_key).or_default().push(idx);
    }

    // Convert to activations - only clone QSOs here when building final struct
    let mut activations: Vec<PotaActivation> = groups
        .into_iter()
        .map(|((park_ref, date), indices)| {
            let activation_qsos = indices.into_iter().map(|i| qsos[i].clone()).collect();
            PotaActivation {
                park_ref,
                date,
                qsos: activation_qsos,
            }
        })
        .collect();

    // Sort by date (newest first), then by park reference
    activations.sort_by(|a, b| {
        b.date
            .cmp(&a.date)
            .then_with(|| a.park_ref.cmp(&b.park_ref))
    });

    (activations, skipped)
}

/// Validate a POTA park reference format
/// Valid formats: XX-NNNN, XXX-NNNN (e.g., US-0001, VE-0123, JA-1234)
fn is_valid_park_ref(park_ref: &str) -> bool {
    let parts: Vec<&str> = park_ref.split('-').collect();
    if parts.len() != 2 {
        return false;
    }

    let entity = parts[0];
    let number = parts[1];

    // Entity should be 1-4 uppercase letters
    if entity.is_empty() || entity.len() > 4 || !entity.chars().all(|c| c.is_ascii_uppercase()) {
        return false;
    }

    // Number should be 4 digits
    if number.len() != 4 || !number.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    true
}

/// Generate a preview of what would be uploaded to POTA
pub fn preview_upload(qsos: &[Qso]) -> PotaUploadPreview {
    let (activations, skipped_qsos) = group_pota_activations(qsos);

    let (valid, invalid): (Vec<_>, Vec<_>) = activations
        .into_iter()
        .partition(|a| a.is_valid_activation());

    let total_qsos = valid.iter().map(|a| a.qsos.len()).sum();

    PotaUploadPreview {
        valid_activations: valid,
        invalid_activations: invalid,
        total_qsos,
        skipped_qsos,
    }
}

/// Upload POTA activations to POTA.app using headless browser authentication
pub async fn upload_to_pota(
    email: &str,
    password: &str,
    activations: &[PotaActivation],
) -> Result<PotaUploadResult> {
    upload_to_pota_with_auth_service(email, password, activations, None, None).await
}

/// Upload POTA activations with optional remote auth service
pub async fn upload_to_pota_with_auth_service(
    email: &str,
    password: &str,
    activations: &[PotaActivation],
    auth_service_config: Option<&crate::config::PotaAuthServiceConfig>,
    progress_callback: Option<ProgressCallback>,
) -> Result<PotaUploadResult> {
    upload_to_pota_internal(
        email,
        password,
        activations,
        auth_service_config,
        progress_callback,
    )
    .await
}

/// Upload POTA activations to POTA.app with progress reporting
pub async fn upload_to_pota_with_progress(
    email: &str,
    password: &str,
    activations: &[PotaActivation],
    progress_callback: Option<ProgressCallback>,
) -> Result<PotaUploadResult> {
    upload_to_pota_internal(email, password, activations, None, progress_callback).await
}

/// Internal upload implementation with optional auth service
async fn upload_to_pota_internal(
    email: &str,
    password: &str,
    activations: &[PotaActivation],
    auth_service_config: Option<&crate::config::PotaAuthServiceConfig>,
    progress_callback: Option<ProgressCallback>,
) -> Result<PotaUploadResult> {
    if activations.is_empty() {
        return Ok(PotaUploadResult {
            activations_uploaded: 0,
            qsos_uploaded: 0,
            errors: vec![],
        });
    }

    // Create the POTA uploader with browser-based authentication
    // Cache tokens in the user's cache directory
    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("logbook-sync");
    fs::create_dir_all(&cache_dir).ok();
    let cache_path = cache_dir.join("pota_tokens.json");

    let mut uploader = PotaUploader::new(
        email.to_string(),
        password.to_string(),
        cache_path,
        true, // headless mode
    );

    // Set up remote auth service client if configured
    if let Some(auth_config) = auth_service_config {
        match auth_service::PotaAuthServiceClient::new(auth_config.clone()) {
            Ok(client) => {
                info!("Using remote POTA auth service at {}", auth_config.url);
                uploader.set_auth_service_client(client);
            }
            Err(e) => {
                warn!(
                    "Failed to create POTA auth service client: {}, falling back to local browser",
                    e
                );
            }
        }
    }

    // Set progress callback if provided
    if let Some(cb) = progress_callback {
        uploader.set_progress_callback(cb);
    }

    // Ensure we're authenticated before uploading
    info!("Authenticating with POTA.app...");
    uploader
        .ensure_authenticated_async()
        .await
        .map_err(|e| Error::Other(format!("POTA authentication failed: {}", e)))?;

    let mut activations_uploaded = 0;
    let mut qsos_uploaded = 0;
    let mut errors = Vec::new();
    let total_activations = activations.len();

    for (idx, activation) in activations.iter().enumerate() {
        // Note: We upload all activations, including incomplete ones (<10 QSOs).
        // Incomplete activations can still be submitted to POTA - they just won't
        // count as a valid activation for the activator's credit.

        // Get the station callsign from the first QSO
        let callsign = activation
            .qsos
            .first()
            .and_then(|q| q.station_callsign.as_deref())
            .unwrap_or("UNKNOWN");

        // Get location from park reference prefix + my_state
        // Park reference format: XX-NNNN (e.g., "US-4571")
        // Location format: XX-SS (e.g., "US-CA")
        let park_prefix = activation.park_ref.split('-').next().unwrap_or("US");

        // Try to get state from QSO my_state field first
        let my_state = activation
            .qsos
            .first()
            .and_then(|q| q.my_state.as_deref())
            .filter(|s| !s.is_empty());

        // Fall back to deriving state from grid square if my_state is empty
        let derived_state = if my_state.is_none() && park_prefix == "US" {
            activation
                .qsos
                .first()
                .and_then(|q| q.my_gridsquare.as_deref())
                .and_then(grid_to_us_state)
        } else {
            None
        };

        let state = my_state.or(derived_state);
        let location = match state {
            Some(s) => format!("{}-{}", park_prefix, s),
            None => {
                warn!(
                    park = %activation.park_ref,
                    "No state found for POTA upload - location may be incomplete"
                );
                park_prefix.to_string()
            }
        };

        // Generate ADIF for this activation with proper POTA header
        let adif_content = write_pota_adif(
            callsign,
            &activation.park_ref,
            &activation.date,
            &activation.qsos,
        );
        // Filename format: {callsign}@{park}-{YYMMDD}.adi (POTA convention)
        // activation.date is YYYYMMDD, we need YYMMDD (last 6 chars)
        let date_str = if activation.date.len() >= 6 {
            &activation.date[activation.date.len() - 6..]
        } else {
            &activation.date
        };
        let filename = format!("{}@{}-{}.adi", callsign, activation.park_ref, date_str);

        // Write ADIF to temp file for debugging
        let debug_path = format!("/tmp/pota_upload_{}", filename);
        if let Err(e) = std::fs::write(&debug_path, &adif_content) {
            warn!(path = %debug_path, error = %e, "Failed to write debug ADIF file");
        } else {
            info!(path = %debug_path, "Wrote debug ADIF file");
        }

        info!(
            park = %activation.park_ref,
            date = %activation.date,
            qsos = activation.qsos.len(),
            location = %location,
            callsign = %callsign,
            idx = idx + 1,
            total = total_activations,
            "Uploading activation to POTA"
        );

        match uploader
            .upload_with_retry(
                &filename,
                adif_content.into_bytes(),
                &activation.park_ref,
                &location,
                callsign,
                3,
            )
            .await
        {
            Ok(result) => {
                if result.accepted {
                    activations_uploaded += 1;
                    qsos_uploaded += activation.qsos.len();
                    info!(
                        park = %activation.park_ref,
                        date = %activation.date,
                        "Activation uploaded successfully"
                    );
                } else {
                    // File was rejected (likely duplicate)
                    let error_msg = format!(
                        "{} on {}: {}",
                        activation.park_ref,
                        format_date(&activation.date),
                        result.message
                    );
                    warn!(
                        park = %activation.park_ref,
                        date = %activation.date,
                        message = %result.message,
                        "Activation upload rejected"
                    );
                    errors.push(error_msg);
                }
            }
            Err(e) => {
                let error_msg = format!(
                    "Failed to upload {} on {}: {}",
                    activation.park_ref,
                    format_date(&activation.date),
                    e
                );
                errors.push(error_msg);
            }
        }
    }

    Ok(PotaUploadResult {
        activations_uploaded,
        qsos_uploaded,
        errors,
    })
}

/// POTA upload job information
#[derive(Debug, Clone, Serialize)]
pub struct PotaJobInfo {
    pub job_id: u64,
    pub status: String,
    pub park_ref: String,
    pub park_name: Option<String>,
    pub submitted: String,
    pub processed: Option<String>,
    /// Total QSOs in upload, can be -1 if parsing failed
    pub total_qsos: i32,
    /// Inserted QSOs, can be -1 if processing failed
    pub inserted_qsos: i32,
    pub callsign: Option<String>,
}

/// Get POTA upload job status using headless browser authentication
pub async fn get_upload_jobs(
    email: &str,
    password: &str,
    auth_service_config: Option<&crate::config::PotaAuthServiceConfig>,
) -> Result<Vec<PotaJobInfo>> {
    // Create the POTA uploader with browser-based authentication
    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("logbook-sync");
    fs::create_dir_all(&cache_dir).ok();
    let cache_path = cache_dir.join("pota_tokens.json");

    let mut uploader = PotaUploader::new(
        email.to_string(),
        password.to_string(),
        cache_path,
        true, // headless mode
    );

    // Configure auth service client if available
    if let Some(auth_config) = auth_service_config
        && let Ok(client) = auth_service::PotaAuthServiceClient::new(auth_config.clone())
    {
        uploader.set_auth_service_client(client);
    }

    let jobs = uploader
        .get_jobs()
        .await
        .map_err(|e| Error::Other(format!("Failed to get POTA jobs: {}", e)))?;

    Ok(jobs
        .into_iter()
        .map(|j| {
            let callsign = j.callsign().map(String::from);
            PotaJobInfo {
                job_id: j.job_id,
                status: j.status_string().to_string(),
                park_ref: j.reference,
                park_name: j.park_name,
                submitted: j.submitted,
                processed: j.processed,
                total_qsos: j.total,
                inserted_qsos: j.inserted,
                callsign,
            }
        })
        .collect())
}

/// Result of verifying a POTA upload job
#[derive(Debug, Clone)]
pub enum VerificationResult {
    /// Job completed successfully with QSOs inserted
    Verified { job_id: u64, inserted: i32 },
    /// Job completed but no QSOs were inserted (rejected/duplicate)
    Rejected { job_id: u64, message: String },
    /// Job failed with an error
    Failed { job_id: u64, message: String },
    /// Job is still processing (not yet complete)
    Pending,
    /// No matching job found
    NotFound,
}

/// Find a matching job from a list of POTA upload jobs
///
/// Matches by park reference, callsign, and submission time within the given window.
pub fn find_matching_job<'a>(
    jobs: &'a [PotaUploadJob],
    park_ref: &str,
    callsign: &str,
    started_at: DateTime<Utc>,
    time_window: Duration,
) -> Option<&'a PotaUploadJob> {
    jobs.iter().find(|job| {
        // Match park reference
        if job.reference != park_ref {
            return false;
        }

        // Match callsign (case-insensitive)
        let job_callsign = job.callsign_used.as_deref().unwrap_or("");
        if !job_callsign.eq_ignore_ascii_case(callsign) {
            return false;
        }

        // Match submission time within window
        // POTA job.submitted format: "2024-12-30T12:34:56Z" or similar
        if let Ok(job_submitted) = DateTime::parse_from_rfc3339(&job.submitted) {
            let job_time = job_submitted.with_timezone(&Utc);
            let diff = if job_time > started_at {
                job_time - started_at
            } else {
                started_at - job_time
            };
            diff <= time_window
        } else {
            // If we can't parse the time, don't match
            false
        }
    })
}

/// Check the status of a matched job and return verification result
pub fn check_job_status(job: &PotaUploadJob) -> VerificationResult {
    match job.status {
        2 => {
            // Completed
            if job.inserted > 0 {
                VerificationResult::Verified {
                    job_id: job.job_id,
                    inserted: job.inserted,
                }
            } else {
                VerificationResult::Rejected {
                    job_id: job.job_id,
                    message: format!("No QSOs inserted (submitted: {}, inserted: 0)", job.total),
                }
            }
        }
        0 | 1 => {
            // Pending or Processing
            VerificationResult::Pending
        }
        7 => {
            // Duplicate
            VerificationResult::Rejected {
                job_id: job.job_id,
                message: "Duplicate upload".to_string(),
            }
        }
        status => {
            // Other error states
            VerificationResult::Failed {
                job_id: job.job_id,
                message: format!("Job failed with status {}", status),
            }
        }
    }
}

/// Verify a POTA upload by polling for job completion
///
/// Polls the POTA jobs API up to `max_attempts` times with increasing delays.
/// Returns the verification result once the job completes or times out.
pub async fn verify_upload(
    uploader: &mut PotaUploader,
    park_ref: &str,
    callsign: &str,
    started_at: DateTime<Utc>,
    max_attempts: u32,
) -> Result<VerificationResult> {
    let time_window = Duration::minutes(5);
    let delays_ms = [5000, 10000, 15000]; // 5s, 10s, 15s

    for attempt in 0..max_attempts {
        // Wait before polling (except first attempt)
        if attempt > 0 {
            let delay = delays_ms
                .get(attempt as usize - 1)
                .copied()
                .unwrap_or(15000);
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }

        // Fetch current jobs
        let jobs = uploader
            .get_jobs()
            .await
            .map_err(|e| Error::Other(format!("Failed to get POTA jobs: {}", e)))?;

        // Find matching job
        if let Some(job) = find_matching_job(&jobs, park_ref, callsign, started_at, time_window) {
            let result = check_job_status(job);
            match &result {
                VerificationResult::Pending => {
                    // Job still processing, continue polling
                    info!(
                        park_ref = %park_ref,
                        job_id = job.job_id,
                        attempt = attempt + 1,
                        "Job still processing, will retry"
                    );
                    continue;
                }
                VerificationResult::Verified { job_id, inserted } => {
                    info!(
                        park_ref = %park_ref,
                        job_id = %job_id,
                        inserted = %inserted,
                        "Upload verified successfully"
                    );
                    return Ok(result);
                }
                VerificationResult::Rejected { job_id, message } => {
                    warn!(
                        park_ref = %park_ref,
                        job_id = %job_id,
                        message = %message,
                        "Upload was rejected"
                    );
                    return Ok(result);
                }
                VerificationResult::Failed { job_id, message } => {
                    warn!(
                        park_ref = %park_ref,
                        job_id = %job_id,
                        message = %message,
                        "Upload job failed"
                    );
                    return Ok(result);
                }
                VerificationResult::NotFound => unreachable!(),
            }
        } else {
            info!(
                park_ref = %park_ref,
                attempt = attempt + 1,
                "No matching job found yet, will retry"
            );
        }
    }

    // After all attempts, check one more time for the job
    let jobs = uploader
        .get_jobs()
        .await
        .map_err(|e| Error::Other(format!("Failed to get POTA jobs: {}", e)))?;

    if let Some(job) = find_matching_job(&jobs, park_ref, callsign, started_at, time_window) {
        Ok(check_job_status(job))
    } else {
        Ok(VerificationResult::NotFound)
    }
}
