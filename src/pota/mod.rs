//! POTA (Parks on the Air) ADIF export functionality.
//!
//! Groups QSOs by UTC date and park reference, generating separate
//! ADIF files suitable for upload to pota.app.

use chrono::NaiveDate;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::info;

use crate::adif::Qso;
use crate::Result;

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
        let mut output = String::new();

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
        let mut record = String::new();

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
}
