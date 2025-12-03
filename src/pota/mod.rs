//! POTA (Parks on the Air) ADIF export functionality.
//!
//! Groups QSOs by UTC date and park reference, generating separate
//! ADIF files suitable for upload to pota.app.

use chrono::NaiveDate;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
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
        qso.is_pota() && qso.my_sig_info.as_ref().is_some_and(|s| !s.is_empty())
    }

    /// Extract the park reference from a QSO
    pub fn get_park_ref(qso: &Qso) -> Option<&str> {
        qso.my_sig_info.as_deref()
    }

    /// Group QSOs by UTC date and park reference
    pub fn group_qsos<'a>(
        &self,
        qsos: impl Iterator<Item = &'a Qso>,
    ) -> HashMap<PotaGroupKey, Vec<&'a Qso>> {
        let mut groups: HashMap<PotaGroupKey, Vec<&Qso>> = HashMap::new();

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
            let adif = self.generate_pota_adif(&group_qsos);

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

    /// Export QSOs to a single POTA ADIF file at the specified path
    pub fn export_to_file(&self, qsos: &[Qso], output_path: &Path) -> Result<usize> {
        let pota_qsos: Vec<&Qso> = qsos.iter().filter(|q| Self::is_pota_qso(q)).collect();

        if pota_qsos.is_empty() {
            return Ok(0);
        }

        // Ensure parent directory exists
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let adif = self.generate_pota_adif(&pota_qsos);
        fs::write(output_path, adif)?;

        Ok(pota_qsos.len())
    }

    /// Generate POTA-compliant ADIF content
    fn generate_pota_adif(&self, qsos: &[&Qso]) -> String {
        let mut output = String::new();

        // Header
        output.push_str("POTA Export from logbook-sync\n");
        output.push_str(&format_field("PROGRAMID", "logbook-sync"));
        output.push_str(&format_field("PROGRAMVERSION", env!("CARGO_PKG_VERSION")));

        let timestamp = chrono::Utc::now().format("%Y%m%d %H%M%S").to_string();
        output.push_str(&format_field("CREATED_TIMESTAMP", &timestamp));
        output.push_str("<EOH>\n\n");

        // QSO records
        for qso in qsos {
            output.push_str(&self.format_qso_record(qso));
            output.push('\n');
        }

        output
    }

    /// Format a single QSO record for POTA ADIF
    fn format_qso_record(&self, qso: &Qso) -> String {
        let mut record = String::new();

        // Required fields
        if let Some(ref v) = qso.station_callsign {
            record.push_str(&format_field("STATION_CALLSIGN", v));
        }
        record.push_str(&format_field("CALL", &qso.call));
        record.push_str(&format_field("QSO_DATE", &qso.qso_date));
        record.push_str(&format_field("TIME_ON", &qso.time_on));
        record.push_str(&format_field("BAND", &qso.band));
        record.push_str(&format_field("MODE", &qso.mode));

        // Frequency
        if let Some(ref v) = qso.freq {
            record.push_str(&format_field("FREQ", v));
        }

        // Signal reports
        if let Some(ref v) = qso.rst_sent {
            record.push_str(&format_field("RST_SENT", v));
        }
        if let Some(ref v) = qso.rst_rcvd {
            record.push_str(&format_field("RST_RCVD", v));
        }

        // POTA-specific fields
        if let Some(ref v) = qso.my_sig {
            record.push_str(&format_field("MY_SIG", v));
        }
        if let Some(ref v) = qso.my_sig_info {
            record.push_str(&format_field("MY_SIG_INFO", v));
        }
        if let Some(ref v) = qso.sig {
            record.push_str(&format_field("SIG", v));
        }
        if let Some(ref v) = qso.sig_info {
            record.push_str(&format_field("SIG_INFO", v));
        }
        if let Some(ref v) = qso.my_state {
            record.push_str(&format_field("MY_STATE", v));
        }

        // Optional but useful fields
        if let Some(ref v) = qso.gridsquare {
            record.push_str(&format_field("GRIDSQUARE", v));
        }
        if let Some(ref v) = qso.my_gridsquare {
            record.push_str(&format_field("MY_GRIDSQUARE", v));
        }
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
