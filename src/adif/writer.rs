use super::{AdifHeader, Qso};

/// Write QSOs to ADIF format
pub fn write_adif(header: Option<&AdifHeader>, qsos: &[Qso]) -> String {
    let mut output = String::new();

    // Write header
    output.push_str("ADIF Export from LogbookSync\n");
    output.push_str(&format_field("ADIF_VER", "3.1.4"));
    output.push_str(&format_field("PROGRAMID", "LogbookSync"));
    output.push_str(&format_field("PROGRAMVERSION", env!("CARGO_PKG_VERSION")));

    if let Some(h) = header {
        for (name, value) in &h.fields {
            if name != "PROGRAMID" && name != "PROGRAMVERSION" && name != "ADIF_VER" {
                output.push_str(&format_field(name, value));
            }
        }
    }

    output.push_str("<EOH>\n\n");

    // Write QSO records
    for qso in qsos {
        output.push_str(&write_qso(qso));
        output.push('\n');
    }

    output
}

/// Write QSOs to ADIF format for POTA activation upload
/// This includes a descriptive header matching the Ham2K format
pub fn write_pota_adif(callsign: &str, park_ref: &str, date: &str, qsos: &[Qso]) -> String {
    let mut output = String::new();

    // Format date for display (YYYYMMDD -> YYYY-MM-DD)
    let display_date = if date.len() == 8 {
        format!("{}-{}-{}", &date[0..4], &date[4..6], &date[6..8])
    } else {
        date.to_string()
    };

    // Write header matching Ham2K format (each field on its own line)
    output.push_str(&format!(
        "ADIF for {}: POTA {} on {}\n",
        callsign, park_ref, display_date
    ));
    output.push_str(&format_field("ADIF_VER", "3.1.4"));
    output.push('\n');
    output.push_str(&format_field("PROGRAMID", "LogbookSync"));
    output.push('\n');
    output.push_str(&format_field("PROGRAMVERSION", env!("CARGO_PKG_VERSION")));
    output.push('\n');
    output.push_str("<EOH>\n");

    // Write QSO records
    for qso in qsos {
        output.push_str(&write_qso(qso));
        output.push('\n');
    }

    output
}

/// Format a single QSO record as ADIF
fn write_qso(qso: &Qso) -> String {
    let mut output = String::new();

    // Required fields
    output.push_str(&format_field("CALL", &qso.call));
    output.push_str(&format_field("QSO_DATE", &qso.qso_date));
    output.push_str(&format_field("TIME_ON", &qso.time_on));
    output.push_str(&format_field("BAND", &qso.band));
    output.push_str(&format_field("MODE", &qso.mode));

    // Optional fields
    if let Some(ref v) = qso.station_callsign {
        output.push_str(&format_field("STATION_CALLSIGN", v));
    }
    if let Some(ref v) = qso.freq {
        output.push_str(&format_field("FREQ", v));
    }
    if let Some(ref v) = qso.rst_sent {
        output.push_str(&format_field("RST_SENT", v));
    }
    if let Some(ref v) = qso.rst_rcvd {
        output.push_str(&format_field("RST_RCVD", v));
    }
    if let Some(ref v) = qso.time_off {
        output.push_str(&format_field("TIME_OFF", v));
    }
    if let Some(ref v) = qso.gridsquare {
        output.push_str(&format_field("GRIDSQUARE", v));
    }
    if let Some(ref v) = qso.my_gridsquare {
        output.push_str(&format_field("MY_GRIDSQUARE", v));
    }
    if let Some(ref v) = qso.my_sig {
        output.push_str(&format_field("MY_SIG", v));
    }
    if let Some(ref v) = qso.my_sig_info {
        output.push_str(&format_field("MY_SIG_INFO", v));
    }
    if let Some(ref v) = qso.sig {
        output.push_str(&format_field("SIG", v));
    }
    if let Some(ref v) = qso.sig_info {
        output.push_str(&format_field("SIG_INFO", v));
    }
    if let Some(ref v) = qso.comment {
        output.push_str(&format_field("COMMENT", v));
    }
    if let Some(ref v) = qso.my_state {
        output.push_str(&format_field("MY_STATE", v));
    }
    if let Some(ref v) = qso.my_cnty {
        output.push_str(&format_field("MY_CNTY", v));
    }
    if let Some(ref v) = qso.state {
        output.push_str(&format_field("STATE", v));
    }
    if let Some(ref v) = qso.cnty {
        output.push_str(&format_field("CNTY", v));
    }

    // Other fields (for lossless round-trip)
    for (name, value) in &qso.other_fields {
        output.push_str(&format_field(name, value));
    }

    output.push_str("<EOR>\n");
    output
}

/// Format a single ADIF field
fn format_field(name: &str, value: &str) -> String {
    format!("<{}:{}>{}", name.to_uppercase(), value.len(), value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_format_field() {
        assert_eq!(format_field("CALL", "W1AW"), "<CALL:4>W1AW");
        assert_eq!(format_field("qso_date", "20241201"), "<QSO_DATE:8>20241201");
    }

    #[test]
    fn test_write_minimal_qso() {
        let qso = Qso {
            call: "W1AW".to_string(),
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
        };

        let output = write_qso(&qso);
        assert!(output.contains("<CALL:4>W1AW"));
        assert!(output.contains("<QSO_DATE:8>20241201"));
        assert!(output.contains("<TIME_ON:4>1430"));
        assert!(output.contains("<BAND:3>20m"));
        assert!(output.contains("<MODE:2>CW"));
        assert!(output.contains("<EOR>"));
    }

    #[test]
    fn test_roundtrip() {
        use crate::adif::parse_adif;

        let qso = Qso {
            call: "K4SWL".to_string(),
            qso_date: "20241201".to_string(),
            time_on: "143527".to_string(),
            band: "20m".to_string(),
            mode: "CW".to_string(),
            station_callsign: Some("W1ABC".to_string()),
            freq: Some("14.06200".to_string()),
            rst_sent: Some("599".to_string()),
            rst_rcvd: Some("579".to_string()),
            time_off: None,
            gridsquare: None,
            my_gridsquare: Some("FN31pr".to_string()),
            my_sig: Some("POTA".to_string()),
            my_sig_info: Some("K-1234".to_string()),
            sig: Some("POTA".to_string()),
            sig_info: Some("K-5678".to_string()),
            comment: None,
            my_state: None,
            my_cnty: None,
            state: None,
            cnty: None,
            other_fields: HashMap::new(),
        };

        let output = write_adif(None, std::slice::from_ref(&qso));
        let parsed = parse_adif(&output).unwrap();

        assert_eq!(parsed.qsos.len(), 1);
        let parsed_qso = &parsed.qsos[0];
        assert_eq!(parsed_qso.call, qso.call);
        assert_eq!(parsed_qso.qso_date, qso.qso_date);
        assert_eq!(parsed_qso.my_sig, qso.my_sig);
        assert_eq!(parsed_qso.my_sig_info, qso.my_sig_info);
    }
}
