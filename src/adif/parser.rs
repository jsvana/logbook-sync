use super::Qso;
use crate::{Error, Result};
use std::collections::HashMap;

/// ADIF file header information
#[derive(Debug, Clone, Default)]
pub struct AdifHeader {
    pub fields: HashMap<String, String>,
}

/// Result of parsing an ADIF file
#[derive(Debug)]
pub struct AdifRecord {
    pub header: AdifHeader,
    pub qsos: Vec<Qso>,
    pub warnings: Vec<String>,
}

/// Parse an ADIF file content into structured records
pub fn parse_adif(content: &str) -> Result<AdifRecord> {
    let mut header = AdifHeader::default();
    let mut qsos = Vec::new();
    let mut warnings = Vec::new();

    // Find the end of header marker
    let content_upper = content.to_uppercase();
    let (header_content, body_content) = if let Some(eoh_pos) = content_upper.find("<EOH>") {
        let header_end = eoh_pos + 5; // length of "<EOH>"
        (&content[..eoh_pos], &content[header_end..])
    } else {
        // No header, treat entire content as body
        ("", content)
    };

    // Parse header fields
    if !header_content.is_empty() {
        for (name, value) in parse_fields(header_content) {
            header.fields.insert(name, value);
        }
    }

    // Parse QSO records
    let body_upper = body_content.to_uppercase();
    let mut last_end = 0;

    while let Some(eor_pos) = body_upper[last_end..].find("<EOR>") {
        let record_content = &body_content[last_end..last_end + eor_pos];
        last_end = last_end + eor_pos + 5; // Move past <EOR>

        match parse_qso_record(record_content) {
            Ok(qso) => qsos.push(qso),
            Err(e) => warnings.push(format!("Failed to parse QSO: {}", e)),
        }
    }

    Ok(AdifRecord {
        header,
        qsos,
        warnings,
    })
}

/// Parse fields from a block of ADIF content
fn parse_fields(content: &str) -> Vec<(String, String)> {
    let mut fields = Vec::new();
    let mut pos = 0;
    let bytes = content.as_bytes();

    while pos < bytes.len() {
        // Find opening <
        let start = match content[pos..].find('<') {
            Some(p) => pos + p,
            None => break,
        };

        // Find closing >
        let end = match content[start..].find('>') {
            Some(p) => start + p,
            None => break,
        };

        let tag_content = &content[start + 1..end];

        // Parse tag: NAME:LENGTH or NAME:LENGTH:TYPE
        let parts: Vec<&str> = tag_content.split(':').collect();
        if parts.is_empty() {
            pos = end + 1;
            continue;
        }

        let field_name = parts[0].to_uppercase();

        // Skip EOR/EOH markers
        if field_name == "EOR" || field_name == "EOH" {
            pos = end + 1;
            continue;
        }

        if parts.len() >= 2 {
            // Has a length specifier
            if let Ok(len) = parts[1].parse::<usize>() {
                let value_start = end + 1;
                let value_end = (value_start + len).min(content.len());
                let value = content[value_start..value_end].to_string();
                fields.push((field_name, value));
                pos = value_end;
            } else {
                pos = end + 1;
            }
        } else {
            // No length - skip
            pos = end + 1;
        }
    }

    fields
}

/// Parse a single QSO record into a Qso struct
fn parse_qso_record(content: &str) -> Result<Qso> {
    let fields: HashMap<String, String> = parse_fields(content).into_iter().collect();

    // Required fields
    let call = fields
        .get("CALL")
        .ok_or_else(|| Error::AdifParse("Missing CALL field".to_string()))?
        .clone();

    let qso_date = fields
        .get("QSO_DATE")
        .ok_or_else(|| Error::AdifParse("Missing QSO_DATE field".to_string()))?
        .clone();

    let time_on = fields
        .get("TIME_ON")
        .ok_or_else(|| Error::AdifParse("Missing TIME_ON field".to_string()))?
        .clone();

    let band = fields
        .get("BAND")
        .ok_or_else(|| Error::AdifParse("Missing BAND field".to_string()))?
        .clone();

    let mode = fields
        .get("MODE")
        .ok_or_else(|| Error::AdifParse("Missing MODE field".to_string()))?
        .clone();

    // Build other_fields with remaining fields
    let known_fields = [
        "CALL",
        "QSO_DATE",
        "TIME_ON",
        "BAND",
        "MODE",
        "STATION_CALLSIGN",
        "FREQ",
        "RST_SENT",
        "RST_RCVD",
        "TIME_OFF",
        "GRIDSQUARE",
        "MY_GRIDSQUARE",
        "MY_SIG",
        "MY_SIG_INFO",
        "SIG",
        "SIG_INFO",
        "COMMENT",
        "MY_STATE",
        "MY_CNTY",
        "STATE",
        "CNTY",
    ];

    let other_fields: HashMap<String, String> = fields
        .iter()
        .filter(|(k, _)| !known_fields.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    Ok(Qso {
        call,
        qso_date,
        time_on,
        band,
        mode,
        station_callsign: fields.get("STATION_CALLSIGN").cloned(),
        freq: fields.get("FREQ").cloned(),
        rst_sent: fields.get("RST_SENT").cloned(),
        rst_rcvd: fields.get("RST_RCVD").cloned(),
        time_off: fields.get("TIME_OFF").cloned(),
        gridsquare: fields.get("GRIDSQUARE").cloned(),
        my_gridsquare: fields.get("MY_GRIDSQUARE").cloned(),
        my_sig: fields.get("MY_SIG").cloned(),
        my_sig_info: fields.get("MY_SIG_INFO").cloned(),
        sig: fields.get("SIG").cloned(),
        sig_info: fields.get("SIG_INFO").cloned(),
        comment: fields.get("COMMENT").cloned(),
        my_state: fields.get("MY_STATE").cloned(),
        my_cnty: fields.get("MY_CNTY").cloned(),
        state: fields.get("STATE").cloned(),
        cnty: fields.get("CNTY").cloned(),
        other_fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_adif() {
        let content = "<EOH>\n<CALL:4>W1AW<QSO_DATE:8>20241201<TIME_ON:4>1430<BAND:3>20m<MODE:2>CW<EOR>";
        let result = parse_adif(content).unwrap();

        assert_eq!(result.qsos.len(), 1);
        let qso = &result.qsos[0];
        assert_eq!(qso.call, "W1AW");
        assert_eq!(qso.qso_date, "20241201");
        assert_eq!(qso.time_on, "1430");
        assert_eq!(qso.band, "20m");
        assert_eq!(qso.mode, "CW");
    }

    #[test]
    fn test_parse_pota_adif() {
        let content = r#"ADIF Export
<PROGRAMID:10>Ham2K PoLo<PROGRAMVERSION:5>1.2.3<EOH>

<CALL:5>K4SWL
<STATION_CALLSIGN:5>W1ABC
<QSO_DATE:8>20241201
<TIME_ON:6>143527
<BAND:3>20m
<FREQ:8>14.06200
<MODE:2>CW
<RST_SENT:3>599
<RST_RCVD:3>579
<MY_SIG:4>POTA
<MY_SIG_INFO:6>K-1234
<SIG:4>POTA
<SIG_INFO:6>K-5678
<EOR>"#;

        let result = parse_adif(content).unwrap();

        assert_eq!(result.header.fields.get("PROGRAMID"), Some(&"Ham2K PoLo".to_string()));
        assert_eq!(result.qsos.len(), 1);

        let qso = &result.qsos[0];
        assert_eq!(qso.call, "K4SWL");
        assert_eq!(qso.station_callsign, Some("W1ABC".to_string()));
        assert_eq!(qso.my_sig, Some("POTA".to_string()));
        assert_eq!(qso.my_sig_info, Some("K-1234".to_string()));
        assert!(qso.is_pota());
    }

    #[test]
    fn test_parse_multiple_qsos() {
        let content = r#"<EOH>
<CALL:4>W1AW<QSO_DATE:8>20241201<TIME_ON:4>1430<BAND:3>20m<MODE:2>CW<EOR>
<CALL:5>N3VEM<QSO_DATE:8>20241201<TIME_ON:4>1445<BAND:3>40m<MODE:3>SSB<EOR>"#;

        let result = parse_adif(content).unwrap();
        assert_eq!(result.qsos.len(), 2);
        assert_eq!(result.qsos[0].call, "W1AW");
        assert_eq!(result.qsos[1].call, "N3VEM");
    }

    #[test]
    fn test_dedup_key() {
        let qso = Qso {
            call: "w1aw".to_string(),
            qso_date: "20241201".to_string(),
            time_on: "1430".to_string(),
            band: "20M".to_string(),
            mode: "cw".to_string(),
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

        assert_eq!(qso.dedup_key(), "W1AW:20241201:1430:20m:CW");
    }
}
