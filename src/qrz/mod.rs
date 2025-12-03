//! QRZ Logbook API client
//!
//! Handles communication with QRZ.com logbook API for uploading and downloading QSOs.

use crate::adif::{parse_adif, Qso};
use crate::{Error, Result};
use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, trace, warn};

const QRZ_API_URL: &str = "https://logbook.qrz.com/api";
const DEFAULT_TIMEOUT_SECS: u64 = 30;
const MAX_FETCH_PER_REQUEST: u32 = 2000;

/// QRZ Logbook API client
pub struct QrzClient {
    api_key: String,
    user_agent: String,
    client: Client,
}

/// Result of uploading a QSO
#[derive(Debug, Clone)]
pub struct UploadResult {
    pub success: bool,
    pub logid: Option<i64>,
    pub error: Option<String>,
    pub is_duplicate: bool,
}

/// QRZ logbook status
#[derive(Debug, Default, Clone)]
pub struct QrzStatus {
    pub callsign: Option<String>,
    pub count: Option<i64>,
    pub confirmed: Option<i64>,
    pub dxcc: Option<i64>,
}

/// A QSO fetched from QRZ with additional metadata
#[derive(Debug, Clone)]
pub struct FetchedQso {
    pub qso: Qso,
    pub qrz_logid: Option<i64>,
    pub lotw_qsl_rcvd: Option<String>,
    pub lotw_qsl_sent: Option<String>,
    pub qsl_rcvd: Option<String>,
    pub qsl_sent: Option<String>,
}

/// Convert a date field to Y/N status
/// QRZ returns date fields (LOTW_QSLRDATE) instead of status (LOTW_QSL_RCVD)
/// If a date is present and valid (not empty or "00000000"), treat as "Y"
fn date_to_status(date: Option<String>) -> Option<String> {
    match date {
        Some(d) if !d.is_empty() && d != "00000000" => Some("Y".to_string()),
        Some(_) => None, // Empty or all zeros means no confirmation
        None => None,
    }
}

/// Convert QRZ APP_QRZLOG_STATUS to Y/N
/// "C" = Confirmed (both parties logged to QRZ), "N" = Not confirmed
fn qrz_status_to_confirmed(status: Option<String>) -> Option<String> {
    match status.as_deref() {
        Some("C") => Some("Y".to_string()),
        _ => None,
    }
}

/// Result of a fetch operation
#[derive(Debug)]
pub struct FetchResult {
    pub qsos: Vec<FetchedQso>,
    pub total_count: usize,
    pub has_more: bool,
}

impl QrzClient {
    /// Create a new QRZ client
    pub fn new(api_key: String, user_agent: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .user_agent(&user_agent)
            .build()
            .expect("Failed to create HTTP client");

        Self {
            api_key,
            user_agent,
            client,
        }
    }

    /// Upload a single QSO to QRZ
    pub async fn upload_qso(&self, qso: &Qso) -> Result<UploadResult> {
        let adif = qso_to_adif_string(qso);

        debug!(call = %qso.call, date = %qso.qso_date, "Uploading QSO to QRZ");
        trace!(adif = %adif, "ADIF payload");

        let response = self
            .client
            .post(QRZ_API_URL)
            .header("User-Agent", &self.user_agent)
            .form(&[
                ("KEY", self.api_key.as_str()),
                ("ACTION", "INSERT"),
                ("ADIF", &adif),
            ])
            .send()
            .await?;

        let body = response.text().await?;
        trace!(response = %body, "QRZ response");
        parse_upload_response(&body)
    }

    /// Upload a QSO with REPLACE option (updates existing if duplicate)
    pub async fn upload_qso_replace(&self, qso: &Qso) -> Result<UploadResult> {
        let adif = qso_to_adif_string(qso);

        debug!(call = %qso.call, date = %qso.qso_date, "Uploading QSO to QRZ (replace mode)");

        let response = self
            .client
            .post(QRZ_API_URL)
            .header("User-Agent", &self.user_agent)
            .form(&[
                ("KEY", self.api_key.as_str()),
                ("ACTION", "INSERT"),
                ("OPTION", "REPLACE"),
                ("ADIF", &adif),
            ])
            .send()
            .await?;

        let body = response.text().await?;
        parse_upload_response(&body)
    }

    /// Delete a QSO from QRZ by logid
    pub async fn delete_qso(&self, logid: i64) -> Result<bool> {
        debug!(logid = logid, "Deleting QSO from QRZ");

        let response = self
            .client
            .post(QRZ_API_URL)
            .header("User-Agent", &self.user_agent)
            .form(&[
                ("KEY", self.api_key.as_str()),
                ("ACTION", "DELETE"),
                ("LOGIDS", &logid.to_string()),
            ])
            .send()
            .await?;

        let body = response.text().await?;
        let pairs = parse_response_pairs(&body);

        Ok(pairs.get("RESULT").is_some_and(|r| *r == "OK"))
    }

    /// Get logbook status from QRZ
    pub async fn get_status(&self) -> Result<QrzStatus> {
        debug!("Fetching QRZ logbook status");

        let response = self
            .client
            .post(QRZ_API_URL)
            .header("User-Agent", &self.user_agent)
            .form(&[("KEY", self.api_key.as_str()), ("ACTION", "STATUS")])
            .send()
            .await?;

        let body = response.text().await?;
        parse_status_response(&body)
    }

    /// Fetch QSOs from QRZ within a date range
    pub async fn fetch_qsos_by_date(
        &self,
        start_date: &str,
        end_date: &str,
    ) -> Result<FetchResult> {
        let option = format!(
            "BETWEEN:{},{},MAX:{}",
            start_date, end_date, MAX_FETCH_PER_REQUEST
        );
        self.fetch_with_option(&option).await
    }

    /// Fetch the most recent QSOs
    pub async fn fetch_recent(&self, count: u32) -> Result<FetchResult> {
        let count = count.min(MAX_FETCH_PER_REQUEST);
        let option = format!("MAX:{}", count);
        self.fetch_with_option(&option).await
    }

    /// Fetch all QSOs (with automatic pagination)
    pub async fn fetch_all(&self) -> Result<Vec<FetchedQso>> {
        let mut all_qsos = Vec::new();
        let mut offset = 0u32;

        loop {
            // QRZ doesn't like OFFSET:0, so only include it when > 0
            let option = if offset == 0 {
                format!("MAX:{}", MAX_FETCH_PER_REQUEST)
            } else {
                format!("MAX:{},OFFSET:{}", MAX_FETCH_PER_REQUEST, offset)
            };
            debug!(option = %option, offset = offset, "Fetching QSOs from QRZ");
            let result = self.fetch_with_option(&option).await?;

            let count = result.qsos.len();
            debug!(
                batch_count = count,
                total_count = result.total_count,
                has_more = result.has_more,
                "QRZ fetch result"
            );
            all_qsos.extend(result.qsos);

            if count < MAX_FETCH_PER_REQUEST as usize || !result.has_more {
                debug!(
                    reason = if count < MAX_FETCH_PER_REQUEST as usize {
                        "batch smaller than max"
                    } else {
                        "has_more=false"
                    },
                    "Stopping pagination"
                );
                break;
            }

            offset += count as u32;
            info!(fetched = all_qsos.len(), "Fetching more QSOs from QRZ...");

            // Small delay to be nice to the API
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        Ok(all_qsos)
    }

    /// Fetch QSOs with confirmation status (LotW, QSL cards)
    pub async fn fetch_confirmed(&self) -> Result<FetchResult> {
        // Fetch QSOs that have been confirmed via LotW
        let option = format!("LOTWCONFIRMED:YES,MAX:{}", MAX_FETCH_PER_REQUEST);
        self.fetch_with_option(&option).await
    }

    /// Internal fetch with arbitrary options
    async fn fetch_with_option(&self, option: &str) -> Result<FetchResult> {
        debug!(option = %option, "Fetching QSOs from QRZ");

        let response = self
            .client
            .post(QRZ_API_URL)
            .header("User-Agent", &self.user_agent)
            .form(&[
                ("KEY", self.api_key.as_str()),
                ("ACTION", "FETCH"),
                ("OPTION", option),
            ])
            .send()
            .await?;

        let body = response.text().await?;
        trace!(response_len = body.len(), "QRZ fetch response received");
        parse_fetch_response(&body)
    }
}

/// Convert a Qso to ADIF string for upload
fn qso_to_adif_string(qso: &Qso) -> String {
    let mut adif = String::new();

    // Required fields
    adif.push_str(&format_field("call", &qso.call));
    adif.push_str(&format_field("qso_date", &qso.qso_date));
    adif.push_str(&format_field("time_on", &qso.time_on));
    adif.push_str(&format_field("band", &qso.band));
    adif.push_str(&format_field("mode", &qso.mode));

    // Optional fields
    if let Some(ref v) = qso.station_callsign {
        adif.push_str(&format_field("station_callsign", v));
    }
    if let Some(ref v) = qso.freq {
        adif.push_str(&format_field("freq", v));
    }
    if let Some(ref v) = qso.rst_sent {
        adif.push_str(&format_field("rst_sent", v));
    }
    if let Some(ref v) = qso.rst_rcvd {
        adif.push_str(&format_field("rst_rcvd", v));
    }
    if let Some(ref v) = qso.time_off {
        adif.push_str(&format_field("time_off", v));
    }
    if let Some(ref v) = qso.gridsquare {
        adif.push_str(&format_field("gridsquare", v));
    }
    if let Some(ref v) = qso.my_gridsquare {
        adif.push_str(&format_field("my_gridsquare", v));
    }
    if let Some(ref v) = qso.my_sig {
        adif.push_str(&format_field("my_sig", v));
    }
    if let Some(ref v) = qso.my_sig_info {
        adif.push_str(&format_field("my_sig_info", v));
    }
    if let Some(ref v) = qso.sig {
        adif.push_str(&format_field("sig", v));
    }
    if let Some(ref v) = qso.sig_info {
        adif.push_str(&format_field("sig_info", v));
    }
    if let Some(ref v) = qso.comment {
        adif.push_str(&format_field("comment", v));
    }
    if let Some(ref v) = qso.my_state {
        adif.push_str(&format_field("my_state", v));
    }
    if let Some(ref v) = qso.my_cnty {
        adif.push_str(&format_field("my_cnty", v));
    }
    if let Some(ref v) = qso.state {
        adif.push_str(&format_field("state", v));
    }
    if let Some(ref v) = qso.cnty {
        adif.push_str(&format_field("cnty", v));
    }

    // Include other fields for lossless upload
    for (name, value) in &qso.other_fields {
        adif.push_str(&format_field(&name.to_lowercase(), value));
    }

    adif.push_str("<eor>");
    adif
}

fn format_field(name: &str, value: &str) -> String {
    format!("<{}:{}>{}", name, value.len(), value)
}

/// Decode HTML entities in a string
fn html_decode(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

/// Parse response key-value pairs
/// Note: The ADIF field can contain & characters (as HTML entities &lt; etc)
/// so we need to handle it specially - it's always the last field
fn parse_response_pairs(body: &str) -> HashMap<&str, &str> {
    let mut result = HashMap::new();

    // Check if there's an ADIF field - it needs special handling
    if let Some(adif_pos) = body.find("ADIF=") {
        // Parse everything before ADIF normally
        let before_adif = &body[..adif_pos];
        for pair in before_adif.split('&') {
            if pair.is_empty() {
                continue;
            }
            let mut parts = pair.splitn(2, '=');
            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                result.insert(key, value);
            }
        }

        // The ADIF value is everything after "ADIF="
        let adif_value = &body[adif_pos + 5..];
        result.insert("ADIF", adif_value);
    } else {
        // No ADIF field, parse normally
        for pair in body.split('&') {
            let mut parts = pair.splitn(2, '=');
            if let (Some(key), value) = (parts.next(), parts.next()) {
                result.insert(key, value.unwrap_or(""));
            }
        }
    }

    result
}

/// Parse QRZ API response for INSERT action
fn parse_upload_response(body: &str) -> Result<UploadResult> {
    let pairs = parse_response_pairs(body);
    let result = pairs.get("RESULT").unwrap_or(&"");

    if *result == "OK" {
        let logid = pairs.get("LOGID").and_then(|s| s.parse::<i64>().ok());

        Ok(UploadResult {
            success: true,
            logid,
            error: None,
            is_duplicate: false,
        })
    } else {
        let reason = pairs.get("REASON").unwrap_or(&"Unknown error").to_string();
        let is_duplicate = reason.to_lowercase().contains("duplicate");

        if is_duplicate {
            debug!("QSO already exists in QRZ (duplicate)");
        } else {
            warn!(error = %reason, "QRZ upload failed");
        }

        Ok(UploadResult {
            success: false,
            logid: None,
            error: Some(reason),
            is_duplicate,
        })
    }
}

/// Parse QRZ API response for STATUS action
fn parse_status_response(body: &str) -> Result<QrzStatus> {
    let pairs = parse_response_pairs(body);
    let result = pairs.get("RESULT").unwrap_or(&"");

    if *result != "OK" {
        let reason = pairs.get("REASON").unwrap_or(&"Unknown error");
        return Err(Error::Qrz(reason.to_string()));
    }

    Ok(QrzStatus {
        callsign: pairs.get("CALLSIGN").map(|s| s.to_string()),
        count: pairs.get("COUNT").and_then(|s| s.parse().ok()),
        confirmed: pairs.get("CONFIRMED").and_then(|s| s.parse().ok()),
        dxcc: pairs.get("DXCC").and_then(|s| s.parse().ok()),
    })
}

/// Parse QRZ API response for FETCH action
fn parse_fetch_response(body: &str) -> Result<FetchResult> {
    let pairs = parse_response_pairs(body);
    let result = pairs.get("RESULT").unwrap_or(&"");

    if *result != "OK" {
        let reason = pairs.get("REASON");
        let count = pairs.get("COUNT").and_then(|s| s.parse::<usize>().ok());

        // "no log entries found" or COUNT=0 with no reason means empty result
        if reason.is_some_and(|r| r.to_lowercase().contains("no log entries"))
            || (reason.is_none() && count == Some(0))
        {
            return Ok(FetchResult {
                qsos: Vec::new(),
                total_count: 0,
                has_more: false,
            });
        }

        return Err(Error::Qrz(reason.unwrap_or(&"Unknown error").to_string()));
    }

    // Get the count for pagination
    let count = pairs
        .get("COUNT")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    // The ADIF field contains the QSO records (HTML and URL encoded)
    let adif_encoded = pairs.get("ADIF").unwrap_or(&"");

    // URL decode the ADIF data
    let adif_url_decoded = urlencoding::decode(adif_encoded)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| adif_encoded.to_string());

    // HTML decode the ADIF data (QRZ returns HTML entities)
    let adif = html_decode(&adif_url_decoded);

    if adif.is_empty() {
        return Ok(FetchResult {
            qsos: Vec::new(),
            total_count: 0,
            has_more: false,
        });
    }

    // Parse the ADIF content
    let parsed = parse_adif(&adif)?;

    // Convert to FetchedQso with QRZ-specific fields
    let qsos: Vec<FetchedQso> = parsed
        .qsos
        .into_iter()
        .map(|mut qso| {
            // Extract QRZ-specific fields from other_fields
            let qrz_logid = qso
                .other_fields
                .remove("APP_QRZLOG_LOGID")
                .and_then(|s| s.parse().ok());

            // QRZ returns date fields (LOTW_QSLRDATE) instead of status fields (LOTW_QSL_RCVD)
            // Check for status first, then fall back to date-based detection
            let lotw_qsl_rcvd = qso
                .other_fields
                .remove("LOTW_QSL_RCVD")
                .or_else(|| date_to_status(qso.other_fields.remove("LOTW_QSLRDATE")));
            let lotw_qsl_sent = qso
                .other_fields
                .remove("LOTW_QSL_SENT")
                .or_else(|| date_to_status(qso.other_fields.remove("LOTW_QSLSDATE")));
            // For QSL confirmation, check QRZ's APP_QRZLOG_STATUS first (highest priority)
            // "C" = Confirmed via QRZ logbook (both parties logged the QSO)
            // This takes priority over standard QSL_RCVD because QRZ returns both fields
            // (QSL_RCVD=N just means no paper QSL, but APP_QRZLOG_STATUS=C indicates QRZ matching)
            let qsl_rcvd = qrz_status_to_confirmed(qso.other_fields.remove("APP_QRZLOG_STATUS"))
                .or_else(|| qso.other_fields.remove("QSL_RCVD"))
                .or_else(|| date_to_status(qso.other_fields.remove("QSLRDATE")));
            let qsl_sent = qso
                .other_fields
                .remove("QSL_SENT")
                .or_else(|| date_to_status(qso.other_fields.remove("QSLSDATE")));

            FetchedQso {
                qso,
                qrz_logid,
                lotw_qsl_rcvd,
                lotw_qsl_sent,
                qsl_rcvd,
                qsl_sent,
            }
        })
        .collect();

    let fetched_count = qsos.len();

    Ok(FetchResult {
        qsos,
        total_count: count,
        has_more: fetched_count >= MAX_FETCH_PER_REQUEST as usize,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_success_response() {
        let body = "RESULT=OK&LOGID=12345&LOGIDS=12345";
        let result = parse_upload_response(body).unwrap();
        assert!(result.success);
        assert_eq!(result.logid, Some(12345));
    }

    #[test]
    fn test_parse_duplicate_response() {
        let body = "RESULT=FAIL&REASON=duplicate record";
        let result = parse_upload_response(body).unwrap();
        assert!(!result.success);
        assert!(result.is_duplicate);
    }

    #[test]
    fn test_parse_error_response() {
        let body = "RESULT=FAIL&REASON=invalid api key";
        let result = parse_upload_response(body).unwrap();
        assert!(!result.success);
        assert!(!result.is_duplicate);
        assert!(result.error.unwrap().contains("invalid"));
    }

    #[test]
    fn test_parse_empty_fetch() {
        let body = "RESULT=FAIL&REASON=no log entries found";
        let result = parse_fetch_response(body).unwrap();
        assert!(result.qsos.is_empty());
    }

    #[test]
    fn test_format_field() {
        assert_eq!(format_field("call", "W1AW"), "<call:4>W1AW");
        assert_eq!(format_field("qso_date", "20241201"), "<qso_date:8>20241201");
    }
}
