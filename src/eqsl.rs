//! eQSL.cc integration for uploading QSOs and downloading confirmations.
//!
//! Note: Downloading confirmations requires an eQSL AG (Authenticity Guaranteed) membership.

use crate::adif::{Qso, parse_adif, write_adif};
use crate::config::EqslConfig;
use crate::{Error, Result};
use reqwest::Client;
use tracing::{debug, info};

/// eQSL client for uploading QSOs and downloading confirmations
pub struct EqslClient {
    client: Client,
    config: EqslConfig,
}

impl EqslClient {
    /// Create a new eQSL client
    pub fn new(config: EqslConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .user_agent(format!("logbook-sync/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(Error::Http)?;

        Ok(Self { client, config })
    }

    /// Upload QSOs to eQSL using form submission
    pub async fn upload(&self, qsos: &[Qso]) -> Result<UploadResult> {
        let username = self
            .config
            .username
            .as_ref()
            .ok_or_else(|| Error::Other("eQSL username not configured".into()))?;
        let password = self
            .config
            .password
            .as_ref()
            .ok_or_else(|| Error::Other("eQSL password not configured".into()))?;

        if qsos.is_empty() {
            return Ok(UploadResult {
                uploaded: 0,
                duplicates: 0,
                errors: 0,
            });
        }

        // Convert QSOs to ADIF
        let adif_content = write_adif(None, qsos);

        debug!(count = qsos.len(), "Uploading QSOs to eQSL");

        // Build form data
        let form = [
            ("eqsl_user", username.as_str()),
            ("eqsl_pswd", password.as_str()),
            ("ADIFData", &adif_content),
        ];

        let response = self
            .client
            .post("https://www.eqsl.cc/qslcard/ImportADIF.cfm")
            .form(&form)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(Error::Other(format!(
                "eQSL upload failed: HTTP {}",
                response.status()
            )));
        }

        let body = response.text().await?;

        // Parse the response to count results
        let result = parse_upload_response(&body);
        info!(
            uploaded = result.uploaded,
            duplicates = result.duplicates,
            errors = result.errors,
            "eQSL upload complete"
        );

        Ok(result)
    }

    /// Download confirmations from eQSL
    ///
    /// Note: This requires an eQSL AG membership for full functionality.
    pub async fn download_confirmations(
        &self,
        since_date: Option<&str>,
    ) -> Result<Vec<EqslConfirmation>> {
        let username = self
            .config
            .username
            .as_ref()
            .ok_or_else(|| Error::Other("eQSL username not configured".into()))?;
        let password = self
            .config
            .password
            .as_ref()
            .ok_or_else(|| Error::Other("eQSL password not configured".into()))?;

        // Build URL with parameters
        let mut url = format!(
            "https://www.eqsl.cc/qslcard/DownloadInbox.cfm?\
             UserName={}&Password={}",
            urlencoding::encode(username),
            urlencoding::encode(password)
        );

        // Add since date if provided (format: YYYYMMDD)
        if let Some(date) = since_date {
            url.push_str(&format!("&RcvdSince={}", urlencoding::encode(date)));
        }

        // Add QTH nickname if configured
        if let Some(ref qth) = self.config.qth_nickname {
            url.push_str(&format!("&QTHNickname={}", urlencoding::encode(qth)));
        }

        debug!("Fetching eQSL confirmations");

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(Error::Other(format!(
                "eQSL download failed: HTTP {}",
                response.status()
            )));
        }

        let body = response.text().await?;

        // Check for error messages
        if body.contains("Error:") || body.contains("not found") {
            let error_msg = extract_error_message(&body);
            return Err(Error::Other(format!("eQSL error: {}", error_msg)));
        }

        // Parse ADIF content
        let parsed = parse_adif(&body)?;

        info!(
            count = parsed.qsos.len(),
            "Downloaded confirmations from eQSL"
        );

        // Convert to EqslConfirmation records
        let confirmations = parsed
            .qsos
            .into_iter()
            .map(|qso| EqslConfirmation {
                qso,
                qsl_rcvd: Some("Y".to_string()),
            })
            .collect();

        Ok(confirmations)
    }

    /// Download Inbox.ADI (confirmed QSOs)
    pub async fn download_inbox(&self) -> Result<Vec<Qso>> {
        let confirmations = self.download_confirmations(None).await?;
        Ok(confirmations.into_iter().map(|c| c.qso).collect())
    }
}

/// Result of an upload operation
#[derive(Debug, Clone, Default)]
pub struct UploadResult {
    pub uploaded: u32,
    pub duplicates: u32,
    pub errors: u32,
}

/// A confirmed QSO from eQSL
#[derive(Debug, Clone)]
pub struct EqslConfirmation {
    /// The QSO data
    pub qso: Qso,
    /// QSL received status
    pub qsl_rcvd: Option<String>,
}

/// Parse the eQSL upload response to extract counts
fn parse_upload_response(body: &str) -> UploadResult {
    let mut result = UploadResult::default();
    let body_lower = body.to_lowercase();

    // Look for patterns like "X QSOs uploaded" or "X duplicates"
    // eQSL responses are HTML, so we need to parse it carefully

    // Find "X qsos uploaded" or "X qso uploaded"
    if let Some(num) = extract_number_before_keyword(&body_lower, "qso") {
        result.uploaded = num;
    }

    // Find "X duplicates" or "X duplicate"
    if let Some(num) = extract_number_before_keyword(&body_lower, "duplicate") {
        result.duplicates = num;
    }

    // Find "X errors" or "X rejected"
    if let Some(num) = extract_number_before_keyword(&body_lower, "error") {
        result.errors = num;
    } else if let Some(num) = extract_number_before_keyword(&body_lower, "reject") {
        result.errors = num;
    }

    result
}

/// Extract a number that appears before a keyword in the text
fn extract_number_before_keyword(text: &str, keyword: &str) -> Option<u32> {
    if let Some(pos) = text.find(keyword) {
        // Look backwards from the keyword position to find a number
        let before = &text[..pos];
        // Find the last number before the keyword
        let mut num_end = before.len();
        while num_end > 0
            && !before[..num_end]
                .chars()
                .last()
                .is_some_and(|c| c.is_ascii_digit())
        {
            num_end -= 1;
        }
        if num_end == 0 {
            return None;
        }
        let mut num_start = num_end;
        while num_start > 0
            && before[..num_start]
                .chars()
                .last()
                .is_some_and(|c| c.is_ascii_digit())
        {
            num_start -= 1;
        }
        // Handle the case where we went one too far back
        if num_start < num_end
            && !before
                .chars()
                .nth(num_start)
                .is_some_and(|c| c.is_ascii_digit())
        {
            num_start += 1;
        }
        before[num_start..num_end].parse().ok()
    } else {
        None
    }
}

/// Extract error message from eQSL response
fn extract_error_message(body: &str) -> String {
    // Look for common error patterns
    for line in body.lines() {
        if line.contains("Error:") || line.contains("error:") {
            return line.trim().to_string();
        }
    }
    "Unknown error".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _test_config() -> EqslConfig {
        EqslConfig {
            enabled: true,
            username: Some("TEST".to_string()),
            password: Some("test123".to_string()),
            qth_nickname: None,
            upload: true,
            download: true,
            download_interval: 86400,
        }
    }

    #[test]
    fn test_parse_upload_response() {
        let body = "<html><body>5 QSOs uploaded successfully. 2 duplicates found.</body></html>";
        let result = parse_upload_response(body);
        assert_eq!(result.uploaded, 5);
        assert_eq!(result.duplicates, 2);
    }

    #[test]
    fn test_extract_number_before_keyword() {
        assert_eq!(
            extract_number_before_keyword("5 qsos uploaded", "qso"),
            Some(5)
        );
        assert_eq!(
            extract_number_before_keyword("no numbers here", "here"),
            None
        );
        assert_eq!(
            extract_number_before_keyword("123 items found", "items"),
            Some(123)
        );
        assert_eq!(
            extract_number_before_keyword("found 10 errors", "error"),
            Some(10)
        );
    }
}
