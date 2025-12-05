//! ClubLog integration for uploading QSOs.
//!
//! ClubLog supports both real-time uploads (single QSOs) and batch uploads (ADIF files).
//! An API key is required, which can be obtained by emailing ClubLog support.

use crate::adif::{Qso, write_adif};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// Configuration for ClubLog integration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClublogConfig {
    /// Whether ClubLog integration is enabled
    #[serde(default)]
    pub enabled: bool,
    /// ClubLog email address (not callsign)
    pub email: Option<String>,
    /// ClubLog application password
    pub password: Option<String>,
    /// Your callsign for uploads
    pub callsign: String,
    /// ClubLog API key (obtain from ClubLog support)
    pub api_key: Option<String>,
}
use reqwest::Client;
use tracing::{debug, info, warn};

/// ClubLog client for uploading QSOs
pub struct ClublogClient {
    client: Client,
    config: ClublogConfig,
}

impl ClublogClient {
    /// Create a new ClubLog client
    pub fn new(config: ClublogConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .user_agent(format!("logbook-sync/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(Error::Http)?;

        Ok(Self { client, config })
    }

    /// Upload a single QSO to ClubLog in real-time
    ///
    /// This is the preferred method for uploading QSOs as they happen.
    pub async fn upload_realtime(&self, qso: &Qso) -> Result<UploadStatus> {
        let email = self
            .config
            .email
            .as_ref()
            .ok_or_else(|| Error::Other("ClubLog email not configured".into()))?;
        let password = self
            .config
            .password
            .as_ref()
            .ok_or_else(|| Error::Other("ClubLog password not configured".into()))?;
        let api_key = self
            .config
            .api_key
            .as_ref()
            .ok_or_else(|| Error::Other("ClubLog API key not configured".into()))?;

        // Convert single QSO to ADIF (just the record, not full file)
        let adif_record = write_adif(None, std::slice::from_ref(qso));

        debug!(call = %qso.call, "Uploading QSO to ClubLog");

        let form = [
            ("email", email.as_str()),
            ("password", password.as_str()),
            ("callsign", &self.config.callsign),
            ("api", api_key.as_str()),
            ("adif", &adif_record),
        ];

        let response = self
            .client
            .post("https://clublog.org/realtime.php")
            .form(&form)
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await?;

        match status.as_u16() {
            200 if body.contains("QSO OK") => {
                info!(call = %qso.call, "QSO uploaded to ClubLog");
                Ok(UploadStatus::Ok)
            }
            200 if body.contains("Duplicate") => {
                debug!(call = %qso.call, "QSO is duplicate in ClubLog");
                Ok(UploadStatus::Duplicate)
            }
            400 => {
                warn!(call = %qso.call, reason = %body, "QSO rejected by ClubLog");
                Ok(UploadStatus::Rejected(body))
            }
            403 => Err(Error::Other(format!(
                "ClubLog authentication failed: {}",
                body
            ))),
            _ => Err(Error::Other(format!(
                "ClubLog upload failed: HTTP {} - {}",
                status, body
            ))),
        }
    }

    /// Upload multiple QSOs to ClubLog as an ADIF file
    ///
    /// Note: This uses the batch upload API which has rate limits.
    /// For real-time uploads, use `upload_realtime` instead.
    pub async fn upload_batch(&self, qsos: &[Qso]) -> Result<BatchUploadResult> {
        let email = self
            .config
            .email
            .as_ref()
            .ok_or_else(|| Error::Other("ClubLog email not configured".into()))?;
        let password = self
            .config
            .password
            .as_ref()
            .ok_or_else(|| Error::Other("ClubLog password not configured".into()))?;
        let api_key = self
            .config
            .api_key
            .as_ref()
            .ok_or_else(|| Error::Other("ClubLog API key not configured".into()))?;

        if qsos.is_empty() {
            return Ok(BatchUploadResult {
                queued: 0,
                status: "No QSOs to upload".to_string(),
            });
        }

        // Convert QSOs to ADIF
        let adif_content = write_adif(None, qsos);

        debug!(count = qsos.len(), "Uploading batch to ClubLog");

        // ClubLog batch upload uses multipart form with file upload
        let form = reqwest::multipart::Form::new()
            .text("email", email.clone())
            .text("password", password.clone())
            .text("callsign", self.config.callsign.clone())
            .text("api", api_key.clone())
            .part(
                "file",
                reqwest::multipart::Part::bytes(adif_content.into_bytes())
                    .file_name("upload.adi")
                    .mime_str("text/plain")?,
            );

        let response = self
            .client
            .post("https://clublog.org/putlogs.php")
            .multipart(form)
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await?;

        if status.is_success() {
            info!(count = qsos.len(), "Batch queued for ClubLog upload");
            Ok(BatchUploadResult {
                queued: qsos.len() as u32,
                status: body,
            })
        } else if status.as_u16() == 403 {
            Err(Error::Other(format!(
                "ClubLog authentication failed: {}",
                body
            )))
        } else {
            Err(Error::Other(format!(
                "ClubLog batch upload failed: HTTP {} - {}",
                status, body
            )))
        }
    }

    /// Upload QSOs using the appropriate method based on count
    ///
    /// Uses real-time API for small batches, batch API for larger uploads.
    pub async fn upload(&self, qsos: &[Qso]) -> Result<UploadResult> {
        if qsos.is_empty() {
            return Ok(UploadResult {
                uploaded: 0,
                duplicates: 0,
                errors: 0,
            });
        }

        // For small batches, use real-time API
        if qsos.len() <= 10 {
            let mut uploaded = 0;
            let mut duplicates = 0;
            let mut errors = 0;

            for qso in qsos {
                match self.upload_realtime(qso).await {
                    Ok(UploadStatus::Ok) => uploaded += 1,
                    Ok(UploadStatus::Duplicate) => duplicates += 1,
                    Ok(UploadStatus::Rejected(_)) => errors += 1,
                    Err(e) => {
                        warn!(error = %e, "Error uploading to ClubLog");
                        errors += 1;
                    }
                }
            }

            Ok(UploadResult {
                uploaded,
                duplicates,
                errors,
            })
        } else {
            // For larger batches, use batch upload API
            let result = self.upload_batch(qsos).await?;
            Ok(UploadResult {
                uploaded: result.queued,
                duplicates: 0,
                errors: 0,
            })
        }
    }
}

/// Status of a single QSO upload
#[derive(Debug, Clone)]
pub enum UploadStatus {
    /// QSO was accepted
    Ok,
    /// QSO was a duplicate (already exists)
    Duplicate,
    /// QSO was rejected with reason
    Rejected(String),
}

/// Result of an upload operation
#[derive(Debug, Clone, Default)]
pub struct UploadResult {
    pub uploaded: u32,
    pub duplicates: u32,
    pub errors: u32,
}

/// Result of a batch upload operation
#[derive(Debug, Clone)]
pub struct BatchUploadResult {
    pub queued: u32,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _test_config() -> ClublogConfig {
        ClublogConfig {
            enabled: true,
            email: Some("test@example.com".to_string()),
            password: Some("test123".to_string()),
            callsign: "W1AW".to_string(),
            api_key: Some("test_api_key".to_string()),
        }
    }

    #[test]
    fn test_client_creation() {
        let config = _test_config();
        let client = ClublogClient::new(config);
        assert!(client.is_ok());
    }
}
