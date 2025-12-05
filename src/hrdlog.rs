//! HRDLog.net integration for uploading QSOs.
//!
//! HRDLog.net is an online amateur radio logbook service.
//! An upload code is required (different from your password), which can be
//! obtained from your HRDLog.net account settings.

use crate::adif::{Qso, write_adif};
use crate::config::HrdlogConfig;
use crate::{Error, Result};
use reqwest::Client;
use tracing::{debug, info, warn};

const HRDLOG_API_URL: &str = "http://robot.hrdlog.net/NewEntry.aspx";
const APP_NAME: &str = "logbook-sync";

/// HRDLog client for uploading QSOs
pub struct HrdlogClient {
    client: Client,
    config: HrdlogConfig,
}

impl HrdlogClient {
    /// Create a new HRDLog client
    pub fn new(config: HrdlogConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .user_agent(format!("logbook-sync/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(Error::Http)?;

        Ok(Self { client, config })
    }

    /// Upload a single QSO to HRDLog
    pub async fn upload_qso(&self, qso: &Qso) -> Result<UploadStatus> {
        let callsign = &self.config.callsign;
        let code = self
            .config
            .upload_code
            .as_ref()
            .ok_or_else(|| Error::Other("HRDLog upload code not configured".into()))?;

        // Convert single QSO to ADIF record
        let adif_data = write_adif(None, std::slice::from_ref(qso));

        debug!(call = %qso.call, "Uploading QSO to HRDLog");

        let form = [
            ("Callsign", callsign.as_str()),
            ("Code", code.as_str()),
            ("App", APP_NAME),
            ("ADIFData", &adif_data),
        ];

        let response = self.client.post(HRDLOG_API_URL).form(&form).send().await?;

        let status = response.status();
        let body = response.text().await?;

        // Parse response
        if status.is_success() {
            // Check for success indicators in response
            if body.to_lowercase().contains("error") || body.to_lowercase().contains("fail") {
                warn!(call = %qso.call, response = %body, "HRDLog upload returned error");
                Ok(UploadStatus::Error(body))
            } else if body.to_lowercase().contains("duplicate") {
                debug!(call = %qso.call, "QSO is duplicate in HRDLog");
                Ok(UploadStatus::Duplicate)
            } else {
                info!(call = %qso.call, "QSO uploaded to HRDLog");
                Ok(UploadStatus::Ok)
            }
        } else {
            Err(Error::Other(format!(
                "HRDLog upload failed: HTTP {} - {}",
                status, body
            )))
        }
    }

    /// Upload multiple QSOs to HRDLog
    ///
    /// Each QSO is uploaded individually as HRDLog's API processes one at a time.
    pub async fn upload(&self, qsos: &[Qso]) -> Result<UploadResult> {
        if qsos.is_empty() {
            return Ok(UploadResult {
                uploaded: 0,
                duplicates: 0,
                errors: 0,
            });
        }

        let mut uploaded = 0;
        let mut duplicates = 0;
        let mut errors = 0;

        info!(count = qsos.len(), "Uploading QSOs to HRDLog");

        for qso in qsos {
            match self.upload_qso(qso).await {
                Ok(UploadStatus::Ok) => uploaded += 1,
                Ok(UploadStatus::Duplicate) => duplicates += 1,
                Ok(UploadStatus::Error(msg)) => {
                    warn!(call = %qso.call, error = %msg, "HRDLog upload error");
                    errors += 1;
                }
                Err(e) => {
                    warn!(call = %qso.call, error = %e, "Failed to upload to HRDLog");
                    errors += 1;
                }
            }
        }

        info!(
            uploaded = uploaded,
            duplicates = duplicates,
            errors = errors,
            "HRDLog upload complete"
        );

        Ok(UploadResult {
            uploaded,
            duplicates,
            errors,
        })
    }
}

/// Status of a single QSO upload
#[derive(Debug, Clone)]
pub enum UploadStatus {
    /// QSO was accepted
    Ok,
    /// QSO was a duplicate
    Duplicate,
    /// Upload returned an error
    Error(String),
}

/// Result of an upload operation
#[derive(Debug, Clone, Default)]
pub struct UploadResult {
    pub uploaded: u32,
    pub duplicates: u32,
    pub errors: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _test_config() -> HrdlogConfig {
        HrdlogConfig {
            enabled: true,
            callsign: "W1AW".to_string(),
            upload_code: Some("test_code".to_string()),
        }
    }

    #[test]
    fn test_client_creation() {
        let config = _test_config();
        let client = HrdlogClient::new(config);
        assert!(client.is_ok());
    }
}
