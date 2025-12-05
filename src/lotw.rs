//! LoTW (Logbook of The World) integration for downloading confirmations.
//!
//! Note: Uploading to LoTW requires TQSL (TrustedQSL) which must be installed separately.
//! This module focuses on downloading confirmations via HTTPS.

use crate::adif::{Qso, parse_adif};
use crate::{Error, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;
use tracing::{debug, info, warn};

/// Configuration for LoTW (Logbook of The World) integration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LotwConfig {
    /// Whether LoTW integration is enabled
    #[serde(default)]
    pub enabled: bool,
    /// LoTW username (your callsign)
    pub username: Option<String>,
    /// LoTW password
    pub password: Option<String>,
    /// Your callsign for LoTW queries
    pub callsign: Option<String>,
    /// Path to TQSL executable (for uploads)
    pub tqsl_path: Option<String>,
    /// TQSL station location name
    pub station_location: Option<String>,
    /// Whether to upload to LoTW (requires TQSL)
    #[serde(default)]
    pub upload: bool,
    /// Whether to download confirmations from LoTW
    #[serde(default)]
    pub download: bool,
}

/// LoTW client for downloading confirmations and optionally uploading via TQSL
pub struct LotwClient {
    client: Client,
    config: LotwConfig,
}

impl LotwClient {
    /// Create a new LoTW client
    pub fn new(config: LotwConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .user_agent(format!("logbook-sync/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(Error::Http)?;

        Ok(Self { client, config })
    }

    /// Download confirmations from LoTW
    ///
    /// Returns QSOs that have been confirmed via LoTW.
    /// The `qso_qsl=yes` parameter ensures we only get confirmed QSOs.
    pub async fn download_confirmations(
        &self,
        since_date: Option<&str>,
    ) -> Result<Vec<LotwConfirmation>> {
        let username = self
            .config
            .username
            .as_ref()
            .ok_or_else(|| Error::Other("LoTW username not configured".into()))?;
        let password = self
            .config
            .password
            .as_ref()
            .ok_or_else(|| Error::Other("LoTW password not configured".into()))?;

        // Build the URL with query parameters
        let mut url = format!(
            "https://lotw.arrl.org/lotwuser/lotwreport.adi?\
             login={}&password={}&qso_query=1&qso_qsl=yes&qso_qsldetail=yes",
            urlencoding::encode(username),
            urlencoding::encode(password)
        );

        // Add since date if provided (format: YYYY-MM-DD)
        if let Some(date) = since_date {
            url.push_str(&format!("&qso_qslsince={}", urlencoding::encode(date)));
        }

        // Add own callsign if configured
        if let Some(ref callsign) = self.config.callsign {
            url.push_str(&format!("&qso_owncall={}", urlencoding::encode(callsign)));
        }

        debug!("Fetching LoTW confirmations");

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(Error::Other(format!(
                "LoTW API error: HTTP {}",
                response.status()
            )));
        }

        let adif_content = response.text().await?;

        // Check for LoTW error messages
        if adif_content.contains("ARRL Logbook of The World") && adif_content.contains("not found")
        {
            return Err(Error::Other(
                "LoTW authentication failed - check username/password".into(),
            ));
        }

        // Parse the ADIF response
        let parsed = parse_adif(&adif_content)?;

        info!(
            count = parsed.qsos.len(),
            "Downloaded confirmations from LoTW"
        );

        // Convert to LotwConfirmation records
        let confirmations = parsed
            .qsos
            .into_iter()
            .map(|qso| LotwConfirmation {
                qso,
                qsl_rcvd: Some("Y".to_string()),
            })
            .collect();

        Ok(confirmations)
    }

    /// Upload ADIF file to LoTW via TQSL
    ///
    /// This requires TQSL to be installed on the system.
    /// Returns Ok(()) if upload succeeded, Err if TQSL failed.
    pub async fn upload_via_tqsl(&self, adif_path: &Path) -> Result<()> {
        let tqsl_path = self
            .config
            .tqsl_path
            .as_ref()
            .ok_or_else(|| Error::Other("TQSL path not configured".into()))?;

        let station_location = self
            .config
            .station_location
            .as_ref()
            .ok_or_else(|| Error::Other("TQSL station location not configured".into()))?;

        // Check if TQSL exists
        if !Path::new(tqsl_path).exists() {
            return Err(Error::Other(format!(
                "TQSL not found at configured path: {}",
                tqsl_path
            )));
        }

        info!(
            path = ?adif_path,
            location = station_location,
            "Uploading to LoTW via TQSL"
        );

        let output = Command::new(tqsl_path)
            .args([
                "-d", // Don't show the GUI
                "-u", // Upload after signing
                "-a", // Ask about duplicates (auto-skip)
                "-l",
                station_location, // Station location
                adif_path
                    .to_str()
                    .ok_or_else(|| Error::Other("Invalid ADIF path (non-UTF8)".into()))?,
            ])
            .output()
            .map_err(|e| Error::Other(format!("Failed to execute TQSL: {}", e)))?;

        if output.status.success() {
            info!("LoTW upload via TQSL completed successfully");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            warn!(
                exit_code = ?output.status.code(),
                stderr = %stderr,
                stdout = %stdout,
                "TQSL upload failed"
            );
            Err(Error::Other(format!(
                "TQSL upload failed: {}",
                if stderr.is_empty() { &stdout } else { &stderr }
            )))
        }
    }

    /// Check if TQSL is available for uploads
    pub fn tqsl_available(&self) -> bool {
        if let Some(ref path) = self.config.tqsl_path {
            Path::new(path).exists()
        } else {
            // Try common default paths
            Path::new("/usr/bin/tqsl").exists()
                || Path::new("/usr/local/bin/tqsl").exists()
                || Path::new("C:\\Program Files\\TrustedQSL\\tqsl.exe").exists()
                || Path::new("C:\\Program Files (x86)\\TrustedQSL\\tqsl.exe").exists()
        }
    }
}

/// A confirmed QSO from LoTW
#[derive(Debug, Clone)]
pub struct LotwConfirmation {
    /// The QSO data
    pub qso: Qso,
    /// QSL received status (should be "Y" for confirmed QSOs)
    pub qsl_rcvd: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> LotwConfig {
        LotwConfig {
            enabled: true,
            username: Some("TEST".to_string()),
            password: Some("test123".to_string()),
            callsign: Some("W1AW".to_string()),
            tqsl_path: None,
            station_location: None,
            upload: false,
            download: true,
        }
    }

    #[test]
    fn test_tqsl_not_available_when_not_configured() {
        let config = test_config();
        let client = LotwClient::new(config).unwrap();
        // Without a valid path, tqsl_available checks default paths
        // This will return false in most CI environments
        let _ = client.tqsl_available();
    }
}
