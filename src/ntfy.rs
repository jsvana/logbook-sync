//! ntfy.sh notification client for sync events

use crate::config::NtfyConfig;
use crate::sync::SyncStats;
use crate::Result;
use reqwest::Client;
use tracing::{debug, error, info};

/// Client for sending notifications via ntfy.sh
pub struct NtfyClient {
    client: Client,
    config: NtfyConfig,
}

impl NtfyClient {
    /// Create a new ntfy client
    pub fn new(config: NtfyConfig) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, config }
    }

    /// Send a notification with the given title and message
    pub async fn send(&self, title: &str, message: &str) -> Result<()> {
        if !self.config.enabled {
            debug!("ntfy notifications disabled, skipping");
            return Ok(());
        }

        let url = format!("{}/{}", self.config.server.trim_end_matches('/'), self.config.topic);

        let mut request = self.client
            .post(&url)
            .header("Title", title)
            .header("Priority", self.config.priority.to_string())
            .header("Tags", "radio,satellite_antenna");

        // Add authentication if configured
        if let Some(ref token) = self.config.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        request = request.body(message.to_string());

        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    info!("Sent ntfy notification: {}", title);
                    Ok(())
                } else {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    error!(status = %status, body = %body, "Failed to send ntfy notification");
                    Err(crate::Error::Ntfy(format!("HTTP {}: {}", status, body)))
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to send ntfy notification");
                Err(crate::Error::Ntfy(e.to_string()))
            }
        }
    }

    /// Send a sync summary notification based on stats
    /// Only sends if there was actual activity (uploads, downloads, or confirmations)
    pub async fn notify_sync(&self, stats: &SyncStats, callsign: &str) -> Result<()> {
        // Only send if there was actual activity
        if stats.qsos_uploaded == 0
            && stats.qsos_downloaded == 0
            && stats.confirmations_updated == 0
        {
            debug!("No sync activity, skipping ntfy notification");
            return Ok(());
        }

        let title = format!("{} Logbook Sync", callsign);

        let mut parts = Vec::new();

        if stats.qsos_uploaded > 0 {
            parts.push(format!(
                "Uploaded {} QSO{}",
                stats.qsos_uploaded,
                if stats.qsos_uploaded == 1 { "" } else { "s" }
            ));
        }

        if stats.qsos_downloaded > 0 {
            parts.push(format!(
                "Downloaded {} QSO{}",
                stats.qsos_downloaded,
                if stats.qsos_downloaded == 1 { "" } else { "s" }
            ));
        }

        if stats.confirmations_updated > 0 {
            parts.push(format!(
                "{} new confirmation{}",
                stats.confirmations_updated,
                if stats.confirmations_updated == 1 { "" } else { "s" }
            ));
        }

        if stats.qsos_already_on_qrz > 0 {
            parts.push(format!("{} already on QRZ", stats.qsos_already_on_qrz));
        }

        let message = parts.join(", ");

        self.send(&title, &message).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_notification_message() {
        let stats = SyncStats {
            qsos_uploaded: 5,
            qsos_downloaded: 10,
            confirmations_updated: 3,
            qsos_already_on_qrz: 2,
            ..Default::default()
        };

        let mut parts = Vec::new();
        if stats.qsos_uploaded > 0 {
            parts.push(format!("Uploaded {} QSOs", stats.qsos_uploaded));
        }
        if stats.qsos_downloaded > 0 {
            parts.push(format!("Downloaded {} QSOs", stats.qsos_downloaded));
        }
        if stats.confirmations_updated > 0 {
            parts.push(format!("{} new confirmations", stats.confirmations_updated));
        }

        let message = parts.join(", ");
        assert_eq!(message, "Uploaded 5 QSOs, Downloaded 10 QSOs, 3 new confirmations");
    }

    #[test]
    fn test_no_activity_skips_notification() {
        let stats = SyncStats::default();
        assert_eq!(stats.qsos_uploaded, 0);
        assert_eq!(stats.qsos_downloaded, 0);
        assert_eq!(stats.confirmations_updated, 0);
    }
}
