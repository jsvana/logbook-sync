//! ntfy.sh notification client for sync events

use crate::Result;
use crate::config::NtfyConfig;
use crate::sync::SyncStats;
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

        let url = format!(
            "{}/{}",
            self.config.server.trim_end_matches('/'),
            self.config.topic
        );

        let mut request = self
            .client
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
    /// Only sends if there was actual new activity (uploads, new downloads, or confirmations)
    pub async fn notify_sync(&self, stats: &SyncStats, callsign: &str) -> Result<()> {
        // Only send if there was actual new activity (not just re-downloading existing QSOs)
        if stats.qsos_uploaded == 0
            && stats.qsos_downloaded_new == 0
            && stats.confirmations_updated == 0
        {
            debug!("No new sync activity, skipping ntfy notification");
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

        if stats.qsos_downloaded_new > 0 {
            parts.push(format!(
                "Downloaded {} new QSO{}",
                stats.qsos_downloaded_new,
                if stats.qsos_downloaded_new == 1 {
                    ""
                } else {
                    "s"
                }
            ));
        }

        if stats.confirmations_updated > 0 {
            parts.push(format!(
                "{} new confirmation{}",
                stats.confirmations_updated,
                if stats.confirmations_updated == 1 {
                    ""
                } else {
                    "s"
                }
            ));
        }

        if stats.qsos_already_on_qrz > 0 {
            parts.push(format!("{} already on QRZ", stats.qsos_already_on_qrz));
        }

        let message = parts.join(", ");

        self.send(&title, &message).await
    }

    /// Send an error notification with high priority
    pub async fn notify_error(&self, callsign: &str, service: &str, error: &str) -> Result<()> {
        if !self.config.enabled {
            debug!("ntfy notifications disabled, skipping error notification");
            return Ok(());
        }

        let url = format!(
            "{}/{}",
            self.config.server.trim_end_matches('/'),
            self.config.topic
        );

        let title = format!("{} Sync Error", callsign);
        let message = format!("{} sync failed: {}", service, error);

        let mut request = self
            .client
            .post(&url)
            .header("Title", title.clone())
            .header("Priority", "4") // High priority for errors
            .header("Tags", "warning,radio");

        // Add authentication if configured
        if let Some(ref token) = self.config.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        request = request.body(message.clone());

        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    info!("Sent error notification: {}", title);
                    Ok(())
                } else {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    error!(status = %status, body = %body, "Failed to send error notification");
                    Err(crate::Error::Ntfy(format!("HTTP {}: {}", status, body)))
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to send error notification");
                Err(crate::Error::Ntfy(e.to_string()))
            }
        }
    }

    /// Send an alert for consecutive sync failures
    pub async fn notify_consecutive_failures(
        &self,
        callsign: &str,
        service: &str,
        failure_count: u32,
        last_error: Option<&str>,
    ) -> Result<()> {
        if !self.config.enabled {
            debug!("ntfy notifications disabled, skipping failure alert");
            return Ok(());
        }

        let url = format!(
            "{}/{}",
            self.config.server.trim_end_matches('/'),
            self.config.topic
        );

        let title = format!("{} Sync Alert", callsign);
        let message = if let Some(err) = last_error {
            format!(
                "{} sync has failed {} consecutive times.\nLast error: {}",
                service, failure_count, err
            )
        } else {
            format!(
                "{} sync has failed {} consecutive times.",
                service, failure_count
            )
        };

        let mut request = self
            .client
            .post(&url)
            .header("Title", title.clone())
            .header("Priority", "5") // Urgent priority for persistent failures
            .header("Tags", "rotating_light,radio");

        // Add authentication if configured
        if let Some(ref token) = self.config.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        request = request.body(message.clone());

        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    info!("Sent failure alert: {}", title);
                    Ok(())
                } else {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    error!(status = %status, body = %body, "Failed to send failure alert");
                    Err(crate::Error::Ntfy(format!("HTTP {}: {}", status, body)))
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to send failure alert");
                Err(crate::Error::Ntfy(e.to_string()))
            }
        }
    }

    /// Send a stale sync warning (no successful sync in configured time)
    pub async fn notify_stale_sync(
        &self,
        callsign: &str,
        service: &str,
        hours_since_last: u32,
    ) -> Result<()> {
        if !self.config.enabled {
            debug!("ntfy notifications disabled, skipping stale sync alert");
            return Ok(());
        }

        let url = format!(
            "{}/{}",
            self.config.server.trim_end_matches('/'),
            self.config.topic
        );

        let title = format!("{} Sync Warning", callsign);
        let message = format!(
            "No successful {} sync in {} hours. Please check the service.",
            service, hours_since_last
        );

        let mut request = self
            .client
            .post(&url)
            .header("Title", title.clone())
            .header("Priority", "4") // High priority for warnings
            .header("Tags", "clock,radio");

        // Add authentication if configured
        if let Some(ref token) = self.config.token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        request = request.body(message.clone());

        match request.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    info!("Sent stale sync warning: {}", title);
                    Ok(())
                } else {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    error!(status = %status, body = %body, "Failed to send stale sync warning");
                    Err(crate::Error::Ntfy(format!("HTTP {}: {}", status, body)))
                }
            }
            Err(e) => {
                error!(error = %e, "Failed to send stale sync warning");
                Err(crate::Error::Ntfy(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_notification_message() {
        let stats = SyncStats {
            qsos_uploaded: 5,
            qsos_downloaded_new: 10,
            confirmations_updated: 3,
            qsos_already_on_qrz: 2,
            ..Default::default()
        };

        let mut parts = Vec::new();
        if stats.qsos_uploaded > 0 {
            parts.push(format!("Uploaded {} QSOs", stats.qsos_uploaded));
        }
        if stats.qsos_downloaded_new > 0 {
            parts.push(format!("Downloaded {} new QSOs", stats.qsos_downloaded_new));
        }
        if stats.confirmations_updated > 0 {
            parts.push(format!("{} new confirmations", stats.confirmations_updated));
        }

        let message = parts.join(", ");
        assert_eq!(
            message,
            "Uploaded 5 QSOs, Downloaded 10 new QSOs, 3 new confirmations"
        );
    }

    #[test]
    fn test_no_activity_skips_notification() {
        let stats = SyncStats::default();
        assert_eq!(stats.qsos_uploaded, 0);
        assert_eq!(stats.qsos_downloaded_new, 0);
        assert_eq!(stats.confirmations_updated, 0);
    }
}
