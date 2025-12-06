//! ntfy.sh notification client for sending notifications

use crate::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

/// Configuration for ntfy.sh notifications
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NtfyConfig {
    /// Whether ntfy notifications are enabled
    #[serde(default)]
    pub enabled: bool,
    /// The ntfy server URL (default: https://ntfy.sh)
    #[serde(default = "default_ntfy_server")]
    pub server: String,
    /// The topic to publish to
    pub topic: String,
    /// Password/token for authentication
    pub token: Option<String>,
    /// Priority level (1-5, default 3)
    #[serde(default = "default_ntfy_priority")]
    pub priority: u8,
}

fn default_ntfy_server() -> String {
    "https://ntfy.sh".to_string()
}

fn default_ntfy_priority() -> u8 {
    3
}

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
            .header("Priority", "4")
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
}
