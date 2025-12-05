//! HTTP client for Ham2K LoFi API.

use crate::error::{Error, Result};
use reqwest::{Client, header};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::models::*;

/// Configuration for Ham2K LoFi client
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LofiConfig {
    /// Whether LoFi integration is enabled
    #[serde(default)]
    pub enabled: bool,
    /// UUID v4 client key
    pub client_key: Option<String>,
    /// Random secret
    pub client_secret: Option<String>,
    /// User's amateur radio callsign
    pub callsign: Option<String>,
    /// Email for device linking
    pub email: Option<String>,
    /// Sync batch size
    #[serde(default = "default_batch_size")]
    pub sync_batch_size: u32,
    /// Delay between pagination requests in milliseconds
    #[serde(default = "default_loop_delay")]
    pub sync_loop_delay_ms: u64,
    /// Sync check period in milliseconds
    #[serde(default = "default_check_period")]
    pub sync_check_period_ms: u64,
    /// Whether device has been linked via email confirmation
    #[serde(default)]
    pub device_linked: bool,
}

fn default_batch_size() -> u32 {
    50
}

fn default_loop_delay() -> u64 {
    10000
}

fn default_check_period() -> u64 {
    300000 // 5 minutes
}

impl LofiConfig {
    /// Check if the configuration has the required credentials for registration
    pub fn has_credentials(&self) -> bool {
        self.client_key.is_some() && self.client_secret.is_some() && self.callsign.is_some()
    }

    /// Check if ready for sync
    pub fn is_ready_for_sync(&self) -> bool {
        self.enabled && self.device_linked && self.has_credentials()
    }
}

const LOFI_BASE_URL: &str = "https://lofi.ham2k.net";
const USER_AGENT: &str = "logbook-sync-server";
const CLIENT_NAME: &str = "logbook-sync-server";
const APP_NAME: &str = "logbook-sync-server";

/// Client for interacting with the Ham2K LoFi API
pub struct LofiClient {
    client: Client,
    config: LofiConfig,
    /// Bearer token stored in database, passed in when creating client for API calls
    bearer_token: Option<String>,
}

impl LofiClient {
    /// Create a new LoFi client without a bearer token (for registration)
    pub fn new(config: LofiConfig) -> Result<Self> {
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(Error::Http)?;

        Ok(Self {
            client,
            config,
            bearer_token: None,
        })
    }

    /// Create a new LoFi client with a bearer token (for API calls)
    pub fn with_token(config: LofiConfig, bearer_token: String) -> Result<Self> {
        let client = Client::builder()
            .user_agent(USER_AGENT)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(Error::Http)?;

        Ok(Self {
            client,
            config,
            bearer_token: Some(bearer_token),
        })
    }

    /// Set the bearer token (for use after registration)
    pub fn set_bearer_token(&mut self, token: String) {
        self.bearer_token = Some(token);
    }

    /// Check if the client has a bearer token
    pub fn has_bearer_token(&self) -> bool {
        self.bearer_token.is_some()
    }

    /// Refresh the bearer token by re-registering with LoFi
    /// Returns the new token so it can be stored in the database
    pub async fn refresh_token(&mut self) -> Result<String> {
        info!("Refreshing LoFi bearer token...");

        let response = self.register().await?;
        let new_token = response.token;

        self.bearer_token = Some(new_token.clone());

        info!("LoFi bearer token refreshed successfully");

        Ok(new_token)
    }

    /// Generate a new UUID v4 client key
    pub fn generate_client_key() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// Generate a random secret (32 bytes, hex encoded = 64 chars)
    pub fn generate_client_secret() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let bytes: [u8; 32] = rng.r#gen();
        hex::encode(bytes)
    }

    /// Register client with LoFi and get bearer token
    /// Call this after setup to get the initial token
    pub async fn register(&self) -> Result<ClientRegistrationResponse> {
        let client_key = self
            .config
            .client_key
            .as_ref()
            .ok_or_else(|| Error::Lofi("client_key not configured".to_string()))?;
        let client_secret = self
            .config
            .client_secret
            .as_ref()
            .ok_or_else(|| Error::Lofi("client_secret not configured".to_string()))?;
        let callsign = self
            .config
            .callsign
            .as_ref()
            .ok_or_else(|| Error::Lofi("callsign not configured".to_string()))?;

        let request = ClientRegistrationRequest {
            client: ClientCredentials {
                key: client_key.clone(),
                name: CLIENT_NAME.to_string(),
                secret: client_secret.clone(),
            },
            account: AccountRequest {
                call: callsign.clone(),
            },
            meta: MetaRequest {
                app: APP_NAME.to_string(),
            },
        };

        let url = format!("{}/v1/client", LOFI_BASE_URL);

        debug!("Registering client with LoFi at {}", url);

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(Error::Http)?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Lofi(format!(
                "LoFi registration failed: {} - {}",
                status, body
            )));
        }

        let registration: ClientRegistrationResponse = response
            .json()
            .await
            .map_err(|e| Error::Lofi(format!("Failed to parse registration response: {}", e)))?;

        info!(
            callsign = %registration.account.call,
            batch_size = registration.meta.flags.suggested_sync_batch_size,
            "Successfully registered with LoFi"
        );

        Ok(registration)
    }

    /// Link device with user's account via email confirmation
    /// This sends an email to the user - they must click the link to complete linking
    pub async fn link_device(&self, email: &str) -> Result<()> {
        let token = self.get_token()?;

        let url = format!("{}/v1/client/link", LOFI_BASE_URL);
        let request = LinkDeviceRequest {
            email: email.to_string(),
        };

        debug!("Linking device via email: {}", email);

        let response = self
            .client
            .post(&url)
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .json(&request)
            .send()
            .await
            .map_err(Error::Http)?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Lofi(format!(
                "LoFi device linking failed: {} - {}",
                status, body
            )));
        }

        info!(
            email = %email,
            "Device link email sent. User must click the confirmation link."
        );

        Ok(())
    }

    /// Fetch operations with pagination
    /// Pass synced_until_millis from previous response's meta to get next page
    /// Returns response with meta.operations.records_left indicating if more pages exist
    pub async fn fetch_operations(
        &self,
        synced_until_millis: Option<f64>,
        limit: Option<u32>,
    ) -> Result<OperationsResponse> {
        let token = self.get_token()?;

        let mut url = format!("{}/v1/operations", LOFI_BASE_URL);
        let mut params = Vec::new();

        if let Some(until) = synced_until_millis {
            // Format as integer milliseconds
            params.push(format!("synced_until_millis={:.0}", until));
        }
        if let Some(lim) = limit {
            params.push(format!("limit={}", lim));
        }

        if !params.is_empty() {
            url = format!("{}?{}", url, params.join("&"));
        }

        debug!("Fetching operations from: {}", url);

        let response = self
            .client
            .get(&url)
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .send()
            .await
            .map_err(Error::Http)?;

        self.handle_response(response).await
    }

    /// Fetch QSOs with pagination
    /// Pass synced_until_millis from previous response's meta to get next page
    pub async fn fetch_qsos(
        &self,
        synced_until_millis: Option<f64>,
        limit: Option<u32>,
    ) -> Result<QsosResponse> {
        let token = self.get_token()?;

        let mut url = format!("{}/v1/qsos", LOFI_BASE_URL);
        let mut params = Vec::new();

        if let Some(until) = synced_until_millis {
            params.push(format!("synced_until_millis={:.0}", until));
        }
        if let Some(lim) = limit {
            params.push(format!("limit={}", lim));
        }

        if !params.is_empty() {
            url = format!("{}?{}", url, params.join("&"));
        }

        debug!("Fetching QSOs from: {}", url);

        let response = self
            .client
            .get(&url)
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .send()
            .await
            .map_err(Error::Http)?;

        self.handle_response(response).await
    }

    fn get_token(&self) -> Result<&str> {
        self.bearer_token.as_deref().ok_or_else(|| {
            Error::Lofi("bearer_token not available - run 'lofi register' first".to_string())
        })
    }

    async fn handle_response<T: serde::de::DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T> {
        let status = response.status();

        // Handle auth errors - token may need refresh
        if status == reqwest::StatusCode::UNAUTHORIZED {
            warn!("LoFi returned 401 - token needs refresh");
            return Err(Error::LofiAuthError);
        }

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(Error::Lofi(format!(
                "LoFi API error: {} - {}",
                status, body
            )));
        }

        response
            .json()
            .await
            .map_err(|e| Error::Lofi(format!("Failed to parse LoFi response: {}", e)))
    }
}
