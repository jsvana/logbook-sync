//! HTTP client for remote POTA authentication service
//!
//! This module provides a client for calling the external Playwright-based
//! authentication service deployed on Railway.

use anyhow::{Context, Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::browser::PotaCachedTokens;
use crate::config::PotaAuthServiceConfig;

/// Request body for the auth endpoint
#[derive(Debug, Serialize)]
struct AuthRequest {
    email: String,
    password: String,
}

/// Successful auth response
#[derive(Debug, Deserialize)]
struct AuthResponse {
    success: bool,
    tokens: Option<AuthTokens>,
    error: Option<String>,
    error_code: Option<String>,
}

/// Token data from the auth service
#[derive(Debug, Deserialize)]
struct AuthTokens {
    id_token: String,
    expires_at: u64,
    callsign: Option<String>,
    refresh_token: Option<String>,
}

/// Client for the remote POTA authentication service
pub struct PotaAuthServiceClient {
    client: Client,
    config: PotaAuthServiceConfig,
}

impl PotaAuthServiceClient {
    /// Create a new auth service client
    pub fn new(config: PotaAuthServiceConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self { client, config })
    }

    /// Authenticate with POTA via the remote service
    pub async fn authenticate(&self, email: &str, password: &str) -> Result<PotaCachedTokens> {
        let url = format!("{}/api/v1/auth", self.config.url);
        info!("Calling remote POTA auth service at {}", self.config.url);

        let request = AuthRequest {
            email: email.to_string(),
            password: password.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .header("X-API-Key", &self.config.api_key)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .context("Failed to send auth request to remote service")?;

        let status = response.status();
        debug!("Auth service response status: {}", status);

        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(anyhow!("Invalid API key for POTA auth service"));
        }

        if status == reqwest::StatusCode::REQUEST_TIMEOUT {
            return Err(anyhow!("POTA auth service timed out"));
        }

        let body: AuthResponse = response
            .json()
            .await
            .context("Failed to parse auth service response")?;

        if !body.success {
            let error = body.error.unwrap_or_else(|| "Unknown error".to_string());
            let code = body.error_code.unwrap_or_else(|| "UNKNOWN".to_string());
            warn!("Remote auth failed: {} ({})", error, code);
            return Err(anyhow!("Authentication failed: {} ({})", error, code));
        }

        let tokens = body
            .tokens
            .ok_or_else(|| anyhow!("Auth succeeded but no tokens returned"))?;

        info!(
            "Remote auth successful, callsign: {:?}, expires: {}",
            tokens.callsign, tokens.expires_at
        );

        Ok(PotaCachedTokens {
            id_token: tokens.id_token,
            expires_at: tokens.expires_at,
            callsign: tokens.callsign,
            refresh_token: tokens.refresh_token,
        })
    }

    /// Check if the auth service is healthy
    pub async fn health_check(&self) -> Result<bool> {
        let url = format!("{}/health", self.config.url);

        let response = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .context("Failed to check auth service health")?;

        Ok(response.status().is_success())
    }
}
