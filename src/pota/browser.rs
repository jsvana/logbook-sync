//! POTA headless browser authentication module
//!
//! This module handles authentication with POTA using a headless browser
//! to navigate the Cognito Hosted UI, then caches the resulting JWT tokens
//! for subsequent direct API calls.

#[cfg(feature = "local-browser")]
use anyhow::Context;
use anyhow::{Result, anyhow};
use base64::Engine;
#[cfg(feature = "local-browser")]
use headless_chrome::{Browser, LaunchOptions};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Progress update for browser operations
#[derive(Debug, Clone, Serialize)]
pub struct BrowserProgress {
    /// Current step description
    pub step: String,
    /// Optional detail message
    pub detail: Option<String>,
    /// Whether this is an error state
    pub is_error: bool,
}

impl BrowserProgress {
    pub fn new(step: impl Into<String>) -> Self {
        Self {
            step: step.into(),
            detail: None,
            is_error: false,
        }
    }

    pub fn with_detail(step: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            step: step.into(),
            detail: Some(detail.into()),
            is_error: false,
        }
    }

    pub fn error(step: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            step: step.into(),
            detail: Some(detail.into()),
            is_error: true,
        }
    }
}

/// Callback type for progress updates
pub type ProgressCallback = Arc<dyn Fn(BrowserProgress) + Send + Sync>;

/// POTA API endpoint
const POTA_API_URL: &str = "https://api.pota.app";

/// POTA web app URL
const POTA_APP_URL: &str = "https://pota.app";

/// Refresh tokens this many seconds before expiry
const TOKEN_EXPIRY_BUFFER_SECS: u64 = 300;

/// Cached POTA authentication tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PotaCachedTokens {
    /// The Cognito ID token (used for Authorization header)
    pub id_token: String,

    /// Unix timestamp when token expires
    pub expires_at: u64,

    /// Callsign extracted from token claims
    pub callsign: Option<String>,

    /// Optional refresh token (not always available from Hosted UI)
    pub refresh_token: Option<String>,
}

impl PotaCachedTokens {
    /// Check if token is still valid (with expiry buffer)
    pub fn is_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now + TOKEN_EXPIRY_BUFFER_SECS < self.expires_at
    }
}

/// Decode JWT claims without cryptographic verification
/// (we trust Cognito issued it)
fn decode_jwt_claims(token: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    let payload = parts[1];

    // JWT uses URL-safe base64 without padding, but we need to handle both cases
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload))
        .or_else(|_| {
            // Add padding if needed
            let padded = match payload.len() % 4 {
                0 => payload.to_string(),
                2 => format!("{}==", payload),
                3 => format!("{}=", payload),
                _ => return Err(base64::DecodeError::InvalidLength(payload.len())),
            };
            base64::engine::general_purpose::URL_SAFE.decode(&padded)
        })
        .ok()?;

    serde_json::from_slice(&decoded).ok()
}

/// Extract expiry timestamp from JWT token
fn extract_token_expiry(token: &str) -> Option<u64> {
    let claims = decode_jwt_claims(token)?;
    claims.get("exp")?.as_u64()
}

/// Extract callsign from JWT token claims
fn extract_callsign(token: &str) -> Option<String> {
    let claims = decode_jwt_claims(token)?;
    claims.get("pota:callsign")?.as_str().map(String::from)
}

/// Helper to report progress if callback is provided
fn report_progress(callback: &Option<ProgressCallback>, progress: BrowserProgress) {
    if let Some(cb) = callback {
        cb(progress);
    }
}

/// Authenticate via headless browser and extract ID token
#[cfg(feature = "local-browser")]
pub fn authenticate_via_browser(
    username: &str,
    password: &str,
    headless: bool,
) -> Result<PotaCachedTokens> {
    authenticate_via_browser_with_progress(username, password, headless, None)
}

/// Authenticate via headless browser with progress reporting
#[cfg(feature = "local-browser")]
pub fn authenticate_via_browser_with_progress(
    username: &str,
    password: &str,
    headless: bool,
    progress_callback: Option<ProgressCallback>,
) -> Result<PotaCachedTokens> {
    info!("Starting browser authentication for POTA");
    report_progress(
        &progress_callback,
        BrowserProgress::new("Launching browser"),
    );

    // Launch browser with sandbox disabled for containerized environments
    let launch_options = LaunchOptions {
        headless,
        sandbox: false, // Required for running in Docker/containers
        ..Default::default()
    };

    let browser = Browser::new(launch_options).context("Failed to launch Chrome/Chromium")?;

    let tab = browser.new_tab().context("Failed to create browser tab")?;

    // Navigate to POTA login page directly
    report_progress(
        &progress_callback,
        BrowserProgress::new("Navigating to POTA login page"),
    );
    let login_url = format!("{}/#/login", POTA_APP_URL);
    debug!(url = %login_url, "Navigating to POTA login");
    tab.navigate_to(&login_url)?;
    tab.wait_until_navigated()?;

    // Wait for Vue.js SPA to fully load
    report_progress(
        &progress_callback,
        BrowserProgress::new("Waiting for page to load"),
    );
    debug!("Waiting for SPA to load");
    std::thread::sleep(Duration::from_secs(5));

    // Use JavaScript to find and click the Sign In button
    report_progress(
        &progress_callback,
        BrowserProgress::new("Clicking Sign In button"),
    );
    debug!("Looking for Sign In button via JavaScript");
    let click_js = r#"
        (function() {
            // Try to find button by text content
            const buttons = document.querySelectorAll('button, a.btn, .btn');
            for (const btn of buttons) {
                const text = btn.textContent.trim().toLowerCase();
                if (text === 'sign in' || text === 'login' || text === 'log in') {
                    btn.click();
                    return 'clicked: ' + text;
                }
            }
            // Try specific selectors
            const signInBtn = document.querySelector('button.btn-primary, a[href*="login"], .login-btn');
            if (signInBtn) {
                signInBtn.click();
                return 'clicked selector';
            }
            // List what buttons exist for debugging
            let found = [];
            document.querySelectorAll('button, a.btn').forEach(b => found.push(b.textContent.trim()));
            return 'not found, buttons: ' + JSON.stringify(found);
        })()
    "#;

    let click_result = tab.evaluate(click_js, false)?;
    let click_msg = click_result
        .value
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| "no result".to_string());
    debug!(result = %click_msg, "Sign In button click result");

    // Wait for redirect to Cognito
    report_progress(
        &progress_callback,
        BrowserProgress::new("Waiting for Cognito redirect"),
    );
    std::thread::sleep(Duration::from_secs(3));

    // Wait for Cognito login page to load
    let mut on_cognito = false;
    for attempt in 0..15 {
        let current_url = tab.get_url();
        debug!(attempt, url = %current_url, "Checking for Cognito redirect");
        if current_url.contains("cognito") || current_url.contains("amazoncognito") {
            on_cognito = true;
            break;
        }
        // If still on POTA login page, try clicking again
        if attempt == 5 && current_url.contains("pota.app") {
            debug!("Still on POTA, trying to click Sign In again");
            let _ = tab.evaluate(click_js, false);
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    if !on_cognito {
        // Failed to reach Cognito - provide detailed error
        let current_url = tab.get_url();
        let page_info_js = r#"
            (function() {
                let btns = [];
                document.querySelectorAll('button, a.btn, .btn').forEach(b => {
                    btns.push({text: b.textContent.trim(), class: b.className});
                });
                return JSON.stringify({
                    title: document.title,
                    buttons: btns.slice(0, 10),
                    bodyText: document.body ? document.body.innerText.substring(0, 500) : 'no body'
                });
            })()
        "#;
        let page_info = tab
            .evaluate(page_info_js, false)
            .ok()
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "unknown".to_string());

        report_progress(
            &progress_callback,
            BrowserProgress::error("Failed to reach Cognito", &page_info),
        );
        return Err(anyhow!(
            "Failed to reach Cognito login page. Current URL: {}, Page info: {}",
            current_url,
            page_info
        ));
    }

    report_progress(
        &progress_callback,
        BrowserProgress::new("Entering credentials"),
    );
    debug!("On Cognito login page, entering credentials");

    // Wait for username field
    let username_field = tab.wait_for_element_with_custom_timeout(
        "input[name='username'], input[type='email'], #signInFormUsername, input[autocomplete='username']",
        Duration::from_secs(15),
    ).context("Could not find username field on Cognito page")?;

    // Clear and enter username
    username_field.click()?;
    std::thread::sleep(Duration::from_millis(200));
    tab.type_str(username)?;

    // Find and fill password field
    std::thread::sleep(Duration::from_millis(300));
    let password_field = tab
        .find_element("input[name='password'], input[type='password'], #signInFormPassword")
        .context("Could not find password field")?;
    password_field.click()?;
    std::thread::sleep(Duration::from_millis(200));
    tab.type_str(password)?;

    // Submit form
    report_progress(
        &progress_callback,
        BrowserProgress::new("Submitting login form"),
    );
    std::thread::sleep(Duration::from_millis(500));
    let submit_result = tab
        .find_element("input[type='submit'], button[type='submit'], .submitButton-customizable, button[name='signInSubmitButton']");

    if let Ok(submit_btn) = submit_result {
        debug!("Clicking submit button");
        submit_btn.click()?;
    } else {
        debug!("No submit button found, pressing Enter");
        tab.press_key("Enter")?;
    }

    // Wait for redirect back to POTA (can take a while)
    report_progress(
        &progress_callback,
        BrowserProgress::new("Waiting for authentication to complete"),
    );
    debug!("Waiting for authentication redirect");
    for i in 0..20 {
        std::thread::sleep(Duration::from_secs(1));
        let current_url = tab.get_url();
        debug!(attempt = i, url = %current_url, "Waiting for redirect");
        if current_url.contains("pota.app") && !current_url.contains("cognito") {
            debug!("Redirected back to POTA");
            // Give the app time to store tokens
            std::thread::sleep(Duration::from_secs(2));
            break;
        }
    }

    report_progress(
        &progress_callback,
        BrowserProgress::new("Extracting authentication token"),
    );

    // Try to extract ID token from cookies, localStorage, or sessionStorage
    // POTA stores the Cognito token in cookies after Hosted UI redirect
    let token_js = r#"
        (function() {
            // Check cookies first - POTA stores tokens here after Cognito redirect
            // Cookie format: CognitoIdentityServiceProvider.<clientId>.<userId>.idToken=<jwt>
            const cookies = document.cookie.split(';');
            for (const cookie of cookies) {
                const trimmed = cookie.trim();
                if (trimmed.includes('idToken=')) {
                    const eqIdx = trimmed.indexOf('=');
                    if (eqIdx > 0) {
                        const val = trimmed.substring(eqIdx + 1);
                        if (val && val.startsWith('eyJ')) {
                            return val;
                        }
                    }
                }
            }

            // Try localStorage
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (key && key.includes('idToken')) {
                    const val = localStorage.getItem(key);
                    if (val && val.startsWith('eyJ')) {
                        return val;
                    }
                }
            }

            // Check sessionStorage as well
            for (let i = 0; i < sessionStorage.length; i++) {
                const key = sessionStorage.key(i);
                if (key && key.includes('idToken')) {
                    const val = sessionStorage.getItem(key);
                    if (val && val.startsWith('eyJ')) {
                        return val;
                    }
                }
            }

            // Try to find Amplify auth data stored as JSON
            for (let i = 0; i < localStorage.length; i++) {
                const key = localStorage.key(i);
                if (key && (key.includes('amplify') || key.includes('Cognito') || key.includes('auth'))) {
                    try {
                        const val = localStorage.getItem(key);
                        const parsed = JSON.parse(val);
                        if (parsed && parsed.idToken) {
                            return parsed.idToken;
                        }
                        if (parsed && parsed.signInUserSession && parsed.signInUserSession.idToken) {
                            return parsed.signInUserSession.idToken.jwtToken;
                        }
                    } catch (e) {}
                }
            }

            return null;
        })()
    "#;

    // Retry token extraction a few times
    let mut id_token: Option<String> = None;
    for attempt in 0..5 {
        let result = tab.evaluate(token_js, false)?;
        if let Some(token) = result
            .value
            .and_then(|v| v.as_str().map(String::from))
            .filter(|t| !t.is_empty() && t != "null")
        {
            id_token = Some(token);
            break;
        }
        debug!(attempt, "Token not found yet, waiting...");
        std::thread::sleep(Duration::from_secs(1));
    }

    let id_token = id_token.ok_or_else(|| {
        // Get storage keys for debugging
        let debug_js = r#"
            (function() {
                let localKeys = [];
                for (let i = 0; i < localStorage.length; i++) {
                    localKeys.push(localStorage.key(i));
                }
                let sessionKeys = [];
                for (let i = 0; i < sessionStorage.length; i++) {
                    sessionKeys.push(sessionStorage.key(i));
                }
                // Also check if there's any user info visible
                let userInfo = document.querySelector('.user-info, .username, .callsign, [class*="user"], [class*="call"]');
                return JSON.stringify({
                    localStorage: localKeys,
                    sessionStorage: sessionKeys,
                    userElement: userInfo ? userInfo.textContent.trim() : null,
                    cookies: document.cookie.substring(0, 200)
                });
            })()
        "#;
        let debug_result = tab.evaluate(debug_js, false).ok();
        let debug_info = debug_result
            .and_then(|r| r.value)
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "unknown".to_string());
        anyhow!(
            "Failed to extract ID token. URL: {}, Debug: {}",
            tab.get_url(),
            debug_info
        )
    })?;

    // Build cached token struct
    let expires_at = extract_token_expiry(&id_token).unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600
    });

    let callsign = extract_callsign(&id_token);

    let success_msg = if let Some(ref cs) = callsign {
        format!("Authenticated as {}", cs)
    } else {
        "Authentication successful".to_string()
    };
    report_progress(&progress_callback, BrowserProgress::new(&success_msg));

    info!(callsign = ?callsign, "POTA authentication successful");

    Ok(PotaCachedTokens {
        id_token,
        expires_at,
        callsign,
        refresh_token: None,
    })
}

/// POTA upload job status
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PotaUploadJob {
    pub job_id: u64,
    /// Status codes: 0=pending, 1=processing, 2=complete, 3+=various error/special states
    pub status: u32,
    pub submitted: String,
    pub processed: Option<String>,
    pub reference: String,
    pub park_name: Option<String>,
    pub location: Option<String>,
    pub total: u32,
    pub inserted: u32,
    pub callsign_used: Option<String>,
    pub user_comment: Option<String>,
    // Allow additional fields we don't use
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

impl PotaUploadJob {
    pub fn status_string(&self) -> &'static str {
        match self.status {
            0 => "Pending",
            1 => "Processing",
            2 => "Completed",
            3 => "Failed",
            7 => "Duplicate",
            _ => "Unknown",
        }
    }

    /// Get the callsign used for this upload
    pub fn callsign(&self) -> Option<&str> {
        self.callsign_used.as_deref()
    }
}

/// Result of an ADIF upload attempt
#[derive(Debug, Clone)]
pub struct UploadResult {
    /// Whether the file was accepted (not a duplicate)
    pub accepted: bool,
    /// Message describing the result
    pub message: String,
}

// =============================================================================
// POTA Download API Types
// =============================================================================

/// Response from /user/activations endpoint
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PotaActivationsResponse {
    pub count: i64,
    pub activations: Vec<PotaRemoteActivation>,
}

/// A single activation from the POTA API
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PotaRemoteActivation {
    pub callsign: String,
    pub date: String,
    pub reference: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub parktype_desc: Option<String>,
    #[serde(default)]
    pub location_desc: Option<String>,
    #[serde(default)]
    pub first_qso: Option<String>,
    #[serde(default)]
    pub last_qso: Option<String>,
    #[serde(default)]
    pub total: i32,
    #[serde(default)]
    pub cw: i32,
    #[serde(default)]
    pub data: i32,
    #[serde(default)]
    pub phone: i32,
}

/// Response from /user/logbook endpoint
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PotaLogbookResponse {
    pub count: i64,
    pub entries: Vec<PotaRemoteQso>,
}

/// Helper to deserialize a field that could be a string or integer
fn deserialize_string_or_int<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct StringOrInt;

    impl<'de> Visitor<'de> for StringOrInt {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string, integer, or null")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value.to_string()))
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value))
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value.to_string()))
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value.to_string()))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(StringOrInt)
}

/// A single QSO from the POTA API logbook
/// Note: The API returns a mix of camelCase and snake_case field names,
/// and some fields can be either strings, integers, or null
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PotaRemoteQso {
    #[serde(rename = "qsoId")]
    pub qso_id: i64,
    #[serde(rename = "userId", default)]
    pub user_id: Option<i64>,
    #[serde(rename = "qsoDateTime")]
    pub qso_date_time: String,
    #[serde(rename = "station_callsign")]
    pub station_callsign: String,
    #[serde(rename = "operator_callsign", default)]
    pub operator_callsign: Option<String>,
    #[serde(rename = "worked_callsign")]
    pub worked_callsign: String,
    #[serde(default)]
    pub band: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(
        rename = "rst_sent",
        default,
        deserialize_with = "deserialize_string_or_int"
    )]
    pub rst_sent: Option<String>,
    #[serde(
        rename = "rst_rcvd",
        default,
        deserialize_with = "deserialize_string_or_int"
    )]
    pub rst_rcvd: Option<String>,
    #[serde(rename = "my_sig", default)]
    pub my_sig: Option<String>,
    #[serde(rename = "my_sig_info", default)]
    pub my_sig_info: Option<String>,
    #[serde(
        rename = "p2pMatch",
        default,
        deserialize_with = "deserialize_string_or_int"
    )]
    pub p2p_match: Option<String>,
    #[serde(rename = "jobId", default)]
    pub job_id: Option<i64>,
    #[serde(rename = "parkId", default)]
    pub park_id: Option<i64>,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(rename = "parktypeDesc", default)]
    pub parktype_desc: Option<String>,
    #[serde(rename = "locationId", default)]
    pub location_id: Option<i64>,
    #[serde(rename = "locationDesc", default)]
    pub location_desc: Option<String>,
    #[serde(rename = "locationName", default)]
    pub location_name: Option<String>,
    #[serde(default)]
    pub sig: Option<String>,
    #[serde(
        rename = "sig_info",
        default,
        deserialize_with = "deserialize_string_or_int"
    )]
    pub sig_info: Option<String>,
    #[serde(rename = "loggedMode", default)]
    pub logged_mode: Option<String>,
}

impl PotaRemoteQso {
    /// Convert to standard QSO format for the main qsos table
    pub fn to_qso(&self) -> Option<crate::adif::Qso> {
        use std::collections::HashMap;

        // Parse datetime: "2025-12-01T23:56:00" -> date "20251201", time "235600"
        let parts: Vec<&str> = self.qso_date_time.split('T').collect();
        if parts.len() != 2 {
            return None;
        }

        let date_str = parts[0].replace('-', "");
        let time_str = parts[1]
            .replace(':', "")
            .chars()
            .take(6)
            .collect::<String>();

        let band = self.band.clone().unwrap_or_default().to_lowercase();
        let mode = self.mode.clone().unwrap_or_default().to_uppercase();

        if band.is_empty() || mode.is_empty() {
            return None;
        }

        let mut other_fields = HashMap::new();

        // Add POTA-specific fields
        if let Some(ref park_ref) = self.reference {
            other_fields.insert("MY_POTA_REF".to_string(), park_ref.clone());
        }
        if let Some(ref sig_info) = self.sig_info
            && sig_info != "NONE"
        {
            other_fields.insert("POTA_REF".to_string(), sig_info.clone());
        }

        Some(crate::adif::Qso {
            call: self.worked_callsign.clone(),
            qso_date: date_str,
            time_on: time_str,
            band,
            mode,
            station_callsign: Some(self.station_callsign.clone()),
            freq: None,
            rst_sent: self.rst_sent.clone(),
            rst_rcvd: self.rst_rcvd.clone(),
            time_off: None,
            gridsquare: None,
            my_gridsquare: None,
            my_sig: self.my_sig.clone(),
            my_sig_info: self.my_sig_info.clone(),
            sig: self.sig.clone().filter(|s| s != "NONE"),
            sig_info: self.sig_info.clone().filter(|s| s != "NONE"),
            comment: None,
            my_state: self.location_desc.as_ref().and_then(|l| {
                // Extract state from "US-CA" -> "CA"
                l.split('-').nth(1).map(String::from)
            }),
            my_cnty: None,
            state: None,
            cnty: None,
            other_fields,
        })
    }
}

/// Get all activations from POTA
pub async fn get_activations(token: &str) -> Result<Vec<PotaRemoteActivation>> {
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/user/activations?all=1", POTA_API_URL))
        .header("Authorization", token)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!(
            "Failed to get POTA activations ({}): {}",
            status,
            body
        ));
    }

    let resp: PotaActivationsResponse = response.json().await?;
    Ok(resp.activations)
}

/// Get QSOs from a specific activation
///
/// Parameters:
/// - `token`: POTA API authentication token
/// - `reference`: Park reference (e.g., "US-0189")
/// - `date`: Activation date in "YYYY-MM-DD" format
/// - `page`: Page number (1-indexed)
/// - `page_size`: Number of QSOs per page (max 100)
pub async fn get_activation_qsos(
    token: &str,
    reference: &str,
    date: &str,
    page: u32,
    page_size: u32,
) -> Result<PotaLogbookResponse> {
    let client = reqwest::Client::new();

    let url = format!(
        "{}/user/logbook?activatorOnly=1&page={}&size={}&startDate={}&endDate={}&reference={}",
        POTA_API_URL, page, page_size, date, date, reference
    );

    debug!(url = %url, "Fetching POTA activation QSOs");

    let response = client
        .get(&url)
        .header("Authorization", token)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("Failed to get POTA logbook ({}): {}", status, body));
    }

    // Get the raw text first for debugging
    let body = response.text().await?;

    // Try to parse it
    match serde_json::from_str::<PotaLogbookResponse>(&body) {
        Ok(resp) => Ok(resp),
        Err(e) => {
            // Log a sample of the response for debugging
            let sample = if body.len() > 500 {
                &body[..500]
            } else {
                &body
            };
            warn!(
                error = %e,
                sample = %sample,
                "Failed to parse POTA logbook response"
            );
            Err(anyhow!("Failed to parse POTA logbook: {}", e))
        }
    }
}

/// Get all QSOs for an activation, handling pagination
pub async fn get_all_activation_qsos(
    token: &str,
    reference: &str,
    date: &str,
) -> Result<Vec<PotaRemoteQso>> {
    let mut all_qsos = Vec::new();
    let mut page = 1;
    let page_size = 100;

    loop {
        let resp = get_activation_qsos(token, reference, date, page, page_size).await?;
        let fetched = resp.entries.len();
        all_qsos.extend(resp.entries);

        // If we got fewer than page_size, we're done
        if fetched < page_size as usize {
            break;
        }

        // Safety check - don't fetch more than 10 pages (1000 QSOs per activation)
        if page >= 10 {
            warn!(
                reference,
                date, "Hit page limit when fetching POTA activation QSOs"
            );
            break;
        }

        page += 1;
    }

    Ok(all_qsos)
}

/// Upload ADIF file to POTA using the ID token
///
/// The POTA API requires:
/// - `adif`: The ADIF file content
/// - `reference`: Park reference (e.g., "US-4571")
/// - `location`: Location code (e.g., "US-CA")
/// - `callsign`: Operator's callsign
pub async fn upload_adif(
    token: &str,
    filename: &str,
    content: Vec<u8>,
    reference: &str,
    location: &str,
    callsign: &str,
) -> Result<UploadResult> {
    let client = reqwest::Client::new();

    let part = reqwest::multipart::Part::bytes(content)
        .file_name(filename.to_string())
        .mime_str("application/octet-stream")?;

    let form = reqwest::multipart::Form::new()
        .part("adif", part)
        .text("reference", reference.to_string())
        .text("location", location.to_string())
        .text("callsign", callsign.to_string());

    let response = client
        .post(format!("{}/adif", POTA_API_URL))
        .header("Authorization", token)
        .multipart(form)
        .send()
        .await?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();

    if !status.is_success() {
        return Err(anyhow!("POTA upload failed ({}): {}", status, body));
    }

    // A 200 response means success - the adif_files array in the response
    // is typically empty even for successful uploads
    info!(
        "POTA ADIF upload successful: {} (response: {})",
        filename, body
    );
    Ok(UploadResult {
        accepted: true,
        message: format!("File '{}' accepted for processing", filename),
    })
}

/// Get upload jobs from POTA
pub async fn get_upload_jobs(token: &str) -> Result<Vec<PotaUploadJob>> {
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/user/jobs", POTA_API_URL))
        .header("Authorization", token)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("Failed to get POTA jobs ({}): {}", status, body));
    }

    let jobs: Vec<PotaUploadJob> = response.json().await?;
    Ok(jobs)
}

/// Save tokens to disk
pub fn save_tokens(tokens: &PotaCachedTokens, path: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(tokens)?;
    std::fs::write(path, json)?;

    // Set restrictive permissions (readable only by owner)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    Ok(())
}

/// Load tokens from disk
pub fn load_tokens(path: &Path) -> Option<PotaCachedTokens> {
    if !path.exists() {
        return None;
    }

    let content = std::fs::read_to_string(path).ok()?;
    let tokens: PotaCachedTokens = serde_json::from_str(&content).ok()?;

    if tokens.is_valid() {
        Some(tokens)
    } else {
        info!("Cached POTA tokens expired");
        None
    }
}

/// High-level POTA uploader with token caching and retry logic
pub struct PotaUploader {
    tokens: Option<PotaCachedTokens>,
    cache_path: std::path::PathBuf,
    username: String,
    password: String,
    headless: bool,
    progress_callback: Option<ProgressCallback>,
    auth_service_client: Option<super::auth_service::PotaAuthServiceClient>,
}

impl PotaUploader {
    /// Create a new POTA uploader
    pub fn new(
        username: String,
        password: String,
        cache_path: std::path::PathBuf,
        headless: bool,
    ) -> Self {
        let tokens = load_tokens(&cache_path);
        Self {
            tokens,
            cache_path,
            username,
            password,
            headless,
            progress_callback: None,
            auth_service_client: None,
        }
    }

    /// Set a remote auth service client for browser-free authentication
    pub fn with_auth_service(mut self, client: super::auth_service::PotaAuthServiceClient) -> Self {
        self.auth_service_client = Some(client);
        self
    }

    /// Set a remote auth service client (mutable reference version)
    pub fn set_auth_service_client(&mut self, client: super::auth_service::PotaAuthServiceClient) {
        self.auth_service_client = Some(client);
    }

    /// Set a progress callback for status updates
    pub fn with_progress(mut self, callback: ProgressCallback) -> Self {
        self.progress_callback = Some(callback);
        self
    }

    /// Set a progress callback for status updates (mutable reference version)
    pub fn set_progress_callback(&mut self, callback: ProgressCallback) {
        self.progress_callback = Some(callback);
    }

    /// Report progress if callback is set
    fn report(&self, progress: BrowserProgress) {
        if let Some(ref cb) = self.progress_callback {
            cb(progress);
        }
    }

    /// Ensure we have valid tokens, authenticating if necessary (sync version, uses local browser)
    #[cfg(feature = "local-browser")]
    pub fn ensure_authenticated(&mut self) -> Result<()> {
        if self.tokens.as_ref().is_none_or(|t| !t.is_valid()) {
            info!("POTA tokens invalid or missing, authenticating via browser");
            self.report(BrowserProgress::new(
                "Cached tokens expired, re-authenticating",
            ));
            let tokens = authenticate_via_browser_with_progress(
                &self.username,
                &self.password,
                self.headless,
                self.progress_callback.clone(),
            )?;
            save_tokens(&tokens, &self.cache_path)?;
            self.tokens = Some(tokens);
        } else {
            self.report(BrowserProgress::new("Using cached authentication"));
        }
        Ok(())
    }

    /// Ensure we have valid tokens, using remote service if configured, otherwise local browser
    pub async fn ensure_authenticated_async(&mut self) -> Result<()> {
        if self.tokens.as_ref().is_none_or(|t| !t.is_valid()) {
            // Try remote auth service first if configured
            if let Some(ref client) = self.auth_service_client {
                info!("POTA tokens invalid or missing, authenticating via remote service");
                self.report(BrowserProgress::new(
                    "Cached tokens expired, authenticating via remote service",
                ));
                let tokens = client.authenticate(&self.username, &self.password).await?;
                save_tokens(&tokens, &self.cache_path)?;
                self.tokens = Some(tokens);
            } else {
                // Fall back to local browser (only available with local-browser feature)
                #[cfg(feature = "local-browser")]
                {
                    info!("POTA tokens invalid or missing, authenticating via local browser");
                    self.report(BrowserProgress::new(
                        "Cached tokens expired, re-authenticating via browser",
                    ));
                    let tokens = authenticate_via_browser_with_progress(
                        &self.username,
                        &self.password,
                        self.headless,
                        self.progress_callback.clone(),
                    )?;
                    save_tokens(&tokens, &self.cache_path)?;
                    self.tokens = Some(tokens);
                }
                #[cfg(not(feature = "local-browser"))]
                {
                    return Err(anyhow!(
                        "POTA authentication requires either a configured remote auth service \
                         or the 'local-browser' feature to be enabled"
                    ));
                }
            }
        } else {
            self.report(BrowserProgress::new("Using cached authentication"));
        }
        Ok(())
    }

    /// Get the current valid ID token
    pub fn id_token(&self) -> Option<&str> {
        self.tokens
            .as_ref()
            .filter(|t| t.is_valid())
            .map(|t| t.id_token.as_str())
    }

    /// Get the authenticated callsign
    pub fn callsign(&self) -> Option<&str> {
        self.tokens.as_ref().and_then(|t| t.callsign.as_deref())
    }

    /// Upload an ADIF file
    pub async fn upload(
        &mut self,
        filename: &str,
        content: Vec<u8>,
        reference: &str,
        location: &str,
        callsign: &str,
    ) -> Result<UploadResult> {
        self.report(BrowserProgress::with_detail(
            "Uploading ADIF file",
            filename,
        ));
        self.ensure_authenticated_async().await?;
        let token = self
            .id_token()
            .ok_or_else(|| anyhow!("No valid token after authentication"))?;
        upload_adif(token, filename, content, reference, location, callsign).await
    }

    /// Upload an ADIF file with retry logic
    pub async fn upload_with_retry(
        &mut self,
        filename: &str,
        content: Vec<u8>,
        reference: &str,
        location: &str,
        callsign: &str,
        max_retries: u32,
    ) -> Result<UploadResult> {
        let mut last_error = None;

        for attempt in 0..max_retries {
            if attempt > 0 {
                self.report(BrowserProgress::with_detail(
                    "Retrying upload",
                    format!("Attempt {} of {}", attempt + 1, max_retries),
                ));
            }
            match self
                .upload(filename, content.clone(), reference, location, callsign)
                .await
            {
                Ok(result) => {
                    if result.accepted {
                        self.report(BrowserProgress::new("Upload successful"));
                    } else {
                        self.report(BrowserProgress::with_detail(
                            "Upload rejected",
                            &result.message,
                        ));
                    }
                    return Ok(result);
                }
                Err(e) => {
                    let err_str = e.to_string();

                    // If auth error, force re-authentication
                    if err_str.contains("401") || err_str.contains("Unauthorized") {
                        warn!("POTA auth error, forcing re-authentication");
                        self.report(BrowserProgress::with_detail(
                            "Authentication expired",
                            "Re-authenticating...",
                        ));
                        self.tokens = None;
                    }

                    // Don't retry client errors (except auth)
                    if err_str.contains("400") {
                        self.report(BrowserProgress::error("Upload failed", &err_str));
                        return Err(e);
                    }

                    warn!(
                        attempt = attempt + 1,
                        max_retries,
                        error = %e,
                        "POTA upload attempt failed"
                    );
                    last_error = Some(e);

                    // Exponential backoff
                    let wait_secs = 2u64.pow(attempt);
                    self.report(BrowserProgress::with_detail(
                        "Upload failed, waiting to retry",
                        format!("Waiting {} seconds", wait_secs),
                    ));
                    tokio::time::sleep(Duration::from_secs(wait_secs)).await;
                }
            }
        }

        let err = last_error.unwrap_or_else(|| anyhow!("Upload failed"));
        self.report(BrowserProgress::error("Upload failed", err.to_string()));
        Err(err)
    }

    /// Get recent upload jobs
    pub async fn get_jobs(&mut self) -> Result<Vec<PotaUploadJob>> {
        self.report(BrowserProgress::new("Fetching upload jobs"));
        self.ensure_authenticated_async().await?;
        let token = self.id_token().ok_or_else(|| anyhow!("No valid token"))?;
        get_upload_jobs(token).await
    }

    /// Get all activations from POTA
    pub async fn get_activations(&mut self) -> Result<Vec<PotaRemoteActivation>> {
        self.report(BrowserProgress::new("Fetching activations from POTA"));
        self.ensure_authenticated_async().await?;
        let token = self.id_token().ok_or_else(|| anyhow!("No valid token"))?;
        get_activations(token).await
    }

    /// Get QSOs for a specific activation
    pub async fn get_activation_qsos(
        &mut self,
        reference: &str,
        date: &str,
    ) -> Result<Vec<PotaRemoteQso>> {
        self.report(BrowserProgress::with_detail(
            "Fetching activation QSOs",
            format!("{} on {}", reference, date),
        ));
        self.ensure_authenticated_async().await?;
        let token = self.id_token().ok_or_else(|| anyhow!("No valid token"))?;
        get_all_activation_qsos(token, reference, date).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_validity() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Valid token
        let valid = PotaCachedTokens {
            id_token: "test".into(),
            expires_at: now + 3600,
            callsign: None,
            refresh_token: None,
        };
        assert!(valid.is_valid());

        // Expired token
        let expired = PotaCachedTokens {
            id_token: "test".into(),
            expires_at: now - 100,
            callsign: None,
            refresh_token: None,
        };
        assert!(!expired.is_valid());

        // Within expiry buffer
        let expiring = PotaCachedTokens {
            id_token: "test".into(),
            expires_at: now + 100, // < 5 min buffer
            callsign: None,
            refresh_token: None,
        };
        assert!(!expiring.is_valid());
    }

    #[test]
    fn test_jwt_decoding() {
        // Create a test JWT with known claims
        // Header: {"alg":"RS256","typ":"JWT"}
        // Payload: {"exp":1764916224,"pota:callsign":"W6JSV"}
        let payload = r#"{"exp":1764916224,"pota:callsign":"W6JSV"}"#;
        let encoded_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
        let token = format!(
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.{}.signature",
            encoded_payload
        );

        let claims = decode_jwt_claims(&token).unwrap();
        assert_eq!(claims["exp"], 1764916224);
        assert_eq!(claims["pota:callsign"], "W6JSV");

        let expiry = extract_token_expiry(&token);
        assert_eq!(expiry, Some(1764916224));

        let callsign = extract_callsign(&token);
        assert_eq!(callsign, Some("W6JSV".to_string()));
    }

    #[test]
    fn test_job_status_string() {
        let job = PotaUploadJob {
            job_id: 1,
            status: 2,
            submitted: "2025-01-01".to_string(),
            processed: None,
            reference: "K-0001".to_string(),
            park_name: None,
            location: None,
            total: 10,
            inserted: 10,
            callsign_used: Some("W6JSV".to_string()),
            user_comment: None,
            extra: std::collections::HashMap::new(),
        };
        assert_eq!(job.status_string(), "Completed");
    }
}
