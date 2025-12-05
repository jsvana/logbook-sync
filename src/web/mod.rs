//! Web interface module for logbook-sync.
//!
//! Provides a browser-based UI for user configuration and management.

use axum::{
    Json, Router,
    extract::{Multipart, Path, State},
    http::{StatusCode, header::SET_COOKIE},
    response::{Html, IntoResponse},
    routing::{get, post, put},
};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tower_http::services::ServeDir;

use crate::config::SyncConfig;
use crate::crypto::MasterKey;
use crate::db::{Database, integrations, users};
use crate::lofi::{LofiClient, LofiConfig};
use crate::ntfy::{NtfyClient, NtfyConfig};
use crate::qrz::QrzClient;
use rusqlite::Connection;

const SESSION_COOKIE_NAME: &str = "logbook_session";

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub db_path: PathBuf,
    pub master_key: Arc<MasterKey>,
    pub sync_config: SyncConfig,
}

// === Request/Response types ===

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserInfo>,
}

#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserInfo {
    pub id: i64,
    pub username: String,
    pub email: Option<String>,
    pub callsign: Option<String>,
    pub is_admin: bool,
    pub theme: String,
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total_qsos: i64,
    pub synced_qrz: i64,
    pub pending_qrz: i64,
    pub lotw_confirmed: i64,
    pub qsl_confirmed: i64,
    pub processed_files: i64,
}

#[derive(Debug, Serialize)]
pub struct IntegrationInfo {
    pub integration_type: String,
    pub enabled: bool,
    pub config: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_state: Option<IntegrationSyncState>,
    /// Sync interval in seconds (from server config)
    pub sync_interval_secs: u64,
}

#[derive(Debug, Serialize)]
pub struct IntegrationSyncState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload: Option<SyncDirectionState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download: Option<SyncDirectionState>,
}

#[derive(Debug, Deserialize)]
pub struct SaveIntegrationRequest {
    pub config: Value,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub email: Option<String>,
    pub callsign: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateThemeRequest {
    pub theme: String,
}

#[derive(Debug, Deserialize)]
pub struct LofiSetupRequest {
    pub callsign: String,
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct LofiSetupResponse {
    pub success: bool,
    pub message: String,
    pub status: Option<LofiStatus>,
}

#[derive(Debug, Serialize)]
pub struct LofiStatus {
    pub client_key: String,
    pub registered: bool,
    pub email_sent: bool,
    pub device_linked: bool,
}

#[derive(Debug, Deserialize)]
pub struct LofiSendLinkRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct SyncStateResponse {
    pub integration_type: String,
    pub upload: Option<SyncDirectionState>,
    pub download: Option<SyncDirectionState>,
}

#[derive(Debug, Serialize)]
pub struct SyncDirectionState {
    pub last_sync_at: Option<String>,
    pub last_sync_result: Option<String>,
    pub last_sync_message: Option<String>,
    pub items_synced: i64,
}

#[derive(Debug, Serialize)]
pub struct SyncResponse {
    pub success: bool,
    pub message: String,
    pub items_synced: i64,
}

// === Auth helpers ===

/// Create a simple signed session token: user_id:timestamp:signature
fn create_session_token(user_id: i64, master_key: &MasterKey) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let payload = format!("{}:{}", user_id, timestamp);

    let mut mac = Hmac::<Sha256>::new_from_slice(master_key.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    format!("{}:{}", payload, signature)
}

/// Validate session token and return user_id if valid (within 7 days)
fn validate_session_token(token: &str, master_key: &MasterKey) -> Option<i64> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let parts: Vec<&str> = token.split(':').collect();
    if parts.len() != 3 {
        return None;
    }

    let user_id: i64 = parts[0].parse().ok()?;
    let timestamp: u64 = parts[1].parse().ok()?;
    let signature = parts[2];

    // Check if token is expired (7 days)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now - timestamp > 7 * 24 * 60 * 60 {
        return None;
    }

    // Verify signature
    let payload = format!("{}:{}", user_id, timestamp);
    let mut mac = Hmac::<Sha256>::new_from_slice(master_key.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    let expected_sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

    if signature == expected_sig {
        Some(user_id)
    } else {
        None
    }
}

/// Get current user from session cookie (returns full db user for internal use)
fn get_current_user_full(jar: &CookieJar, state: &AppState) -> Option<(users::User, Connection)> {
    let cookie = jar.get(SESSION_COOKIE_NAME)?;
    let user_id = validate_session_token(cookie.value(), &state.master_key)?;

    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database in get_current_user_full: {}", e);
            return None;
        }
    };

    let user = match users::get_user_by_id(&conn, user_id) {
        Ok(Some(u)) => u,
        Ok(None) => {
            tracing::debug!("User {} not found in database", user_id);
            return None;
        }
        Err(e) => {
            tracing::error!("Database error fetching user {}: {}", user_id, e);
            return None;
        }
    };

    if !user.is_active {
        return None;
    }

    Some((user, conn))
}

/// Get current user info from session cookie
fn get_current_user(jar: &CookieJar, state: &AppState) -> Option<UserInfo> {
    let (user, _conn) = get_current_user_full(jar, state)?;

    Some(UserInfo {
        id: user.id,
        username: user.username,
        email: user.email,
        callsign: user.callsign,
        is_admin: user.is_admin,
        theme: user.theme,
    })
}

// === Handlers ===

async fn index() -> Html<&'static str> {
    Html(include_str!("../../static/index.html"))
}

async fn login(State(state): State<AppState>, Json(req): Json<LoginRequest>) -> impl IntoResponse {
    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to open database: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("", "".to_string())],
                Json(LoginResponse {
                    success: false,
                    message: "Database error".into(),
                    user: None,
                }),
            );
        }
    };

    let user = match users::get_user_by_username(&conn, &req.username) {
        Ok(Some(u)) if u.is_active => u,
        Ok(Some(_)) => {
            return (
                StatusCode::FORBIDDEN,
                [("", "".to_string())],
                Json(LoginResponse {
                    success: false,
                    message: "Account is disabled".into(),
                    user: None,
                }),
            );
        }
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                [("", "".to_string())],
                Json(LoginResponse {
                    success: false,
                    message: "Invalid username or password".into(),
                    user: None,
                }),
            );
        }
        Err(e) => {
            tracing::error!(
                "Database error during login for user '{}': {}",
                req.username,
                e
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [("", "".to_string())],
                Json(LoginResponse {
                    success: false,
                    message: "Database error".into(),
                    user: None,
                }),
            );
        }
    };

    if !users::verify_password(&req.password, &user.password_hash) {
        return (
            StatusCode::UNAUTHORIZED,
            [("", "".to_string())],
            Json(LoginResponse {
                success: false,
                message: "Invalid username or password".into(),
                user: None,
            }),
        );
    }

    // Record login
    let _ = users::record_login(&conn, user.id);

    // Create session token
    let token = create_session_token(user.id, &state.master_key);

    // Set cookie
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        SESSION_COOKIE_NAME,
        token,
        7 * 24 * 60 * 60 // 7 days
    );

    let user_info = UserInfo {
        id: user.id,
        username: user.username,
        email: user.email,
        callsign: user.callsign,
        is_admin: user.is_admin,
        theme: user.theme,
    };

    (
        StatusCode::OK,
        [(SET_COOKIE.as_str(), cookie)],
        Json(LoginResponse {
            success: true,
            message: "Logged in successfully".into(),
            user: Some(user_info),
        }),
    )
}

async fn logout() -> impl IntoResponse {
    // Clear the session cookie
    let cookie = format!(
        "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        SESSION_COOKIE_NAME
    );

    (
        StatusCode::OK,
        [(SET_COOKIE.as_str(), cookie)],
        Json(SuccessResponse {
            success: true,
            message: None,
        }),
    )
}

async fn get_me(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    match get_current_user(&jar, &state) {
        Some(user) => (StatusCode::OK, Json(Some(user))),
        None => (StatusCode::UNAUTHORIZED, Json(None)),
    }
}

async fn get_stats(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    // Require authentication
    if get_current_user(&jar, &state).is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(StatsResponse {
                total_qsos: 0,
                synced_qrz: 0,
                pending_qrz: 0,
                lotw_confirmed: 0,
                qsl_confirmed: 0,
                processed_files: 0,
            }),
        );
    }

    let db = match Database::open(&state.db_path) {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(StatsResponse {
                    total_qsos: 0,
                    synced_qrz: 0,
                    pending_qrz: 0,
                    lotw_confirmed: 0,
                    qsl_confirmed: 0,
                    processed_files: 0,
                }),
            );
        }
    };

    match db.get_stats() {
        Ok(stats) => (
            StatusCode::OK,
            Json(StatsResponse {
                total_qsos: stats.total_qsos,
                synced_qrz: stats.synced_qrz,
                pending_qrz: stats.pending_qrz,
                lotw_confirmed: stats.lotw_confirmed,
                qsl_confirmed: stats.qsl_confirmed,
                processed_files: stats.processed_files,
            }),
        ),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(StatsResponse {
                total_qsos: 0,
                synced_qrz: 0,
                pending_qrz: 0,
                lotw_confirmed: 0,
                qsl_confirmed: 0,
                processed_files: 0,
            }),
        ),
    }
}

async fn list_users(State(state): State<AppState>) -> impl IntoResponse {
    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<UserInfo>::new()),
            );
        }
    };

    match users::list_users(&conn) {
        Ok(users_list) => {
            let info: Vec<UserInfo> = users_list
                .iter()
                .map(|u| UserInfo {
                    id: u.id,
                    username: u.username.clone(),
                    email: u.email.clone(),
                    callsign: u.callsign.clone(),
                    is_admin: u.is_admin,
                    theme: u.theme.clone(),
                })
                .collect();
            (StatusCode::OK, Json(info))
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(Vec::new())),
    }
}

async fn health() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(SuccessResponse {
            success: true,
            message: None,
        }),
    )
}

// === Integration handlers ===

async fn list_integrations(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let (user, conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(Vec::<IntegrationInfo>::new()),
            );
        }
    };

    let user_salt = match users::get_user_encryption_salt(&user) {
        Ok(s) => s,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(Vec::new())),
    };

    // Get all sync states for user
    let all_sync_states = integrations::get_all_sync_states(&conn, user.id).unwrap_or_default();

    match integrations::get_user_integrations(&conn, &state.master_key, user.id, &user_salt) {
        Ok(ints) => {
            let info: Vec<IntegrationInfo> = ints
                .into_iter()
                .map(|i| {
                    // Find sync states for this integration
                    let integration_states: Vec<_> = all_sync_states
                        .iter()
                        .filter(|s| s.integration_type == i.integration_type)
                        .collect();

                    let upload_state = integration_states
                        .iter()
                        .find(|s| s.direction == "upload")
                        .map(|s| SyncDirectionState {
                            last_sync_at: s.last_sync_at.clone(),
                            last_sync_result: s.last_sync_result.clone(),
                            last_sync_message: s.last_sync_message.clone(),
                            items_synced: s.items_synced,
                        });

                    let download_state = integration_states
                        .iter()
                        .find(|s| s.direction == "download")
                        .map(|s| SyncDirectionState {
                            last_sync_at: s.last_sync_at.clone(),
                            last_sync_result: s.last_sync_result.clone(),
                            last_sync_message: s.last_sync_message.clone(),
                            items_synced: s.items_synced,
                        });

                    let sync_state = if upload_state.is_some() || download_state.is_some() {
                        Some(IntegrationSyncState {
                            upload: upload_state,
                            download: download_state,
                        })
                    } else {
                        None
                    };

                    let sync_interval_secs = state.sync_config.interval_for(&i.integration_type);

                    IntegrationInfo {
                        integration_type: i.integration_type,
                        enabled: i.enabled,
                        config: serde_json::to_value(&i.config).unwrap_or(Value::Null),
                        sync_state,
                        sync_interval_secs,
                    }
                })
                .collect();
            (StatusCode::OK, Json(info))
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(Vec::new())),
    }
}

async fn save_integration(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(integration_type): Path<String>,
    Json(req): Json<SaveIntegrationRequest>,
) -> impl IntoResponse {
    let (user, conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(SuccessResponse {
                    success: false,
                    message: Some("Unauthorized".into()),
                }),
            );
        }
    };

    let user_salt = match users::get_user_encryption_salt(&user) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SuccessResponse {
                    success: false,
                    message: Some("Failed to get user salt".into()),
                }),
            );
        }
    };

    // Parse the config based on integration type
    let config = match parse_integration_config(&integration_type, &req.config) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SuccessResponse {
                    success: false,
                    message: Some(format!("Invalid config: {}", e)),
                }),
            );
        }
    };

    match integrations::save_integration(
        &conn,
        &state.master_key,
        user.id,
        &user_salt,
        &integration_type,
        &config,
        req.enabled,
    ) {
        Ok(_) => (
            StatusCode::OK,
            Json(SuccessResponse {
                success: true,
                message: None,
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SuccessResponse {
                success: false,
                message: Some(format!("Failed to save: {}", e)),
            }),
        ),
    }
}

fn parse_integration_config(
    integration_type: &str,
    config: &Value,
) -> Result<integrations::IntegrationConfig, String> {
    match integration_type {
        "qrz" => {
            let c: integrations::QrzIntegrationConfig =
                serde_json::from_value(config.clone()).map_err(|e| e.to_string())?;
            Ok(integrations::IntegrationConfig::Qrz(c))
        }
        "lofi" => {
            let c: integrations::LofiIntegrationConfig =
                serde_json::from_value(config.clone()).map_err(|e| e.to_string())?;
            Ok(integrations::IntegrationConfig::Lofi(c))
        }
        "lotw" => {
            let c: integrations::LotwIntegrationConfig =
                serde_json::from_value(config.clone()).map_err(|e| e.to_string())?;
            Ok(integrations::IntegrationConfig::Lotw(c))
        }
        "clublog" => {
            let c: integrations::ClublogIntegrationConfig =
                serde_json::from_value(config.clone()).map_err(|e| e.to_string())?;
            Ok(integrations::IntegrationConfig::Clublog(c))
        }
        "eqsl" => {
            let c: integrations::EqslIntegrationConfig =
                serde_json::from_value(config.clone()).map_err(|e| e.to_string())?;
            Ok(integrations::IntegrationConfig::Eqsl(c))
        }
        "hrdlog" => {
            let c: integrations::HrdlogIntegrationConfig =
                serde_json::from_value(config.clone()).map_err(|e| e.to_string())?;
            Ok(integrations::IntegrationConfig::Hrdlog(c))
        }
        "wavelog" => {
            let c: integrations::WavelogIntegrationConfig =
                serde_json::from_value(config.clone()).map_err(|e| e.to_string())?;
            Ok(integrations::IntegrationConfig::Wavelog(c))
        }
        "ntfy" => {
            let c: integrations::NtfyIntegrationConfig =
                serde_json::from_value(config.clone()).map_err(|e| e.to_string())?;
            Ok(integrations::IntegrationConfig::Ntfy(c))
        }
        "pota" => {
            let c: integrations::PotaIntegrationConfig =
                serde_json::from_value(config.clone()).map_err(|e| e.to_string())?;
            Ok(integrations::IntegrationConfig::Pota(c))
        }
        _ => Err(format!("Unknown integration type: {}", integration_type)),
    }
}

async fn delete_integration(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(integration_type): Path<String>,
) -> impl IntoResponse {
    let (user, conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(SuccessResponse {
                    success: false,
                    message: Some("Unauthorized".into()),
                }),
            );
        }
    };

    match integrations::delete_integration(&conn, user.id, &integration_type) {
        Ok(_) => (
            StatusCode::OK,
            Json(SuccessResponse {
                success: true,
                message: None,
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SuccessResponse {
                success: false,
                message: Some(format!("Failed to delete: {}", e)),
            }),
        ),
    }
}

#[derive(Debug, Deserialize)]
pub struct TestIntegrationRequest {
    pub config: Value,
}

async fn test_integration(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(integration_type): Path<String>,
    Json(req): Json<TestIntegrationRequest>,
) -> impl IntoResponse {
    // Just verify user is authenticated
    if get_current_user(&jar, &state).is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(SuccessResponse {
                success: false,
                message: Some("Unauthorized".into()),
            }),
        );
    }

    // Parse and test based on integration type
    match integration_type.as_str() {
        "qrz" => match serde_json::from_value::<integrations::QrzIntegrationConfig>(req.config) {
            Ok(config) => test_qrz_connection(&config).await,
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(SuccessResponse {
                    success: false,
                    message: Some(format!("Invalid config: {}", e)),
                }),
            ),
        },
        "lofi" => (
            StatusCode::OK,
            Json(SuccessResponse {
                success: true,
                message: Some("LoFi test not implemented yet".into()),
            }),
        ),
        "ntfy" => match serde_json::from_value::<integrations::NtfyIntegrationConfig>(req.config) {
            Ok(config) => test_ntfy_connection(&config).await,
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(SuccessResponse {
                    success: false,
                    message: Some(format!("Invalid config: {}", e)),
                }),
            ),
        },
        "pota" => match serde_json::from_value::<integrations::PotaIntegrationConfig>(req.config) {
            Ok(config) => test_pota_connection(&config).await,
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(SuccessResponse {
                    success: false,
                    message: Some(format!("Invalid config: {}", e)),
                }),
            ),
        },
        _ => (
            StatusCode::OK,
            Json(SuccessResponse {
                success: true,
                message: Some(format!("Test for {} not implemented yet", integration_type)),
            }),
        ),
    }
}

async fn test_qrz_connection(
    config: &integrations::QrzIntegrationConfig,
) -> (StatusCode, Json<SuccessResponse>) {
    use crate::qrz::QrzClient;

    if config.api_key.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(SuccessResponse {
                success: false,
                message: Some("API key is required".into()),
            }),
        );
    }

    let client = QrzClient::new(config.api_key.clone(), config.user_agent.clone());

    match client.get_status().await {
        Ok(status) => {
            let msg = if let Some(callsign) = status.callsign {
                format!(
                    "Connected! Callsign: {}, QSOs: {}",
                    callsign,
                    status.count.unwrap_or(0)
                )
            } else {
                "Connected successfully".into()
            };
            (
                StatusCode::OK,
                Json(SuccessResponse {
                    success: true,
                    message: Some(msg),
                }),
            )
        }
        Err(e) => (
            StatusCode::OK,
            Json(SuccessResponse {
                success: false,
                message: Some(format!("Connection failed: {}", e)),
            }),
        ),
    }
}

async fn test_ntfy_connection(
    config: &integrations::NtfyIntegrationConfig,
) -> (StatusCode, Json<SuccessResponse>) {
    if config.topic.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(SuccessResponse {
                success: false,
                message: Some("Topic is required".into()),
            }),
        );
    }

    let client_config = NtfyConfig {
        enabled: true,
        server: config.server.clone(),
        topic: config.topic.clone(),
        token: config.token.clone(),
        priority: config.priority,
    };

    let client = NtfyClient::new(client_config);

    let title = "logbook-sync - Test Notification";
    let message = "This is a test notification from logbook-sync. If you see this, ntfy is configured correctly!";

    match client.send(title, message).await {
        Ok(()) => (
            StatusCode::OK,
            Json(SuccessResponse {
                success: true,
                message: Some("Test notification sent successfully".into()),
            }),
        ),
        Err(e) => (
            StatusCode::OK,
            Json(SuccessResponse {
                success: false,
                message: Some(format!("Failed to send notification: {}", e)),
            }),
        ),
    }
}

async fn test_pota_connection(
    config: &integrations::PotaIntegrationConfig,
) -> (StatusCode, Json<SuccessResponse>) {
    use pota_adif_upload::PotaClient;

    if config.email.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(SuccessResponse {
                success: false,
                message: Some("Email is required".into()),
            }),
        );
    }

    if config.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(SuccessResponse {
                success: false,
                message: Some("Password is required".into()),
            }),
        );
    }

    // Try to authenticate with POTA - successful auth is sufficient to verify credentials
    match PotaClient::authenticate(&config.email, &config.password).await {
        Ok(_client) => (
            StatusCode::OK,
            Json(SuccessResponse {
                success: true,
                message: Some("Authentication successful!".into()),
            }),
        ),
        Err(e) => (
            StatusCode::OK,
            Json(SuccessResponse {
                success: false,
                message: Some(format!("Authentication failed: {}", e)),
            }),
        ),
    }
}

// === LoFi integration handlers ===

/// Setup LoFi integration: generate keys, register with LoFi, and send email link
async fn lofi_setup(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LofiSetupRequest>,
) -> impl IntoResponse {
    use crate::lofi::LofiClient;
    use crate::lofi::LofiConfig;

    let (user, conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(LofiSetupResponse {
                    success: false,
                    message: "Unauthorized".into(),
                    status: None,
                }),
            );
        }
    };

    let user_salt = match users::get_user_encryption_salt(&user) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to get user salt: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(LofiSetupResponse {
                    success: false,
                    message: "Internal error".into(),
                    status: None,
                }),
            );
        }
    };

    // Generate client key and secret
    let client_key = LofiClient::generate_client_key();
    let client_secret = LofiClient::generate_client_secret();

    tracing::info!("Generated LoFi client_key: {}", client_key);

    // Create LoFi config for registration
    let lofi_config = LofiConfig {
        enabled: true,
        client_key: Some(client_key.clone()),
        client_secret: Some(client_secret.clone()),
        callsign: Some(req.callsign.clone()),
        email: Some(req.email.clone()),
        sync_batch_size: 50,
        sync_loop_delay_ms: 10000,
        sync_check_period_ms: 300000, // 5 minutes
        device_linked: false,
    };

    // Create client and register
    let mut client = match LofiClient::new(lofi_config) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to create LoFi client: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(LofiSetupResponse {
                    success: false,
                    message: format!("Failed to create LoFi client: {}", e),
                    status: None,
                }),
            );
        }
    };

    // Register with LoFi
    let registration = match client.register().await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to register with LoFi: {}", e);
            return (
                StatusCode::OK,
                Json(LofiSetupResponse {
                    success: false,
                    message: format!("Failed to register with LoFi: {}", e),
                    status: None,
                }),
            );
        }
    };

    let bearer_token = registration.token;
    client.set_bearer_token(bearer_token.clone());

    // Send device link email
    if let Err(e) = client.link_device(&req.email).await {
        tracing::error!("Failed to send LoFi link email: {}", e);
        // Continue anyway - user can resend
    }

    // Save the integration config
    let config = integrations::LofiIntegrationConfig {
        client_key: client_key.clone(),
        client_secret,
        bearer_token: Some(bearer_token),
        account_uuid: Some(registration.account.uuid),
        device_linked: false,
        sync_batch_size: 50,
        sync_loop_delay_ms: 10000,
    };

    if let Err(e) = integrations::save_integration(
        &conn,
        &state.master_key,
        user.id,
        &user_salt,
        "lofi",
        &integrations::IntegrationConfig::Lofi(config),
        false, // Not enabled until device is linked
    ) {
        tracing::error!("Failed to save LoFi integration: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(LofiSetupResponse {
                success: false,
                message: "Failed to save integration".into(),
                status: None,
            }),
        );
    }

    (
        StatusCode::OK,
        Json(LofiSetupResponse {
            success: true,
            message: format!(
                "LoFi registered! Check {} for a confirmation email from Ham2K.",
                req.email
            ),
            status: Some(LofiStatus {
                client_key,
                registered: true,
                email_sent: true,
                device_linked: false,
            }),
        }),
    )
}

/// Get current LoFi integration status
async fn lofi_status(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let (user, conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(LofiSetupResponse {
                    success: false,
                    message: "Unauthorized".into(),
                    status: None,
                }),
            );
        }
    };

    let user_salt = match users::get_user_encryption_salt(&user) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(LofiSetupResponse {
                    success: false,
                    message: "Internal error".into(),
                    status: None,
                }),
            );
        }
    };

    let integration = match integrations::get_integration(
        &conn,
        &state.master_key,
        user.id,
        &user_salt,
        "lofi",
    ) {
        Ok(Some(i)) => i,
        Ok(None) => {
            return (
                StatusCode::OK,
                Json(LofiSetupResponse {
                    success: true,
                    message: "No LoFi integration configured".into(),
                    status: None,
                }),
            );
        }
        Err(e) => {
            tracing::error!("Failed to get LoFi integration: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(LofiSetupResponse {
                    success: false,
                    message: "Failed to get integration".into(),
                    status: None,
                }),
            );
        }
    };

    if let integrations::IntegrationConfig::Lofi(config) = integration.config {
        (
            StatusCode::OK,
            Json(LofiSetupResponse {
                success: true,
                message: if config.device_linked {
                    "LoFi integration is active".into()
                } else {
                    "Waiting for email confirmation".into()
                },
                status: Some(LofiStatus {
                    client_key: config.client_key,
                    registered: config.bearer_token.is_some(),
                    email_sent: true,
                    device_linked: config.device_linked,
                }),
            }),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(LofiSetupResponse {
                success: false,
                message: "Invalid integration type".into(),
                status: None,
            }),
        )
    }
}

/// Resend LoFi device link email
async fn lofi_send_link(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LofiSendLinkRequest>,
) -> impl IntoResponse {
    use crate::lofi::LofiClient;
    use crate::lofi::LofiConfig;

    let (user, conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(SuccessResponse {
                    success: false,
                    message: Some("Unauthorized".into()),
                }),
            );
        }
    };

    let user_salt = match users::get_user_encryption_salt(&user) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SuccessResponse {
                    success: false,
                    message: Some("Internal error".into()),
                }),
            );
        }
    };

    let integration = match integrations::get_integration(
        &conn,
        &state.master_key,
        user.id,
        &user_salt,
        "lofi",
    ) {
        Ok(Some(i)) => i,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SuccessResponse {
                    success: false,
                    message: Some("LoFi integration not set up yet".into()),
                }),
            );
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SuccessResponse {
                    success: false,
                    message: Some("Failed to get integration".into()),
                }),
            );
        }
    };

    if let integrations::IntegrationConfig::Lofi(config) = integration.config {
        let bearer_token = match config.bearer_token {
            Some(t) => t,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(SuccessResponse {
                        success: false,
                        message: Some("LoFi not registered yet".into()),
                    }),
                );
            }
        };

        let lofi_config = LofiConfig {
            enabled: true,
            client_key: Some(config.client_key),
            client_secret: Some(config.client_secret),
            callsign: None,
            email: None,
            sync_batch_size: config.sync_batch_size,
            sync_loop_delay_ms: config.sync_loop_delay_ms,
            sync_check_period_ms: 300000,
            device_linked: false,
        };

        let client = match LofiClient::with_token(lofi_config, bearer_token) {
            Ok(c) => c,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(SuccessResponse {
                        success: false,
                        message: Some(format!("Failed to create client: {}", e)),
                    }),
                );
            }
        };

        match client.link_device(&req.email).await {
            Ok(_) => (
                StatusCode::OK,
                Json(SuccessResponse {
                    success: true,
                    message: Some(format!("Confirmation email sent to {}", req.email)),
                }),
            ),
            Err(e) => (
                StatusCode::OK,
                Json(SuccessResponse {
                    success: false,
                    message: Some(format!("Failed to send email: {}", e)),
                }),
            ),
        }
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SuccessResponse {
                success: false,
                message: Some("Invalid integration type".into()),
            }),
        )
    }
}

/// Confirm LoFi device link (user clicked email)
async fn lofi_confirm(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let (user, conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(SuccessResponse {
                    success: false,
                    message: Some("Unauthorized".into()),
                }),
            );
        }
    };

    let user_salt = match users::get_user_encryption_salt(&user) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SuccessResponse {
                    success: false,
                    message: Some("Internal error".into()),
                }),
            );
        }
    };

    let integration = match integrations::get_integration(
        &conn,
        &state.master_key,
        user.id,
        &user_salt,
        "lofi",
    ) {
        Ok(Some(i)) => i,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SuccessResponse {
                    success: false,
                    message: Some("LoFi integration not set up yet".into()),
                }),
            );
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SuccessResponse {
                    success: false,
                    message: Some("Failed to get integration".into()),
                }),
            );
        }
    };

    if let integrations::IntegrationConfig::Lofi(mut config) = integration.config {
        // Mark device as linked
        config.device_linked = true;

        // Save updated config
        if let Err(e) = integrations::save_integration(
            &conn,
            &state.master_key,
            user.id,
            &user_salt,
            "lofi",
            &integrations::IntegrationConfig::Lofi(config),
            true, // Enable the integration
        ) {
            tracing::error!("Failed to save LoFi integration: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SuccessResponse {
                    success: false,
                    message: Some("Failed to save integration".into()),
                }),
            );
        }

        (
            StatusCode::OK,
            Json(SuccessResponse {
                success: true,
                message: Some("LoFi integration activated!".into()),
            }),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SuccessResponse {
                success: false,
                message: Some("Invalid integration type".into()),
            }),
        )
    }
}

// === Sync handlers ===

/// Get sync state for all integrations
async fn get_sync_states(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let (user, conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(Vec::<SyncStateResponse>::new()),
            );
        }
    };

    let states = match integrations::get_all_sync_states(&conn, user.id) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<SyncStateResponse>::new()),
            );
        }
    };

    // Group by integration type
    let mut grouped: std::collections::HashMap<String, SyncStateResponse> =
        std::collections::HashMap::new();

    for state in states {
        let entry = grouped
            .entry(state.integration_type.clone())
            .or_insert_with(|| SyncStateResponse {
                integration_type: state.integration_type.clone(),
                upload: None,
                download: None,
            });

        let direction_state = SyncDirectionState {
            last_sync_at: state.last_sync_at,
            last_sync_result: state.last_sync_result,
            last_sync_message: state.last_sync_message,
            items_synced: state.items_synced,
        };

        match state.direction.as_str() {
            "upload" => entry.upload = Some(direction_state),
            "download" => entry.download = Some(direction_state),
            _ => {}
        }
    }

    let response: Vec<SyncStateResponse> = grouped.into_values().collect();
    (StatusCode::OK, Json(response))
}

/// Sync from LoFi (download only - read-only integration)
async fn sync_lofi(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let (user, conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(SyncResponse {
                    success: false,
                    message: "Unauthorized".into(),
                    items_synced: 0,
                }),
            );
        }
    };

    let user_salt = match users::get_user_encryption_salt(&user) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SyncResponse {
                    success: false,
                    message: "Internal error".into(),
                    items_synced: 0,
                }),
            );
        }
    };

    // Get LoFi integration config
    let integration = match integrations::get_integration(
        &conn,
        &state.master_key,
        user.id,
        &user_salt,
        "lofi",
    ) {
        Ok(Some(i)) => i,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SyncResponse {
                    success: false,
                    message: "LoFi integration not configured".into(),
                    items_synced: 0,
                }),
            );
        }
        Err(e) => {
            tracing::error!("Failed to get LoFi integration: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SyncResponse {
                    success: false,
                    message: "Failed to get integration config".into(),
                    items_synced: 0,
                }),
            );
        }
    };

    let lofi_config = match integration.config {
        integrations::IntegrationConfig::Lofi(c) => c,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SyncResponse {
                    success: false,
                    message: "Invalid integration type".into(),
                    items_synced: 0,
                }),
            );
        }
    };

    if !lofi_config.device_linked {
        return (
            StatusCode::BAD_REQUEST,
            Json(SyncResponse {
                success: false,
                message: "Device not linked. Please complete email confirmation.".into(),
                items_synced: 0,
            }),
        );
    }

    // Convert to client config
    let client_config = LofiConfig {
        enabled: true,
        client_key: Some(lofi_config.client_key),
        client_secret: Some(lofi_config.client_secret),
        callsign: user.callsign.clone(),
        email: None,
        sync_batch_size: lofi_config.sync_batch_size,
        sync_loop_delay_ms: lofi_config.sync_loop_delay_ms,
        sync_check_period_ms: 0,
        device_linked: lofi_config.device_linked,
    };

    // Create client
    let client = match LofiClient::new(client_config) {
        Ok(c) => c,
        Err(e) => {
            let _ =
                integrations::record_sync_error(&conn, user.id, "lofi", "download", &e.to_string());
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SyncResponse {
                    success: false,
                    message: format!("Failed to create LoFi client: {}", e),
                    items_synced: 0,
                }),
            );
        }
    };

    // Set bearer token if we have one
    let mut client = client;
    if let Some(token) = lofi_config.bearer_token {
        client.set_bearer_token(token);
    }

    // Open database for writing QSOs
    let db = match Database::open(&state.db_path) {
        Ok(db) => db,
        Err(e) => {
            let _ =
                integrations::record_sync_error(&conn, user.id, "lofi", "download", &e.to_string());
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SyncResponse {
                    success: false,
                    message: format!("Database error: {}", e),
                    items_synced: 0,
                }),
            );
        }
    };

    // Fetch QSOs from LoFi
    let mut total_qsos = 0i64;
    let mut cursor: Option<f64> = None;

    loop {
        let response = match client.fetch_qsos(cursor, Some(50)).await {
            Ok(r) => r,
            Err(e) => {
                let err_msg = e.to_string();
                let _ =
                    integrations::record_sync_error(&conn, user.id, "lofi", "download", &err_msg);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(SyncResponse {
                        success: false,
                        message: format!("Failed to fetch from LoFi: {}", err_msg),
                        items_synced: total_qsos,
                    }),
                );
            }
        };

        for qso in &response.qsos {
            if qso.deleted != 0 {
                continue;
            }

            if let Err(e) = db.upsert_lofi_qso(qso) {
                tracing::warn!("Failed to save LoFi QSO: {}", e);
            } else {
                total_qsos += 1;
            }
        }

        if response.meta.qsos.records_left == 0 {
            break;
        }

        cursor = Some(response.meta.qsos.synced_until_millis);

        // Small delay between requests
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    // Record success
    let _ = integrations::record_sync_success(
        &conn,
        user.id,
        "lofi",
        "download",
        total_qsos,
        Some(&format!("Downloaded {} QSOs", total_qsos)),
    );

    (
        StatusCode::OK,
        Json(SyncResponse {
            success: true,
            message: format!("Downloaded {} QSOs from LoFi", total_qsos),
            items_synced: total_qsos,
        }),
    )
}

/// Sync QRZ - upload QSOs
async fn sync_qrz_upload(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let (user, conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(SyncResponse {
                    success: false,
                    message: "Unauthorized".into(),
                    items_synced: 0,
                }),
            );
        }
    };

    let user_salt = match users::get_user_encryption_salt(&user) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SyncResponse {
                    success: false,
                    message: "Internal error".into(),
                    items_synced: 0,
                }),
            );
        }
    };

    // Get QRZ integration config
    let integration =
        match integrations::get_integration(&conn, &state.master_key, user.id, &user_salt, "qrz") {
            Ok(Some(i)) => i,
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(SyncResponse {
                        success: false,
                        message: "QRZ integration not configured".into(),
                        items_synced: 0,
                    }),
                );
            }
            Err(e) => {
                tracing::error!("Failed to get QRZ integration: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(SyncResponse {
                        success: false,
                        message: "Failed to get integration config".into(),
                        items_synced: 0,
                    }),
                );
            }
        };

    let qrz_config = match integration.config {
        integrations::IntegrationConfig::Qrz(c) => c,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SyncResponse {
                    success: false,
                    message: "Invalid integration type".into(),
                    items_synced: 0,
                }),
            );
        }
    };

    if !qrz_config.upload_enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(SyncResponse {
                success: false,
                message: "QRZ upload is disabled".into(),
                items_synced: 0,
            }),
        );
    }

    // Create QRZ client
    let client = QrzClient::new(qrz_config.api_key.clone(), qrz_config.user_agent.clone());

    // Get unsynced QSOs
    let db = match Database::open(&state.db_path) {
        Ok(db) => db,
        Err(e) => {
            let err_msg = e.to_string();
            let _ = integrations::record_sync_error(&conn, user.id, "qrz", "upload", &err_msg);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SyncResponse {
                    success: false,
                    message: format!("Database error: {}", err_msg),
                    items_synced: 0,
                }),
            );
        }
    };

    let unsynced = match db.get_unsynced_qrz() {
        Ok(q) => q,
        Err(e) => {
            let err_msg = e.to_string();
            let _ = integrations::record_sync_error(&conn, user.id, "qrz", "upload", &err_msg);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SyncResponse {
                    success: false,
                    message: format!("Failed to get unsynced QSOs: {}", err_msg),
                    items_synced: 0,
                }),
            );
        }
    };

    if unsynced.is_empty() {
        let _ = integrations::record_sync_success(
            &conn,
            user.id,
            "qrz",
            "upload",
            0,
            Some("No QSOs to upload"),
        );
        return (
            StatusCode::OK,
            Json(SyncResponse {
                success: true,
                message: "No QSOs to upload".into(),
                items_synced: 0,
            }),
        );
    }

    let mut uploaded = 0i64;
    let mut errors = Vec::new();

    for stored_qso in &unsynced {
        // Parse the stored ADIF record to get the original Qso
        let qso: crate::adif::Qso = match serde_json::from_str(&stored_qso.adif_record) {
            Ok(q) => q,
            Err(e) => {
                errors.push(format!("{}: Failed to parse QSO: {}", stored_qso.call, e));
                continue;
            }
        };

        match client.upload_qso(&qso).await {
            Ok(result) => {
                if let Some(logid) = result.logid {
                    let _ = db.mark_qrz_synced(stored_qso.id, logid);
                }
                if !result.is_duplicate {
                    uploaded += 1;
                }
            }
            Err(e) => {
                errors.push(format!("{}: {}", stored_qso.call, e));
                if errors.len() >= 5 {
                    break; // Stop after 5 errors
                }
            }
        }

        // Small delay between uploads
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    let message = if errors.is_empty() {
        format!("Uploaded {} QSOs to QRZ", uploaded)
    } else {
        format!(
            "Uploaded {} QSOs with {} errors: {}",
            uploaded,
            errors.len(),
            errors.join(", ")
        )
    };

    if errors.is_empty() {
        let _ = integrations::record_sync_success(
            &conn,
            user.id,
            "qrz",
            "upload",
            uploaded,
            Some(&message),
        );
    } else {
        let _ = integrations::record_sync_error(&conn, user.id, "qrz", "upload", &message);
    }

    (
        StatusCode::OK,
        Json(SyncResponse {
            success: errors.is_empty(),
            message,
            items_synced: uploaded,
        }),
    )
}

/// Sync QRZ - download QSOs
async fn sync_qrz_download(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let (user, conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(SyncResponse {
                    success: false,
                    message: "Unauthorized".into(),
                    items_synced: 0,
                }),
            );
        }
    };

    let user_salt = match users::get_user_encryption_salt(&user) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SyncResponse {
                    success: false,
                    message: "Internal error".into(),
                    items_synced: 0,
                }),
            );
        }
    };

    // Get QRZ integration config
    let integration =
        match integrations::get_integration(&conn, &state.master_key, user.id, &user_salt, "qrz") {
            Ok(Some(i)) => i,
            Ok(None) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(SyncResponse {
                        success: false,
                        message: "QRZ integration not configured".into(),
                        items_synced: 0,
                    }),
                );
            }
            Err(e) => {
                tracing::error!("Failed to get QRZ integration: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(SyncResponse {
                        success: false,
                        message: "Failed to get integration config".into(),
                        items_synced: 0,
                    }),
                );
            }
        };

    let qrz_config = match integration.config {
        integrations::IntegrationConfig::Qrz(c) => c,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SyncResponse {
                    success: false,
                    message: "Invalid integration type".into(),
                    items_synced: 0,
                }),
            );
        }
    };

    if !qrz_config.download_enabled {
        return (
            StatusCode::BAD_REQUEST,
            Json(SyncResponse {
                success: false,
                message: "QRZ download is disabled".into(),
                items_synced: 0,
            }),
        );
    }

    // Create QRZ client
    let client = QrzClient::new(qrz_config.api_key.clone(), qrz_config.user_agent.clone());

    let db = match Database::open(&state.db_path) {
        Ok(db) => db,
        Err(e) => {
            let err_msg = e.to_string();
            let _ = integrations::record_sync_error(&conn, user.id, "qrz", "download", &err_msg);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SyncResponse {
                    success: false,
                    message: format!("Database error: {}", err_msg),
                    items_synced: 0,
                }),
            );
        }
    };

    // Fetch all QSOs from QRZ
    let fetched_qsos = match client.fetch_all().await {
        Ok(q) => q,
        Err(e) => {
            let err_msg = e.to_string();
            let _ = integrations::record_sync_error(&conn, user.id, "qrz", "download", &err_msg);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SyncResponse {
                    success: false,
                    message: format!("Failed to fetch from QRZ: {}", err_msg),
                    items_synced: 0,
                }),
            );
        }
    };

    let mut imported = 0i64;
    for fetched in &fetched_qsos {
        let source_id = fetched.qrz_logid.map(|id| id.to_string());
        if let Err(e) = db.upsert_qso_with_source(&fetched.qso, None, "qrz", source_id.as_deref()) {
            tracing::warn!("Failed to save QRZ QSO: {}", e);
        } else {
            imported += 1;
        }
    }

    let message = format!("Downloaded {} QSOs from QRZ", imported);
    let _ = integrations::record_sync_success(
        &conn,
        user.id,
        "qrz",
        "download",
        imported,
        Some(&message),
    );

    (
        StatusCode::OK,
        Json(SyncResponse {
            success: true,
            message,
            items_synced: imported,
        }),
    )
}

// === POTA sync handlers ===

/// Response for POTA preview (dry run)
#[derive(Debug, Serialize)]
pub struct PotaPreviewResponse {
    pub success: bool,
    pub valid_activations: Vec<PotaActivationInfo>,
    pub invalid_activations: Vec<PotaActivationInfo>,
    pub total_qsos: usize,
    pub skipped_qsos: usize,
    pub message: Option<String>,
}

/// Info about a single POTA activation
#[derive(Debug, Serialize)]
pub struct PotaActivationInfo {
    pub park_ref: String,
    pub date: String,
    pub qso_count: usize,
    pub is_valid: bool,
    pub qsos: Vec<PotaQsoInfo>,
}

/// Brief info about a QSO in a POTA activation
#[derive(Debug, Serialize)]
pub struct PotaQsoInfo {
    pub call: String,
    pub time: String,
    pub band: String,
    pub mode: String,
}

/// Request for POTA upload (can specify which activations to upload)
#[derive(Debug, Deserialize)]
pub struct PotaUploadRequest {
    /// If provided, only upload these specific activations (park_ref + date pairs)
    /// Format: ["US-0001:20240101", "US-0002:20240102"]
    pub activations: Option<Vec<String>>,
}

/// Response for POTA upload
#[derive(Debug, Serialize)]
pub struct PotaUploadResponse {
    pub success: bool,
    pub message: String,
    pub activations_uploaded: usize,
    pub qsos_uploaded: usize,
    pub errors: Vec<String>,
}

/// Preview POTA activations (dry run)
async fn pota_preview(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    if get_current_user(&jar, &state).is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(PotaPreviewResponse {
                success: false,
                valid_activations: vec![],
                invalid_activations: vec![],
                total_qsos: 0,
                skipped_qsos: 0,
                message: Some("Unauthorized".into()),
            }),
        );
    }

    // Get all QSOs
    let db = match Database::open(&state.db_path) {
        Ok(db) => db,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PotaPreviewResponse {
                    success: false,
                    valid_activations: vec![],
                    invalid_activations: vec![],
                    total_qsos: 0,
                    skipped_qsos: 0,
                    message: Some(format!("Database error: {}", e)),
                }),
            );
        }
    };

    let qsos = match db.get_all_qsos() {
        Ok(q) => q,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PotaPreviewResponse {
                    success: false,
                    valid_activations: vec![],
                    invalid_activations: vec![],
                    total_qsos: 0,
                    skipped_qsos: 0,
                    message: Some(format!("Failed to get QSOs: {}", e)),
                }),
            );
        }
    };

    // Generate preview
    let preview = crate::pota::preview_upload(&qsos);

    let valid_activations: Vec<PotaActivationInfo> = preview
        .valid_activations
        .iter()
        .map(|a| PotaActivationInfo {
            park_ref: a.park_ref.clone(),
            date: a.date.clone(),
            qso_count: a.qsos.len(),
            is_valid: true,
            qsos: a
                .qsos
                .iter()
                .map(|q| PotaQsoInfo {
                    call: q.call.clone(),
                    time: q.time_on.clone(),
                    band: q.band.clone(),
                    mode: q.mode.clone(),
                })
                .collect(),
        })
        .collect();

    let invalid_activations: Vec<PotaActivationInfo> = preview
        .invalid_activations
        .iter()
        .map(|a| PotaActivationInfo {
            park_ref: a.park_ref.clone(),
            date: a.date.clone(),
            qso_count: a.qsos.len(),
            is_valid: false,
            qsos: a
                .qsos
                .iter()
                .map(|q| PotaQsoInfo {
                    call: q.call.clone(),
                    time: q.time_on.clone(),
                    band: q.band.clone(),
                    mode: q.mode.clone(),
                })
                .collect(),
        })
        .collect();

    (
        StatusCode::OK,
        Json(PotaPreviewResponse {
            success: true,
            valid_activations,
            invalid_activations,
            total_qsos: preview.total_qsos,
            skipped_qsos: preview.skipped_qsos,
            message: None,
        }),
    )
}

/// Upload POTA activations
async fn pota_upload(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<PotaUploadRequest>,
) -> impl IntoResponse {
    let (user, conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(PotaUploadResponse {
                    success: false,
                    message: "Unauthorized".into(),
                    activations_uploaded: 0,
                    qsos_uploaded: 0,
                    errors: vec![],
                }),
            );
        }
    };

    let user_salt = match users::get_user_encryption_salt(&user) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PotaUploadResponse {
                    success: false,
                    message: "Internal error".into(),
                    activations_uploaded: 0,
                    qsos_uploaded: 0,
                    errors: vec![],
                }),
            );
        }
    };

    // Get POTA integration config
    let integration = match integrations::get_integration(
        &conn,
        &state.master_key,
        user.id,
        &user_salt,
        "pota",
    ) {
        Ok(Some(i)) => i,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(PotaUploadResponse {
                    success: false,
                    message: "POTA integration not configured".into(),
                    activations_uploaded: 0,
                    qsos_uploaded: 0,
                    errors: vec![],
                }),
            );
        }
        Err(e) => {
            tracing::error!("Failed to get POTA integration: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PotaUploadResponse {
                    success: false,
                    message: "Failed to get integration config".into(),
                    activations_uploaded: 0,
                    qsos_uploaded: 0,
                    errors: vec![],
                }),
            );
        }
    };

    let pota_config = match integration.config {
        integrations::IntegrationConfig::Pota(c) => c,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PotaUploadResponse {
                    success: false,
                    message: "Invalid integration type".into(),
                    activations_uploaded: 0,
                    qsos_uploaded: 0,
                    errors: vec![],
                }),
            );
        }
    };

    // Get all QSOs
    let db = match Database::open(&state.db_path) {
        Ok(db) => db,
        Err(e) => {
            let err_msg = e.to_string();
            let _ = integrations::record_sync_error(&conn, user.id, "pota", "upload", &err_msg);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PotaUploadResponse {
                    success: false,
                    message: format!("Database error: {}", err_msg),
                    activations_uploaded: 0,
                    qsos_uploaded: 0,
                    errors: vec![],
                }),
            );
        }
    };

    let qsos = match db.get_all_qsos() {
        Ok(q) => q,
        Err(e) => {
            let err_msg = e.to_string();
            let _ = integrations::record_sync_error(&conn, user.id, "pota", "upload", &err_msg);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PotaUploadResponse {
                    success: false,
                    message: format!("Failed to get QSOs: {}", err_msg),
                    activations_uploaded: 0,
                    qsos_uploaded: 0,
                    errors: vec![],
                }),
            );
        }
    };

    // Group into activations
    let (all_activations, _skipped) = crate::pota::group_pota_activations(&qsos);

    // Filter to valid activations and optionally filter by requested activation keys
    let activations_to_upload: Vec<_> = all_activations
        .into_iter()
        .filter(|a| a.is_valid_activation())
        .filter(|a| {
            if let Some(ref requested) = req.activations {
                let key = format!("{}:{}", a.park_ref, a.date);
                requested.contains(&key)
            } else {
                true
            }
        })
        .collect();

    if activations_to_upload.is_empty() {
        return (
            StatusCode::OK,
            Json(PotaUploadResponse {
                success: true,
                message: "No valid activations to upload".into(),
                activations_uploaded: 0,
                qsos_uploaded: 0,
                errors: vec![],
            }),
        );
    }

    // Upload to POTA
    let result = match crate::pota::upload_to_pota(
        &pota_config.email,
        &pota_config.password,
        &activations_to_upload,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            let err_msg = e.to_string();
            let _ = integrations::record_sync_error(&conn, user.id, "pota", "upload", &err_msg);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PotaUploadResponse {
                    success: false,
                    message: format!("Upload failed: {}", err_msg),
                    activations_uploaded: 0,
                    qsos_uploaded: 0,
                    errors: vec![err_msg],
                }),
            );
        }
    };

    // Record sync result
    if result.errors.is_empty() {
        let _ = integrations::record_sync_success(
            &conn,
            user.id,
            "pota",
            "upload",
            result.qsos_uploaded as i64,
            Some(&format!(
                "Uploaded {} activations",
                result.activations_uploaded
            )),
        );
    } else {
        let _ = integrations::record_sync_error(
            &conn,
            user.id,
            "pota",
            "upload",
            &result.errors.join("; "),
        );
    }

    let message = format!(
        "Uploaded {} activations ({} QSOs){}",
        result.activations_uploaded,
        result.qsos_uploaded,
        if result.errors.is_empty() {
            String::new()
        } else {
            format!(" with {} errors", result.errors.len())
        }
    );

    (
        StatusCode::OK,
        Json(PotaUploadResponse {
            success: result.errors.is_empty(),
            message,
            activations_uploaded: result.activations_uploaded,
            qsos_uploaded: result.qsos_uploaded,
            errors: result.errors,
        }),
    )
}

#[derive(Debug, Serialize)]
pub struct PotaJobsResponse {
    pub success: bool,
    pub jobs: Vec<crate::pota::PotaJobInfo>,
    pub message: Option<String>,
}

async fn pota_jobs(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let (user, conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(PotaJobsResponse {
                    success: false,
                    jobs: vec![],
                    message: Some("Unauthorized".into()),
                }),
            );
        }
    };

    let user_salt = match users::get_user_encryption_salt(&user) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PotaJobsResponse {
                    success: false,
                    jobs: vec![],
                    message: Some("Internal error".into()),
                }),
            );
        }
    };

    // Get POTA integration config
    let integration = match integrations::get_integration(
        &conn,
        &state.master_key,
        user.id,
        &user_salt,
        "pota",
    ) {
        Ok(Some(i)) => i,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(PotaJobsResponse {
                    success: false,
                    jobs: vec![],
                    message: Some("POTA integration not configured".into()),
                }),
            );
        }
        Err(e) => {
            tracing::error!("Failed to get POTA integration: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PotaJobsResponse {
                    success: false,
                    jobs: vec![],
                    message: Some("Failed to get integration config".into()),
                }),
            );
        }
    };

    let pota_config = match integration.config {
        integrations::IntegrationConfig::Pota(c) => c,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PotaJobsResponse {
                    success: false,
                    jobs: vec![],
                    message: Some("Invalid integration type".into()),
                }),
            );
        }
    };

    match crate::pota::get_upload_jobs(&pota_config.email, &pota_config.password).await {
        Ok(jobs) => (
            StatusCode::OK,
            Json(PotaJobsResponse {
                success: true,
                jobs,
                message: None,
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(PotaJobsResponse {
                success: false,
                jobs: vec![],
                message: Some(format!("Failed to get jobs: {}", e)),
            }),
        ),
    }
}

// === User profile handlers ===

async fn update_profile(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<UpdateProfileRequest>,
) -> impl IntoResponse {
    let (user, conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(SuccessResponse {
                    success: false,
                    message: Some("Unauthorized".into()),
                }),
            );
        }
    };

    match users::update_user_profile(
        &conn,
        user.id,
        req.email.as_deref(),
        req.callsign.as_deref(),
    ) {
        Ok(_) => (
            StatusCode::OK,
            Json(SuccessResponse {
                success: true,
                message: None,
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SuccessResponse {
                success: false,
                message: Some(format!("Failed to update profile: {}", e)),
            }),
        ),
    }
}

async fn update_theme(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<UpdateThemeRequest>,
) -> impl IntoResponse {
    let (user, conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(SuccessResponse {
                    success: false,
                    message: Some("Unauthorized".into()),
                }),
            );
        }
    };

    match users::update_user_theme(&conn, user.id, &req.theme) {
        Ok(_) => (
            StatusCode::OK,
            Json(SuccessResponse {
                success: true,
                message: None,
            }),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(SuccessResponse {
                success: false,
                message: Some(format!("{}", e)),
            }),
        ),
    }
}

async fn change_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    let (user, conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(SuccessResponse {
                    success: false,
                    message: Some("Unauthorized".into()),
                }),
            );
        }
    };

    // Verify current password
    if !users::verify_password(&req.current_password, &user.password_hash) {
        return (
            StatusCode::BAD_REQUEST,
            Json(SuccessResponse {
                success: false,
                message: Some("Current password is incorrect".into()),
            }),
        );
    }

    // Check new password length
    if req.new_password.len() < 12 {
        return (
            StatusCode::BAD_REQUEST,
            Json(SuccessResponse {
                success: false,
                message: Some("New password must be at least 12 characters".into()),
            }),
        );
    }

    match users::update_password(&conn, user.id, &req.new_password) {
        Ok(_) => (
            StatusCode::OK,
            Json(SuccessResponse {
                success: true,
                message: Some("Password changed successfully".into()),
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SuccessResponse {
                success: false,
                message: Some(format!("Failed to change password: {}", e)),
            }),
        ),
    }
}

// === Log upload handler ===

async fn upload_log(
    State(state): State<AppState>,
    jar: CookieJar,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let (user, _conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(SuccessResponse {
                    success: false,
                    message: Some("Unauthorized".into()),
                }),
            );
        }
    };

    // Get the uploaded file
    let field = match multipart.next_field().await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SuccessResponse {
                    success: false,
                    message: Some("No file uploaded".into()),
                }),
            );
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SuccessResponse {
                    success: false,
                    message: Some(format!("Failed to read upload: {}", e)),
                }),
            );
        }
    };

    let filename = field
        .file_name()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "upload.adi".to_string());

    // Validate file extension
    if !filename.to_lowercase().ends_with(".adi") && !filename.to_lowercase().ends_with(".adif") {
        return (
            StatusCode::BAD_REQUEST,
            Json(SuccessResponse {
                success: false,
                message: Some("File must be an ADIF file (.adi or .adif)".into()),
            }),
        );
    }

    // Read file contents
    let data = match field.bytes().await {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SuccessResponse {
                    success: false,
                    message: Some(format!("Failed to read file: {}", e)),
                }),
            );
        }
    };

    // Create user-specific upload directory
    let upload_dir = state
        .db_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("uploads")
        .join(format!("user_{}", user.id));

    if let Err(e) = tokio::fs::create_dir_all(&upload_dir).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SuccessResponse {
                success: false,
                message: Some(format!("Failed to create upload directory: {}", e)),
            }),
        );
    }

    // Generate unique filename with timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let safe_filename = format!("{}_{}", timestamp, sanitize_filename(&filename));
    let file_path = upload_dir.join(&safe_filename);

    // Save the file
    let mut file = match tokio::fs::File::create(&file_path).await {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SuccessResponse {
                    success: false,
                    message: Some(format!("Failed to create file: {}", e)),
                }),
            );
        }
    };

    if let Err(e) = file.write_all(&data).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SuccessResponse {
                success: false,
                message: Some(format!("Failed to write file: {}", e)),
            }),
        );
    }

    // Parse the ADIF file to count QSOs
    let content = String::from_utf8_lossy(&data);
    let qso_count = match crate::adif::parse_adif(&content) {
        Ok(parsed) => parsed.qsos.len(),
        Err(e) => {
            // File saved but couldn't parse - still report success but note the issue
            return (
                StatusCode::OK,
                Json(SuccessResponse {
                    success: true,
                    message: Some(format!(
                        "File saved but could not parse ADIF: {}. File: {}",
                        e, safe_filename
                    )),
                }),
            );
        }
    };

    (
        StatusCode::OK,
        Json(SuccessResponse {
            success: true,
            message: Some(format!("Uploaded {} with {} QSOs", filename, qso_count)),
        }),
    )
}

/// Sanitize a filename to prevent path traversal
fn sanitize_filename(filename: &str) -> String {
    filename
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
        .collect()
}

/// Build the web application router
pub async fn build_router(
    db_path: PathBuf,
    master_key: MasterKey,
    sync_config: SyncConfig,
) -> Router {
    let state = AppState {
        db_path,
        master_key: Arc::new(master_key),
        sync_config,
    };

    // API routes
    let api_routes = Router::new()
        // Auth
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(get_me))
        // Health/stats
        .route("/health", get(health))
        .route("/stats", get(get_stats))
        .route("/qsos/stats", get(get_stats))
        // Users
        .route("/users", get(list_users))
        .route("/users/me", put(update_profile))
        .route("/users/me/password", put(change_password))
        .route("/users/me/theme", put(update_theme))
        // Integrations
        .route("/integrations", get(list_integrations))
        .route(
            "/integrations/:integration_type",
            put(save_integration).delete(delete_integration),
        )
        .route(
            "/integrations/:integration_type/test",
            post(test_integration),
        )
        // LoFi specific endpoints
        .route("/integrations/lofi/setup", post(lofi_setup))
        .route("/integrations/lofi/status", get(lofi_status))
        .route("/integrations/lofi/send-link", post(lofi_send_link))
        .route("/integrations/lofi/confirm", post(lofi_confirm))
        // Sync endpoints
        .route("/sync/status", get(get_sync_states))
        .route("/sync/lofi", post(sync_lofi))
        .route("/sync/qrz/upload", post(sync_qrz_upload))
        .route("/sync/qrz/download", post(sync_qrz_download))
        // POTA endpoints
        .route("/sync/pota/preview", get(pota_preview))
        .route("/sync/pota/upload", post(pota_upload))
        .route("/sync/pota/jobs", get(pota_jobs))
        // Log upload
        .route("/logs/upload", post(upload_log));

    // Static files
    let static_service = ServeDir::new("static").fallback(get(index));

    Router::new()
        .nest("/api", api_routes)
        .fallback_service(static_service)
        .with_state(state)
}

/// Start the web server
pub async fn serve(
    db_path: PathBuf,
    master_key: MasterKey,
    sync_config: SyncConfig,
    bind: &str,
) -> std::result::Result<(), std::io::Error> {
    // Run migrations before starting the server
    tracing::info!("Running database migrations...");
    match Database::open(&db_path) {
        Ok(_db) => {
            tracing::info!("Database migrations completed");
        }
        Err(e) => {
            tracing::error!("Failed to run database migrations: {}", e);
            return Err(std::io::Error::other(e.to_string()));
        }
    }

    let app = build_router(db_path, master_key, sync_config).await;

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("Web server listening on {}", bind);

    axum::serve(listener, app).await
}
