//! Web interface module for logbook-sync.
//!
//! Provides a browser-based UI for user configuration and management.

use axum::{
    extract::{Multipart, Path, State},
    http::{header::SET_COOKIE, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post, put},
    Json, Router,
};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tower_http::services::ServeDir;

use crate::crypto::MasterKey;
use crate::db::{integrations, users, Database};
use rusqlite::Connection;

const SESSION_COOKIE_NAME: &str = "logbook_session";

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub db_path: PathBuf,
    pub master_key: Arc<MasterKey>,
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

// === Auth helpers ===

/// Create a simple signed session token: user_id:timestamp:signature
fn create_session_token(user_id: i64, master_key: &MasterKey) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
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
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
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
fn get_current_user_full(
    jar: &CookieJar,
    state: &AppState,
) -> Option<(users::User, Connection)> {
    let cookie = jar.get(SESSION_COOKIE_NAME)?;
    let user_id = validate_session_token(cookie.value(), &state.master_key)?;

    let conn = Connection::open(&state.db_path).ok()?;
    let user = users::get_user_by_id(&conn, user_id).ok()??;

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
    })
}

// === Handlers ===

async fn index() -> Html<&'static str> {
    Html(include_str!("../../static/index.html"))
}

async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> impl IntoResponse {
    let conn = match Connection::open(&state.db_path) {
        Ok(c) => c,
        Err(_) => {
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
        _ => {
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
            )
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
            )
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

async fn list_integrations(
    State(state): State<AppState>,
    jar: CookieJar,
) -> impl IntoResponse {
    let (user, conn) = match get_current_user_full(&jar, &state) {
        Some(u) => u,
        None => return (StatusCode::UNAUTHORIZED, Json(Vec::<IntegrationInfo>::new())),
    };

    let user_salt = match users::get_user_encryption_salt(&user) {
        Ok(s) => s,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(Vec::new())),
    };

    match integrations::get_user_integrations(&conn, &state.master_key, user.id, &user_salt) {
        Ok(ints) => {
            let info: Vec<IntegrationInfo> = ints
                .into_iter()
                .map(|i| IntegrationInfo {
                    integration_type: i.integration_type,
                    enabled: i.enabled,
                    config: serde_json::to_value(&i.config).unwrap_or(Value::Null),
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
            )
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
            )
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
            )
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
            )
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
        "qrz" => {
            match serde_json::from_value::<integrations::QrzIntegrationConfig>(req.config) {
                Ok(config) => test_qrz_connection(&config).await,
                Err(e) => (
                    StatusCode::BAD_REQUEST,
                    Json(SuccessResponse {
                        success: false,
                        message: Some(format!("Invalid config: {}", e)),
                    }),
                ),
            }
        }
        "lofi" => (
            StatusCode::OK,
            Json(SuccessResponse {
                success: true,
                message: Some("LoFi test not implemented yet".into()),
            }),
        ),
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
            )
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
            )
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
            )
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
            )
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SuccessResponse {
                    success: false,
                    message: Some(format!("Failed to read upload: {}", e)),
                }),
            )
        }
    };

    let filename = field
        .file_name()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "upload.adi".to_string());

    // Validate file extension
    if !filename.to_lowercase().ends_with(".adi")
        && !filename.to_lowercase().ends_with(".adif")
    {
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
            )
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
            )
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
            message: Some(format!(
                "Uploaded {} with {} QSOs",
                filename, qso_count
            )),
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
pub async fn build_router(db_path: PathBuf, master_key: MasterKey) -> Router {
    let state = AppState {
        db_path,
        master_key: Arc::new(master_key),
    };

    // API routes
    let api_routes = Router::new()
        // Auth
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(get_me))
        // Health/stats
        .route("/health", get(health))
        .route("/stats", get(get_stats.clone()))
        .route("/qsos/stats", get(get_stats))
        // Users
        .route("/users", get(list_users))
        .route("/users/me", put(update_profile))
        .route("/users/me/password", put(change_password))
        // Integrations
        .route("/integrations", get(list_integrations))
        .route(
            "/integrations/:integration_type",
            put(save_integration).delete(delete_integration),
        )
        .route("/integrations/:integration_type/test", post(test_integration))
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
    bind: &str,
) -> std::result::Result<(), std::io::Error> {
    let app = build_router(db_path, master_key).await;

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("Web server listening on {}", bind);

    axum::serve(listener, app).await
}
