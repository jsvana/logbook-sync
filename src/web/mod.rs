//! Web interface module for logbook-sync.
//!
//! Provides a browser-based UI for user configuration and management.

use axum::{
    extract::State,
    http::{header::SET_COOKIE, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tower_http::services::ServeDir;

use crate::crypto::MasterKey;
use crate::db::{users, Database};
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

/// Get current user from session cookie
fn get_current_user(jar: &CookieJar, state: &AppState) -> Option<UserInfo> {
    let cookie = jar.get(SESSION_COOKIE_NAME)?;
    let user_id = validate_session_token(cookie.value(), &state.master_key)?;

    let conn = Connection::open(&state.db_path).ok()?;
    let user = users::get_user_by_id(&conn, user_id).ok()??;

    if !user.is_active {
        return None;
    }

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

async fn get_stats(State(state): State<AppState>) -> impl IntoResponse {
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

/// Build the web application router
pub async fn build_router(db_path: PathBuf, master_key: MasterKey) -> Router {
    let state = AppState {
        db_path,
        master_key: Arc::new(master_key),
    };

    // API routes
    let api_routes = Router::new()
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(get_me))
        .route("/health", get(health))
        .route("/stats", get(get_stats))
        .route("/users", get(list_users));

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
