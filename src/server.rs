//! HTTP server for health checks and metrics endpoints.

use crate::config::ServerConfig;
use crate::metrics;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, info};

/// Health status of the service
#[derive(Debug, Clone, Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub checks: HealthChecks,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthChecks {
    pub database: CheckResult,
    pub qrz: CheckResult,
    pub last_sync: CheckResult,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub status: String,
    pub message: Option<String>,
}

impl CheckResult {
    pub fn ok() -> Self {
        Self {
            status: "ok".to_string(),
            message: None,
        }
    }

    pub fn ok_with_message(msg: impl Into<String>) -> Self {
        Self {
            status: "ok".to_string(),
            message: Some(msg.into()),
        }
    }

    pub fn degraded(msg: impl Into<String>) -> Self {
        Self {
            status: "degraded".to_string(),
            message: Some(msg.into()),
        }
    }

    pub fn unhealthy(msg: impl Into<String>) -> Self {
        Self {
            status: "unhealthy".to_string(),
            message: Some(msg.into()),
        }
    }

    pub fn is_ok(&self) -> bool {
        self.status == "ok"
    }
}

/// Shared state for the HTTP server
#[derive(Clone)]
pub struct ServerState {
    pub start_time: Instant,
    pub db_path: PathBuf,
    pub last_sync_time: Arc<RwLock<Option<Instant>>>,
    pub last_sync_error: Arc<RwLock<Option<String>>>,
    pub qrz_healthy: Arc<RwLock<bool>>,
    pub total_qsos: Arc<RwLock<i64>>,
}

impl ServerState {
    pub fn new(db_path: PathBuf) -> Self {
        Self {
            start_time: Instant::now(),
            db_path,
            last_sync_time: Arc::new(RwLock::new(None)),
            last_sync_error: Arc::new(RwLock::new(None)),
            qrz_healthy: Arc::new(RwLock::new(true)),
            total_qsos: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn record_sync_success(&self) {
        *self.last_sync_time.write().await = Some(Instant::now());
        *self.last_sync_error.write().await = None;
    }

    pub async fn record_sync_error(&self, error: String) {
        *self.last_sync_error.write().await = Some(error);
    }

    pub async fn set_qrz_health(&self, healthy: bool) {
        *self.qrz_healthy.write().await = healthy;
    }

    pub async fn set_total_qsos(&self, count: i64) {
        *self.total_qsos.write().await = count;
    }
}

/// Start the HTTP server for health checks and metrics
pub async fn start_server(
    config: ServerConfig,
    db_path: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = ServerState::new(db_path);

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/health/live", get(liveness_handler))
        .route("/health/ready", get(readiness_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(state);

    let addr = SocketAddr::new(config.bind_address, config.port);
    info!(address = %addr, "Starting HTTP server for health checks and metrics");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Full health check endpoint
async fn health_handler(State(state): State<ServerState>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();

    // Check database - verify file exists
    let db_check = if state.db_path.exists() {
        let total = *state.total_qsos.read().await;
        CheckResult::ok_with_message(format!("{} QSOs", total))
    } else {
        CheckResult::unhealthy("Database file not found")
    };

    // Check QRZ health
    let qrz_healthy = *state.qrz_healthy.read().await;
    let qrz_check = if qrz_healthy {
        CheckResult::ok()
    } else {
        CheckResult::degraded("QRZ API experiencing issues")
    };

    // Check last sync
    let last_sync_check = {
        let last_sync = state.last_sync_time.read().await;
        let last_error = state.last_sync_error.read().await;

        match (&*last_sync, &*last_error) {
            (Some(time), None) => {
                let elapsed = time.elapsed();
                if elapsed > Duration::from_secs(3600) {
                    CheckResult::degraded(format!(
                        "Last sync was {} minutes ago",
                        elapsed.as_secs() / 60
                    ))
                } else {
                    CheckResult::ok_with_message(format!(
                        "Last sync {} seconds ago",
                        elapsed.as_secs()
                    ))
                }
            }
            (_, Some(error)) => CheckResult::degraded(format!("Last sync failed: {}", error)),
            (None, None) => CheckResult::ok_with_message("No sync performed yet"),
        }
    };

    let checks = HealthChecks {
        database: db_check,
        qrz: qrz_check,
        last_sync: last_sync_check,
    };

    // Determine overall status
    let overall_status = if !checks.database.is_ok() {
        "unhealthy"
    } else if !checks.qrz.is_ok() || !checks.last_sync.is_ok() {
        "degraded"
    } else {
        "healthy"
    };

    let health = HealthStatus {
        status: overall_status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        checks,
    };

    let status_code = match overall_status {
        "healthy" => StatusCode::OK,
        "degraded" => StatusCode::OK, // Still return 200 for degraded
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };

    (status_code, Json(health))
}

/// Kubernetes liveness probe - is the process alive?
async fn liveness_handler() -> impl IntoResponse {
    // Simple check - if we can respond, we're alive
    (StatusCode::OK, "OK")
}

/// Kubernetes readiness probe - can the service handle traffic?
async fn readiness_handler(State(state): State<ServerState>) -> impl IntoResponse {
    // Check if database file exists
    if state.db_path.exists() {
        (StatusCode::OK, "Ready")
    } else {
        error!("Readiness check failed: database not found");
        (StatusCode::SERVICE_UNAVAILABLE, "Not ready")
    }
}

/// Prometheus metrics endpoint
async fn metrics_handler() -> impl IntoResponse {
    let metrics = metrics::gather_metrics();
    (
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        metrics,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_result() {
        let ok = CheckResult::ok();
        assert!(ok.is_ok());

        let degraded = CheckResult::degraded("test");
        assert!(!degraded.is_ok());

        let unhealthy = CheckResult::unhealthy("error");
        assert!(!unhealthy.is_ok());
    }
}
