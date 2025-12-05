//! Background sync worker pool for automatic integration synchronization.
//!
//! This module provides a worker pool that periodically syncs enabled integrations
//! for all users based on configured intervals.

use crate::config::SyncConfig;
use crate::crypto::MasterKey;
use crate::db::{Database, integrations, users};
use crate::lofi::{LofiClient, LofiConfig};
use crate::qrz::QrzClient;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Information about a pending sync task
#[derive(Debug, Clone)]
struct PendingSyncTask {
    user_id: i64,
    #[allow(dead_code)]
    user_salt: Vec<u8>,
    integration_type: String,
    direction: String,
    config: integrations::IntegrationConfig,
}

/// Shared state for the sync worker
pub struct SyncWorkerState {
    db_path: PathBuf,
    master_key: Arc<MasterKey>,
    sync_config: SyncConfig,
    /// Track when each (user_id, integration, direction) was last synced
    last_sync_times: RwLock<HashMap<(i64, String, String), DateTime<Utc>>>,
}

impl SyncWorkerState {
    pub fn new(db_path: PathBuf, master_key: Arc<MasterKey>, sync_config: SyncConfig) -> Self {
        Self {
            db_path,
            master_key,
            sync_config,
            last_sync_times: RwLock::new(HashMap::new()),
        }
    }

    /// Check if a sync task is due based on last sync time and configured interval
    async fn is_sync_due(&self, user_id: i64, integration_type: &str, direction: &str) -> bool {
        let key = (user_id, integration_type.to_string(), direction.to_string());
        let last_sync_times = self.last_sync_times.read().await;

        if let Some(last_sync) = last_sync_times.get(&key) {
            let interval_secs = self.sync_config.interval_for(integration_type);
            let elapsed = Utc::now().signed_duration_since(*last_sync);
            elapsed.num_seconds() >= interval_secs as i64
        } else {
            // Never synced in this session, it's due
            true
        }
    }

    /// Update the last sync time for a task
    async fn record_sync_time(&self, user_id: i64, integration_type: &str, direction: &str) {
        let key = (user_id, integration_type.to_string(), direction.to_string());
        let mut last_sync_times = self.last_sync_times.write().await;
        last_sync_times.insert(key, Utc::now());
    }

    /// Load last sync times from database on startup (synchronous, before spawning tasks)
    fn load_sync_times_from_db_sync(
        &self,
    ) -> crate::Result<HashMap<(i64, String, String), DateTime<Utc>>> {
        let db = Database::open(&self.db_path)?;
        let conn = db.conn();

        let all_users = users::list_users(conn)?;
        let mut times = HashMap::new();

        for user in all_users {
            let states = integrations::get_all_sync_states(conn, user.id)?;
            for state in states {
                if let Some(last_sync_at) = &state.last_sync_at
                    && let Ok(dt) = DateTime::parse_from_rfc3339(last_sync_at)
                {
                    let key = (
                        user.id,
                        state.integration_type.clone(),
                        state.direction.clone(),
                    );
                    times.insert(key, dt.with_timezone(&Utc));
                }
            }
        }

        Ok(times)
    }
}

/// Start the background sync worker pool
pub async fn start_sync_workers(
    db_path: PathBuf,
    master_key: Arc<MasterKey>,
    sync_config: SyncConfig,
) {
    if !sync_config.enabled {
        info!("Background sync is disabled");
        return;
    }

    let state = Arc::new(SyncWorkerState::new(
        db_path,
        master_key,
        sync_config.clone(),
    ));

    // Load existing sync times from database
    match state.load_sync_times_from_db_sync() {
        Ok(times) => {
            let mut last_sync_times = state.last_sync_times.write().await;
            *last_sync_times = times;
            info!(
                count = last_sync_times.len(),
                "Loaded sync times from database"
            );
        }
        Err(e) => {
            warn!("Failed to load sync times from database: {}", e);
        }
    }

    let num_workers = sync_config.worker_threads.max(1);
    info!(
        workers = num_workers,
        "Starting background sync worker pool"
    );

    // Start the scheduler task
    let scheduler_state = state.clone();
    tokio::spawn(async move {
        sync_scheduler(scheduler_state).await;
    });
}

/// Scheduler that periodically checks for sync tasks that need to run
async fn sync_scheduler(state: Arc<SyncWorkerState>) {
    // Initial delay to let the server start up
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

    // Check every 30 seconds for work to do
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

    loop {
        interval.tick().await;

        // Collect pending tasks synchronously (no await while holding db connection)
        let pending_tasks = match collect_pending_tasks(&state).await {
            Ok(tasks) => tasks,
            Err(e) => {
                error!("Error collecting sync tasks: {}", e);
                continue;
            }
        };

        // Run each task (async operations happen here, after db is dropped)
        for task in pending_tasks {
            let result = run_sync_task(&state, &task).await;

            // Record sync time regardless of result
            state
                .record_sync_time(task.user_id, &task.integration_type, &task.direction)
                .await;

            if let Err(e) = result {
                warn!(
                    user_id = task.user_id,
                    integration = %task.integration_type,
                    direction = %task.direction,
                    "Sync failed: {}", e
                );
            }
        }
    }
}

/// Collect pending sync tasks (synchronous db access, returns data for async processing)
async fn collect_pending_tasks(
    state: &Arc<SyncWorkerState>,
) -> crate::Result<Vec<PendingSyncTask>> {
    // Open database and collect all needed data synchronously
    let tasks = {
        let db = Database::open(&state.db_path)?;
        let conn = db.conn();

        let all_users = users::list_users(conn)?;
        let mut pending = Vec::new();

        for user in all_users {
            if !user.is_active {
                continue;
            }

            let user_salt = match users::get_user_encryption_salt(&user) {
                Ok(s) => s,
                Err(e) => {
                    warn!(user_id = user.id, "Failed to get user salt: {}", e);
                    continue;
                }
            };

            let user_integrations = match integrations::get_user_integrations(
                conn,
                &state.master_key,
                user.id,
                &user_salt,
            ) {
                Ok(i) => i,
                Err(e) => {
                    warn!(user_id = user.id, "Failed to get user integrations: {}", e);
                    continue;
                }
            };

            for integration in user_integrations {
                if !integration.enabled {
                    continue;
                }

                let directions =
                    get_sync_directions(&integration.integration_type, &integration.config);

                for direction in directions {
                    pending.push(PendingSyncTask {
                        user_id: user.id,
                        user_salt: user_salt.to_vec(),
                        integration_type: integration.integration_type.clone(),
                        direction,
                        config: integration.config.clone(),
                    });
                }
            }
        }

        pending
    }; // db dropped here

    // Now filter by due tasks (async operation)
    let mut due_tasks = Vec::new();
    for task in tasks {
        if state
            .is_sync_due(task.user_id, &task.integration_type, &task.direction)
            .await
        {
            debug!(
                user_id = task.user_id,
                integration = %task.integration_type,
                direction = %task.direction,
                "Sync is due"
            );
            due_tasks.push(task);
        }
    }

    Ok(due_tasks)
}

/// Get the sync directions supported by an integration based on its config
fn get_sync_directions(
    integration_type: &str,
    config: &integrations::IntegrationConfig,
) -> Vec<String> {
    let mut directions = Vec::new();

    match (integration_type, config) {
        ("qrz", integrations::IntegrationConfig::Qrz(c)) => {
            if c.upload_enabled {
                directions.push("upload".to_string());
            }
            if c.download_enabled {
                directions.push("download".to_string());
            }
        }
        ("lofi", integrations::IntegrationConfig::Lofi(c)) => {
            // LoFi is download-only
            if c.device_linked {
                directions.push("download".to_string());
            }
        }
        ("lotw", integrations::IntegrationConfig::Lotw(c)) => {
            // LotW uses auto_upload for upload
            if c.auto_upload {
                directions.push("upload".to_string());
            }
            // Download is always available if configured
            directions.push("download".to_string());
        }
        ("eqsl", integrations::IntegrationConfig::Eqsl(_)) => {
            directions.push("upload".to_string());
            directions.push("download".to_string());
        }
        ("clublog", integrations::IntegrationConfig::Clublog(_)) => {
            directions.push("upload".to_string());
        }
        ("hrdlog", integrations::IntegrationConfig::Hrdlog(_)) => {
            directions.push("upload".to_string());
        }
        ("wavelog", integrations::IntegrationConfig::Wavelog(_)) => {
            directions.push("upload".to_string());
            directions.push("download".to_string());
        }
        _ => {}
    }

    directions
}

/// Run a single sync task
async fn run_sync_task(state: &Arc<SyncWorkerState>, task: &PendingSyncTask) -> crate::Result<()> {
    info!(
        user_id = task.user_id,
        integration = %task.integration_type,
        direction = %task.direction,
        "Running background sync"
    );

    match (
        &task.integration_type[..],
        &task.direction[..],
        &task.config,
    ) {
        ("lofi", "download", integrations::IntegrationConfig::Lofi(lofi_config)) => {
            run_lofi_download(&state.db_path, task.user_id, lofi_config).await
        }
        ("qrz", "upload", integrations::IntegrationConfig::Qrz(qrz_config)) => {
            run_qrz_upload(&state.db_path, task.user_id, qrz_config).await
        }
        ("qrz", "download", integrations::IntegrationConfig::Qrz(qrz_config)) => {
            run_qrz_download(&state.db_path, task.user_id, qrz_config).await
        }
        _ => {
            debug!(
                integration = %task.integration_type,
                direction = %task.direction,
                "Sync not implemented for this integration/direction"
            );
            Ok(())
        }
    }
}

/// Run LoFi download sync
async fn run_lofi_download(
    db_path: &Path,
    user_id: i64,
    config: &integrations::LofiIntegrationConfig,
) -> crate::Result<()> {
    if !config.device_linked {
        return Ok(());
    }

    let client_config = LofiConfig {
        enabled: true,
        client_key: Some(config.client_key.clone()),
        client_secret: Some(config.client_secret.clone()),
        callsign: None,
        email: None,
        sync_batch_size: config.sync_batch_size,
        sync_loop_delay_ms: config.sync_loop_delay_ms,
        sync_check_period_ms: 0,
        device_linked: config.device_linked,
    };

    let mut client = LofiClient::new(client_config)?;

    if let Some(ref token) = config.bearer_token {
        client.set_bearer_token(token.clone());
    }

    let mut total_qsos = 0i64;
    let mut cursor: Option<f64> = None;

    loop {
        let response = client.fetch_qsos(cursor, Some(50)).await?;

        // Save QSOs to database (open/close connection for each batch)
        {
            let db = Database::open(db_path)?;
            for qso in &response.qsos {
                if qso.deleted != 0 {
                    continue;
                }

                if let Err(e) = db.upsert_lofi_qso(qso) {
                    warn!("Failed to save LoFi QSO: {}", e);
                } else {
                    total_qsos += 1;
                }
            }
        }

        if response.meta.qsos.records_left == 0 {
            break;
        }

        cursor = response.qsos.last().map(|q| q.updated_at_millis);

        // Small delay between batches
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    // Record sync result
    {
        let db = Database::open(db_path)?;
        let message = format!("Downloaded {} QSOs from LoFi", total_qsos);
        integrations::record_sync_success(
            db.conn(),
            user_id,
            "lofi",
            "download",
            total_qsos,
            Some(&message),
        )?;
    }

    info!(user_id = user_id, qsos = total_qsos, "LoFi sync completed");
    Ok(())
}

/// Run QRZ upload sync
async fn run_qrz_upload(
    db_path: &Path,
    user_id: i64,
    config: &integrations::QrzIntegrationConfig,
) -> crate::Result<()> {
    if !config.upload_enabled {
        return Ok(());
    }

    let client = QrzClient::new(config.api_key.clone(), config.user_agent.clone());

    // Get unsynced QSOs
    let unsynced = {
        let db = Database::open(db_path)?;
        db.get_unsynced_qrz()?
    };

    if unsynced.is_empty() {
        let db = Database::open(db_path)?;
        integrations::record_sync_success(
            db.conn(),
            user_id,
            "qrz",
            "upload",
            0,
            Some("No QSOs to upload"),
        )?;
        return Ok(());
    }

    let mut uploaded = 0i64;
    let mut errors = 0;

    for stored_qso in &unsynced {
        let qso: crate::adif::Qso = match serde_json::from_str(&stored_qso.adif_record) {
            Ok(q) => q,
            Err(e) => {
                warn!("Failed to parse QSO {}: {}", stored_qso.id, e);
                errors += 1;
                continue;
            }
        };

        match client.upload_qso(&qso).await {
            Ok(result) => {
                if let Some(logid) = result.logid {
                    let db = Database::open(db_path)?;
                    let _ = db.mark_qrz_synced(stored_qso.id, logid);
                }
                if !result.is_duplicate {
                    uploaded += 1;
                }
            }
            Err(e) => {
                warn!("Failed to upload QSO to QRZ: {}", e);
                errors += 1;
                if errors >= 5 {
                    break;
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    // Record sync result
    {
        let db = Database::open(db_path)?;
        let message = format!("Uploaded {} QSOs to QRZ", uploaded);
        if errors == 0 {
            integrations::record_sync_success(
                db.conn(),
                user_id,
                "qrz",
                "upload",
                uploaded,
                Some(&message),
            )?;
        } else {
            integrations::record_sync_error(
                db.conn(),
                user_id,
                "qrz",
                "upload",
                &format!("{} ({} errors)", message, errors),
            )?;
        }
    }

    info!(
        user_id = user_id,
        uploaded = uploaded,
        errors = errors,
        "QRZ upload sync completed"
    );
    Ok(())
}

/// Run QRZ download sync
async fn run_qrz_download(
    db_path: &Path,
    user_id: i64,
    config: &integrations::QrzIntegrationConfig,
) -> crate::Result<()> {
    if !config.download_enabled {
        return Ok(());
    }

    let client = QrzClient::new(config.api_key.clone(), config.user_agent.clone());

    let fetched_qsos = client.fetch_all().await?;

    let mut imported = 0i64;

    // Save QSOs to database
    {
        let db = Database::open(db_path)?;
        for fetched in &fetched_qsos {
            let source_id = fetched.qrz_logid.map(|id| id.to_string());
            if let Err(e) =
                db.upsert_qso_with_source(&fetched.qso, None, "qrz", source_id.as_deref())
            {
                warn!("Failed to save QRZ QSO: {}", e);
            } else {
                imported += 1;
            }
        }
    }

    // Record sync result
    {
        let db = Database::open(db_path)?;
        let message = format!("Downloaded {} QSOs from QRZ", imported);
        integrations::record_sync_success(
            db.conn(),
            user_id,
            "qrz",
            "download",
            imported,
            Some(&message),
        )?;
    }

    info!(
        user_id = user_id,
        imported = imported,
        "QRZ download sync completed"
    );
    Ok(())
}
