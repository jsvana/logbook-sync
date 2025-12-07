//! Background sync worker pool for automatic integration synchronization.
//!
//! This module provides a worker pool that periodically syncs enabled integrations
//! for all users based on configured intervals.

use crate::config::SyncConfig;
use crate::crypto::MasterKey;
use crate::db::{Database, integrations, users};
use crate::lofi::{LofiClient, LofiConfig};
use crate::ntfy::{NtfyClient, NtfyConfig};
use crate::qrz::QrzClient;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Result of a sync task for tracking what changed
#[derive(Debug, Default)]
struct SyncTaskResult {
    /// Number of new QSOs downloaded (not previously in db)
    new_downloads: i64,
    /// Number of QSOs uploaded
    uploads: i64,
    /// Whether there was an error
    error: Option<String>,
}

/// Aggregated results for a sync cycle
#[derive(Debug, Default)]
struct SyncCycleResults {
    /// Results by (integration, direction)
    results: HashMap<(String, String), SyncTaskResult>,
}

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

    // Test ntfy notification on startup for all users with ntfy configured
    test_ntfy_on_startup(&state.db_path, &state.master_key).await;

    // Start the scheduler task
    let scheduler_state = state.clone();
    tokio::spawn(async move {
        sync_scheduler(scheduler_state).await;
    });
}

/// Test ntfy notifications on startup
async fn test_ntfy_on_startup(db_path: &Path, master_key: &MasterKey) {
    let db = match Database::open(db_path) {
        Ok(db) => db,
        Err(e) => {
            warn!("Failed to open database for ntfy test: {}", e);
            return;
        }
    };
    let conn = db.conn();

    let all_users = match users::list_users(conn) {
        Ok(users) => users,
        Err(e) => {
            warn!("Failed to list users for ntfy test: {}", e);
            return;
        }
    };

    for user in all_users {
        if !user.is_active {
            continue;
        }

        let user_salt = match users::get_user_encryption_salt(&user) {
            Ok(s) => s,
            Err(_) => continue,
        };

        if let Some((client, callsign)) =
            get_user_ntfy_client(db_path, master_key, user.id, &user_salt)
        {
            info!(user_id = user.id, callsign = %callsign, "Sending startup test notification");
            let title = format!("{} - Server Started", callsign);
            let message = "logbook-sync server has started and ntfy notifications are working.";
            if let Err(e) = client.send(&title, message).await {
                error!(user_id = user.id, error = %e, "Startup ntfy test failed");
            } else {
                info!(user_id = user.id, "Startup ntfy test succeeded");
            }
        }
    }
}

/// Get the ntfy client for a user if they have it configured
fn get_user_ntfy_client(
    db_path: &Path,
    master_key: &MasterKey,
    user_id: i64,
    user_salt: &[u8],
) -> Option<(NtfyClient, String)> {
    let db = Database::open(db_path).ok()?;
    let conn = db.conn();

    // Convert salt to fixed-size array
    let salt_array: [u8; 32] = user_salt.try_into().ok()?;

    let user_integrations =
        integrations::get_user_integrations(conn, master_key, user_id, &salt_array).ok()?;

    for integration in user_integrations {
        if integration.enabled
            && integration.integration_type == "ntfy"
            && let integrations::IntegrationConfig::Ntfy(config) = integration.config
        {
            info!(
                server = %config.server,
                topic = %config.topic,
                has_token = config.token.is_some(),
                token_len = config.token.as_ref().map(|t| t.len()).unwrap_or(0),
                priority = config.priority,
                "Creating ntfy client for sync notifications"
            );
            let ntfy_config = NtfyConfig {
                enabled: true,
                server: config.server,
                topic: config.topic,
                token: config.token,
                priority: config.priority,
            };

            // Get user's callsign for notification title
            let callsign = users::get_user_by_id(conn, user_id)
                .ok()
                .flatten()
                .and_then(|u| u.callsign)
                .unwrap_or_else(|| "Unknown".to_string());

            return Some((NtfyClient::new(ntfy_config), callsign));
        }
    }

    None
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

        if pending_tasks.is_empty() {
            continue;
        }

        // Group tasks by user to send one notification per user
        let mut tasks_by_user: HashMap<i64, Vec<PendingSyncTask>> = HashMap::new();
        for task in pending_tasks {
            tasks_by_user.entry(task.user_id).or_default().push(task);
        }

        // Process each user's tasks
        for (user_id, user_tasks) in tasks_by_user {
            let mut cycle_results = SyncCycleResults::default();

            // Get the user salt from the first task (all tasks for same user have same salt)
            let user_salt = user_tasks[0].user_salt.clone();

            // Get ntfy client for this user (if configured)
            let ntfy_client =
                get_user_ntfy_client(&state.db_path, &state.master_key, user_id, &user_salt);

            // Run each task for this user
            let task_count = user_tasks.len();
            for (idx, task) in user_tasks.into_iter().enumerate() {
                info!(
                    user_id = task.user_id,
                    integration = %task.integration_type,
                    direction = %task.direction,
                    task_num = idx + 1,
                    total_tasks = task_count,
                    "Starting sync task"
                );

                let result = run_sync_task(&state, &task).await;

                // Record sync time regardless of result
                state
                    .record_sync_time(task.user_id, &task.integration_type, &task.direction)
                    .await;

                match result {
                    Ok(task_result) => {
                        info!(
                            user_id = task.user_id,
                            integration = %task.integration_type,
                            direction = %task.direction,
                            new_downloads = task_result.new_downloads,
                            uploads = task_result.uploads,
                            "Sync task completed successfully"
                        );
                        cycle_results.results.insert(
                            (task.integration_type.clone(), task.direction.clone()),
                            task_result,
                        );
                    }
                    Err(e) => {
                        let error_msg = e.to_string();
                        warn!(
                            user_id = task.user_id,
                            integration = %task.integration_type,
                            direction = %task.direction,
                            task_num = idx + 1,
                            total_tasks = task_count,
                            "Sync task failed (continuing with remaining tasks): {}", error_msg
                        );

                        // Send error notification immediately
                        if let Some((ref client, ref callsign)) = ntfy_client {
                            let service_name = format!(
                                "{} {}",
                                task.integration_type.to_uppercase(),
                                task.direction
                            );
                            if let Err(ntfy_err) = client
                                .notify_error(callsign, &service_name, &error_msg)
                                .await
                            {
                                warn!("Failed to send error notification: {}", ntfy_err);
                            }
                        }

                        // Record error in results
                        cycle_results.results.insert(
                            (task.integration_type.clone(), task.direction.clone()),
                            SyncTaskResult {
                                error: Some(error_msg),
                                ..Default::default()
                            },
                        );
                    }
                }
            }

            // Log completion of all tasks for this user
            let successful = cycle_results
                .results
                .values()
                .filter(|r| r.error.is_none())
                .count();
            let failed = cycle_results
                .results
                .values()
                .filter(|r| r.error.is_some())
                .count();
            info!(
                user_id = user_id,
                successful = successful,
                failed = failed,
                "Completed sync cycle for user"
            );

            // Send summary notification if anything changed
            if let Some((client, callsign)) = ntfy_client {
                send_sync_summary_notification(&client, &callsign, &cycle_results).await;
            }
        }
    }
}

/// Send a summary notification for a sync cycle if there were any new downloads or uploads
async fn send_sync_summary_notification(
    client: &NtfyClient,
    callsign: &str,
    results: &SyncCycleResults,
) {
    let mut total_new_downloads = 0i64;
    let mut total_uploads = 0i64;
    let mut download_details = Vec::new();
    let mut upload_details = Vec::new();

    for ((integration, direction), result) in &results.results {
        if result.error.is_some() {
            continue; // Errors are already notified separately
        }

        match direction.as_str() {
            "download" if result.new_downloads > 0 => {
                total_new_downloads += result.new_downloads;
                download_details.push(format!(
                    "{}: {} new",
                    integration.to_uppercase(),
                    result.new_downloads
                ));
            }
            "upload" if result.uploads > 0 => {
                total_uploads += result.uploads;
                upload_details.push(format!(
                    "{}: {}",
                    integration.to_uppercase(),
                    result.uploads
                ));
            }
            _ => {}
        }
    }

    // Only send notification if something changed
    if total_new_downloads == 0 && total_uploads == 0 {
        return;
    }

    let title = format!("{} Sync Complete", callsign);
    let mut message_parts = Vec::new();

    if total_new_downloads > 0 {
        message_parts.push(format!(
            "Downloaded {} new QSO{} ({})",
            total_new_downloads,
            if total_new_downloads == 1 { "" } else { "s" },
            download_details.join(", ")
        ));
    }

    if total_uploads > 0 {
        message_parts.push(format!(
            "Uploaded {} QSO{} ({})",
            total_uploads,
            if total_uploads == 1 { "" } else { "s" },
            upload_details.join(", ")
        ));
    }

    let message = message_parts.join("\n");

    if let Err(e) = client.send(&title, &message).await {
        warn!("Failed to send sync summary notification: {}", e);
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

    // Sort tasks so downloads run before uploads
    // This ensures we have the latest data from all sources before uploading
    due_tasks.sort_by(|a, b| {
        // First, sort by direction: download < upload
        let dir_order = |dir: &str| match dir {
            "download" => 0,
            "upload" => 1,
            _ => 2,
        };
        dir_order(&a.direction).cmp(&dir_order(&b.direction))
    });

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
        ("pota", integrations::IntegrationConfig::Pota(_)) => {
            // POTA supports both download (from POTA.app) and upload
            directions.push("download".to_string());
            directions.push("upload".to_string());
        }
        _ => {}
    }

    directions
}

/// Run a single sync task
async fn run_sync_task(
    state: &Arc<SyncWorkerState>,
    task: &PendingSyncTask,
) -> crate::Result<SyncTaskResult> {
    use crate::metrics;

    info!(
        user_id = task.user_id,
        integration = %task.integration_type,
        direction = %task.direction,
        "Running background sync"
    );

    // Track in-flight operations
    metrics::inc_sync_in_flight(&task.integration_type, &task.direction);
    let start = std::time::Instant::now();

    let result = match (
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
        ("pota", "download", integrations::IntegrationConfig::Pota(pota_config)) => {
            run_pota_download(&state.db_path, task.user_id, pota_config).await
        }
        ("pota", "upload", integrations::IntegrationConfig::Pota(pota_config)) => {
            run_pota_upload(&state.db_path, task.user_id, pota_config).await
        }
        _ => {
            debug!(
                integration = %task.integration_type,
                direction = %task.direction,
                "Sync not implemented for this integration/direction"
            );
            Ok(SyncTaskResult::default())
        }
    };

    // Record metrics
    let duration_secs = start.elapsed().as_secs_f64();
    metrics::dec_sync_in_flight(&task.integration_type, &task.direction);
    metrics::record_sync_duration(&task.integration_type, &task.direction, duration_secs);

    match &result {
        Ok(task_result) => {
            metrics::record_sync_success(&task.integration_type);
            metrics::inc_sync_operations(&task.integration_type, &task.direction, "success");

            // Record QSO counts
            if task_result.new_downloads > 0 {
                metrics::record_qso_downloaded(
                    &task.integration_type,
                    task_result.new_downloads as u64,
                );
            }
            if task_result.uploads > 0 {
                metrics::record_qso_uploaded(&task.integration_type);
                // If multiple uploaded, record them
                for _ in 1..task_result.uploads {
                    metrics::record_qso_uploaded(&task.integration_type);
                }
            }
        }
        Err(e) => {
            let error_type = categorize_error(e);
            metrics::record_sync_error(&task.integration_type, &error_type);
            metrics::inc_sync_operations(&task.integration_type, &task.direction, "failure");
        }
    }

    result
}

/// Categorize an error for metrics purposes
fn categorize_error(error: &crate::Error) -> String {
    match error {
        crate::Error::LofiAuthError => "auth".to_string(),
        crate::Error::Lofi(msg) if msg.contains("404") => "not_found".to_string(),
        crate::Error::Lofi(_) => "api".to_string(),
        crate::Error::Http(_) => "http".to_string(),
        crate::Error::Database(_) => "database".to_string(),
        crate::Error::Io(_) => "io".to_string(),
        _ => "other".to_string(),
    }
}

/// Run LoFi download sync
async fn run_lofi_download(
    db_path: &Path,
    user_id: i64,
    config: &integrations::LofiIntegrationConfig,
) -> crate::Result<SyncTaskResult> {
    if !config.device_linked {
        return Ok(SyncTaskResult::default());
    }

    let client_config = LofiConfig {
        enabled: true,
        client_key: Some(config.client_key.clone()),
        client_secret: Some(config.client_secret.clone()),
        callsign: config.callsign.clone(),
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

    let batch_size = config.sync_batch_size;

    // Get last sync timestamp (0 means get all)
    let initial_synced_since = {
        let db = Database::open(db_path)?;
        db.get_lofi_last_sync_millis()?
    };

    // Record sync start time to save after successful sync
    let sync_start_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    debug!(
        user_id = user_id,
        synced_since_millis = initial_synced_since,
        "Fetching LoFi operations since timestamp"
    );

    // Track if we've already tried refreshing the token
    let mut token_refreshed = false;

    // First, sync operations with proper pagination
    // Fetch both active and deleted operations (API filters by deleted status)
    for include_deleted in [false, true] {
        let mut ops_synced_since = initial_synced_since;
        loop {
            let response = match client
                .fetch_operations(ops_synced_since, Some(batch_size), Some(include_deleted))
                .await
            {
                Ok(r) => r,
                Err(crate::Error::LofiAuthError) if !token_refreshed => {
                    // Token expired, try to refresh it
                    warn!(user_id = user_id, "LoFi token expired, refreshing...");
                    match client.refresh_token().await {
                        Ok(new_token) => {
                            info!(user_id = user_id, "LoFi token refreshed successfully");
                            // Save the new token to the database
                            if let Ok(db) = Database::open(db_path)
                                && let Err(e) = db.set_lofi_bearer_token(&new_token)
                            {
                                warn!("Failed to save refreshed LoFi token: {}", e);
                            }
                            token_refreshed = true;
                            // Retry this iteration
                            continue;
                        }
                        Err(e) => {
                            error!(user_id = user_id, error = %e, "Failed to refresh LoFi token");
                            return Err(e);
                        }
                    }
                }
                Err(crate::Error::LofiAuthError) => {
                    // Already tried refreshing, give up
                    return Err(crate::Error::LofiAuthError);
                }
                Err(crate::Error::Lofi(msg)) if msg.contains("404") => {
                    debug!(
                        user_id = user_id,
                        "LoFi returned 404 - device may need to be re-linked"
                    );
                    return Ok(SyncTaskResult::default());
                }
                Err(e) => return Err(e),
            };

            let meta = &response.meta.operations;

            // Save operations to database
            {
                let db = Database::open(db_path)?;
                for op in &response.operations {
                    if let Err(e) = db.upsert_lofi_operation(op) {
                        warn!("Failed to save LoFi operation: {}", e);
                    }
                }
            }

            if meta.records_left == 0 {
                break;
            }

            // Get next page cursor from metadata
            if let Some(next_millis) = meta.next_updated_at_millis.or(meta.next_synced_at_millis) {
                ops_synced_since = next_millis as i64;
            } else {
                warn!("LoFi API indicated more operations but no pagination cursor provided");
                break;
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }

    // Now get all operations from database and sync QSOs for each
    let operations = {
        let db = Database::open(db_path)?;
        db.get_lofi_operations()?
    };

    let mut total_qsos = 0i64;
    let mut new_qsos = 0i64;

    for op in operations {
        if op.deleted != 0 {
            continue;
        }

        // Fetch QSOs for this operation using the correct endpoint with proper pagination
        let mut qsos_synced_since = initial_synced_since;
        loop {
            let response = match client
                .fetch_operation_qsos(&op.uuid, qsos_synced_since, Some(batch_size))
                .await
            {
                Ok(r) => r,
                Err(crate::Error::LofiAuthError) if !token_refreshed => {
                    // Token expired, try to refresh it
                    warn!(
                        user_id = user_id,
                        "LoFi token expired during QSO fetch, refreshing..."
                    );
                    match client.refresh_token().await {
                        Ok(new_token) => {
                            info!(user_id = user_id, "LoFi token refreshed successfully");
                            if let Ok(db) = Database::open(db_path)
                                && let Err(e) = db.set_lofi_bearer_token(&new_token)
                            {
                                warn!("Failed to save refreshed LoFi token: {}", e);
                            }
                            token_refreshed = true;
                            continue;
                        }
                        Err(e) => {
                            error!(user_id = user_id, error = %e, "Failed to refresh LoFi token");
                            return Err(e);
                        }
                    }
                }
                Err(crate::Error::LofiAuthError) => {
                    return Err(crate::Error::LofiAuthError);
                }
                Err(crate::Error::Lofi(msg)) if msg.contains("404") => {
                    debug!(
                        user_id = user_id,
                        operation = %op.uuid,
                        "LoFi returned 404 for operation QSOs"
                    );
                    break;
                }
                Err(e) => return Err(e),
            };

            let meta = &response.meta.qsos;

            // Save QSOs to database
            {
                let db = Database::open(db_path)?;
                for qso in &response.qsos {
                    if qso.deleted != 0 {
                        continue;
                    }

                    match db.upsert_lofi_qso(qso, Some(&op.account)) {
                        Ok(is_new) => {
                            total_qsos += 1;
                            if is_new {
                                new_qsos += 1;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to save LoFi QSO: {}", e);
                        }
                    }
                }
            }

            if meta.records_left == 0 {
                break;
            }

            // Get next page cursor from metadata
            if let Some(next_millis) = meta.next_updated_at_millis.or(meta.next_synced_at_millis) {
                qsos_synced_since = next_millis as i64;
            } else {
                warn!(
                    operation = %op.uuid,
                    "LoFi API indicated more QSOs but no pagination cursor provided"
                );
                break;
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        // Small delay between operations
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    // Record sync result and save sync timestamp
    {
        let db = Database::open(db_path)?;

        // Save the sync timestamp for next time
        if let Err(e) = db.set_lofi_last_sync_millis(sync_start_millis) {
            warn!(error = %e, "Failed to save LoFi sync timestamp");
        }

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

    info!(
        user_id = user_id,
        total = total_qsos,
        new = new_qsos,
        "LoFi sync completed"
    );
    Ok(SyncTaskResult {
        new_downloads: new_qsos,
        ..Default::default()
    })
}

/// Run QRZ upload sync
async fn run_qrz_upload(
    db_path: &Path,
    user_id: i64,
    config: &integrations::QrzIntegrationConfig,
) -> crate::Result<SyncTaskResult> {
    use crate::db::users;

    if !config.upload_enabled {
        return Ok(SyncTaskResult::default());
    }

    // Get the user's callsign to filter QSOs
    let user_callsign = {
        let db = Database::open(db_path)?;
        match users::get_user_by_id(db.conn(), user_id)? {
            Some(user) => user.callsign,
            None => {
                warn!(user_id = user_id, "User not found for QRZ upload");
                return Ok(SyncTaskResult::default());
            }
        }
    };

    let user_callsign = match user_callsign {
        Some(c) => c.to_uppercase(),
        None => {
            warn!(
                user_id = user_id,
                "User has no callsign configured, skipping QRZ upload"
            );
            return Ok(SyncTaskResult::default());
        }
    };

    let client = QrzClient::new(config.api_key.clone(), config.user_agent.clone());

    // Get unsynced QSOs
    let unsynced = {
        let db = Database::open(db_path)?;
        db.get_unsynced_qrz()?
    };

    // Filter to only QSOs that belong to this user (by station_callsign)
    let unsynced: Vec<_> = unsynced
        .into_iter()
        .filter(|stored_qso| {
            if let Ok(qso) = serde_json::from_str::<crate::adif::Qso>(&stored_qso.adif_record) {
                qso.station_callsign
                    .as_ref()
                    .map(|c| c.to_uppercase() == user_callsign)
                    .unwrap_or(false)
            } else {
                false
            }
        })
        .collect();

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
        return Ok(SyncTaskResult::default());
    }

    info!(
        user_id = user_id,
        callsign = %user_callsign,
        count = unsynced.len(),
        "Uploading QSOs to QRZ"
    );

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
    Ok(SyncTaskResult {
        uploads: uploaded,
        ..Default::default()
    })
}

/// Run QRZ download sync
async fn run_qrz_download(
    db_path: &Path,
    user_id: i64,
    config: &integrations::QrzIntegrationConfig,
) -> crate::Result<SyncTaskResult> {
    if !config.download_enabled {
        return Ok(SyncTaskResult::default());
    }

    let client = QrzClient::new(config.api_key.clone(), config.user_agent.clone());

    let fetched_qsos = client.fetch_all().await?;

    let mut imported = 0i64;
    let mut new_qsos = 0i64;

    // Save QSOs to database
    {
        let db = Database::open(db_path)?;
        for fetched in &fetched_qsos {
            let source_id = fetched.qrz_logid.map(|id| id.to_string());
            match db.upsert_qso_with_source_ext(&fetched.qso, None, "qrz", source_id.as_deref()) {
                Ok((_id, is_new)) => {
                    imported += 1;
                    if is_new {
                        new_qsos += 1;
                    }
                }
                Err(e) => {
                    warn!("Failed to save QRZ QSO: {}", e);
                }
            }
        }
    }

    // Record sync result
    {
        let db = Database::open(db_path)?;
        let message = format!("Downloaded {} QSOs from QRZ ({} new)", imported, new_qsos);
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
        total = imported,
        new = new_qsos,
        "QRZ download sync completed"
    );
    Ok(SyncTaskResult {
        new_downloads: new_qsos,
        ..Default::default()
    })
}

/// Run POTA download sync (downloads activations and QSOs from POTA.app)
async fn run_pota_download(
    db_path: &Path,
    user_id: i64,
    config: &integrations::PotaIntegrationConfig,
) -> crate::Result<SyncTaskResult> {
    use crate::pota::browser::PotaUploader;

    info!(user_id = user_id, "Starting POTA download sync");

    // Create POTA uploader (which also handles downloads)
    let cache_dir = dirs::cache_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("logbook-sync");
    std::fs::create_dir_all(&cache_dir).ok();
    let cache_path = cache_dir.join("pota_tokens.json");

    let mut uploader = PotaUploader::new(
        config.email.clone(),
        config.password.clone(),
        cache_path,
        true, // headless mode
    );

    // Ensure authenticated (sync operation)
    uploader
        .ensure_authenticated()
        .map_err(|e| crate::Error::Other(format!("POTA authentication failed: {}", e)))?;

    // Get activations
    let activations = uploader
        .get_activations()
        .await
        .map_err(|e| crate::Error::Other(format!("Failed to get POTA activations: {}", e)))?;

    let mut activations_saved = 0i64;
    let mut qsos_saved = 0i64;
    let mut new_qsos = 0i64;

    // Save activations to database
    {
        let db = Database::open(db_path)?;
        for activation in &activations {
            if let Err(e) = db.upsert_pota_activation(activation) {
                warn!(
                    reference = %activation.reference,
                    "Failed to save POTA activation: {}", e
                );
            } else {
                activations_saved += 1;
            }
        }
    }

    // Download QSOs for each activation
    for activation in &activations {
        let qsos = match uploader
            .get_activation_qsos(&activation.reference, &activation.date)
            .await
        {
            Ok(q) => q,
            Err(e) => {
                warn!(
                    reference = %activation.reference,
                    date = %activation.date,
                    "Failed to fetch POTA QSOs: {}", e
                );
                continue;
            }
        };

        // Save QSOs to database
        {
            let db = Database::open(db_path)?;
            for qso in &qsos {
                match db.upsert_pota_qso(qso) {
                    Ok(is_new) => {
                        qsos_saved += 1;
                        if is_new {
                            new_qsos += 1;
                        }
                    }
                    Err(e) => {
                        warn!("Failed to save POTA QSO: {}", e);
                    }
                }
            }
        }

        // Small delay between activation fetches to be polite to the API
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }

    // Record sync result
    {
        let db = Database::open(db_path)?;
        let message = format!(
            "Downloaded {} activations, {} QSOs ({} new) from POTA.app",
            activations_saved, qsos_saved, new_qsos
        );
        integrations::record_sync_success(
            db.conn(),
            user_id,
            "pota",
            "download",
            qsos_saved,
            Some(&message),
        )?;
    }

    info!(
        user_id = user_id,
        activations = activations_saved,
        total = qsos_saved,
        new = new_qsos,
        "POTA download sync completed"
    );
    Ok(SyncTaskResult {
        new_downloads: new_qsos,
        ..Default::default()
    })
}

/// Run POTA upload sync (uploads pending POTA QSOs to POTA.app)
async fn run_pota_upload(
    db_path: &Path,
    user_id: i64,
    config: &integrations::PotaIntegrationConfig,
) -> crate::Result<SyncTaskResult> {
    info!(user_id = user_id, "Starting POTA upload sync");

    // Get all QSOs from database
    let qsos = {
        let db = Database::open(db_path)?;
        db.get_all_qsos()?
    };

    // Generate preview to see what activations need uploading
    let preview = crate::pota::preview_upload(&qsos);

    // Check which activations have pending QSOs (not fully uploaded)
    let mut activations_to_upload = Vec::new();

    {
        let db = Database::open(db_path)?;
        for activation in preview
            .valid_activations
            .iter()
            .chain(preview.invalid_activations.iter())
        {
            // Check how many QSOs are already uploaded for this activation
            let uploaded_keys = db
                .get_pota_uploaded_qso_keys(&activation.park_ref, &activation.date)
                .unwrap_or_default();

            // Count how many QSOs in this activation are NOT already uploaded
            let pending_count = activation
                .qsos
                .iter()
                .filter(|q| {
                    let key = (
                        q.call.to_uppercase(),
                        q.time_on[..4.min(q.time_on.len())].to_string(),
                    );
                    !uploaded_keys.contains(&key)
                })
                .count();

            if pending_count > 0 {
                debug!(
                    park_ref = %activation.park_ref,
                    date = %activation.date,
                    pending = pending_count,
                    "Activation has pending QSOs to upload"
                );
                activations_to_upload.push(activation.clone());
            }
        }
    }

    if activations_to_upload.is_empty() {
        info!(user_id = user_id, "No pending POTA activations to upload");
        // Record sync success with 0 items
        let db = Database::open(db_path)?;
        integrations::record_sync_success(
            db.conn(),
            user_id,
            "pota",
            "upload",
            0,
            Some("No pending activations"),
        )?;
        return Ok(SyncTaskResult::default());
    }

    info!(
        user_id = user_id,
        count = activations_to_upload.len(),
        "Uploading pending POTA activations"
    );

    // Upload activations
    let result =
        crate::pota::upload_to_pota(&config.email, &config.password, &activations_to_upload)
            .await
            .map_err(|e| crate::Error::Other(format!("POTA upload failed: {}", e)))?;

    // Record sync result
    {
        let db = Database::open(db_path)?;
        if result.errors.is_empty() {
            let message = format!(
                "Uploaded {} activations, {} QSOs to POTA.app",
                result.activations_uploaded, result.qsos_uploaded
            );
            integrations::record_sync_success(
                db.conn(),
                user_id,
                "pota",
                "upload",
                result.qsos_uploaded as i64,
                Some(&message),
            )?;
        } else {
            let message = format!(
                "Uploaded {} activations, {} QSOs ({} errors)",
                result.activations_uploaded,
                result.qsos_uploaded,
                result.errors.len()
            );
            integrations::record_sync_error(db.conn(), user_id, "pota", "upload", &message)?;
        }
    }

    info!(
        user_id = user_id,
        activations = result.activations_uploaded,
        qsos = result.qsos_uploaded,
        errors = result.errors.len(),
        "POTA upload sync completed"
    );
    Ok(SyncTaskResult {
        uploads: result.qsos_uploaded as i64,
        ..Default::default()
    })
}
