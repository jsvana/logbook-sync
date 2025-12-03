//! Sync service that coordinates file watching, database, and QRZ uploads

use crate::adif::Qso;
use crate::db::Database;
use crate::ntfy::NtfyClient;
use crate::qrz::{QrzClient, UploadResult};
use crate::watcher::{process_adif_file, FileWatcher, ProcessResult, WatchEvent};
use crate::{Config, Result};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Configuration for retry behavior
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub exponential_base: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_delay_ms: 1000,
            max_delay_ms: 60000,
            exponential_base: 2.0,
        }
    }
}

impl RetryConfig {
    /// Calculate delay for a given attempt number (0-indexed)
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let delay_ms =
            (self.initial_delay_ms as f64 * self.exponential_base.powi(attempt as i32)) as u64;
        Duration::from_millis(delay_ms.min(self.max_delay_ms))
    }
}

/// Statistics for sync operations
#[derive(Debug, Default, Clone)]
pub struct SyncStats {
    pub files_processed: usize,
    pub qsos_found: usize,
    pub qsos_new: usize,
    pub qsos_duplicate: usize,
    pub qsos_uploaded: usize,
    pub qsos_upload_failed: usize,
    pub qsos_already_on_qrz: usize,
    // Download stats
    pub qsos_downloaded: usize,
    pub confirmations_updated: usize,
}

impl SyncStats {
    pub fn add_process_result(&mut self, result: &ProcessResult) {
        self.files_processed += 1;
        self.qsos_found += result.total_qsos;
        self.qsos_new += result.new_qsos;
        self.qsos_duplicate += result.skipped_duplicate;
    }
}

/// The main sync service
pub struct SyncService {
    config: Config,
    db: Arc<Database>,
    qrz_client: Option<QrzClient>,
    ntfy_client: Option<NtfyClient>,
    retry_config: RetryConfig,
}

impl SyncService {
    #[allow(clippy::arc_with_non_send_sync)]
    pub fn new(config: Config, db: Database) -> Self {
        let qrz_client = if config.qrz.enabled {
            Some(QrzClient::new(
                config.qrz.api_key.clone(),
                config.qrz.user_agent.clone(),
            ))
        } else {
            None
        };

        let ntfy_client = config
            .ntfy
            .as_ref()
            .filter(|c| c.enabled)
            .map(|c| NtfyClient::new(c.clone()));

        Self {
            config,
            db: Arc::new(db),
            qrz_client,
            ntfy_client,
            retry_config: RetryConfig::default(),
        }
    }

    /// Send a notification about sync activity (if ntfy is configured)
    async fn notify_sync(&self, stats: &SyncStats) {
        if let Some(ref client) = self.ntfy_client {
            if let Err(e) = client.notify_sync(stats, &self.config.general.callsign).await {
                warn!(error = %e, "Failed to send ntfy notification");
            }
        }
    }

    /// Process all existing files in the watch directory
    pub fn process_existing_files(&self) -> Result<SyncStats> {
        let mut stats = SyncStats::default();
        let watcher = FileWatcher::new(&self.config);
        let files = watcher.get_existing_files()?;

        info!(count = files.len(), "Processing existing ADIF files");

        for path in files {
            match process_adif_file(&path, &self.db) {
                Ok(result) => {
                    stats.add_process_result(&result);
                }
                Err(e) => {
                    error!(path = %path.display(), error = %e, "Failed to process file");
                }
            }
        }

        Ok(stats)
    }

    /// Process a single file
    pub fn process_file(&self, path: &Path) -> Result<ProcessResult> {
        process_adif_file(path, &self.db)
    }

    /// Upload all pending QSOs to QRZ with retry logic
    pub async fn upload_pending_to_qrz(&self) -> Result<SyncStats> {
        let mut stats = SyncStats::default();

        let client = match &self.qrz_client {
            Some(c) => c,
            None => {
                debug!("QRZ client not configured, skipping upload");
                return Ok(stats);
            }
        };

        if !self.config.qrz.upload {
            debug!("QRZ upload disabled");
            return Ok(stats);
        }

        let pending = self.db.get_unsynced_qrz()?;
        if pending.is_empty() {
            debug!("No pending QSOs to upload");
            return Ok(stats);
        }

        info!(count = pending.len(), "Uploading pending QSOs to QRZ");

        for stored in pending {
            let qso: Qso = match serde_json::from_str(&stored.adif_record) {
                Ok(q) => q,
                Err(e) => {
                    error!(id = stored.id, error = %e, "Failed to deserialize stored QSO");
                    continue;
                }
            };

            match self.upload_qso_with_retry(client, &qso, stored.id).await {
                Ok(result) => {
                    if result.success {
                        stats.qsos_uploaded += 1;
                    } else if result.is_duplicate {
                        stats.qsos_already_on_qrz += 1;
                    } else {
                        stats.qsos_upload_failed += 1;
                    }
                }
                Err(e) => {
                    stats.qsos_upload_failed += 1;
                    error!(
                        call = %qso.call,
                        error = %e,
                        "Failed to upload QSO after retries"
                    );
                }
            }

            // Rate limiting between uploads
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        info!(
            uploaded = stats.qsos_uploaded,
            duplicates = stats.qsos_already_on_qrz,
            failed = stats.qsos_upload_failed,
            "QRZ upload complete"
        );

        Ok(stats)
    }

    /// Upload a single QSO with retry logic
    async fn upload_qso_with_retry(
        &self,
        client: &QrzClient,
        qso: &Qso,
        db_id: i64,
    ) -> Result<UploadResult> {
        let mut last_error = None;

        for attempt in 0..self.retry_config.max_attempts {
            if attempt > 0 {
                let delay = self.retry_config.delay_for_attempt(attempt - 1);
                debug!(
                    attempt = attempt,
                    delay_ms = delay.as_millis(),
                    call = %qso.call,
                    "Retrying QRZ upload"
                );
                tokio::time::sleep(delay).await;
            }

            match client.upload_qso(qso).await {
                Ok(result) => {
                    if result.success {
                        if let Some(logid) = result.logid {
                            self.db.mark_qrz_synced(db_id, logid)?;
                        }
                        return Ok(result);
                    } else if result.is_duplicate {
                        // Mark as synced since it exists on QRZ
                        self.db.mark_qrz_synced(db_id, 0)?;
                        debug!(
                            call = %qso.call,
                            date = %qso.qso_date,
                            "QSO already exists on QRZ (duplicate)"
                        );
                        return Ok(result);
                    } else {
                        // Non-retryable error (e.g., invalid data)
                        let error_msg = result.error.clone().unwrap_or_default();
                        if is_permanent_error(&error_msg) {
                            warn!(
                                call = %qso.call,
                                error = %error_msg,
                                "Permanent QRZ error, not retrying"
                            );
                            return Ok(result);
                        }
                        last_error = Some(error_msg);
                    }
                }
                Err(e) => {
                    // Network or transient error - retry
                    warn!(
                        attempt = attempt + 1,
                        max_attempts = self.retry_config.max_attempts,
                        call = %qso.call,
                        error = %e,
                        "QRZ upload failed, will retry"
                    );
                    last_error = Some(e.to_string());
                }
            }
        }

        Err(crate::Error::Qrz(format!(
            "Failed after {} attempts: {}",
            self.retry_config.max_attempts,
            last_error.unwrap_or_default()
        )))
    }

    /// Download QSOs and confirmations from QRZ
    pub async fn download_from_qrz(&self) -> Result<SyncStats> {
        let mut stats = SyncStats::default();

        let client = match &self.qrz_client {
            Some(c) => c,
            None => {
                debug!("QRZ client not configured, skipping download");
                return Ok(stats);
            }
        };

        if !self.config.qrz.download {
            debug!("QRZ download disabled");
            return Ok(stats);
        }

        info!("Downloading QSOs from QRZ...");

        match client.fetch_all().await {
            Ok(fetched_qsos) => {
                stats.qsos_downloaded = fetched_qsos.len();
                debug!(count = stats.qsos_downloaded, "Downloaded QSOs from QRZ");

                // Count confirmations available
                let confirmed_count = fetched_qsos
                    .iter()
                    .filter(|q| {
                        q.lotw_qsl_rcvd.as_deref() == Some("Y")
                            || q.qsl_rcvd.as_deref() == Some("Y")
                    })
                    .count();
                debug!(
                    confirmed = confirmed_count,
                    "QSOs with confirmations in download"
                );

                // Log first few QSOs for debugging
                for (i, fetched) in fetched_qsos.iter().take(3).enumerate() {
                    debug!(
                        idx = i,
                        call = %fetched.qso.call,
                        date = %fetched.qso.qso_date,
                        time = %fetched.qso.time_on,
                        band = %fetched.qso.band,
                        mode = %fetched.qso.mode,
                        lotw_rcvd = ?fetched.lotw_qsl_rcvd,
                        "Sample downloaded QSO"
                    );
                }

                let mut matched = 0;
                let mut unmatched_samples = 0;
                for fetched in &fetched_qsos {
                    let lotw_rcvd = fetched.lotw_qsl_rcvd.as_deref();
                    let lotw_sent = fetched.lotw_qsl_sent.as_deref();
                    let qsl_rcvd = fetched.qsl_rcvd.as_deref();
                    let qsl_sent = fetched.qsl_sent.as_deref();

                    if self.db.update_confirmation(
                        &fetched.qso.call,
                        &fetched.qso.qso_date,
                        &fetched.qso.time_on,
                        &fetched.qso.band,
                        &fetched.qso.mode,
                        lotw_rcvd,
                        lotw_sent,
                        qsl_rcvd,
                        qsl_sent,
                    )? {
                        matched += 1;
                        if lotw_rcvd == Some("Y") || qsl_rcvd == Some("Y") {
                            stats.confirmations_updated += 1;
                        }
                    } else if unmatched_samples < 3 {
                        // Log a few unmatched QSOs to help debug
                        debug!(
                            call = %fetched.qso.call,
                            date = %fetched.qso.qso_date,
                            time = %fetched.qso.time_on,
                            band = %fetched.qso.band,
                            mode = %fetched.qso.mode,
                            "QSO from QRZ not found in local DB"
                        );
                        unmatched_samples += 1;
                    }
                }

                info!(
                    downloaded = stats.qsos_downloaded,
                    matched = matched,
                    confirmations = stats.confirmations_updated,
                    "QRZ download complete"
                );
            }
            Err(e) => {
                error!(error = %e, "QRZ download failed");
            }
        }

        Ok(stats)
    }

    /// Run the daemon loop
    pub async fn run_daemon(self) -> Result<()> {
        info!(
            callsign = %self.config.general.callsign,
            watch_dir = %self.config.local.watch_dir.display(),
            "Starting sync daemon"
        );

        // Process existing files if configured
        if self.config.local.process_existing {
            let stats = self.process_existing_files()?;
            info!(
                files = stats.files_processed,
                qsos = stats.qsos_new,
                "Processed existing files"
            );

            // Upload any pending QSOs and notify
            match self.upload_pending_to_qrz().await {
                Ok(stats) => self.notify_sync(&stats).await,
                Err(e) => error!(error = %e, "Initial QRZ upload failed"),
            }
        }

        // Notify systemd we're ready
        let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);

        // Start file watcher
        let watcher = FileWatcher::new(&self.config);
        let mut rx = watcher.start()?;

        // Set up periodic sync timer
        let sync_interval = Duration::from_secs(self.config.general.sync_interval);
        let mut sync_timer = tokio::time::interval(sync_interval);

        // Set up QRZ download timer (less frequent)
        let download_interval = Duration::from_secs(self.config.qrz.download_interval);
        let mut download_timer = tokio::time::interval(download_interval);

        loop {
            tokio::select! {
                // Handle file watcher events
                Some(event) = rx.recv() => {
                    match event {
                        WatchEvent::FileChanged(path) => {
                            info!(path = %path.display(), "ADIF file changed");

                            match self.process_file(&path) {
                                Ok(result) => {
                                    if result.new_qsos > 0 {
                                        info!(
                                            path = %path.display(),
                                            new = result.new_qsos,
                                            total = result.total_qsos,
                                            "New QSOs detected"
                                        );

                                        // Trigger upload and notify
                                        match self.upload_pending_to_qrz().await {
                                            Ok(stats) => self.notify_sync(&stats).await,
                                            Err(e) => error!(error = %e, "Failed to upload to QRZ"),
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!(path = %path.display(), error = %e, "Failed to process file");
                                }
                            }
                        }
                        WatchEvent::FileRemoved(path) => {
                            debug!(path = %path.display(), "ADIF file removed");
                        }
                    }
                }

                // Periodic sync check
                _ = sync_timer.tick() => {
                    debug!("Running periodic sync check");

                    // Check for any unsynced QSOs and notify
                    match self.upload_pending_to_qrz().await {
                        Ok(stats) => self.notify_sync(&stats).await,
                        Err(e) => error!(error = %e, "Periodic QRZ sync failed"),
                    }
                }

                // Periodic QRZ download (for confirmations)
                _ = download_timer.tick() => {
                    if self.config.qrz.download {
                        match self.download_from_qrz().await {
                            Ok(stats) => self.notify_sync(&stats).await,
                            Err(e) => error!(error = %e, "Periodic QRZ download failed"),
                        }
                    }
                }

                // Handle Ctrl+C
                _ = tokio::signal::ctrl_c() => {
                    info!("Received shutdown signal");
                    break;
                }
            }
        }

        info!("Sync daemon stopped");
        Ok(())
    }

    /// Get database reference
    pub fn db(&self) -> &Database {
        &self.db
    }
}

/// Check if an error message indicates a permanent (non-retryable) error
fn is_permanent_error(error: &str) -> bool {
    let error_lower = error.to_lowercase();
    error_lower.contains("invalid api key")
        || error_lower.contains("invalid call")
        || error_lower.contains("invalid date")
        || error_lower.contains("invalid band")
        || error_lower.contains("invalid mode")
        || error_lower.contains("malformed")
        || error_lower.contains("station_callsign")
        || error_lower.contains("doesnt match")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_config_delay() {
        let config = RetryConfig::default();

        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(1000));
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(2000));
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(4000));
        assert_eq!(config.delay_for_attempt(3), Duration::from_millis(8000));

        // Should cap at max_delay_ms
        assert_eq!(config.delay_for_attempt(10), Duration::from_millis(60000));
    }

    #[test]
    fn test_is_permanent_error() {
        assert!(is_permanent_error("invalid api key"));
        assert!(is_permanent_error("INVALID CALL"));
        assert!(is_permanent_error("malformed adif"));
        assert!(!is_permanent_error("timeout"));
        assert!(!is_permanent_error("connection refused"));
    }
}
