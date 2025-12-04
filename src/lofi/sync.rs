//! LoFi sync service for automatic data synchronization.

use crate::db::Database;
use crate::error::Result;
use crate::metrics;
use crate::ntfy::NtfyClient;
use std::time::Instant;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

use super::client::LofiClient;
use super::models::*;

/// Service for syncing data from LoFi
pub struct LofiSyncService<'a> {
    client: &'a LofiClient,
    db: &'a Database,
    ntfy: Option<&'a NtfyClient>,
    batch_size: u32,
    loop_delay_ms: u64,
}

impl<'a> LofiSyncService<'a> {
    /// Create a new sync service
    pub fn new(
        client: &'a LofiClient,
        db: &'a Database,
        ntfy: Option<&'a NtfyClient>,
        batch_size: u32,
        loop_delay_ms: u64,
    ) -> Self {
        Self {
            client,
            db,
            ntfy,
            batch_size,
            loop_delay_ms,
        }
    }

    /// Perform a full sync of operations and QSOs
    pub async fn sync_all(&self) -> Result<SyncStats> {
        let start_time = Instant::now();
        info!("Starting LoFi sync");

        let mut stats = SyncStats::default();

        // Sync operations first
        match self.sync_operations().await {
            Ok((new, updated, total)) => {
                stats.new_operations = new;
                stats.updated_operations = updated;
                stats.total_operations = total;
            }
            Err(e) => {
                warn!(error = %e, "Failed to sync operations, continuing with QSOs");
                metrics::record_sync_error("lofi", "operations_sync");
            }
        }

        // Delay between sync types as suggested by API
        sleep(Duration::from_millis(self.loop_delay_ms)).await;

        // Sync QSOs
        match self.sync_qsos().await {
            Ok((new, updated, total)) => {
                stats.new_qsos = new;
                stats.updated_qsos = updated;
                stats.total_qsos = total;
            }
            Err(e) => {
                warn!(error = %e, "Failed to sync QSOs");
                metrics::record_sync_error("lofi", "qsos_sync");
                return Err(e);
            }
        }

        // Record metrics
        let duration = start_time.elapsed();
        metrics::record_sync_duration("lofi", "full_sync", duration.as_secs_f64());

        if stats.new_operations > 0 || stats.updated_operations > 0 {
            metrics::record_qso_downloaded(
                "lofi",
                (stats.new_operations + stats.updated_operations) as u64,
            );
        }
        if stats.new_qsos > 0 || stats.updated_qsos > 0 {
            metrics::record_qso_downloaded("lofi", (stats.new_qsos + stats.updated_qsos) as u64);
        }

        // Send notifications for new data (only if truly new)
        if stats.new_qsos > 0 || stats.new_operations > 0 {
            if let Err(e) = self.send_notifications(&stats).await {
                warn!(error = %e, "Failed to send LoFi sync notifications");
            }
            metrics::record_sync_success("lofi");
        }

        info!(
            new_operations = stats.new_operations,
            updated_operations = stats.updated_operations,
            total_operations = stats.total_operations,
            new_qsos = stats.new_qsos,
            updated_qsos = stats.updated_qsos,
            total_qsos = stats.total_qsos,
            duration_ms = duration.as_millis(),
            "LoFi sync completed"
        );

        Ok(stats)
    }

    /// Sync all operations using pagination
    /// Returns (new_count, updated_count, total_on_server)
    async fn sync_operations(&self) -> Result<(u32, u32, u32)> {
        let mut new_count = 0u32;
        let mut updated_count = 0u32;
        let mut total_on_server: u32;

        // Start with no cursor (gets most recent first)
        let mut cursor: Option<f64> = None;

        loop {
            let response = self
                .client
                .fetch_operations(cursor, Some(self.batch_size))
                .await?;

            let meta = &response.meta.operations;
            total_on_server = meta.total_records;

            debug!(
                count = response.operations.len(),
                records_left = meta.records_left,
                total = meta.total_records,
                "Fetched operations batch"
            );

            for op in &response.operations {
                // Skip deleted operations
                if op.deleted != 0 {
                    continue;
                }

                let is_new = self.db.upsert_lofi_operation(op)?;
                if is_new {
                    new_count += 1;
                } else {
                    updated_count += 1;
                }
            }

            // Check if we should continue paginating
            // Stop if: records_left is 0 (no more pages)
            if meta.records_left == 0 {
                break;
            }

            // Use the synced_until_millis as cursor for next page
            cursor = Some(meta.synced_until_millis);

            // Delay between pagination requests
            sleep(Duration::from_millis(self.loop_delay_ms)).await;
        }

        Ok((new_count, updated_count, total_on_server))
    }

    /// Sync all QSOs using pagination
    /// Returns (new_count, updated_count, total_on_server)
    async fn sync_qsos(&self) -> Result<(u32, u32, u32)> {
        let mut new_count = 0u32;
        let mut updated_count = 0u32;
        let mut total_on_server: u32;

        // Start with no cursor (gets most recent first)
        let mut cursor: Option<f64> = None;

        loop {
            let response = self
                .client
                .fetch_qsos(cursor, Some(self.batch_size))
                .await?;

            let meta = &response.meta.qsos;
            total_on_server = meta.total_records;

            debug!(
                count = response.qsos.len(),
                records_left = meta.records_left,
                total = meta.total_records,
                "Fetched QSOs batch"
            );

            for qso in &response.qsos {
                // Skip deleted QSOs
                if qso.deleted != 0 {
                    continue;
                }

                let is_new = self.db.upsert_lofi_qso(qso)?;
                if is_new {
                    new_count += 1;
                } else {
                    updated_count += 1;
                }
            }

            // Check if we should continue paginating
            if meta.records_left == 0 {
                break;
            }

            cursor = Some(meta.synced_until_millis);
            sleep(Duration::from_millis(self.loop_delay_ms)).await;
        }

        Ok((new_count, updated_count, total_on_server))
    }

    /// Send notifications for new data
    async fn send_notifications(&self, stats: &SyncStats) -> Result<()> {
        let ntfy = match self.ntfy {
            Some(n) => n,
            None => return Ok(()),
        };

        // Only notify for truly new data
        if stats.new_qsos == 0 && stats.new_operations == 0 {
            return Ok(());
        }

        // Get the new QSOs that were just synced
        let new_qsos = self.db.get_and_mark_new_lofi_qsos()?;

        if new_qsos.is_empty() && stats.new_operations == 0 {
            return Ok(());
        }

        // Build notification message
        let mut message = String::new();

        if stats.new_operations > 0 {
            message.push_str(&format!("{} new operation(s)\n", stats.new_operations));
        }

        if !new_qsos.is_empty() {
            message.push_str(&format!("{} new QSO(s):\n", new_qsos.len()));

            // List first few QSOs
            for qso in new_qsos.iter().take(5) {
                let band = qso.band.as_deref().unwrap_or("?");
                let mode = qso.mode.as_deref().unwrap_or("?");
                message.push_str(&format!("  {} on {} {}\n", qso.their_call, band, mode));
            }

            if new_qsos.len() > 5 {
                message.push_str(&format!("  ... and {} more\n", new_qsos.len() - 5));
            }
        }

        ntfy.send("LoFi Sync: New Data", &message).await?;

        Ok(())
    }
}

/// Run LoFi sync as a background task
pub async fn run_lofi_sync_loop(
    client: LofiClient,
    db: Database,
    ntfy: Option<NtfyClient>,
    batch_size: u32,
    loop_delay_ms: u64,
    check_period_ms: u64,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    info!(
        batch_size = batch_size,
        loop_delay_ms = loop_delay_ms,
        check_period_ms = check_period_ms,
        "Starting LoFi sync loop"
    );

    let check_interval = Duration::from_millis(check_period_ms);

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("LoFi sync loop shutting down");
                    break;
                }
            }
            _ = sleep(check_interval) => {
                let service = LofiSyncService::new(
                    &client,
                    &db,
                    ntfy.as_ref(),
                    batch_size,
                    loop_delay_ms,
                );

                if let Err(e) = service.sync_all().await {
                    error!(error = %e, "LoFi sync failed");
                    metrics::record_sync_error("lofi", "sync_loop");
                }
            }
        }
    }
}
