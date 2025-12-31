//! LoFi sync service for automatic data synchronization.

use crate::db::Database;
use crate::error::Result;
use crate::ntfy::NtfyClient;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::time::{Duration, sleep};
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
    user_id: i64,
}

impl<'a> LofiSyncService<'a> {
    /// Create a new sync service
    pub fn new(
        client: &'a LofiClient,
        db: &'a Database,
        ntfy: Option<&'a NtfyClient>,
        batch_size: u32,
        loop_delay_ms: u64,
        user_id: i64,
    ) -> Self {
        Self {
            client,
            db,
            ntfy,
            batch_size,
            loop_delay_ms,
            user_id,
        }
    }

    /// Perform a full sync of operations and QSOs
    pub async fn sync_all(&self) -> Result<SyncStats> {
        let start_time = Instant::now();
        info!("Starting LoFi sync");

        // Record the sync start time (we'll save it after successful sync)
        let sync_start_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);

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
                return Err(e);
            }
        }

        // Save the sync timestamp for next time
        if let Err(e) = self.db.set_lofi_last_sync_millis(sync_start_millis) {
            warn!(error = %e, "Failed to save LoFi sync timestamp");
        }

        let duration = start_time.elapsed();

        // Send notifications for new data (only if truly new)
        if (stats.new_qsos > 0 || stats.new_operations > 0)
            && let Err(e) = self.send_notifications(&stats).await
        {
            warn!(error = %e, "Failed to send LoFi sync notifications");
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
        let mut total_on_server = 0u32;

        // Get last sync timestamp (0 means get all)
        let initial_synced_since = self.db.get_lofi_last_sync_millis()?;

        debug!(
            synced_since_millis = initial_synced_since,
            "Fetching operations since timestamp"
        );

        // Fetch both active and deleted operations
        // The API filters by deleted status, so we need two passes
        for include_deleted in [false, true] {
            let mut synced_since_millis = initial_synced_since;

            loop {
                let response = self
                    .client
                    .fetch_operations(
                        synced_since_millis,
                        Some(self.batch_size),
                        Some(include_deleted),
                    )
                    .await?;

                let meta = &response.meta.operations;
                if !include_deleted {
                    total_on_server = meta.total_records;
                }

                debug!(
                    count = response.operations.len(),
                    records_left = meta.records_left,
                    total = meta.total_records,
                    next_millis = ?meta.next_updated_at_millis,
                    deleted = include_deleted,
                    "Fetched operations batch"
                );

                for op in &response.operations {
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

                // Get the next page cursor from metadata
                // The API returns next_updated_at_millis or next_synced_at_millis for pagination
                if let Some(next_millis) =
                    meta.next_updated_at_millis.or(meta.next_synced_at_millis)
                {
                    synced_since_millis = next_millis as i64;
                } else {
                    // No cursor provided, stop pagination
                    warn!("LoFi API indicated more records but no pagination cursor provided");
                    break;
                }

                // Delay between pagination requests
                sleep(Duration::from_millis(self.loop_delay_ms)).await;
            }

            // Delay between active/deleted passes
            sleep(Duration::from_millis(self.loop_delay_ms)).await;
        }

        Ok((new_count, updated_count, total_on_server))
    }

    /// Sync all QSOs by iterating over operations
    /// Returns (new_count, updated_count, total_on_server)
    async fn sync_qsos(&self) -> Result<(u32, u32, u32)> {
        let mut new_count = 0u32;
        let mut updated_count = 0u32;
        let mut total_qsos = 0u32;

        // Get all operations from the database
        let operations = self.db.get_lofi_operations()?;

        for op in operations {
            // Skip deleted operations
            if op.deleted != 0 {
                continue;
            }

            // Fetch QSOs for this operation
            let (op_new, op_updated, op_total) =
                self.sync_operation_qsos(&op.uuid, &op.account).await?;

            new_count += op_new;
            updated_count += op_updated;
            total_qsos += op_total;

            // Delay between operations
            sleep(Duration::from_millis(self.loop_delay_ms)).await;
        }

        Ok((new_count, updated_count, total_qsos))
    }

    /// Sync QSOs for a single operation
    /// Returns (new_count, updated_count, total_in_operation)
    async fn sync_operation_qsos(
        &self,
        operation_uuid: &str,
        account_uuid: &str,
    ) -> Result<(u32, u32, u32)> {
        let mut new_count = 0u32;
        let mut updated_count = 0u32;
        let mut total_in_operation;

        // Get last sync timestamp (0 means get all)
        let initial_synced_since = self.db.get_lofi_last_sync_millis()?;
        let mut synced_since_millis = initial_synced_since;

        loop {
            let response = self
                .client
                .fetch_operation_qsos(operation_uuid, synced_since_millis, Some(self.batch_size))
                .await?;

            let meta = &response.meta.qsos;
            total_in_operation = meta.total_records;

            debug!(
                operation = %operation_uuid,
                count = response.qsos.len(),
                records_left = meta.records_left,
                total = meta.total_records,
                next_millis = ?meta.next_updated_at_millis,
                "Fetched operation QSOs batch"
            );

            for qso in &response.qsos {
                // Skip deleted QSOs
                if qso.deleted != 0 {
                    continue;
                }

                let is_new = self
                    .db
                    .upsert_lofi_qso(qso, Some(account_uuid), self.user_id)?;
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

            // Get the next page cursor from metadata
            if let Some(next_millis) = meta.next_updated_at_millis.or(meta.next_synced_at_millis) {
                synced_since_millis = next_millis as i64;
            } else {
                // No cursor provided, stop pagination
                warn!(
                    operation = %operation_uuid,
                    "LoFi API indicated more QSOs but no pagination cursor provided"
                );
                break;
            }

            sleep(Duration::from_millis(self.loop_delay_ms)).await;
        }

        Ok((new_count, updated_count, total_in_operation))
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
                let their_call = qso.their_call().unwrap_or("?");
                message.push_str(&format!("  {} on {} {}\n", their_call, band, mode));
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
#[allow(clippy::too_many_arguments)]
pub async fn run_lofi_sync_loop(
    client: LofiClient,
    db: Database,
    ntfy: Option<NtfyClient>,
    batch_size: u32,
    loop_delay_ms: u64,
    check_period_ms: u64,
    user_id: i64,
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
                    user_id,
                );

                if let Err(e) = service.sync_all().await {
                    error!(error = %e, "LoFi sync failed");
                }
            }
        }
    }
}
