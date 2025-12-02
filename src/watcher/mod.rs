use crate::db::{compute_file_checksum, Database};
use crate::adif::parse_adif;
use crate::{Config, Result};
use notify::RecursiveMode;
use notify_debouncer_mini::{new_debouncer, DebouncedEventKind};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;
use tokio::sync::mpsc as async_mpsc;
use tracing::{debug, error, info, warn};

/// Events emitted by the file watcher
#[derive(Debug, Clone)]
pub enum WatchEvent {
    /// A new or modified ADIF file was detected
    FileChanged(PathBuf),
    /// A file was removed
    FileRemoved(PathBuf),
}

/// File watcher service
pub struct FileWatcher {
    watch_dir: PathBuf,
    patterns: Vec<String>,
    debounce_secs: u64,
}

impl FileWatcher {
    pub fn new(config: &Config) -> Self {
        Self {
            watch_dir: config.local.watch_dir.clone(),
            patterns: config.local.patterns.clone(),
            debounce_secs: config.local.debounce_secs,
        }
    }

    /// Start watching for file changes, returning a receiver for events
    pub fn start(&self) -> Result<async_mpsc::Receiver<WatchEvent>> {
        let (tx, rx) = async_mpsc::channel(100);
        let watch_dir = self.watch_dir.clone();
        let patterns = self.patterns.clone();
        let debounce_secs = self.debounce_secs;

        std::thread::spawn(move || {
            if let Err(e) = run_watcher(watch_dir, patterns, debounce_secs, tx) {
                error!(error = %e, "File watcher error");
            }
        });

        Ok(rx)
    }

    /// Get existing files matching our patterns
    pub fn get_existing_files(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();

        for entry in std::fs::read_dir(&self.watch_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() && matches_patterns(&path, &self.patterns) {
                files.push(path);
            }
        }

        // Sort by modification time (oldest first)
        files.sort_by(|a, b| {
            let a_time = a.metadata().and_then(|m| m.modified()).ok();
            let b_time = b.metadata().and_then(|m| m.modified()).ok();
            a_time.cmp(&b_time)
        });

        Ok(files)
    }
}

/// Run the file watcher (blocking, runs in separate thread)
fn run_watcher(
    watch_dir: PathBuf,
    patterns: Vec<String>,
    debounce_secs: u64,
    tx: async_mpsc::Sender<WatchEvent>,
) -> Result<()> {
    let (sync_tx, sync_rx) = mpsc::channel();

    let mut debouncer = new_debouncer(
        Duration::from_secs(debounce_secs),
        move |res: std::result::Result<Vec<notify_debouncer_mini::DebouncedEvent>, notify::Error>| {
            if let Ok(events) = res {
                for event in events {
                    let _ = sync_tx.send(event);
                }
            }
        },
    )?;

    debouncer
        .watcher()
        .watch(&watch_dir, RecursiveMode::NonRecursive)?;

    info!(path = %watch_dir.display(), "Watching directory for ADIF files");

    while let Ok(event) = sync_rx.recv() {
        let path = &event.path;

        if !path.is_file() || !matches_patterns(path, &patterns) {
            continue;
        }

        debug!(path = %path.display(), kind = ?event.kind, "File event");

        let watch_event = match event.kind {
            DebouncedEventKind::Any => WatchEvent::FileChanged(path.clone()),
            DebouncedEventKind::AnyContinuous => continue, // Still being modified
            _ => continue, // Handle any future variants
        };

        if tx.blocking_send(watch_event).is_err() {
            // Channel closed, exit
            break;
        }
    }

    Ok(())
}

/// Check if a path matches any of our patterns
fn matches_patterns(path: &Path, patterns: &[String]) -> bool {
    let file_name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n.to_lowercase(),
        None => return false,
    };

    for pattern in patterns {
        let pattern_lower = pattern.to_lowercase();
        if let Some(ext) = pattern_lower.strip_prefix("*.") {
            if file_name.ends_with(&format!(".{}", ext)) {
                return true;
            }
        } else if file_name == pattern_lower {
            return true;
        }
    }

    false
}

/// Process a single ADIF file, adding new QSOs to the database
pub fn process_adif_file(path: &Path, db: &Database) -> Result<ProcessResult> {
    let path_str = path.to_string_lossy().to_string();

    // Check if file has changed since last processing
    let checksum = compute_file_checksum(path)?;
    if let Some(old_checksum) = db.get_file_checksum(&path_str)? {
        if old_checksum == checksum {
            debug!(path = %path.display(), "File unchanged, skipping");
            return Ok(ProcessResult {
                path: path.to_path_buf(),
                total_qsos: 0,
                new_qsos: 0,
                skipped_duplicate: 0,
                errors: 0,
            });
        }
    }

    // Read and parse the file
    let content = std::fs::read_to_string(path)?;
    let adif = parse_adif(&content)?;

    for warning in &adif.warnings {
        warn!(path = %path.display(), warning = %warning, "ADIF parse warning");
    }

    let total = adif.qsos.len();
    let mut new_count = 0;
    let mut dup_count = 0;
    let mut error_count = 0;

    for qso in adif.qsos {
        if db.qso_exists(&qso)? {
            dup_count += 1;
            continue;
        }

        match db.upsert_qso(&qso, Some(&path_str)) {
            Ok(_) => {
                new_count += 1;
                debug!(
                    call = %qso.call,
                    date = %qso.qso_date,
                    "Added new QSO"
                );
            }
            Err(e) => {
                error_count += 1;
                error!(error = %e, call = %qso.call, "Failed to insert QSO");
            }
        }
    }

    // Record file as processed
    db.record_processed_file(&path_str, &checksum, total as i64)?;

    info!(
        path = %path.display(),
        total = total,
        new = new_count,
        duplicates = dup_count,
        "Processed ADIF file"
    );

    Ok(ProcessResult {
        path: path.to_path_buf(),
        total_qsos: total,
        new_qsos: new_count,
        skipped_duplicate: dup_count,
        errors: error_count,
    })
}

#[derive(Debug)]
pub struct ProcessResult {
    pub path: PathBuf,
    pub total_qsos: usize,
    pub new_qsos: usize,
    pub skipped_duplicate: usize,
    pub errors: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_patterns() {
        let patterns = vec!["*.adi".to_string(), "*.adif".to_string()];

        assert!(matches_patterns(Path::new("test.adi"), &patterns));
        assert!(matches_patterns(Path::new("TEST.ADI"), &patterns));
        assert!(matches_patterns(Path::new("log.adif"), &patterns));
        assert!(!matches_patterns(Path::new("test.txt"), &patterns));
        assert!(!matches_patterns(Path::new("test.adi.bak"), &patterns));
    }
}
