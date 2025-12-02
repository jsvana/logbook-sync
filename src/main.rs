use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use logbook_sync::db::Database;
use logbook_sync::qrz::QrzClient;
use logbook_sync::{Config, SyncService};
use std::path::PathBuf;
use tracing::{error, Level};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "logbook-sync")]
#[command(about = "ADIF log synchronization daemon for amateur radio")]
#[command(version)]
struct Cli {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/logbook-sync/config.toml")]
    config: PathBuf,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Suppress non-error output
    #[arg(short, long)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as background service (systemd mode)
    Daemon,

    /// Perform one-time sync and exit
    Sync,

    /// Show sync status and statistics
    Status,

    /// Manually upload specific ADIF file
    Upload {
        /// Path to ADIF file
        file: PathBuf,
    },

    /// Download logs from remote services
    Download,

    /// Validate configuration file
    Config {
        /// Only validate, don't show contents
        #[arg(long)]
        validate: bool,
    },

    /// Watch directory and show events (debug mode)
    Watch,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.quiet {
        Level::ERROR
    } else {
        match cli.verbose {
            0 => Level::INFO,
            1 => Level::DEBUG,
            _ => Level::TRACE,
        }
    };

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(log_level.into()))
        .init();

    // Load configuration
    let config = Config::load(&cli.config)
        .with_context(|| format!("Failed to load config from {:?}", cli.config))?;

    match cli.command {
        Commands::Daemon => run_daemon(config).await,
        Commands::Sync => run_sync(config).await,
        Commands::Status => run_status(config).await,
        Commands::Upload { file } => run_upload(config, file).await,
        Commands::Download => run_download(config).await,
        Commands::Config { validate } => run_config_check(config, validate),
        Commands::Watch => run_watch(config).await,
    }
}

async fn run_daemon(config: Config) -> Result<()> {
    config.validate()?;

    let db = Database::open(&config.database.path).context("Failed to open database")?;
    let service = SyncService::new(config, db);

    service.run_daemon().await?;

    Ok(())
}

async fn run_sync(config: Config) -> Result<()> {
    config.validate()?;

    println!("Running one-time sync...\n");

    let db = Database::open(&config.database.path)?;
    let service = SyncService::new(config, db);

    // Process existing files
    let stats = service.process_existing_files()?;

    println!("File Processing:");
    println!("  Files processed: {}", stats.files_processed);
    println!("  QSOs found:      {}", stats.qsos_found);
    println!("  New QSOs:        {}", stats.qsos_new);
    println!("  Duplicates:      {}", stats.qsos_duplicate);

    // Upload to QRZ
    println!("\nUploading to QRZ...");
    let upload_stats = service.upload_pending_to_qrz().await?;

    println!("QRZ Upload:");
    println!("  Uploaded:     {}", upload_stats.qsos_uploaded);
    println!("  Already exist:{}", upload_stats.qsos_already_on_qrz);
    println!("  Failed:       {}", upload_stats.qsos_upload_failed);

    println!("\nSync complete!");
    Ok(())
}

async fn run_status(config: Config) -> Result<()> {
    let db = Database::open(&config.database.path)?;
    let stats = db.get_stats()?;

    println!("Logbook Sync Status");
    println!("===================");
    println!("Callsign: {}", config.general.callsign);
    println!();
    println!("Local Database:");
    println!("  Total QSOs:      {}", stats.total_qsos);
    println!("  Synced to QRZ:   {}", stats.synced_qrz);
    println!("  Pending upload:  {}", stats.pending_qrz);
    println!("  LotW confirmed:  {}", stats.lotw_confirmed);
    println!("  QSL confirmed:   {}", stats.qsl_confirmed);
    println!("  Files processed: {}", stats.processed_files);

    if config.qrz.enabled {
        println!();
        println!("QRZ Logbook:");
        let client = QrzClient::new(config.qrz.api_key.clone(), config.qrz.user_agent.clone());
        match client.get_status().await {
            Ok(status) => {
                if let Some(count) = status.count {
                    println!("  Total QSOs:   {}", count);
                }
                if let Some(confirmed) = status.confirmed {
                    println!("  Confirmed:    {}", confirmed);
                }
                if let Some(dxcc) = status.dxcc {
                    println!("  DXCC:         {}", dxcc);
                }
            }
            Err(e) => {
                println!("  Error: {}", e);
            }
        }
    }

    Ok(())
}

async fn run_upload(config: Config, file: PathBuf) -> Result<()> {
    config.validate()?;

    if !file.exists() {
        anyhow::bail!("File not found: {:?}", file);
    }

    println!("Processing: {}", file.display());

    let db = Database::open(&config.database.path)?;
    let service = SyncService::new(config, db);

    // Process the file
    let result = service.process_file(&file)?;
    println!(
        "  {} QSOs found ({} new, {} duplicates)",
        result.total_qsos, result.new_qsos, result.skipped_duplicate
    );

    // Upload to QRZ
    if result.new_qsos > 0 {
        println!("\nUploading to QRZ...");
        let upload_stats = service.upload_pending_to_qrz().await?;
        println!(
            "  Uploaded: {}, Already exist: {}, Failed: {}",
            upload_stats.qsos_uploaded,
            upload_stats.qsos_already_on_qrz,
            upload_stats.qsos_upload_failed
        );
    } else {
        println!("\nNo new QSOs to upload.");
    }

    Ok(())
}

async fn run_download(config: Config) -> Result<()> {
    config.validate()?;

    if !config.qrz.enabled || !config.qrz.download {
        println!("QRZ download is disabled");
        return Ok(());
    }

    println!("Downloading from QRZ...\n");

    let client = QrzClient::new(config.qrz.api_key.clone(), config.qrz.user_agent.clone());
    let db = Database::open(&config.database.path)?;

    // Download all QSOs from QRZ with pagination
    println!("Fetching all QSOs from QRZ...");

    match client.fetch_all().await {
        Ok(fetched_qsos) => {
            println!("Downloaded {} QSOs", fetched_qsos.len());
            let result_qsos = fetched_qsos;

            let mut updated = 0;
            let mut new_confirmations = 0;

            for fetched in &result_qsos {
                // Update confirmation status in local database
                let lotw_rcvd = fetched.lotw_qsl_rcvd.as_deref();
                let lotw_sent = fetched.lotw_qsl_sent.as_deref();
                let qsl_rcvd = fetched.qsl_rcvd.as_deref();
                let qsl_sent = fetched.qsl_sent.as_deref();

                if db.update_confirmation(
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
                    updated += 1;
                    if lotw_rcvd == Some("Y") || qsl_rcvd == Some("Y") {
                        new_confirmations += 1;
                    }
                }
            }

            println!("\nResults:");
            println!("  QSOs matched:     {}", updated);
            println!("  Confirmations:    {}", new_confirmations);

            // Optionally save to ADIF file
            if !result_qsos.is_empty() {
                use logbook_sync::adif::write_adif;

                let qsos: Vec<_> = result_qsos.iter().map(|f| f.qso.clone()).collect();
                let adif_content = write_adif(None, &qsos);

                let date_str = chrono::Utc::now().format("%Y%m%d").to_string();
                let output_path = config
                    .local
                    .output_dir
                    .join(format!("qrz_download_{}.adi", date_str));

                std::fs::create_dir_all(&config.local.output_dir)?;
                std::fs::write(&output_path, adif_content)?;
                println!("  Saved to:         {}", output_path.display());
            }
        }
        Err(e) => {
            error!(error = %e, "Download failed");
            println!("Download failed: {}", e);
        }
    }

    Ok(())
}

fn run_config_check(config: Config, validate_only: bool) -> Result<()> {
    match config.validate() {
        Ok(()) => {
            if validate_only {
                println!("Configuration is valid");
            } else {
                println!("Configuration:");
                println!("  Callsign: {}", config.general.callsign);
                println!("  Watch dir: {:?}", config.local.watch_dir);
                println!("  Output dir: {:?}", config.local.output_dir);
                println!("  Database: {:?}", config.database.path);
                println!("  Patterns: {:?}", config.local.patterns);
                println!("  Debounce: {}s", config.local.debounce_secs);
                println!("  QRZ enabled: {}", config.qrz.enabled);
                println!("  QRZ upload: {}", config.qrz.upload);
                println!("  QRZ download: {}", config.qrz.download);
                println!("  Sync interval: {}s", config.general.sync_interval);
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Debug command to watch for file changes
async fn run_watch(config: Config) -> Result<()> {
    config.validate()?;

    use logbook_sync::watcher::{FileWatcher, WatchEvent};

    println!("Watching directory: {}", config.local.watch_dir.display());
    println!("Patterns: {:?}", config.local.patterns);
    println!("Debounce: {}s", config.local.debounce_secs);
    println!("\nPress Ctrl+C to stop.\n");

    let watcher = FileWatcher::new(&config);

    // Show existing files
    let existing = watcher.get_existing_files()?;
    if !existing.is_empty() {
        println!("Existing ADIF files:");
        for path in &existing {
            println!("  {}", path.display());
        }
        println!();
    }

    // Start watching
    let mut rx = watcher.start()?;

    loop {
        tokio::select! {
            Some(event) = rx.recv() => {
                match event {
                    WatchEvent::FileChanged(path) => {
                        println!("[CHANGED] {}", path.display());
                    }
                    WatchEvent::FileRemoved(path) => {
                        println!("[REMOVED] {}", path.display());
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\nStopped.");
                break;
            }
        }
    }

    Ok(())
}
