use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use logbook_sync::db::Database;
use logbook_sync::qrz::QrzClient;
use logbook_sync::{Config, PotaExporter, SyncOptions, SyncService, WavelogClient};
use std::path::PathBuf;
use tracing::{error, info, warn, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

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

    /// Dry run mode - preview changes without making them
    #[arg(long, global = true)]
    dry_run: bool,

    /// Output logs in JSON format (for log aggregation)
    #[arg(long, global = true)]
    json_logs: bool,

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

    /// Show QSO statistics by source and date
    Stats,

    /// Manually upload specific ADIF file
    Upload {
        /// Path to ADIF file
        file: PathBuf,
    },

    /// Download logs from remote services (QRZ or Wavelog)
    Download {
        /// Source to download from (qrz, wavelog)
        #[arg(long, short, default_value = "qrz")]
        source: String,
    },

    /// Export POTA activation logs
    #[command(name = "pota-export")]
    PotaExport {
        /// Source of QSOs: "database" or path to ADIF file
        #[arg(long, default_value = "database")]
        source: String,

        /// Output directory (overrides config)
        #[arg(long, short)]
        output: Option<PathBuf>,

        /// Filter by date (YYYYMMDD)
        #[arg(long)]
        date: Option<String>,

        /// Filter by park reference (e.g., US-3315)
        #[arg(long)]
        park: Option<String>,
    },

    /// Validate configuration file
    Config {
        /// Only validate, don't show contents
        #[arg(long)]
        validate: bool,
    },

    /// Watch directory and show events (debug mode)
    Watch,

    /// Database maintenance operations
    Db {
        #[command(subcommand)]
        action: DbAction,
    },

    /// Send a test notification via ntfy
    #[command(name = "test-ntfy")]
    TestNtfy {
        /// Custom message to send (optional)
        #[arg(long, short)]
        message: Option<String>,
    },
}

#[derive(Subcommand)]
enum DbAction {
    /// Compact the database (VACUUM)
    Vacuum,
    /// Show database statistics
    Info,
    /// Analyze and optimize query performance
    Optimize,
    /// Export all QSOs to ADIF file
    Export {
        /// Output file path
        #[arg(short, long)]
        output: std::path::PathBuf,
    },
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

    let filter = EnvFilter::from_default_env().add_directive(log_level.into());

    if cli.json_logs {
        // JSON format for log aggregation (Loki, ELK, etc.)
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .init();
    } else {
        // Human-readable format for development
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer())
            .init();
    }

    // Create sync options from CLI flags
    let sync_options = SyncOptions {
        dry_run: cli.dry_run,
    };

    if cli.dry_run {
        warn!("DRY RUN MODE - no changes will be made");
    }

    // Load configuration
    let config = Config::load(&cli.config)
        .with_context(|| format!("Failed to load config from {:?}", cli.config))?;

    match cli.command {
        Commands::Daemon => run_daemon(config, sync_options).await,
        Commands::Sync => run_sync(config, sync_options).await,
        Commands::Status => run_status(config).await,
        Commands::Stats => run_stats(config),
        Commands::Upload { file } => run_upload(config, file, sync_options).await,
        Commands::Download { source } => run_download(config, &source).await,
        Commands::PotaExport {
            source,
            output,
            date,
            park,
        } => run_pota_export(config, &source, output, date, park).await,
        Commands::Config { validate } => run_config_check(config, validate),
        Commands::Watch => run_watch(config).await,
        Commands::Db { action } => run_db_command(config, action),
        Commands::TestNtfy { message } => run_test_ntfy(config, message).await,
    }
}

async fn run_daemon(config: Config, sync_options: SyncOptions) -> Result<()> {
    config.validate()?;

    let db = Database::open(&config.database.path).context("Failed to open database")?;
    let service = SyncService::with_options(config, db, sync_options);

    service.run_daemon().await?;

    Ok(())
}

async fn run_sync(config: Config, sync_options: SyncOptions) -> Result<()> {
    config.validate()?;

    if sync_options.dry_run {
        println!("DRY RUN MODE - no changes will be made\n");
    }
    println!("Running one-time sync...\n");

    let db = Database::open(&config.database.path)?;
    let service = SyncService::with_options(config, db, sync_options);

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

    // Download from QRZ (confirmations)
    println!("\nDownloading from QRZ...");
    let download_stats = service.download_from_qrz().await?;

    println!("QRZ Download:");
    println!("  QSOs fetched:    {}", download_stats.qsos_downloaded);
    println!(
        "  Confirmations:   {}",
        download_stats.confirmations_updated
    );

    println!("\nSync complete!");
    Ok(())
}

async fn run_status(config: Config) -> Result<()> {
    use logbook_sync::adif::parse_adif;
    use logbook_sync::watcher::FileWatcher;

    let db = Database::open(&config.database.path)?;
    let stats = db.get_stats()?;

    println!("Logbook Sync Status");
    println!("===================");
    println!("Callsign: {}", config.general.callsign);

    // Scan watch directory for ADIF files
    println!();
    println!("Watch Directory: {}", config.local.watch_dir.display());

    let watcher = FileWatcher::new(&config);
    let files = watcher.get_existing_files().unwrap_or_default();

    let mut total_file_qsos = 0;
    let mut new_qsos = 0;

    for file in &files {
        if let Ok(content) = std::fs::read_to_string(file) {
            if let Ok(parsed) = parse_adif(&content) {
                total_file_qsos += parsed.qsos.len();
                for qso in &parsed.qsos {
                    if !db.qso_exists(qso).unwrap_or(true) {
                        new_qsos += 1;
                    }
                }
            }
        }
    }

    println!("  ADIF files:      {}", files.len());
    println!("  QSOs in files:   {}", total_file_qsos);
    println!("  Not in database: {}", new_qsos);

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
                    // Calculate potential downloads
                    let local_synced = stats.synced_qrz;
                    if count > local_synced {
                        let potential = count - local_synced;
                        println!(
                            "  Available:    ~{} (QRZ has more than local synced)",
                            potential
                        );
                    }
                }
                if let Some(confirmed) = status.confirmed {
                    println!("  Confirmed:    {}", confirmed);
                    // Check for new confirmations
                    let local_confirmed = stats.lotw_confirmed + stats.qsl_confirmed;
                    if confirmed > local_confirmed {
                        let diff = confirmed - local_confirmed;
                        // If QRZ has more QSOs than local DB, the diff includes confirmations
                        // for QSOs not in local DB - so we can't accurately show "new confirms"
                        let local_synced = stats.synced_qrz;
                        if let Some(count) = status.count {
                            if local_synced >= count {
                                // All QRZ QSOs are local, so all confirmations are actionable
                                println!("  New confirms: ~{} (run 'download' to sync)", diff);
                            }
                            // If local_synced < count, the diff includes non-local QSOs
                            // so we don't show it (would be misleading)
                        } else {
                            println!("  New confirms: ~{} (run 'download' to sync)", diff);
                        }
                    }
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

    // Check Wavelog status if enabled
    if let Some(ref wavelog_config) = config.wavelog {
        if wavelog_config.enabled {
            println!();
            println!("Wavelog ({}):", wavelog_config.base_url);
            match WavelogClient::new(wavelog_config.clone()) {
                Ok(client) => {
                    // Try to get station info
                    match client.get_station_info().await {
                        Ok(stations) => {
                            println!("  Stations:     {}", stations.len());
                            for station in &stations {
                                println!(
                                    "    - {} ({})",
                                    station.station_callsign, station.station_profile_name
                                );
                            }
                        }
                        Err(e) => {
                            println!("  Station info: Error - {}", e);
                        }
                    }

                    // Try to get recent QSO count
                    if wavelog_config.logbook_slug.is_some() {
                        match client.get_recent_qsos(50).await {
                            Ok(response) => {
                                println!("  Recent QSOs:  {} available", response.count);
                                if response.count > 0 {
                                    // Check how many are new
                                    let qsos: Vec<_> = response
                                        .qsos
                                        .into_iter()
                                        .map(|wl| {
                                            let qso: logbook_sync::adif::Qso = wl.into();
                                            qso
                                        })
                                        .collect();
                                    let mut new_count = 0;
                                    for qso in &qsos {
                                        if !db.qso_exists(qso).unwrap_or(true) {
                                            new_count += 1;
                                        }
                                    }
                                    if new_count > 0 {
                                        println!(
                                            "  New QSOs:     {} (run 'download -s wavelog' to sync)",
                                            new_count
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                println!("  Recent QSOs:  Error - {}", e);
                            }
                        }
                    } else {
                        println!("  Recent QSOs:  (logbook_slug not configured)");
                    }
                }
                Err(e) => {
                    println!("  Error: {}", e);
                }
            }
        }
    }

    // POTA summary
    let pota_qsos = db.get_all_qsos().unwrap_or_default();
    let pota_count = pota_qsos
        .iter()
        .filter(|q| {
            q.my_sig
                .as_ref()
                .is_some_and(|s| s.eq_ignore_ascii_case("POTA"))
                && q.my_sig_info.is_some()
        })
        .count();
    if pota_count > 0 {
        println!();
        println!("POTA:");
        println!("  Activation QSOs: {}", pota_count);
        println!("  (run 'pota-export' to generate upload files)");
    }

    Ok(())
}

fn run_stats(config: Config) -> Result<()> {
    let db = Database::open(&config.database.path)?;

    let total = db.get_total_qso_count()?;
    let sources = db.get_source_statistics()?;

    println!("QSO Statistics");
    println!("==============\n");

    println!("Total QSOs: {}\n", total);

    // Source table
    println!("By Source:");
    println!("{:-<30}", "");
    println!("{:<15} {:>10}", "Source", "Count");
    println!("{:-<30}", "");
    for (source, count) in &sources {
        println!("{:<15} {:>10}", source, count);
    }
    println!("{:-<30}", "");

    // Recent dates table for each source
    for (source, _) in &sources {
        let recent_dates = db.get_recent_date_statistics_by_source(source, 10)?;
        if recent_dates.is_empty() {
            continue;
        }

        println!("\nLatest 10 Dates ({}):", source);
        println!("{:-<30}", "");
        println!("{:<15} {:>10}", "Date", "QSOs");
        println!("{:-<30}", "");
        for (date, count) in &recent_dates {
            // Format date from YYYYMMDD to YYYY-MM-DD
            let formatted = if date.len() == 8 {
                format!("{}-{}-{}", &date[0..4], &date[4..6], &date[6..8])
            } else {
                date.clone()
            };
            println!("{:<15} {:>10}", formatted, count);
        }
        println!("{:-<30}", "");
    }

    Ok(())
}

async fn run_upload(config: Config, file: PathBuf, sync_options: SyncOptions) -> Result<()> {
    config.validate()?;

    if !file.exists() {
        anyhow::bail!("File not found: {:?}", file);
    }

    if sync_options.dry_run {
        println!("DRY RUN MODE - no changes will be made\n");
    }
    println!("Processing: {}", file.display());

    let db = Database::open(&config.database.path)?;
    let service = SyncService::with_options(config, db, sync_options);

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

async fn run_download(config: Config, source: &str) -> Result<()> {
    config.validate()?;

    match source.to_lowercase().as_str() {
        "qrz" => run_download_qrz(config).await,
        "wavelog" => run_download_wavelog(config).await,
        "lotw" => run_download_lotw(config).await,
        "eqsl" => run_download_eqsl(config).await,
        _ => {
            anyhow::bail!(
                "Unknown download source: {}. Use 'qrz', 'wavelog', 'lotw', or 'eqsl'",
                source
            );
        }
    }
}

async fn run_download_qrz(config: Config) -> Result<()> {
    use logbook_sync::qso_source;

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

            let mut new_count = 0;
            let mut updated = 0;
            let mut new_confirmations = 0;

            for fetched in &result_qsos {
                // Check if QSO exists locally
                if !db.qso_exists(&fetched.qso)? {
                    // Insert new QSO from QRZ
                    db.insert_qso_with_source(&fetched.qso, qso_source::QRZ, None)?;
                    new_count += 1;
                }

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
            println!("  New QSOs:         {}", new_count);
            println!("  QSOs updated:     {}", updated);
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

async fn run_download_wavelog(config: Config) -> Result<()> {
    use logbook_sync::qso_source;

    let wavelog_config = config
        .wavelog
        .as_ref()
        .filter(|w| w.enabled)
        .ok_or_else(|| anyhow::anyhow!("Wavelog is not configured or not enabled"))?;

    println!("Downloading from Wavelog...\n");
    println!("  URL: {}", wavelog_config.base_url);

    let client = WavelogClient::new(wavelog_config.clone())
        .map_err(|e| anyhow::anyhow!("Failed to create Wavelog client: {}", e))?;

    // Get station info first
    match client.get_station_info().await {
        Ok(stations) => {
            println!("\nStation Profiles:");
            for station in &stations {
                println!(
                    "  {} ({}) - {}",
                    station.station_callsign, station.station_id, station.station_profile_name
                );
            }
        }
        Err(e) => {
            println!("  Warning: Could not fetch station info: {}", e);
        }
    }

    // Open database
    let db = Database::open(&config.database.path)?;

    // Get last fetched ID for incremental sync
    let fetch_from_id = db.get_wavelog_last_fetched_id()?;

    // Download QSOs using the get_contacts_adif API
    println!("\nDownloading QSOs via API...");
    if fetch_from_id > 0 {
        println!("  Incremental sync from ID: {}", fetch_from_id);
    } else {
        println!("  Full sync (fetching all QSOs)");
    }

    let api_response = client
        .get_contacts_adif(fetch_from_id)
        .await
        .map_err(|e| anyhow::anyhow!("ADIF download failed: {}", e))?;

    let adif_content = &api_response.adif;
    let new_last_fetched_id = api_response.lastfetchedid;

    // Parse the ADIF content
    use logbook_sync::adif::parse_adif;
    let qsos: Vec<logbook_sync::adif::Qso> =
        if adif_content.contains("<EOH>") || adif_content.contains("<eoh>") {
            let record = parse_adif(adif_content)
                .map_err(|e| anyhow::anyhow!("Failed to parse ADIF: {}", e))?;
            println!("Downloaded {} QSOs", record.qsos.len());
            record.qsos
        } else {
            println!("No QSOs returned (empty ADIF)");
            Vec::new()
        };

    if qsos.is_empty() {
        println!("\nNo new QSOs to download");
        // Still update the last fetched ID
        if new_last_fetched_id > fetch_from_id {
            db.set_wavelog_last_fetched_id(new_last_fetched_id)?;
        }
        return Ok(());
    }

    // Save to database with source tracking
    let mut new_count = 0;
    let mut dup_count = 0;

    for qso in &qsos {
        if db.qso_exists(qso)? {
            dup_count += 1;
        } else {
            db.insert_qso_with_source(qso, qso_source::WAVELOG, None)?;
            new_count += 1;
        }
    }

    // Update the last fetched ID for next incremental sync
    db.set_wavelog_last_fetched_id(new_last_fetched_id)?;

    println!("\nResults:");
    println!("  New QSOs:         {}", new_count);
    println!("  Duplicates:       {}", dup_count);
    println!("  Last fetched ID:  {}", new_last_fetched_id);

    // Save to ADIF file
    if new_count > 0 {
        use logbook_sync::adif::write_adif;

        let adif_content = write_adif(None, &qsos);

        let date_str = chrono::Utc::now().format("%Y%m%d").to_string();
        let output_path = config
            .local
            .output_dir
            .join(format!("wavelog_download_{}.adi", date_str));

        std::fs::create_dir_all(&config.local.output_dir)?;
        std::fs::write(&output_path, adif_content)?;
        println!("  Saved to:         {}", output_path.display());
    }

    Ok(())
}

async fn run_download_lotw(config: Config) -> Result<()> {
    use logbook_sync::qso_source;
    use logbook_sync::LotwClient;

    let lotw_config = config
        .lotw
        .as_ref()
        .filter(|l| l.enabled && l.download)
        .ok_or_else(|| {
            anyhow::anyhow!("LoTW is not configured, not enabled, or download is disabled")
        })?;

    println!("Downloading confirmations from LoTW...\n");

    let client = LotwClient::new(lotw_config.clone())
        .map_err(|e| anyhow::anyhow!("Failed to create LoTW client: {}", e))?;

    // Open database to get last download date
    let db = Database::open(&config.database.path)?;

    // Get last download date from sync state
    let since_date = db.get_sync_state("lotw_last_download")?;
    if let Some(ref date) = since_date {
        println!("  Fetching confirmations since: {}", date);
    } else {
        println!("  Fetching all confirmations (first sync)");
    }

    let confirmations = client
        .download_confirmations(since_date.as_deref())
        .await
        .map_err(|e| anyhow::anyhow!("LoTW download failed: {}", e))?;

    println!("\nDownloaded {} confirmation(s)", confirmations.len());

    if confirmations.is_empty() {
        println!("No new confirmations from LoTW");
        return Ok(());
    }

    // Update confirmation status in local database
    let mut updated_count = 0;
    let mut new_count = 0;

    for conf in &confirmations {
        // Try to update existing QSO confirmation status
        let updated = db.update_confirmation(
            &conf.qso.call,
            &conf.qso.qso_date,
            &conf.qso.time_on,
            &conf.qso.band,
            &conf.qso.mode,
            Some("Y"), // lotw_qsl_rcvd
            None,      // lotw_qsl_sent
            None,      // qsl_rcvd
            None,      // qsl_sent
        )?;

        if updated {
            updated_count += 1;
        } else {
            // QSO doesn't exist locally, insert it with source tracking
            db.insert_qso_with_source(&conf.qso, qso_source::LOTW, None)?;
            new_count += 1;
        }
    }

    // Update the last download date
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    db.set_sync_state("lotw_last_download", &today)?;

    println!("\nResults:");
    println!("  Confirmations updated: {}", updated_count);
    println!("  New QSOs imported:     {}", new_count);
    println!("  Last sync date saved:  {}", today);

    // Save to ADIF file if there are new confirmations
    if !confirmations.is_empty() {
        use logbook_sync::adif::write_adif;

        let qsos: Vec<_> = confirmations.iter().map(|c| c.qso.clone()).collect();
        let adif_content = write_adif(None, &qsos);

        let date_str = chrono::Utc::now().format("%Y%m%d").to_string();
        let output_path = config
            .local
            .output_dir
            .join(format!("lotw_confirmations_{}.adi", date_str));

        std::fs::create_dir_all(&config.local.output_dir)?;
        std::fs::write(&output_path, adif_content)?;
        println!("  Saved to:              {}", output_path.display());
    }

    Ok(())
}

async fn run_download_eqsl(config: Config) -> Result<()> {
    use logbook_sync::qso_source;
    use logbook_sync::EqslClient;

    let eqsl_config = config
        .eqsl
        .as_ref()
        .filter(|e| e.enabled && e.download)
        .ok_or_else(|| {
            anyhow::anyhow!("eQSL is not configured, not enabled, or download is disabled")
        })?;

    println!("Downloading confirmations from eQSL...\n");
    println!("  Note: Full confirmation download requires AG membership");

    let client = EqslClient::new(eqsl_config.clone())
        .map_err(|e| anyhow::anyhow!("Failed to create eQSL client: {}", e))?;

    // Open database
    let db = Database::open(&config.database.path)?;

    // Get last download date from sync state
    let since_date = db.get_sync_state("eqsl_last_download")?;
    if let Some(ref date) = since_date {
        println!("  Fetching confirmations since: {}", date);
    } else {
        println!("  Fetching all confirmations (first sync)");
    }

    let confirmations = client
        .download_confirmations(since_date.as_deref())
        .await
        .map_err(|e| anyhow::anyhow!("eQSL download failed: {}", e))?;

    println!("\nDownloaded {} confirmation(s)", confirmations.len());

    if confirmations.is_empty() {
        println!("No new confirmations from eQSL");
        return Ok(());
    }

    // Update confirmation status in local database
    let mut updated_count = 0;
    let mut new_count = 0;

    for conf in &confirmations {
        // Try to update existing QSO confirmation status
        let updated = db.update_confirmation(
            &conf.qso.call,
            &conf.qso.qso_date,
            &conf.qso.time_on,
            &conf.qso.band,
            &conf.qso.mode,
            None,      // lotw_qsl_rcvd
            None,      // lotw_qsl_sent
            Some("Y"), // qsl_rcvd (eQSL uses this field)
            None,      // qsl_sent
        )?;

        if updated {
            updated_count += 1;
        } else {
            // QSO doesn't exist locally, insert it with source tracking
            db.insert_qso_with_source(&conf.qso, qso_source::EQSL, None)?;
            new_count += 1;
        }
    }

    // Update the last download date
    let today = chrono::Utc::now().format("%Y%m%d").to_string();
    db.set_sync_state("eqsl_last_download", &today)?;

    println!("\nResults:");
    println!("  Confirmations updated: {}", updated_count);
    println!("  New QSOs imported:     {}", new_count);
    println!("  Last sync date saved:  {}", today);

    // Save to ADIF file if there are new confirmations
    if !confirmations.is_empty() {
        use logbook_sync::adif::write_adif;

        let qsos: Vec<_> = confirmations.iter().map(|c| c.qso.clone()).collect();
        let adif_content = write_adif(None, &qsos);

        let date_str = chrono::Utc::now().format("%Y%m%d").to_string();
        let output_path = config
            .local
            .output_dir
            .join(format!("eqsl_confirmations_{}.adi", date_str));

        std::fs::create_dir_all(&config.local.output_dir)?;
        std::fs::write(&output_path, adif_content)?;
        println!("  Saved to:              {}", output_path.display());
    }

    Ok(())
}

async fn run_pota_export(
    config: Config,
    source: &str,
    output: Option<PathBuf>,
    date_filter: Option<String>,
    park_filter: Option<String>,
) -> Result<()> {
    use logbook_sync::adif::parse_adif;

    // Determine output directory
    let output_dir = output
        .or_else(|| config.pota.output_dir.clone())
        .unwrap_or_else(|| config.local.output_dir.join("pota"));

    println!("POTA Export");
    println!("===========");
    println!("Output directory: {}", output_dir.display());

    // Load QSOs from source
    let qsos = match source.to_lowercase().as_str() {
        "database" => {
            println!("Source: local database");
            let db = Database::open(&config.database.path)?;
            db.get_all_qsos()?
        }
        path => {
            // Treat as ADIF file path
            let file_path = PathBuf::from(path);
            if !file_path.exists() {
                anyhow::bail!("ADIF file not found: {}", path);
            }
            println!("Source: {}", path);
            let content = std::fs::read_to_string(&file_path)?;
            let parsed = parse_adif(&content)?;
            parsed.qsos
        }
    };

    println!("Total QSOs loaded: {}", qsos.len());

    // Apply filters
    let filtered_qsos: Vec<_> = qsos
        .into_iter()
        .filter(|q| {
            // Must be a POTA QSO
            if !PotaExporter::is_pota_qso(q) {
                return false;
            }

            // Date filter
            if let Some(ref d) = date_filter {
                let normalized = q.qso_date.replace('-', "");
                let filter_normalized = d.replace('-', "");
                if !normalized.starts_with(&filter_normalized) {
                    return false;
                }
            }

            // Park filter
            if let Some(ref p) = park_filter {
                if let Some(ref qp) = q.my_sig_info {
                    if !qp.eq_ignore_ascii_case(p) {
                        return false;
                    }
                } else {
                    return false;
                }
            }

            true
        })
        .collect();

    let pota_count = filtered_qsos.len();
    println!("POTA QSOs to export: {}", pota_count);

    if pota_count == 0 {
        println!("\nNo POTA QSOs found matching the criteria.");
        return Ok(());
    }

    // Export
    let exporter = PotaExporter::new(output_dir, config.general.callsign.clone());
    let files = exporter.export(&filtered_qsos)?;

    println!("\nCreated {} POTA export file(s):", files.len());
    for f in &files {
        println!("  {}", f.display());
    }

    info!(
        files = files.len(),
        qsos = pota_count,
        "POTA export complete"
    );

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

/// Database maintenance commands
fn run_db_command(config: Config, action: DbAction) -> Result<()> {
    let db = Database::open(&config.database.path)?;

    match action {
        DbAction::Vacuum => {
            println!("Compacting database...");
            let before = db.file_size()?;
            db.vacuum()?;
            let after = db.file_size()?;
            let saved = before.saturating_sub(after);
            println!("Done!");
            println!("  Before: {} bytes", before);
            println!("  After:  {} bytes", after);
            if saved > 0 {
                println!("  Saved:  {} bytes", saved);
            }
        }
        DbAction::Info => {
            let info = db.detailed_info()?;
            let stats = db.get_stats()?;
            let integrity = db.integrity_check()?;

            println!("Database Information");
            println!("====================\n");

            println!("Location: {}", config.database.path.display());
            println!();

            println!("Storage:");
            println!(
                "  Total size:     {} bytes ({:.2} KB)",
                info.total_size,
                info.total_size as f64 / 1024.0
            );
            println!("  Page size:      {} bytes", info.page_size);
            println!("  Page count:     {}", info.page_count);
            println!("  Freelist pages: {}", info.freelist_count);
            println!("  Wasted space:   {} bytes", info.wasted_space);
            println!("  Journal mode:   {}", info.journal_mode);
            println!();

            println!("Schema:");
            println!("  Schema version: {}", info.schema_version);
            println!("  User version:   {}", info.user_version);
            println!();

            println!("Contents:");
            println!("  Total QSOs:      {}", stats.total_qsos);
            println!("  Synced to QRZ:   {}", stats.synced_qrz);
            println!("  Pending upload:  {}", stats.pending_qrz);
            println!("  LotW confirmed:  {}", stats.lotw_confirmed);
            println!("  QSL confirmed:   {}", stats.qsl_confirmed);
            println!("  Files processed: {}", stats.processed_files);
            println!();

            println!("Integrity: {}", integrity);
        }
        DbAction::Optimize => {
            println!("Optimizing database...");

            // First vacuum
            println!("  Running VACUUM...");
            let before = db.file_size()?;
            db.vacuum()?;
            let after = db.file_size()?;

            // Then analyze
            println!("  Running ANALYZE...");
            db.analyze()?;

            println!("Done!");
            let saved = before.saturating_sub(after);
            if saved > 0 {
                println!("  Space recovered: {} bytes", saved);
            }
            println!("  Query statistics updated");
        }
        DbAction::Export { output } => {
            use logbook_sync::adif::write_adif;

            println!("Exporting all QSOs to ADIF...");
            let qsos = db.get_all_qsos()?;

            if qsos.is_empty() {
                println!("No QSOs in database");
                return Ok(());
            }

            let adif_content = write_adif(None, &qsos);

            // Create parent directory if needed
            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }

            std::fs::write(&output, adif_content)?;

            println!("Done!");
            println!("  QSOs exported: {}", qsos.len());
            println!("  Output file:   {}", output.display());
        }
    }

    Ok(())
}

/// Test ntfy notifications
async fn run_test_ntfy(config: Config, custom_message: Option<String>) -> Result<()> {
    use logbook_sync::NtfyClient;

    let ntfy_config = config
        .ntfy
        .as_ref()
        .filter(|n| n.enabled)
        .ok_or_else(|| anyhow::anyhow!("ntfy is not configured or not enabled"))?;

    println!("Testing ntfy notifications...\n");
    println!("  Server: {}", ntfy_config.server);
    println!("  Topic:  {}", ntfy_config.topic);

    let client = NtfyClient::new(ntfy_config.clone());

    let title = format!("Test from {}", config.general.callsign);
    let message = custom_message.unwrap_or_else(|| {
        format!(
            "This is a test notification from logbook-sync for {}",
            config.general.callsign
        )
    });

    println!("\nSending notification...");
    client.send(&title, &message).await?;

    println!("Success! Check your ntfy client for the notification.");
    Ok(())
}
