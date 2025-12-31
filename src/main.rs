use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use logbook_sync::Config;
use logbook_sync::crypto::MasterKey;
use logbook_sync::db::{Database, users};
use std::path::PathBuf;
use tracing::Level;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "logbook-sync")]
#[command(about = "Amateur radio logbook web application")]
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

    /// Output logs in JSON format (for log aggregation)
    #[arg(long, global = true)]
    json_logs: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the web server
    Web {
        /// Override bind address (default from config or 127.0.0.1:3000)
        #[arg(long)]
        bind: Option<String>,
    },

    /// Database maintenance operations
    Db {
        #[command(subcommand)]
        action: DbAction,
    },

    /// Add a new user
    UserAdd {
        /// Username (required)
        #[arg(long)]
        username: String,

        /// Email address (optional)
        #[arg(long)]
        email: Option<String>,

        /// Amateur radio callsign
        #[arg(long)]
        callsign: Option<String>,

        /// Make this user an admin
        #[arg(long)]
        admin: bool,

        /// Password (if not provided, will prompt interactively)
        #[arg(long, env = "LOGBOOK_SYNC_PASSWORD")]
        password: Option<String>,
    },

    /// Remove a user
    UserRemove {
        /// Username to remove
        username: String,

        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },

    /// List all users
    UserList {
        /// Output format (table, json, csv)
        #[arg(long, default_value = "table")]
        format: String,
    },

    /// Reset a user's password
    UserResetPw {
        /// Username
        username: String,
    },

    /// Enable/disable a user
    UserSetActive {
        /// Username
        username: String,

        /// Active status
        #[arg(long)]
        active: bool,
    },

    /// Generate a new master encryption key
    GenerateMasterKey {
        /// Output format (hex or base64)
        #[arg(long, default_value = "base64")]
        format: String,
    },

    /// Validate configuration file
    Config,
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
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer())
            .init();
    }

    // Load configuration
    let config = Config::load(&cli.config)
        .with_context(|| format!("Failed to load config from {:?}", cli.config))?;

    match cli.command {
        Commands::Web { bind } => run_web_server(config, bind).await,
        Commands::Db { action } => run_db_command(config, action),
        Commands::UserAdd {
            username,
            email,
            callsign,
            admin,
            password,
        } => run_user_add(&config, username, email, callsign, admin, password),
        Commands::UserRemove { username, force } => run_user_remove(&config, &username, force),
        Commands::UserList { format } => run_user_list(&config, &format),
        Commands::UserResetPw { username } => run_user_reset_pw(&config, &username),
        Commands::UserSetActive { username, active } => {
            run_user_set_active(&config, &username, active)
        }
        Commands::GenerateMasterKey { format } => {
            run_generate_master_key(&format);
            Ok(())
        }
        Commands::Config => run_config_check(config),
    }
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

            println!("  Running VACUUM...");
            let before = db.file_size()?;
            db.vacuum()?;
            let after = db.file_size()?;

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

fn run_config_check(config: Config) -> Result<()> {
    println!("Configuration:");
    println!("  Database: {:?}", config.database.path);
    println!(
        "  Server:   {}:{}",
        config.server.bind_address, config.server.port
    );
    println!("  Log level: {}", config.general.log_level);
    println!("\nConfiguration is valid");
    Ok(())
}

// === User Management Commands ===

fn run_user_add(
    config: &Config,
    username: String,
    email: Option<String>,
    callsign: Option<String>,
    admin: bool,
    password_arg: Option<String>,
) -> Result<()> {
    use rusqlite::Connection;

    let password = if let Some(pw) = password_arg {
        if pw.len() < 12 {
            anyhow::bail!("Password must be at least 12 characters");
        }
        pw
    } else {
        let password = rpassword::prompt_password("Enter password: ")?;
        let confirm = rpassword::prompt_password("Confirm password: ")?;

        if password != confirm {
            anyhow::bail!("Passwords do not match");
        }

        if password.len() < 12 {
            anyhow::bail!("Password must be at least 12 characters");
        }
        password
    };

    let conn = Connection::open(&config.database.path)?;

    let user = users::create_user(
        &conn,
        users::CreateUser {
            username: username.clone(),
            password,
            email,
            callsign,
            is_admin: admin,
        },
    )?;

    println!("Created user '{}' (ID: {})", user.username, user.id);
    if admin {
        println!("  -> User has admin privileges");
    }

    Ok(())
}

fn run_user_list(config: &Config, format: &str) -> Result<()> {
    use rusqlite::Connection;

    let conn = Connection::open(&config.database.path)?;
    let users_list = users::list_users(&conn)?;

    match format {
        "json" => {
            #[derive(serde::Serialize)]
            struct UserOutput {
                id: i64,
                username: String,
                email: Option<String>,
                callsign: Option<String>,
                is_admin: bool,
                is_active: bool,
                last_login: Option<String>,
            }

            let output: Vec<_> = users_list
                .iter()
                .map(|u| UserOutput {
                    id: u.id,
                    username: u.username.clone(),
                    email: u.email.clone(),
                    callsign: u.callsign.clone(),
                    is_admin: u.is_admin,
                    is_active: u.is_active,
                    last_login: u.last_login_at.clone(),
                })
                .collect();

            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        "csv" => {
            println!("id,username,email,callsign,is_admin,is_active,last_login");
            for u in users_list {
                println!(
                    "{},{},{},{},{},{},{}",
                    u.id,
                    u.username,
                    u.email.unwrap_or_default(),
                    u.callsign.unwrap_or_default(),
                    u.is_admin,
                    u.is_active,
                    u.last_login_at.unwrap_or_default(),
                );
            }
        }
        _ => {
            println!(
                "{:<5} {:<20} {:<30} {:<10} {:<6} {:<6}",
                "ID", "Username", "Email", "Callsign", "Admin", "Active"
            );
            println!("{}", "-".repeat(80));
            for u in users_list {
                println!(
                    "{:<5} {:<20} {:<30} {:<10} {:<6} {:<6}",
                    u.id,
                    u.username,
                    u.email.unwrap_or("-".into()),
                    u.callsign.unwrap_or("-".into()),
                    if u.is_admin { "yes" } else { "no" },
                    if u.is_active { "yes" } else { "no" },
                );
            }
        }
    }

    Ok(())
}

fn run_user_remove(config: &Config, username: &str, force: bool) -> Result<()> {
    use rusqlite::Connection;
    use std::io::Write;

    let conn = Connection::open(&config.database.path)?;
    let user = users::get_user_by_username(&conn, username)?
        .ok_or_else(|| anyhow::anyhow!("User '{}' not found", username))?;

    if !force {
        print!(
            "Are you sure you want to delete user '{}' and ALL their data? [y/N] ",
            username
        );
        std::io::stdout().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Cancelled.");
            return Ok(());
        }
    }

    users::delete_user(&conn, user.id)?;
    println!("Deleted user '{}'", username);

    Ok(())
}

fn run_user_reset_pw(config: &Config, username: &str) -> Result<()> {
    use rusqlite::Connection;

    let conn = Connection::open(&config.database.path)?;
    let user = users::get_user_by_username(&conn, username)?
        .ok_or_else(|| anyhow::anyhow!("User '{}' not found", username))?;

    let password = rpassword::prompt_password("Enter new password: ")?;
    let confirm = rpassword::prompt_password("Confirm new password: ")?;

    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }

    if password.len() < 12 {
        anyhow::bail!("Password must be at least 12 characters");
    }

    users::update_password(&conn, user.id, &password)?;
    println!("Password updated for user '{}'", username);

    Ok(())
}

fn run_user_set_active(config: &Config, username: &str, active: bool) -> Result<()> {
    use rusqlite::Connection;

    let conn = Connection::open(&config.database.path)?;
    let user = users::get_user_by_username(&conn, username)?
        .ok_or_else(|| anyhow::anyhow!("User '{}' not found", username))?;

    if active {
        users::activate_user(&conn, user.id)?;
        println!("User '{}' activated", username);
    } else {
        users::deactivate_user(&conn, user.id)?;
        println!("User '{}' deactivated", username);
    }

    Ok(())
}

fn run_generate_master_key(format: &str) {
    let key = MasterKey::generate();

    match format {
        "hex" => println!("{}", key.to_hex()),
        _ => println!("{}", key.to_base64()),
    }

    eprintln!("\nStore this key securely! You can set it via:");
    eprintln!("  Environment: LOGBOOK_SYNC_MASTER_KEY=<key>");
    eprintln!("  Or file: /etc/logbook-sync/master.key (chmod 600)");
}

async fn run_web_server(config: Config, bind_override: Option<String>) -> Result<()> {
    use logbook_sync::{start_sync_workers, web};
    use std::sync::Arc;

    let master_key = MasterKey::from_env().context(
        "LOGBOOK_SYNC_MASTER_KEY environment variable not set or invalid. \
         Generate one with: logbook-sync generate-master-key",
    )?;

    let bind = bind_override.unwrap_or_else(|| config.bind_address());

    println!("Starting web server on {}", bind);
    println!("Database: {}", config.database.path.display());

    // Start background sync workers
    // Check if POTA auth service is configured (used by both sync workers and web endpoints)
    let pota_auth_config = if config.pota_auth_service.is_configured() {
        println!(
            "POTA auth service configured: {}",
            config.pota_auth_service.url
        );
        Some(config.pota_auth_service.clone())
    } else {
        println!("POTA auth service not configured, using local browser");
        None
    };

    if config.sync.enabled {
        println!(
            "Starting background sync workers ({} threads)",
            config.sync.worker_threads
        );
        let master_key_arc = Arc::new(master_key.clone());
        start_sync_workers(
            config.database.path.clone(),
            master_key_arc,
            config.sync.clone(),
            pota_auth_config.clone(),
        )
        .await;
    } else {
        println!("Background sync is disabled");
    }

    web::serve(
        config.database.path,
        master_key,
        config.sync,
        pota_auth_config,
        &bind,
    )
    .await
    .context("Web server error")?;

    Ok(())
}
