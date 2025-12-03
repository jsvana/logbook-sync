use crate::wavelog::WavelogConfig;
use serde::Deserialize;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub general: GeneralConfig,
    pub local: LocalConfig,
    pub qrz: QrzConfig,
    #[serde(default)]
    pub pota: PotaConfig,
    #[serde(default)]
    pub wavelog: Option<WavelogConfig>,
    #[serde(default)]
    pub lotw: Option<LotwConfig>,
    #[serde(default)]
    pub eqsl: Option<EqslConfig>,
    #[serde(default)]
    pub clublog: Option<ClublogConfig>,
    #[serde(default)]
    pub hrdlog: Option<HrdlogConfig>,
    #[serde(default)]
    pub ntfy: Option<NtfyConfig>,
    #[serde(default)]
    pub resilience: ResilienceConfig,
    #[serde(default)]
    pub server: Option<ServerConfig>,
    pub database: DatabaseConfig,
}

/// Configuration for the HTTP server (health checks and metrics)
#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    /// Whether the HTTP server is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Port to listen on
    #[serde(default = "default_server_port")]
    pub port: u16,
    /// Address to bind to
    #[serde(default = "default_bind_address")]
    pub bind_address: IpAddr,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: default_server_port(),
            bind_address: default_bind_address(),
        }
    }
}

fn default_server_port() -> u16 {
    9090
}

fn default_bind_address() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}

/// Configuration for retry and resilience behavior
#[derive(Debug, Deserialize, Clone)]
pub struct ResilienceConfig {
    /// Maximum retry attempts for transient failures
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Initial backoff delay in milliseconds
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: u64,
    /// Maximum backoff delay in milliseconds
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: u64,
    /// Backoff multiplier (exponential)
    #[serde(default = "default_backoff_multiplier")]
    pub backoff_multiplier: f64,
    /// Whether to add jitter to backoff delays
    #[serde(default = "default_true")]
    pub jitter: bool,
    /// Alert after this many consecutive failures
    #[serde(default = "default_consecutive_failures_alert")]
    pub consecutive_failures_alert: u32,
    /// Alert if no successful sync in this many hours
    #[serde(default = "default_stale_sync_hours")]
    pub stale_sync_hours: u32,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            initial_backoff_ms: default_initial_backoff_ms(),
            max_backoff_ms: default_max_backoff_ms(),
            backoff_multiplier: default_backoff_multiplier(),
            jitter: true,
            consecutive_failures_alert: default_consecutive_failures_alert(),
            stale_sync_hours: default_stale_sync_hours(),
        }
    }
}

fn default_max_retries() -> u32 {
    5
}

fn default_initial_backoff_ms() -> u64 {
    1000
}

fn default_max_backoff_ms() -> u64 {
    60000
}

fn default_backoff_multiplier() -> f64 {
    2.0
}

fn default_consecutive_failures_alert() -> u32 {
    3
}

fn default_stale_sync_hours() -> u32 {
    24
}

/// Configuration for ntfy.sh notifications
#[derive(Debug, Deserialize, Clone)]
pub struct NtfyConfig {
    /// Whether ntfy notifications are enabled
    #[serde(default)]
    pub enabled: bool,
    /// The ntfy server URL (default: https://ntfy.sh)
    #[serde(default = "default_ntfy_server")]
    pub server: String,
    /// The topic to publish to
    pub topic: String,
    /// Optional authentication token
    pub token: Option<String>,
    /// Priority level (1-5, default 3)
    #[serde(default = "default_ntfy_priority")]
    pub priority: u8,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GeneralConfig {
    pub callsign: String,
    #[serde(default = "default_sync_interval")]
    pub sync_interval: u64,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LocalConfig {
    pub watch_dir: PathBuf,
    pub output_dir: PathBuf,
    #[serde(default = "default_patterns")]
    pub patterns: Vec<String>,
    #[serde(default = "default_debounce_secs")]
    pub debounce_secs: u64,
    #[serde(default = "default_true")]
    pub process_existing: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct QrzConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub api_key: String,
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    #[serde(default = "default_true")]
    pub upload: bool,
    #[serde(default = "default_true")]
    pub download: bool,
    #[serde(default = "default_download_interval")]
    pub download_interval: u64,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct PotaConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Directory for POTA export files
    pub output_dir: Option<PathBuf>,
    /// Directory for importing POTA CSV files (future feature)
    pub import_dir: Option<PathBuf>,
    #[serde(default)]
    pub auto_import_csv: bool,
}

/// Configuration for LoTW (Logbook of The World) integration
#[derive(Debug, Deserialize, Clone, Default)]
pub struct LotwConfig {
    /// Whether LoTW integration is enabled
    #[serde(default)]
    pub enabled: bool,
    /// LoTW username (your callsign)
    pub username: Option<String>,
    /// LoTW password
    pub password: Option<String>,
    /// Your callsign for LoTW queries
    pub callsign: Option<String>,
    /// Path to TQSL executable (for uploads)
    pub tqsl_path: Option<String>,
    /// TQSL station location name
    pub station_location: Option<String>,
    /// Whether to upload to LoTW (requires TQSL)
    #[serde(default)]
    pub upload: bool,
    /// Whether to download confirmations from LoTW
    #[serde(default = "default_true")]
    pub download: bool,
    /// Interval between confirmation downloads in seconds (default: 1 day)
    #[serde(default = "default_lotw_download_interval")]
    pub download_interval: u64,
}

fn default_lotw_download_interval() -> u64 {
    86400 // 1 day
}

/// Configuration for eQSL.cc integration
#[derive(Debug, Deserialize, Clone, Default)]
pub struct EqslConfig {
    /// Whether eQSL integration is enabled
    #[serde(default)]
    pub enabled: bool,
    /// eQSL username (your callsign)
    pub username: Option<String>,
    /// eQSL password
    pub password: Option<String>,
    /// QTH nickname (optional, for multi-location stations)
    pub qth_nickname: Option<String>,
    /// Whether to upload to eQSL
    #[serde(default)]
    pub upload: bool,
    /// Whether to download confirmations from eQSL (requires AG membership)
    #[serde(default)]
    pub download: bool,
    /// Interval between confirmation downloads in seconds (default: 1 day)
    #[serde(default = "default_eqsl_download_interval")]
    pub download_interval: u64,
}

fn default_eqsl_download_interval() -> u64 {
    86400 // 1 day
}

/// Configuration for ClubLog integration
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ClublogConfig {
    /// Whether ClubLog integration is enabled
    #[serde(default)]
    pub enabled: bool,
    /// ClubLog email address (not callsign)
    pub email: Option<String>,
    /// ClubLog application password
    pub password: Option<String>,
    /// Your callsign for uploads
    pub callsign: String,
    /// ClubLog API key (obtain from ClubLog support)
    pub api_key: Option<String>,
}

/// Configuration for HRDLog.net integration
#[derive(Debug, Deserialize, Clone, Default)]
pub struct HrdlogConfig {
    /// Whether HRDLog integration is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Your callsign for uploads
    pub callsign: String,
    /// HRDLog upload code (not your password)
    pub upload_code: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub path: PathBuf,
}

fn default_sync_interval() -> u64 {
    300
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_patterns() -> Vec<String> {
    vec!["*.adi".to_string(), "*.adif".to_string()]
}

fn default_debounce_secs() -> u64 {
    5
}

fn default_true() -> bool {
    true
}

fn default_user_agent() -> String {
    "LogbookSync/0.1.0".to_string()
}

fn default_download_interval() -> u64 {
    3600
}

fn default_ntfy_server() -> String {
    "https://ntfy.sh".to_string()
}

fn default_ntfy_priority() -> u8 {
    3
}

impl Config {
    pub fn load(path: &std::path::Path) -> crate::Result<Self> {
        let settings = config::Config::builder()
            .add_source(config::File::from(path))
            .add_source(
                config::Environment::with_prefix("ADIF_SYNC")
                    .separator("_")
                    .try_parsing(true),
            )
            .build()?;

        let mut config: Config = settings.try_deserialize()?;

        // Override API key from environment if set
        if let Ok(key) = std::env::var("ADIF_SYNC_QRZ_API_KEY") {
            config.qrz.api_key = key;
        }

        // Update user agent with callsign
        if !config.qrz.user_agent.contains(&config.general.callsign) {
            config.qrz.user_agent = format!("LogbookSync/0.1.0 ({})", config.general.callsign);
        }

        Ok(config)
    }

    pub fn validate(&self) -> crate::Result<()> {
        if self.general.callsign.is_empty() {
            return Err(crate::Error::Config(config::ConfigError::Message(
                "callsign is required".to_string(),
            )));
        }

        if !self.local.watch_dir.exists() {
            return Err(crate::Error::Config(config::ConfigError::Message(format!(
                "watch_dir does not exist: {:?}",
                self.local.watch_dir
            ))));
        }

        if self.qrz.enabled && self.qrz.api_key.is_empty() {
            return Err(crate::Error::Config(config::ConfigError::Message(
                "QRZ API key is required when QRZ sync is enabled".to_string(),
            )));
        }

        Ok(())
    }
}
