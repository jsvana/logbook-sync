use serde::Deserialize;
use std::net::IpAddr;
use std::path::PathBuf;

/// Server-level configuration (not per-user settings)
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub database: DatabaseConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub resilience: ResilienceConfig,
    #[serde(default)]
    pub sync: SyncConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub path: PathBuf,
}

/// Configuration for the HTTP server
#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
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
            port: default_server_port(),
            bind_address: default_bind_address(),
        }
    }
}

fn default_server_port() -> u16 {
    3000
}

fn default_bind_address() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}

/// General server settings
#[derive(Debug, Deserialize, Clone)]
pub struct GeneralConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
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
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            initial_backoff_ms: default_initial_backoff_ms(),
            max_backoff_ms: default_max_backoff_ms(),
            backoff_multiplier: default_backoff_multiplier(),
            jitter: true,
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

fn default_true() -> bool {
    true
}

/// Configuration for background sync intervals (in seconds)
#[derive(Debug, Deserialize, Clone)]
pub struct SyncConfig {
    /// Whether background sync is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Number of worker threads for background sync
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,
    /// QRZ sync interval in seconds (default: 15 minutes)
    #[serde(default = "default_qrz_interval")]
    pub qrz_interval_secs: u64,
    /// LoFi sync interval in seconds (default: 5 minutes)
    #[serde(default = "default_lofi_interval")]
    pub lofi_interval_secs: u64,
    /// LotW sync interval in seconds (default: 1 hour)
    #[serde(default = "default_lotw_interval")]
    pub lotw_interval_secs: u64,
    /// eQSL sync interval in seconds (default: 30 minutes)
    #[serde(default = "default_eqsl_interval")]
    pub eqsl_interval_secs: u64,
    /// ClubLog sync interval in seconds (default: 30 minutes)
    #[serde(default = "default_clublog_interval")]
    pub clublog_interval_secs: u64,
    /// HRDLog sync interval in seconds (default: 30 minutes)
    #[serde(default = "default_hrdlog_interval")]
    pub hrdlog_interval_secs: u64,
    /// Wavelog sync interval in seconds (default: 10 minutes)
    #[serde(default = "default_wavelog_interval")]
    pub wavelog_interval_secs: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            worker_threads: default_worker_threads(),
            qrz_interval_secs: default_qrz_interval(),
            lofi_interval_secs: default_lofi_interval(),
            lotw_interval_secs: default_lotw_interval(),
            eqsl_interval_secs: default_eqsl_interval(),
            clublog_interval_secs: default_clublog_interval(),
            hrdlog_interval_secs: default_hrdlog_interval(),
            wavelog_interval_secs: default_wavelog_interval(),
        }
    }
}

impl SyncConfig {
    /// Get the sync interval for a given integration type
    pub fn interval_for(&self, integration_type: &str) -> u64 {
        match integration_type {
            "qrz" => self.qrz_interval_secs,
            "lofi" => self.lofi_interval_secs,
            "lotw" => self.lotw_interval_secs,
            "eqsl" => self.eqsl_interval_secs,
            "clublog" => self.clublog_interval_secs,
            "hrdlog" => self.hrdlog_interval_secs,
            "wavelog" => self.wavelog_interval_secs,
            _ => 900, // Default 15 minutes for unknown types
        }
    }
}

fn default_worker_threads() -> usize {
    2
}

fn default_qrz_interval() -> u64 {
    900 // 15 minutes
}

fn default_lofi_interval() -> u64 {
    300 // 5 minutes
}

fn default_lotw_interval() -> u64 {
    3600 // 1 hour
}

fn default_eqsl_interval() -> u64 {
    1800 // 30 minutes
}

fn default_clublog_interval() -> u64 {
    1800 // 30 minutes
}

fn default_hrdlog_interval() -> u64 {
    1800 // 30 minutes
}

fn default_wavelog_interval() -> u64 {
    600 // 10 minutes
}

impl Config {
    pub fn load(path: &std::path::Path) -> crate::Result<Self> {
        let settings = config::Config::builder()
            .add_source(config::File::from(path))
            .add_source(
                config::Environment::with_prefix("LOGBOOK_SYNC")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;

        let config: Config = settings.try_deserialize()?;
        Ok(config)
    }

    /// Get the bind address string for the server
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.server.bind_address, self.server.port)
    }
}
