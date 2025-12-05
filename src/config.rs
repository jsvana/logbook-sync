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
