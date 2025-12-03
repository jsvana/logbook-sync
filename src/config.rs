use crate::wavelog::WavelogConfig;
use serde::Deserialize;
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
    pub ntfy: Option<NtfyConfig>,
    pub database: DatabaseConfig,
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
