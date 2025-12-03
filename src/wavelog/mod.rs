//! Wavelog API client for downloading QSOs from a self-hosted Wavelog instance.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

use crate::adif::Qso;
use crate::{Error, Result};

/// Configuration for Wavelog integration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WavelogConfig {
    /// Whether Wavelog integration is enabled
    #[serde(default)]
    pub enabled: bool,
    /// Base URL of the Wavelog instance (e.g., "https://log.example.com")
    pub base_url: String,
    /// API key for authentication
    pub api_key: String,
    /// Username for ADIF export (optional, for full log download)
    pub username: Option<String>,
    /// Password for ADIF export (optional, for full log download)
    pub password: Option<String>,
    /// Station ID to export from (optional, auto-detected if not set)
    pub station_id: Option<String>,
    /// Public slug for the logbook (required for recent_qsos endpoint)
    pub logbook_slug: Option<String>,
    /// Interval between download checks in seconds
    #[serde(default = "default_download_interval")]
    pub download_interval: u64,
    /// User agent string
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    /// Accept invalid/self-signed SSL certificates (for self-hosted instances)
    #[serde(default)]
    pub accept_invalid_certs: bool,
}

fn default_download_interval() -> u64 {
    3600
}

fn default_user_agent() -> String {
    format!("logbook-sync/{}", env!("CARGO_PKG_VERSION"))
}

impl Default for WavelogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: String::new(),
            api_key: String::new(),
            username: None,
            password: None,
            station_id: None,
            logbook_slug: None,
            download_interval: default_download_interval(),
            user_agent: default_user_agent(),
            accept_invalid_certs: false,
        }
    }
}

/// Station profile from Wavelog
#[derive(Debug, Clone, Deserialize)]
pub struct StationProfile {
    pub station_id: String,
    pub station_profile_name: String,
    pub station_gridsquare: String,
    pub station_callsign: String,
    pub station_active: Option<String>,
}

/// QSO record from Wavelog's recent_qsos endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct WavelogQso {
    pub date: String,
    pub time: String,
    pub callsign: String,
    pub mode: String,
    pub band: String,
    #[serde(default)]
    pub rst_sent: Option<String>,
    #[serde(default)]
    pub rst_rcvd: Option<String>,
    #[serde(default)]
    pub gridsquare: Option<String>,
    #[serde(default)]
    pub qth: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    // POTA fields if present
    #[serde(default)]
    pub my_sig: Option<String>,
    #[serde(default)]
    pub my_sig_info: Option<String>,
    #[serde(default)]
    pub sig: Option<String>,
    #[serde(default)]
    pub sig_info: Option<String>,
    #[serde(default)]
    pub my_state: Option<String>,
    #[serde(default)]
    pub station_callsign: Option<String>,
}

/// Response from recent_qsos endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct RecentQsosResponse {
    pub qsos: Vec<WavelogQso>,
    pub count: u32,
    pub logbook_slug: String,
}

/// Response from get_contacts_adif API endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct GetContactsAdifResponse {
    /// Status of the request ("successfull" on success)
    #[serde(default)]
    pub status: String,
    /// Number of exported QSOs
    pub exported_qsos: i64,
    /// Internal primary key of the last exported QSO (use as next fetchfromid)
    /// Note: This is returned as a string from the API
    #[serde(deserialize_with = "deserialize_string_to_i64")]
    pub lastfetchedid: i64,
    /// Status message ("Export successfull" on success)
    pub message: String,
    /// ADIF content with all QSOs since the last pull
    #[serde(default)]
    pub adif: String,
}

fn deserialize_string_to_i64<'de, D>(deserializer: D) -> std::result::Result<i64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    let s: String = Deserialize::deserialize(deserializer)?;
    s.parse::<i64>().map_err(D::Error::custom)
}

/// Wavelog API client
pub struct WavelogClient {
    client: Client,
    config: WavelogConfig,
}

impl WavelogClient {
    /// Create a new Wavelog client
    pub fn new(config: WavelogConfig) -> Result<Self> {
        let mut builder = Client::builder().user_agent(&config.user_agent);

        if config.accept_invalid_certs {
            builder = builder.danger_accept_invalid_certs(true);
        }

        let client = builder.build().map_err(Error::Http)?;

        Ok(Self { client, config })
    }

    /// Get station profiles
    pub async fn get_station_info(&self) -> Result<Vec<StationProfile>> {
        let url = format!(
            "{}/index.php/api/station_info/{}",
            self.config.base_url.trim_end_matches('/'),
            self.config.api_key
        );

        debug!(url = %url, "Fetching station info from Wavelog");

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(Error::Other(format!(
                "Wavelog API error: {}",
                response.status()
            )));
        }

        let stations: Vec<StationProfile> = response.json().await?;
        info!(
            count = stations.len(),
            "Retrieved station profiles from Wavelog"
        );
        Ok(stations)
    }

    /// Get recent QSOs from a logbook
    ///
    /// Note: This endpoint has a maximum limit of 50 QSOs per request.
    pub async fn get_recent_qsos(&self, limit: u32) -> Result<RecentQsosResponse> {
        let slug = self
            .config
            .logbook_slug
            .as_ref()
            .ok_or_else(|| Error::Other("logbook_slug is required for recent_qsos".into()))?;

        let limit = limit.min(50); // API maximum is 50

        let url = format!(
            "{}/index.php/api/recent_qsos/{}/{}",
            self.config.base_url.trim_end_matches('/'),
            slug,
            limit
        );

        debug!(url = %url, limit = limit, "Fetching recent QSOs from Wavelog");

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(Error::Other(format!(
                "Wavelog API error: {}",
                response.status()
            )));
        }

        let qsos: RecentQsosResponse = response.json().await?;
        info!(count = qsos.count, "Retrieved recent QSOs from Wavelog");
        Ok(qsos)
    }

    /// Download all available QSOs via recent_qsos endpoint
    ///
    /// Note: The recent_qsos endpoint only returns up to 50 QSOs.
    /// For bulk downloads, use the get_contacts_adif API instead.
    pub async fn download_recent_qsos(&self) -> Result<Vec<Qso>> {
        let response = self.get_recent_qsos(50).await?;
        let qsos: Vec<Qso> = response.qsos.into_iter().map(|wl| wl.into()).collect();
        Ok(qsos)
    }

    /// Download ADIF export from Wavelog using the get_contacts_adif API
    ///
    /// This method uses the Wavelog API with the API key (no login required).
    /// Returns the ADIF content and the last fetched ID for incremental syncs.
    pub async fn get_contacts_adif(&self, fetch_from_id: i64) -> Result<GetContactsAdifResponse> {
        let station_id = self
            .config
            .station_id
            .clone()
            .unwrap_or_else(|| "1".to_string());

        let url = format!(
            "{}/index.php/api/get_contacts_adif",
            self.config.base_url.trim_end_matches('/')
        );

        debug!(url = %url, station_id = %station_id, fetch_from_id = fetch_from_id, "Fetching contacts ADIF from Wavelog");

        let request_body = serde_json::json!({
            "key": self.config.api_key,
            "station_id": station_id,
            "fetchfromid": fetch_from_id
        });

        let response = self
            .client
            .post(&url)
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(Error::Other(format!(
                "Wavelog API error: {}",
                response.status()
            )));
        }

        let api_response: GetContactsAdifResponse = response.json().await?;

        info!(
            exported_qsos = api_response.exported_qsos,
            last_fetched_id = api_response.lastfetchedid,
            message = %api_response.message,
            "Retrieved contacts ADIF from Wavelog"
        );

        Ok(api_response)
    }

    /// Download all QSOs as ADIF using the get_contacts_adif API
    ///
    /// This is the preferred method for downloading QSOs from Wavelog.
    /// Set fetch_from_id to 0 to get all QSOs, or use a previous lastfetchedid
    /// for incremental sync.
    pub async fn download_adif(&self, fetch_from_id: i64) -> Result<String> {
        let response = self.get_contacts_adif(fetch_from_id).await?;

        if response.message != "OK" && response.exported_qsos == 0 {
            // Not necessarily an error - might just be no new QSOs
            debug!(message = %response.message, "No QSOs to export");
        }

        Ok(response.adif)
    }
}

/// Convert WavelogQso to the application's QSO type
impl From<WavelogQso> for Qso {
    fn from(wl: WavelogQso) -> Self {
        // Convert date from YYYY-MM-DD to YYYYMMDD
        let qso_date = wl.date.replace('-', "");

        // Convert time from HH:MM to HHMM or HHMMSS
        let time_on = wl.time.replace(':', "");

        // Normalize band (Wavelog may use "20M" format, we use "20m")
        let band = wl.band.to_lowercase();

        Qso {
            call: wl.callsign,
            qso_date,
            time_on,
            band,
            mode: wl.mode,
            station_callsign: wl.station_callsign,
            freq: None,
            rst_sent: wl.rst_sent,
            rst_rcvd: wl.rst_rcvd,
            time_off: None,
            gridsquare: wl.gridsquare,
            my_gridsquare: None,
            my_sig: wl.my_sig,
            my_sig_info: wl.my_sig_info,
            sig: wl.sig,
            sig_info: wl.sig_info,
            comment: None,
            my_state: wl.my_state,
            my_cnty: None,
            state: None,
            cnty: None,
            other_fields: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_station_info() {
        let json = r#"[{"station_id":"1","station_profile_name":"Home","station_gridsquare":"CM87","station_callsign":"W6JSV","station_active":"1"}]"#;
        let stations: Vec<StationProfile> = serde_json::from_str(json).unwrap();
        assert_eq!(stations.len(), 1);
        assert_eq!(stations[0].station_callsign, "W6JSV");
        assert_eq!(stations[0].station_gridsquare, "CM87");
    }

    #[test]
    fn test_parse_recent_qsos() {
        let json = r#"{"qsos":[{"date":"2024-01-15","time":"14:30","callsign":"W1AW","mode":"SSB","band":"20M"}],"count":1,"logbook_slug":"test"}"#;
        let response: RecentQsosResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.count, 1);
        assert_eq!(response.qsos[0].callsign, "W1AW");
        assert_eq!(response.qsos[0].band, "20M");
    }

    #[test]
    fn test_wavelog_qso_conversion() {
        let wl = WavelogQso {
            date: "2024-01-15".to_string(),
            time: "14:30".to_string(),
            callsign: "W1AW".to_string(),
            mode: "SSB".to_string(),
            band: "20M".to_string(),
            rst_sent: Some("59".to_string()),
            rst_rcvd: Some("57".to_string()),
            gridsquare: Some("FN31".to_string()),
            qth: Some("Newington".to_string()),
            name: Some("ARRL".to_string()),
            my_sig: Some("POTA".to_string()),
            my_sig_info: Some("US-3315".to_string()),
            sig: None,
            sig_info: None,
            my_state: Some("CT".to_string()),
            station_callsign: Some("W6JSV".to_string()),
        };

        let qso: Qso = wl.into();

        assert_eq!(qso.call, "W1AW");
        assert_eq!(qso.qso_date, "20240115"); // Converted from YYYY-MM-DD
        assert_eq!(qso.time_on, "1430"); // Converted from HH:MM
        assert_eq!(qso.band, "20m"); // Lowercased
        assert_eq!(qso.mode, "SSB");
        assert_eq!(qso.rst_sent, Some("59".to_string()));
        assert_eq!(qso.gridsquare, Some("FN31".to_string()));
        assert_eq!(qso.my_sig, Some("POTA".to_string()));
        assert_eq!(qso.my_sig_info, Some("US-3315".to_string()));
    }
}
