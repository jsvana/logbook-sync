//! Prometheus metrics for monitoring logbook-sync operations.

use lazy_static::lazy_static;
use prometheus::{
    Gauge, GaugeVec, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
    Opts, Registry,
};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    // QSO metrics
    pub static ref QSOS_UPLOADED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("logbook_qsos_uploaded_total", "Total number of QSOs uploaded")
            .namespace("logbook_sync"),
        &["service"]
    ).expect("metric can be created");

    pub static ref QSOS_DOWNLOADED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("logbook_qsos_downloaded_total", "Total number of QSOs downloaded")
            .namespace("logbook_sync"),
        &["service"]
    ).expect("metric can be created");

    pub static ref QSOS_DUPLICATES_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("logbook_qsos_duplicates_total", "Total number of duplicate QSOs detected")
            .namespace("logbook_sync"),
        &["service"]
    ).expect("metric can be created");

    pub static ref QSOS_FAILED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("logbook_qsos_failed_total", "Total number of failed QSO operations")
            .namespace("logbook_sync"),
        &["service", "operation"]
    ).expect("metric can be created");

    pub static ref QSOS_PENDING: IntGauge = IntGauge::new(
        "logbook_sync_qsos_pending",
        "Number of QSOs pending upload"
    ).expect("metric can be created");

    pub static ref QSOS_TOTAL: IntGauge = IntGauge::new(
        "logbook_sync_qsos_total",
        "Total number of QSOs in database"
    ).expect("metric can be created");

    // Confirmation metrics
    pub static ref CONFIRMATIONS_RECEIVED_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("logbook_confirmations_received_total", "Total confirmations received")
            .namespace("logbook_sync"),
        &["service"]
    ).expect("metric can be created");

    pub static ref CONFIRMATIONS_LOTW: IntGauge = IntGauge::new(
        "logbook_sync_confirmations_lotw",
        "Number of LoTW confirmations"
    ).expect("metric can be created");

    pub static ref CONFIRMATIONS_QSL: IntGauge = IntGauge::new(
        "logbook_sync_confirmations_qsl",
        "Number of QSL confirmations"
    ).expect("metric can be created");

    // Sync operation metrics
    pub static ref SYNC_DURATION_SECONDS: HistogramVec = HistogramVec::new(
        HistogramOpts::new(
            "logbook_sync_duration_seconds",
            "Duration of sync operations"
        )
        .namespace("logbook_sync")
        .buckets(vec![0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0]),
        &["service", "operation"]
    ).expect("metric can be created");

    pub static ref SYNC_LAST_SUCCESS_TIMESTAMP: GaugeVec = GaugeVec::new(
        Opts::new("logbook_sync_last_success_timestamp", "Timestamp of last successful sync")
            .namespace("logbook_sync"),
        &["service"]
    ).expect("metric can be created");

    pub static ref SYNC_ERRORS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("logbook_sync_errors_total", "Total sync errors")
            .namespace("logbook_sync"),
        &["service", "error_type"]
    ).expect("metric can be created");

    pub static ref SYNC_CONSECUTIVE_FAILURES: IntGaugeVec = IntGaugeVec::new(
        Opts::new("logbook_sync_consecutive_failures", "Number of consecutive sync failures")
            .namespace("logbook_sync"),
        &["service"]
    ).expect("metric can be created");

    // File processing metrics
    pub static ref FILES_PROCESSED_TOTAL: IntCounter = IntCounter::new(
        "logbook_sync_files_processed_total",
        "Total number of ADIF files processed"
    ).expect("metric can be created");

    pub static ref FILES_WATCHED: IntGauge = IntGauge::new(
        "logbook_sync_files_watched",
        "Number of ADIF files being watched"
    ).expect("metric can be created");

    // HTTP/API metrics
    pub static ref HTTP_REQUESTS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("logbook_http_requests_total", "Total HTTP requests made")
            .namespace("logbook_sync"),
        &["service", "status"]
    ).expect("metric can be created");

    pub static ref HTTP_REQUEST_DURATION_SECONDS: HistogramVec = HistogramVec::new(
        HistogramOpts::new(
            "logbook_http_request_duration_seconds",
            "Duration of HTTP requests"
        )
        .namespace("logbook_sync")
        .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        &["service"]
    ).expect("metric can be created");

    // Circuit breaker metrics
    pub static ref CIRCUIT_BREAKER_STATE: IntGaugeVec = IntGaugeVec::new(
        Opts::new("logbook_circuit_breaker_state", "Circuit breaker state (0=closed, 1=half-open, 2=open)")
            .namespace("logbook_sync"),
        &["service"]
    ).expect("metric can be created");

    pub static ref CIRCUIT_BREAKER_TRIPS_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("logbook_circuit_breaker_trips_total", "Total number of circuit breaker trips")
            .namespace("logbook_sync"),
        &["service"]
    ).expect("metric can be created");

    // Retry metrics
    pub static ref RETRIES_TOTAL: IntCounterVec = IntCounterVec::new(
        Opts::new("logbook_retries_total", "Total number of retries")
            .namespace("logbook_sync"),
        &["service", "operation"]
    ).expect("metric can be created");

    // Process metrics
    pub static ref PROCESS_START_TIME: Gauge = Gauge::new(
        "logbook_sync_process_start_time_seconds",
        "Start time of the process since unix epoch"
    ).expect("metric can be created");

    pub static ref BUILD_INFO: IntGaugeVec = IntGaugeVec::new(
        Opts::new("logbook_sync_build_info", "Build information")
            .namespace("logbook_sync"),
        &["version"]
    ).expect("metric can be created");
}

/// Register all metrics with the registry (idempotent - safe to call multiple times)
pub fn register_metrics() {
    use std::sync::Once;
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        REGISTRY
            .register(Box::new(QSOS_UPLOADED_TOTAL.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(QSOS_DOWNLOADED_TOTAL.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(QSOS_DUPLICATES_TOTAL.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(QSOS_FAILED_TOTAL.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(QSOS_PENDING.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(QSOS_TOTAL.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(CONFIRMATIONS_RECEIVED_TOTAL.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(CONFIRMATIONS_LOTW.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(CONFIRMATIONS_QSL.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(SYNC_DURATION_SECONDS.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(SYNC_LAST_SUCCESS_TIMESTAMP.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(SYNC_ERRORS_TOTAL.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(SYNC_CONSECUTIVE_FAILURES.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(FILES_PROCESSED_TOTAL.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(FILES_WATCHED.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(HTTP_REQUESTS_TOTAL.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(HTTP_REQUEST_DURATION_SECONDS.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(CIRCUIT_BREAKER_STATE.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(CIRCUIT_BREAKER_TRIPS_TOTAL.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(RETRIES_TOTAL.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(PROCESS_START_TIME.clone()))
            .expect("collector can be registered");
        REGISTRY
            .register(Box::new(BUILD_INFO.clone()))
            .expect("collector can be registered");

        // Set build info
        BUILD_INFO
            .with_label_values(&[env!("CARGO_PKG_VERSION")])
            .set(1);

        // Set process start time
        PROCESS_START_TIME.set(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
        );
    });
}

/// Record a successful QSO upload
pub fn record_qso_uploaded(service: &str) {
    QSOS_UPLOADED_TOTAL.with_label_values(&[service]).inc();
}

/// Record a successful QSO download
pub fn record_qso_downloaded(service: &str, count: u64) {
    QSOS_DOWNLOADED_TOTAL
        .with_label_values(&[service])
        .inc_by(count);
}

/// Record a duplicate QSO
pub fn record_qso_duplicate(service: &str) {
    QSOS_DUPLICATES_TOTAL.with_label_values(&[service]).inc();
}

/// Record a failed QSO operation
pub fn record_qso_failed(service: &str, operation: &str) {
    QSOS_FAILED_TOTAL
        .with_label_values(&[service, operation])
        .inc();
}

/// Update the pending QSO count
pub fn set_qsos_pending(count: i64) {
    QSOS_PENDING.set(count);
}

/// Update the total QSO count
pub fn set_qsos_total(count: i64) {
    QSOS_TOTAL.set(count);
}

/// Record a confirmation received
pub fn record_confirmation(service: &str) {
    CONFIRMATIONS_RECEIVED_TOTAL
        .with_label_values(&[service])
        .inc();
}

/// Update confirmation counts
pub fn set_confirmations(lotw: i64, qsl: i64) {
    CONFIRMATIONS_LOTW.set(lotw);
    CONFIRMATIONS_QSL.set(qsl);
}

/// Record sync duration
pub fn record_sync_duration(service: &str, operation: &str, duration_secs: f64) {
    SYNC_DURATION_SECONDS
        .with_label_values(&[service, operation])
        .observe(duration_secs);
}

/// Record last successful sync timestamp
pub fn record_sync_success(service: &str) {
    SYNC_LAST_SUCCESS_TIMESTAMP
        .with_label_values(&[service])
        .set(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs_f64(),
        );
    SYNC_CONSECUTIVE_FAILURES
        .with_label_values(&[service])
        .set(0);
}

/// Record a sync error
pub fn record_sync_error(service: &str, error_type: &str) {
    SYNC_ERRORS_TOTAL
        .with_label_values(&[service, error_type])
        .inc();
    SYNC_CONSECUTIVE_FAILURES
        .with_label_values(&[service])
        .inc();
}

/// Record a file processed
pub fn record_file_processed() {
    FILES_PROCESSED_TOTAL.inc();
}

/// Update watched files count
pub fn set_files_watched(count: i64) {
    FILES_WATCHED.set(count);
}

/// Record an HTTP request
pub fn record_http_request(service: &str, status: &str) {
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[service, status])
        .inc();
}

/// Record HTTP request duration
pub fn record_http_duration(service: &str, duration_secs: f64) {
    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&[service])
        .observe(duration_secs);
}

/// Update circuit breaker state (0=closed, 1=half-open, 2=open)
pub fn set_circuit_breaker_state(service: &str, state: i64) {
    CIRCUIT_BREAKER_STATE
        .with_label_values(&[service])
        .set(state);
}

/// Record a circuit breaker trip
pub fn record_circuit_breaker_trip(service: &str) {
    CIRCUIT_BREAKER_TRIPS_TOTAL
        .with_label_values(&[service])
        .inc();
}

/// Record a retry
pub fn record_retry(service: &str, operation: &str) {
    RETRIES_TOTAL.with_label_values(&[service, operation]).inc();
}

/// Get metrics in Prometheus text format
pub fn gather_metrics() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_registration() {
        // This test just ensures metrics can be created without panicking
        register_metrics();
    }

    #[test]
    fn test_record_functions() {
        register_metrics();
        record_qso_uploaded("qrz");
        record_qso_downloaded("qrz", 5);
        record_qso_duplicate("qrz");
        record_sync_success("qrz");
        record_file_processed();
    }
}
