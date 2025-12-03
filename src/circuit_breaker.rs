//! Circuit breaker pattern implementation for resilient service calls.
//!
//! The circuit breaker prevents cascading failures by tracking errors and
//! temporarily blocking requests when a service is experiencing issues.

use crate::metrics;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is closed, requests flow through normally
    Closed = 0,
    /// Circuit is half-open, allowing test requests through
    HalfOpen = 1,
    /// Circuit is open, blocking all requests
    Open = 2,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "closed"),
            CircuitState::HalfOpen => write!(f, "half-open"),
            CircuitState::Open => write!(f, "open"),
        }
    }
}

/// Configuration for the circuit breaker
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening the circuit
    pub failure_threshold: u32,
    /// Duration to keep circuit open before trying again
    pub reset_timeout: Duration,
    /// Number of successful calls to close the circuit from half-open
    pub success_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            reset_timeout: Duration::from_secs(60),
            success_threshold: 2,
        }
    }
}

/// A circuit breaker for a specific service
pub struct CircuitBreaker {
    name: String,
    config: CircuitBreakerConfig,
    state: RwLock<CircuitState>,
    failure_count: AtomicU32,
    success_count: AtomicU32,
    last_failure_time: RwLock<Option<Instant>>,
    last_state_change: RwLock<Instant>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker for a service
    pub fn new(name: impl Into<String>, config: CircuitBreakerConfig) -> Self {
        let name = name.into();
        metrics::set_circuit_breaker_state(&name, CircuitState::Closed as i64);

        Self {
            name,
            config,
            state: RwLock::new(CircuitState::Closed),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            last_failure_time: RwLock::new(None),
            last_state_change: RwLock::new(Instant::now()),
        }
    }

    /// Get the current state of the circuit breaker
    pub async fn state(&self) -> CircuitState {
        *self.state.read().await
    }

    /// Check if a request should be allowed through
    pub async fn should_allow(&self) -> bool {
        let current_state = *self.state.read().await;

        match current_state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if we should transition to half-open
                let last_failure = self.last_failure_time.read().await;
                if let Some(time) = *last_failure {
                    if time.elapsed() >= self.config.reset_timeout {
                        self.transition_to(CircuitState::HalfOpen).await;
                        true
                    } else {
                        debug!(
                            circuit = %self.name,
                            remaining_secs = (self.config.reset_timeout - time.elapsed()).as_secs(),
                            "Circuit open, rejecting request"
                        );
                        false
                    }
                } else {
                    // No failure time recorded, allow the request
                    true
                }
            }
            CircuitState::HalfOpen => {
                // Allow limited requests in half-open state
                true
            }
        }
    }

    /// Record a successful call
    pub async fn record_success(&self) {
        let current_state = *self.state.read().await;

        match current_state {
            CircuitState::Closed => {
                // Reset failure count on success
                self.failure_count.store(0, Ordering::SeqCst);
            }
            CircuitState::HalfOpen => {
                let count = self.success_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count >= self.config.success_threshold {
                    self.transition_to(CircuitState::Closed).await;
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but reset anyway
                self.success_count.store(1, Ordering::SeqCst);
            }
        }
    }

    /// Record a failed call
    pub async fn record_failure(&self) {
        *self.last_failure_time.write().await = Some(Instant::now());
        let current_state = *self.state.read().await;

        match current_state {
            CircuitState::Closed => {
                let count = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count >= self.config.failure_threshold {
                    self.transition_to(CircuitState::Open).await;
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open state opens the circuit again
                self.transition_to(CircuitState::Open).await;
            }
            CircuitState::Open => {
                // Already open, just update failure time
            }
        }
    }

    /// Transition to a new state
    async fn transition_to(&self, new_state: CircuitState) {
        let mut state = self.state.write().await;
        let old_state = *state;

        if old_state == new_state {
            return;
        }

        *state = new_state;
        *self.last_state_change.write().await = Instant::now();

        // Reset counters on state change
        match new_state {
            CircuitState::Closed => {
                self.failure_count.store(0, Ordering::SeqCst);
                self.success_count.store(0, Ordering::SeqCst);
                info!(
                    circuit = %self.name,
                    from = %old_state,
                    to = %new_state,
                    "Circuit breaker closed - service recovered"
                );
            }
            CircuitState::HalfOpen => {
                self.success_count.store(0, Ordering::SeqCst);
                info!(
                    circuit = %self.name,
                    from = %old_state,
                    to = %new_state,
                    "Circuit breaker half-open - testing service"
                );
            }
            CircuitState::Open => {
                self.success_count.store(0, Ordering::SeqCst);
                metrics::record_circuit_breaker_trip(&self.name);
                warn!(
                    circuit = %self.name,
                    from = %old_state,
                    to = %new_state,
                    timeout_secs = self.config.reset_timeout.as_secs(),
                    "Circuit breaker opened - service unhealthy"
                );
            }
        }

        metrics::set_circuit_breaker_state(&self.name, new_state as i64);
    }

    /// Get statistics about the circuit breaker
    pub async fn stats(&self) -> CircuitBreakerStats {
        CircuitBreakerStats {
            name: self.name.clone(),
            state: *self.state.read().await,
            failure_count: self.failure_count.load(Ordering::SeqCst),
            success_count: self.success_count.load(Ordering::SeqCst),
            last_state_change: *self.last_state_change.read().await,
        }
    }

    /// Reset the circuit breaker to closed state
    pub async fn reset(&self) {
        self.transition_to(CircuitState::Closed).await;
        *self.last_failure_time.write().await = None;
    }
}

/// Statistics about a circuit breaker
#[derive(Debug, Clone)]
pub struct CircuitBreakerStats {
    pub name: String,
    pub state: CircuitState,
    pub failure_count: u32,
    pub success_count: u32,
    pub last_state_change: Instant,
}

/// Execute a function with circuit breaker protection
pub async fn with_circuit_breaker<F, T, E>(
    circuit: &CircuitBreaker,
    operation: F,
) -> Result<T, CircuitBreakerError<E>>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    if !circuit.should_allow().await {
        return Err(CircuitBreakerError::CircuitOpen);
    }

    match operation.await {
        Ok(result) => {
            circuit.record_success().await;
            Ok(result)
        }
        Err(e) => {
            circuit.record_failure().await;
            Err(CircuitBreakerError::ServiceError(e))
        }
    }
}

/// Error type for circuit breaker protected operations
#[derive(Debug)]
pub enum CircuitBreakerError<E> {
    /// The circuit is open, request was rejected
    CircuitOpen,
    /// The underlying service returned an error
    ServiceError(E),
}

impl<E: std::fmt::Display> std::fmt::Display for CircuitBreakerError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitBreakerError::CircuitOpen => write!(f, "Circuit breaker is open"),
            CircuitBreakerError::ServiceError(e) => write!(f, "Service error: {}", e),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for CircuitBreakerError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CircuitBreakerError::CircuitOpen => None,
            CircuitBreakerError::ServiceError(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_starts_closed() {
        let cb = CircuitBreaker::new("test", CircuitBreakerConfig::default());
        assert_eq!(cb.state().await, CircuitState::Closed);
        assert!(cb.should_allow().await);
    }

    #[tokio::test]
    async fn test_circuit_opens_after_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            reset_timeout: Duration::from_secs(60),
            success_threshold: 2,
        };
        let cb = CircuitBreaker::new("test", config);

        // Record failures
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Closed);

        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Closed);

        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Open);
        assert!(!cb.should_allow().await);
    }

    #[tokio::test]
    async fn test_success_resets_failure_count() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let cb = CircuitBreaker::new("test", config);

        cb.record_failure().await;
        cb.record_failure().await;
        cb.record_success().await;

        // Failure count should be reset
        cb.record_failure().await;
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_half_open_closes_on_success() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            reset_timeout: Duration::from_millis(1),
            success_threshold: 2,
        };
        let cb = CircuitBreaker::new("test", config);

        // Open the circuit
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Open);

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Should transition to half-open
        assert!(cb.should_allow().await);
        assert_eq!(cb.state().await, CircuitState::HalfOpen);

        // Record successes to close
        cb.record_success().await;
        cb.record_success().await;
        assert_eq!(cb.state().await, CircuitState::Closed);
    }
}
