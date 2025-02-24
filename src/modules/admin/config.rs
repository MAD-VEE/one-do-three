use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::distributions::Alphanumeric;
use rand::Rng;

use crate::ADMIN_LOCKOUT_DURATION;
use crate::SETUP_TOKEN_DURATION;
use super::credentials::SecureAdminConfig;

/// Structure to track admin authentication attempts
#[derive(Serialize, Deserialize)]
pub struct AdminAuthTracker {
    pub failed_attempts: u32,
    pub last_attempt: u64,
    pub lockout_until: u64,
}

impl AdminAuthTracker {
    /// Create new authentication tracker with default values
    pub fn new() -> Self {
        Self {
            failed_attempts: 0,
            last_attempt: 0,
            lockout_until: 0,
        }
    }

    /// Check if the admin account is currently locked out
    pub fn is_locked_out(&self, current_time: u64) -> bool {
        current_time < self.lockout_until
    }

    /// Reset attempt counter if lockout duration has passed
    pub fn maybe_reset_attempts(&mut self, current_time: u64) {
        if current_time - self.last_attempt > ADMIN_LOCKOUT_DURATION {
            self.failed_attempts = 0;
            self.lockout_until = 0;
        }
    }

    /// Record a failed authentication attempt and implement lockout if needed
    pub fn record_failed_attempt(&mut self, current_time: u64) {
        self.failed_attempts += 1;
        self.last_attempt = current_time;

        if self.failed_attempts >= crate::MAX_ADMIN_ATTEMPTS {
            self.lockout_until = current_time + ADMIN_LOCKOUT_DURATION;
        }
    }

    /// Record successful authentication and reset counters
    pub fn record_success(&mut self) {
        self.failed_attempts = 0;
        self.lockout_until = 0;
    }
}

/// Configuration structure for admin settings and security
#[derive(Serialize, Deserialize)]
pub struct AdminConfig {
    pub auth_tracker: AdminAuthTracker,
    pub setup_token: Option<String>,     // One-time setup token
    pub setup_token_expiry: Option<u64>, // Token expiration timestamp
    pub allowed_setup_ips: Vec<String>,  // Optional IP whitelist for setup
}

impl AdminConfig {
    /// Create new admin configuration with default values
    pub fn new() -> Self {
        Self {
            auth_tracker: AdminAuthTracker::new(),
            setup_token: None,
            setup_token_expiry: None,
            allowed_setup_ips: Vec::new(),
        }
    }

    /// Generate a new one-time setup token
    pub fn generate_setup_token(&mut self) -> String {
        // Generate cryptographically secure random token
        let token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        // Store token and set expiration
        self.setup_token = Some(token.clone());
        self.setup_token_expiry = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + SETUP_TOKEN_DURATION,
        );

        token
    }

    /// Validate a provided setup token
    pub fn validate_setup_token(&self, token: &str) -> bool {
        if let (Some(stored_token), Some(expiry)) = (&self.setup_token, self.setup_token_expiry) {
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            stored_token == token && current_time < expiry
        } else {
            false
        }
    }

    /// Load configuration from secure storage
    pub fn load() -> Result<Self, String> {
        let secure_config = SecureAdminConfig::new();
        secure_config.load_config()
    }

    /// Save configuration to secure storage
    pub fn save(&self) -> Result<(), String> {
        let secure_config = SecureAdminConfig::new();
        secure_config.save_config(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_admin_auth_tracker() {
        let mut tracker = AdminAuthTracker::new();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Initially no failed attempts
        assert_eq!(tracker.failed_attempts, 0);
        assert_eq!(tracker.lockout_until, 0);

        // Record a failed attempt
        tracker.record_failed_attempt(current_time);
        assert_eq!(tracker.failed_attempts, 1);
        assert_eq!(tracker.last_attempt, current_time);

        // Not locked out yet
        assert!(!tracker.is_locked_out(current_time));

        // Record more failed attempts up to the limit
        tracker.record_failed_attempt(current_time);
        tracker.record_failed_attempt(current_time);

        // Should be locked out now (3 failed attempts)
        assert_eq!(tracker.failed_attempts, 3);
        assert!(tracker.is_locked_out(current_time));

        // Lock should expire after ADMIN_LOCKOUT_DURATION
        let future_time = current_time + ADMIN_LOCKOUT_DURATION + 1;
        assert!(!tracker.is_locked_out(future_time));

        // Reset attempts if lockout duration has passed
        tracker.maybe_reset_attempts(future_time);
        assert_eq!(tracker.failed_attempts, 0);

        // Record success resets counters
        tracker.record_failed_attempt(current_time);
        assert_eq!(tracker.failed_attempts, 1);
        tracker.record_success();
        assert_eq!(tracker.failed_attempts, 0);
    }

    #[test]
    fn test_setup_token() {
        let mut config = AdminConfig::new();

        // Initially, there should be no token
        assert!(config.setup_token.is_none());
        assert!(config.setup_token_expiry.is_none());

        // Generate a token
        let token = config.generate_setup_token();

        // Token should be set and have an expiry
        assert!(config.setup_token.is_some());
        assert!(config.setup_token_expiry.is_some());
        assert_eq!(config.setup_token.as_ref().unwrap(), &token);

        // Token should be valid
        assert!(config.validate_setup_token(&token));

        // Invalid token should not validate
        assert!(!config.validate_setup_token("invalid-token"));

        // Set token expiry to the past
        let past_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600;

        config.setup_token_expiry = Some(past_time);

        // Expired token should not validate
        assert!(!config.validate_setup_token(&token));
    }
}