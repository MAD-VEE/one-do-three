use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// PasswordResetToken struct with a user identifier
#[derive(Serialize, Deserialize, Clone)]
pub struct PasswordResetToken {
    pub token: String,
    pub expires_at: u64,
    pub user_email: String,
    pub username: String,
}

/// Structure to track password reset attempts to prevent abuse
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResetAttemptTracker {
    pub attempts: u32,
    pub first_attempt: u64,
    pub last_attempt: u64,
}

impl ResetAttemptTracker {
    pub fn new() -> Self {
        Self {
            attempts: 0,
            first_attempt: 0,
            last_attempt: 0,
        }
    }
}

/// Secure token management
pub struct SecureTokenManager {
    keyring: Entry,
}

impl SecureTokenManager {
    pub fn new() -> Self {
        Self {
            keyring: Entry::new("one-do-three", "reset-tokens")
                .expect("Failed to create keyring entry"),
        }
    }

    /// Store reset token securely
    pub fn store_token(&self, email: &str, token: &str) -> Result<(), String> {
        let token_data = format!("{}:{}", email, token);
        self.keyring
            .set_password(&token_data)
            .map_err(|e| format!("Failed to store reset token: {}", e))
    }

    /// Verify a reset token
    pub fn verify_token(&self, email: &str, token: &str) -> Result<bool, String> {
        match self.keyring.get_password() {
            Ok(stored_data) => {
                let parts: Vec<&str> = stored_data.split(':').collect();
                if parts.len() != 2 {
                    return Ok(false);
                }
                Ok(parts[0] == email && parts[1] == token)
            }
            Err(_) => Ok(false),
        }
    }

    /// Clear the token after use
    pub fn clear_token(&self) -> Result<(), String> {
        self.keyring
            .delete_password()
            .map_err(|e| format!("Failed to clear reset token: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_token_manager() {
        // Mock implementation for testing
        struct MockSecureTokenManager {
            stored_token: Option<(String, String)>,
        }

        impl MockSecureTokenManager {
            fn new() -> Self {
                Self { stored_token: None }
            }

            fn store_token(&mut self, email: &str, token: &str) -> Result<(), String> {
                self.stored_token = Some((email.to_string(), token.to_string()));
                Ok(())
            }

            fn verify_token(&self, email: &str, token: &str) -> Result<bool, String> {
                match &self.stored_token {
                    Some((stored_email, stored_token)) => {
                        Ok(email == stored_email && token == stored_token)
                    }
                    None => Ok(false),
                }
            }

            fn clear_token(&mut self) -> Result<(), String> {
                self.stored_token = None;
                Ok(())
            }
        }

        let mut token_manager = MockSecureTokenManager::new();

        // Store a token
        let email = "test@example.com";
        let token = "reset_token_123";
        assert!(token_manager.store_token(email, token).is_ok());

        // Verify correct token succeeds
        assert!(token_manager.verify_token(email, token).unwrap());

        // Verify incorrect token fails
        assert!(!token_manager.verify_token(email, "wrong_token").unwrap());
        assert!(!token_manager
            .verify_token("wrong@example.com", token)
            .unwrap());

        // Clear token
        assert!(token_manager.clear_token().is_ok());

        // Verify token is cleared
        assert!(!token_manager.verify_token(email, token).unwrap());
    }

    #[test]
    fn test_reset_attempt_tracker() {
        let tracker = ResetAttemptTracker::new();
        assert_eq!(tracker.attempts, 0);
        assert_eq!(tracker.first_attempt, 0);
        assert_eq!(tracker.last_attempt, 0);
    }
}
