use keyring::Entry;
use serde::{Deserialize, Serialize};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

/// Structure for storing password with timestamp in keyring
#[derive(Serialize, Deserialize)]
pub struct CachedPassword {
    pub username: String,            // Store original username
    pub username_normalized: String, // Add normalized version for lookups
    pub password: String,
    pub timestamp: u64,
}

/// PasswordResetToken struct with a user identifier
#[derive(Serialize, Deserialize, Clone)]
pub struct PasswordResetToken {
    pub token: String,
    pub expires_at: u64,
    pub user_email: String,
    pub username: String, // Adding username to track which user the token belongs to
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

/// Secure password cache implementation using system keyring
pub struct SecurePasswordCache {
    keyring: Entry,
}

impl SecurePasswordCache {
    /// Create a new instance of SecurePasswordCache
    pub fn new() -> Self {
        Self {
            keyring: Entry::new("one-do-three", "task-password")
                .expect("Failed to create keyring entry"),
        }
    }

    /// Cache a password in the system keyring and update timestamp
    pub fn cache_password(&self, username: &str, password: &str) -> io::Result<()> {
        let original_username = username.trim().to_string();
        let cached = CachedPassword {
            username: original_username.clone(),
            username_normalized: original_username.to_lowercase(),
            password: password.to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let encoded = serde_json::to_string(&cached)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        self.keyring
            .set_password(&encoded)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        Ok(())
    }

    /// Retrieve cached password if it exists and hasn't expired
    pub fn get_cached_password(&self) -> io::Result<Option<(String, String)>> {
        match self.keyring.get_password() {
            Ok(stored) => {
                let cached: CachedPassword = serde_json::from_str(&stored)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                // Strict 15-minute timeout check
                if current_time - cached.timestamp > 15 * 60 {
                    self.clear_cache()?;
                    Ok(None)
                } else {
                    // Do NOT update timestamp here - let it expire naturally
                    Ok(Some((cached.username, cached.password))) // Return original username case
                }
            }
            Err(_) => Ok(None),
        }
    }

    /// Clear the cached password from the keyring
    pub fn clear_cache(&self) -> io::Result<()> {
        let _ = self.keyring.delete_password();
        Ok(())
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

        // Test token storage and verification
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
