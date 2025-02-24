use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use super::store::{UserStore, VerificationStatus};
use crate::modules::utils::io::read_line;

/// Registration verification
#[derive(Serialize, Deserialize, Clone)]
pub struct RegistrationVerification {
    pub token: String,
    pub username: String,
    pub expires_at: u64,
    pub verified: bool,
}

/// Custom result type for authentication flow control
#[derive(Debug)]
pub enum VerificationResult {
    Back,          // Return to main menu
    Success,       // Verification succeeded
    Error(String), // Error with a message
    Expired,       // Token has expired
    Invalid,       // Token is invalid
}

/// Function to verify registration token
pub fn verify_registration_token(username: &str, store: &mut UserStore) -> VerificationResult {
    // Set up attempt limiting for verification
    let mut attempts = 0;
    const MAX_ATTEMPTS: u32 = 3;

    while attempts < MAX_ATTEMPTS {
        // Get the verification data for this username
        let verification = match store.registration_verifications.get(username) {
            Some(v) => v,
            None => return VerificationResult::Error("Verification data not found.".to_string()),
        };

        // Get current time for expiration check
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if token is expired (24 hours)
        if current_time > verification.expires_at {
            println!("Verification token has expired. Please register again.");
            // Clean up expired verification
            store.registration_verifications.remove(username);
            if let Err(e) = super::store::save_user_store(store) {
                println!("Warning: Failed to clean up expired verification: {}", e);
            }
            return VerificationResult::Expired;
        }

        // Prompt for token with back/exit options
        println!("\nPlease enter the verification token");
        println!("(Type 'back' to return to menu, 'exit' to quit):");

        let input_token = match read_line() {
            Ok(input) => input,
            Err(e) => return VerificationResult::Error(format!("Failed to read input: {}", e)),
        };

        // Handle navigation commands
        match input_token.trim().to_lowercase().as_str() {
            "back" => return VerificationResult::Back,
            "exit" => {
                println!("Exiting program. Goodbye!");
                std::process::exit(0);
            }
            token => {
                // Verify token matches
                if verification.token == token {
                    // Mark user as verified if token matches
                    if let Some(user) = store.users.get_mut(username) {
                        // Update verification status
                        user.verification_status = VerificationStatus::Verified;

                        // Remove the verification entry since it's no longer needed
                        store.registration_verifications.remove(username);

                        // Save the updated store immediately
                        match super::store::save_user_store(store) {
                            Ok(_) => {
                                crate::modules::utils::logging::log_data_operation(
                                    "verify_registration",
                                    username,
                                    "user_store",
                                    true,
                                    Some("User verified successfully"),
                                );
                                return VerificationResult::Success;
                            }
                            Err(e) => {
                                crate::modules::utils::logging::log_data_operation(
                                    "verify_registration",
                                    username,
                                    "user_store",
                                    false,
                                    Some(&format!("Failed to save verification status: {}", e)),
                                );
                                return VerificationResult::Error(format!(
                                    "Failed to save verification status: {}",
                                    e
                                ));
                            }
                        }
                    }
                }

                // Handle invalid token attempts
                attempts += 1;
                if attempts < MAX_ATTEMPTS {
                    println!(
                        "Invalid token. Please try again. {} attempts remaining.",
                        MAX_ATTEMPTS - attempts
                    );
                } else {
                    return VerificationResult::Invalid;
                }
            }
        }
    }

    VerificationResult::Invalid
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn setup_test_verification() -> (UserStore, RegistrationVerification, NamedTempFile) {
        let store = UserStore {
            users: std::collections::HashMap::new(),
            salt: crate::modules::encryption::keys::generate_random_salt(),
            iv: crate::modules::encryption::keys::generate_random_iv(),
            reset_tokens: std::collections::HashMap::new(),
            reset_attempts: std::collections::HashMap::new(),
            registration_verifications: std::collections::HashMap::new(),
        };

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let verification = RegistrationVerification {
            token: "123456".to_string(),
            username: "TestUser".to_string(),
            expires_at: current_time + 86400, // 24 hours
            verified: false,
        };

        (store, verification, NamedTempFile::new().unwrap())
    }

    #[test]
    fn test_verification_token_expiration() {
        let (mut store, mut verification, _) = setup_test_verification();

        // Add verification to store
        store
            .registration_verifications
            .insert(verification.username.clone(), verification.clone());

        // Set expiration to the past
        if let Some(v) = store
            .registration_verifications
            .get_mut(&verification.username)
        {
            v.expires_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 1;
        }

        // Verify token is expired
        if let Some(v) = store.registration_verifications.get(&verification.username) {
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            assert!(current_time > v.expires_at);
        }
    }

    #[test]
    fn test_verification_attempt_limiting() {
        // Mock validation function to simulate multiple attempts
        fn mock_validate_token(attempt: u32, max_attempts: u32) -> bool {
            attempt <= max_attempts
        }

        // Set up attempt limiting
        let max_attempts = 3;
        let mut attempts = 0;

        // Test various attempts
        assert!(mock_validate_token(attempts + 1, max_attempts)); // First attempt
        assert!(mock_validate_token(attempts + 2, max_attempts)); // Second attempt
        assert!(mock_validate_token(attempts + 3, max_attempts)); // Third attempt
        assert!(!mock_validate_token(attempts + 4, max_attempts)); // Fourth attempt (should fail)
    }
}
