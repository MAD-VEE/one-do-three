use std::time::{SystemTime, UNIX_EPOCH};
use keyring::Entry;
use serde_json;

use super::smtp::SmtpCredentials;

/// Structure to manage secure email credentials
pub struct SecureEmailManager {
    // Keyring entry for storing credentials
    keyring: Entry,
}

impl SecureEmailManager {
    // Create a new instance of SecureEmailManager
    pub fn new() -> Self {
        let service_name = "task-manager-email".to_string();
        Self {
            // Create a new keyring entry for storing SMTP credentials
            keyring: Entry::new(&service_name, "smtp-credentials")
                .expect("Failed to create keyring entry"),
        }
    }

    // Store new SMTP credentials in the system keyring
    pub fn store_credentials(
        &self,
        username: &str,
        password: &str,
        host: &str,
        port: u16,
    ) -> Result<(), String> {
        // Create new credentials structure
        let credentials = SmtpCredentials {
            username: username.to_string(),
            password: password.to_string(),
            host: host.to_string(),
            port,
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Serialize credentials to JSON string
        let creds_json = serde_json::to_string(&credentials)
            .map_err(|e| format!("Failed to serialize credentials: {}", e))?;

        // Store in system keyring
        self.keyring
            .set_password(&creds_json)
            .map_err(|e| format!("Failed to store credentials: {}", e))
    }

    // Retrieve stored SMTP credentials from the system keyring
    pub fn get_credentials(&self) -> Result<SmtpCredentials, String> {
        // Get credentials JSON from keyring
        let creds_json = self
            .keyring
            .get_password()
            .map_err(|e| format!("Failed to retrieve credentials: {}", e))?;

        // Deserialize JSON to SmtpCredentials structure
        serde_json::from_str(&creds_json).map_err(|e| format!("Failed to parse credentials: {}", e))
    }

    // Delete stored credentials from the system keyring
    pub fn delete_credentials(&self) -> Result<(), String> {
        self.keyring
            .delete_password()
            .map_err(|e| format!("Failed to delete credentials: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockEmailManager {
        stored_credentials: Option<SmtpCredentials>,
    }

    impl MockEmailManager {
        fn new() -> Self {
            Self {
                stored_credentials: None,
            }
        }

        fn store_credentials(
            &mut self,
            username: &str,
            password: &str,
            host: &str,
            port: u16,
        ) -> Result<(), String> {
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            self.stored_credentials = Some(SmtpCredentials {
                username: username.to_string(),
                password: password.to_string(),
                host: host.to_string(),
                port,
                last_updated: current_time,
            });
            Ok(())
        }

        fn get_credentials(&self) -> Result<SmtpCredentials, String> {
            match &self.stored_credentials {
                Some(creds) => Ok(SmtpCredentials {
                    username: creds.username.clone(),
                    password: creds.password.clone(),
                    host: creds.host.clone(),
                    port: creds.port,
                    last_updated: creds.last_updated,
                }),
                None => Err("No credentials stored".to_string()),
            }
        }

        fn delete_credentials(&mut self) -> Result<(), String> {
            self.stored_credentials = None;
            Ok(())
        }
    }

    #[test]
    fn test_email_manager() {
        let mut email_manager = MockEmailManager::new();

        // Initially, no credentials
        assert!(email_manager.get_credentials().is_err());

        // Store credentials
        assert!(email_manager
            .store_credentials("test@example.com", "password123", "smtp.example.com", 587)
            .is_ok());

        // Retrieve credentials
        let creds = email_manager.get_credentials().unwrap();
        assert_eq!(creds.username, "test@example.com");
        assert_eq!(creds.password, "password123");
        assert_eq!(creds.host, "smtp.example.com");
        assert_eq!(creds.port, 587);

        // Delete credentials
        assert!(email_manager.delete_credentials().is_ok());

        // Verify credentials were deleted
        assert!(email_manager.get_credentials().is_err());
    }
}