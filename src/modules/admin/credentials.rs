use base64::{engine::general_purpose::STANDARD as base64, Engine as _};
use keyring::Entry;

use super::config::AdminConfig;
use crate::modules::encryption::{decrypt_data, encrypt_data};

/// Structure to manage admin credentials securely
pub struct SecureAdminManager {
    keyring: Entry,
}

impl SecureAdminManager {
    pub fn new() -> Self {
        Self {
            keyring: Entry::new("one-do-three", "admin-credentials")
                .expect("Failed to create keyring entry"),
        }
    }

    /// Check if admin credentials are initialized
    pub fn is_initialized(&self) -> bool {
        self.keyring.get_password().is_ok()
    }

    /// Initialize admin credentials
    pub fn initialize_admin(&self, password: &str) -> Result<(), String> {
        if self.is_initialized() {
            return Err("Admin credentials already initialized".to_string());
        }

        // Generate a secure salt for admin password
        let salt = crate::modules::encryption::keys::generate_random_salt();

        // Hash the password with the salt
        let password_hash =
            crate::modules::encryption::keys::derive_key_from_passphrase(password, &salt);

        // Store both salt and hash
        let admin_data = format!("{}:{}", hex::encode(&salt), hex::encode(password_hash));

        self.keyring
            .set_password(&admin_data)
            .map_err(|e| format!("Failed to store admin credentials: {}", e))
    }

    /// Verify admin password
    pub fn verify_admin(&self, password: &str) -> Result<bool, String> {
        let stored_data = self
            .keyring
            .get_password()
            .map_err(|e| format!("Failed to retrieve admin credentials: {}", e))?;

        let parts: Vec<&str> = stored_data.split(':').collect();
        if parts.len() != 2 {
            return Err("Invalid admin credential format".to_string());
        }

        let salt = hex::decode(parts[0]).map_err(|e| format!("Failed to decode salt: {}", e))?;
        let stored_hash = parts[1];

        let test_hash = hex::encode(
            crate::modules::encryption::keys::derive_key_from_passphrase(password, &salt),
        );

        Ok(test_hash == stored_hash)
    }

    /// Change admin password
    pub fn change_admin_password(
        &self,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), String> {
        if !self.verify_admin(current_password)? {
            return Err("Current password is incorrect".to_string());
        }

        // Generate new salt
        let new_salt = crate::modules::encryption::keys::generate_random_salt();

        // Hash the new password
        let new_hash =
            crate::modules::encryption::keys::derive_key_from_passphrase(new_password, &new_salt);

        // Store new credentials
        let admin_data = format!("{}:{}", hex::encode(&new_salt), hex::encode(new_hash));

        self.keyring
            .set_password(&admin_data)
            .map_err(|e| format!("Failed to update admin credentials: {}", e))
    }
}

// Secure storage handler for admin configuration
// This struct provides encrypted keyring storage for admin settings
pub struct SecureAdminConfig {
    keyring: Entry, // Keyring entry specifically for admin config
    master_key: crate::modules::security::SecureMasterKey, // Master key for encryption/decryption
}

impl SecureAdminConfig {
    // Initialize secure storage handler with dedicated keyring entry
    pub fn new() -> Self {
        Self {
            keyring: Entry::new("one-do-three", "admin-config")
                .expect("Failed to create keyring entry"),
            master_key: crate::modules::security::SecureMasterKey::new(),
        }
    }

    /// Save admin configuration securely to keyring using encryption
    pub fn save_config(&self, config: &AdminConfig) -> Result<(), String> {
        // Get the master key for encryption
        let master_key = self
            .master_key
            .get_key()
            .map_err(|e| format!("Failed to get master key: {}", e))?;

        // Generate new IV for each save operation for better security
        let iv = crate::modules::encryption::keys::generate_random_iv();

        // Convert config to JSON string for storage
        let config_json = serde_json::to_string(config)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;

        // Encrypt the configuration data
        let encrypted_data = encrypt_data(&config_json, &master_key, &iv);

        // Combine IV and encrypted data for storage
        let mut storage_data = Vec::new();
        storage_data.extend_from_slice(&iv);
        storage_data.extend_from_slice(&encrypted_data);

        // Store as base64 encoded string in keyring
        let encoded_data = base64.encode(&storage_data);
        self.keyring
            .set_password(&encoded_data)
            .map_err(|e| format!("Failed to store admin config: {}", e))
    }

    /// Load admin configuration securely from keyring
    pub fn load_config(&self) -> Result<AdminConfig, String> {
        // Get the master key for decryption
        let master_key = self
            .master_key
            .get_key()
            .map_err(|e| format!("Failed to get master key: {}", e))?;

        // Attempt to retrieve stored configuration
        match self.keyring.get_password() {
            Ok(encoded_data) => {
                // Decode the base64 stored data
                let storage_data = base64
                    .decode(&encoded_data)
                    .map_err(|e| format!("Failed to decode stored data: {}", e))?;

                // Ensure we have at least enough data for the IV
                if storage_data.len() < 16 {
                    return Ok(AdminConfig::new()); // Return new config if data is invalid
                }

                // Split IV and encrypted data
                let iv = &storage_data[..16];
                let encrypted_data = &storage_data[16..];

                // Decrypt and parse the configuration
                let decrypted_data = decrypt_data(encrypted_data, &master_key, iv)
                    .map_err(|e| format!("Failed to decrypt config: {}", e))?;

                serde_json::from_str(&decrypted_data)
                    .map_err(|e| format!("Failed to parse config: {}", e))
            }
            // If no configuration exists yet, return a new default configuration
            Err(_) => Ok(AdminConfig::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Test admin credential initialization
    fn test_admin_credentials() {
        let admin_manager = SecureAdminManager::new();
        let test_password = "AdminTest123!";

        // Initially should not be initialized
        assert!(!admin_manager.is_initialized());

        // Initialize with password
        assert!(admin_manager.initialize_admin(test_password).is_ok());

        // Should now be initialized
        assert!(admin_manager.is_initialized());

        // Verify correct password
        assert!(admin_manager.verify_admin(test_password).unwrap());

        // Verify incorrect password
        assert!(!admin_manager.verify_admin("WrongPassword123!").unwrap());

        // Change password
        assert!(admin_manager
            .change_admin_password(test_password, "NewPassword123!")
            .is_ok());

        // Old password should no longer work
        assert!(!admin_manager.verify_admin(test_password).unwrap());

        // New password should work
        assert!(admin_manager.verify_admin("NewPassword123!").unwrap());
    }

    #[test]
    fn test_admin_config_storage() {
        let secure_config = SecureAdminConfig::new();
        let mut config = AdminConfig::new();

        // Add some test data
        config.generate_setup_token();
        config.allowed_setup_ips.push("192.168.1.1".to_string());

        // Save config
        assert!(secure_config.save_config(&config).is_ok());

        // Load config
        let loaded_config = secure_config.load_config().unwrap();

        // Verify data
        assert_eq!(loaded_config.allowed_setup_ips.len(), 1);
        assert_eq!(loaded_config.allowed_setup_ips[0], "192.168.1.1");
        assert!(loaded_config.setup_token.is_some());
        assert!(loaded_config.setup_token_expiry.is_some());

        // Test loading non-existent config returns default
        let empty_config = secure_config.load_config().unwrap();
        assert_eq!(empty_config.allowed_setup_ips.len(), 0);
        assert!(empty_config.setup_token.is_none());
    }
}
