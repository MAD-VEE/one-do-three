use super::{AdminConfig, SecureAdminManager};
use crate::modules::auth::password::validate_password;
use rpassword::read_password;

/// Initialize admin credentials with enhanced security
pub fn enhanced_initialize_admin_credentials(setup_token: &str) -> Result<(), String> {
    // Load and verify admin configuration
    let mut config =
        AdminConfig::load().map_err(|e| format!("Failed to load admin configuration: {}", e))?;

    // Validate setup token
    if !config.validate_setup_token(setup_token) {
        return Err("Invalid or expired setup token".to_string());
    }

    // Proceed with admin initialization
    let admin_manager = SecureAdminManager::new();

    if admin_manager.is_initialized() {
        return Err("Admin credentials are already initialized.".to_string());
    }

    println!("\n=== Initial Admin Setup ===");
    println!("Please set the administrator password.");
    println!("This password will be required for system configuration changes.");

    // Get and validate admin password
    let password = loop {
        println!("\nEnter admin password (min 12 chars, must include uppercase, lowercase, number, and special char):");
        let pwd = read_password().map_err(|e| format!("Failed to read password: {}", e))?;

        if pwd.len() < 12 {
            println!("Admin password must be at least 12 characters long.");
            continue;
        }

        if let Err(e) = validate_password(&pwd) {
            println!("Password validation failed: {:?}", e);
            continue;
        }

        println!("Confirm password:");
        let confirm = read_password().map_err(|e| format!("Failed to read password: {}", e))?;

        if pwd != confirm {
            println!("Passwords don't match. Please try again.");
            continue;
        }

        break pwd;
    };

    // Initialize admin credentials
    admin_manager.initialize_admin(&password)?;

    // Clear used setup token
    config.setup_token = None;
    config.setup_token_expiry = None;
    config
        .save()
        .map_err(|e| format!("Failed to update admin configuration: {}", e))?;

    println!("\nAdmin credentials initialized successfully!");
    Ok(())
}

/// Function to generate initial admin setup token
pub fn generate_admin_setup_token() -> Result<String, String> {
    // Load current configuration
    let mut config =
        AdminConfig::load().map_err(|e| format!("Failed to load admin configuration: {}", e))?;

    // Verify admin is not already initialized
    let admin_manager = SecureAdminManager::new();
    if admin_manager.is_initialized() {
        return Err("Admin is already initialized".to_string());
    }

    // Generate and save new token
    let token = config.generate_setup_token();

    config
        .save()
        .map_err(|e| format!("Failed to save admin configuration: {}", e))?;

    Ok(token)
}

/// Enhanced admin verification with rate limiting
pub fn enhanced_verify_admin(password: &str) -> Result<bool, String> {
    // Load admin configuration
    let mut config =
        AdminConfig::load().map_err(|e| format!("Failed to load admin configuration: {}", e))?;

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Check for account lockout
    if config.auth_tracker.is_locked_out(current_time) {
        let remaining = config.auth_tracker.lockout_until - current_time;
        return Err(format!(
            "Admin authentication is locked. Try again in {} minutes.",
            remaining / 60 + 1
        ));
    }

    // Reset attempts if lockout duration has passed
    config.auth_tracker.maybe_reset_attempts(current_time);

    // Verify admin password
    let admin_manager = SecureAdminManager::new();
    match admin_manager.verify_admin(password) {
        Ok(true) => {
            config.auth_tracker.record_success();
            config
                .save()
                .map_err(|e| format!("Failed to update admin configuration: {}", e))?;
            Ok(true)
        }
        Ok(false) => {
            config.auth_tracker.record_failed_attempt(current_time);
            config
                .save()
                .map_err(|e| format!("Failed to update admin configuration: {}", e))?;
            Ok(false)
        }
        Err(e) => Err(e),
    }
}

/// Handle the admin password change flow
pub fn handle_admin_password_change() -> Result<(), String> {
    let admin_manager = SecureAdminManager::new();

    // Check if admin credentials exist
    if !admin_manager.is_initialized() {
        return Err(
            "Admin credentials not initialized. Please run --admin-setup first.".to_string(),
        );
    }

    println!("\n=== Admin Password Change ===");
    println!("Please enter current admin password:");
    let current_password =
        read_password().map_err(|e| format!("Failed to read current password: {}", e))?;

    // Verify current password
    if !admin_manager.verify_admin(&current_password)? {
        return Err("Current password is incorrect".to_string());
    }

    // Get and validate new password
    println!("\nEnter new admin password (min 12 chars, must include uppercase, lowercase, number, and special char):");
    let new_password =
        read_password().map_err(|e| format!("Failed to read new password: {}", e))?;

    // Extra strong validation for admin password
    if new_password.len() < 12 {
        return Err("Admin password must be at least 12 characters long.".to_string());
    }

    if let Err(e) = validate_password(&new_password) {
        return Err(format!("Password validation failed: {:?}", e));
    }

    // Confirm new password
    println!("Confirm new password:");
    let confirm_password =
        read_password().map_err(|e| format!("Failed to read password confirmation: {}", e))?;

    if new_password != confirm_password {
        return Err("Passwords don't match".to_string());
    }

    // Change the password using the existing method
    admin_manager.change_admin_password(&current_password, &new_password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::admin::config::AdminAuthTracker;

    // Create a mock keyring for testing
    struct MockKeyring {
        data: Option<String>,
    }

    impl MockKeyring {
        fn new() -> Self {
            Self { data: None }
        }

        fn set_password(&mut self, password: &str) -> Result<(), String> {
            self.data = Some(password.to_string());
            Ok(())
        }

        fn get_password(&self) -> Result<String, String> {
            match &self.data {
                Some(data) => Ok(data.clone()),
                None => Err("No password set".to_string()),
            }
        }
    }

    // Mock the entire admin configuration for tests
    struct MockAdminConfig {
        auth_tracker: AdminAuthTracker,
    }

    impl MockAdminConfig {
        fn new() -> Self {
            Self {
                auth_tracker: AdminAuthTracker::new(),
            }
        }

        fn load() -> Result<MockAdminConfig, String> {
            Ok(MockAdminConfig::new())
        }

        fn save(&self) -> Result<(), String> {
            Ok(())
        }
    }

    // Mock SecureAdminManager for testing
    struct MockSecureAdminManager {
        keyring: MockKeyring,
        initialized: bool,
    }

    impl MockSecureAdminManager {
        fn new() -> Self {
            Self {
                keyring: MockKeyring::new(),
                initialized: false,
            }
        }

        fn is_initialized(&self) -> bool {
            self.initialized
        }

        fn initialize_admin(&mut self, password: &str) -> Result<(), String> {
            if self.is_initialized() {
                return Err("Admin credentials already initialized".to_string());
            }

            let salt = crate::modules::encryption::keys::generate_random_salt();
            let password_hash =
                crate::modules::encryption::keys::derive_key_from_passphrase(password, &salt);

            let admin_data = format!("{}:{}", hex::encode(&salt), hex::encode(password_hash));

            self.keyring.set_password(&admin_data)?;
            self.initialized = true;
            Ok(())
        }

        fn verify_admin(&self, password: &str) -> Result<bool, String> {
            if !self.initialized {
                return Err("Admin not initialized".to_string());
            }

            let stored_data = self.keyring.get_password()?;

            let parts: Vec<&str> = stored_data.split(':').collect();
            if parts.len() != 2 {
                return Err("Invalid admin credential format".to_string());
            }

            let salt =
                hex::decode(parts[0]).map_err(|e| format!("Failed to decode salt: {}", e))?;
            let stored_hash = parts[1];

            let test_hash = hex::encode(
                crate::modules::encryption::keys::derive_key_from_passphrase(password, &salt),
            );

            Ok(test_hash == stored_hash)
        }
    }

    // Mock version of enhanced_verify_admin for testing
    fn mock_enhanced_verify_admin(
        admin_manager: &MockSecureAdminManager,
        password: &str,
        config: &mut MockAdminConfig,
    ) -> Result<bool, String> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check for account lockout
        if config.auth_tracker.is_locked_out(current_time) {
            let remaining = config.auth_tracker.lockout_until - current_time;
            return Err(format!(
                "Admin authentication is locked. Try again in {} minutes.",
                remaining / 60 + 1
            ));
        }

        // Reset attempts if lockout duration has passed
        config.auth_tracker.maybe_reset_attempts(current_time);

        // Verify admin password
        match admin_manager.verify_admin(password) {
            Ok(true) => {
                config.auth_tracker.record_success();
                config.save()?;
                Ok(true)
            }
            Ok(false) => {
                config.auth_tracker.record_failed_attempt(current_time);
                config.save()?;
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    #[test]
    fn test_admin_setup_flow() {
        // Generate setup token
        let mut config = AdminConfig::new();
        let token = config.generate_setup_token();
        assert!(!token.is_empty());

        // Test token validation
        assert!(config.validate_setup_token(&token));
        assert!(!config.validate_setup_token("invalid_token"));

        // Test token expiration
        config.setup_token_expiry = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 1,
        );
        assert!(!config.validate_setup_token(&token));
    }

    #[test]
    fn test_admin_verification() {
        // Create mock objects
        let mut admin_manager = MockSecureAdminManager::new();
        let password = "AdminTest123!";

        // Initialize admin
        assert!(admin_manager.initialize_admin(password).is_ok());

        // Load the config instead of creating it directly
        let mut config = MockAdminConfig::load().expect("Failed to load config");

        // Test correct password
        let result = mock_enhanced_verify_admin(&admin_manager, password, &mut config);
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Test incorrect password
        let result = mock_enhanced_verify_admin(&admin_manager, "WrongPassword123!", &mut config);
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // Test that failed attempts are tracked
        assert!(config.auth_tracker.failed_attempts > 0);

        // Test reset
        config.auth_tracker.record_success();
        assert_eq!(config.auth_tracker.failed_attempts, 0);
    }
}
