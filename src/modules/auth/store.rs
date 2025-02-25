use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::modules::encryption::keys::{
    derive_key_from_passphrase, generate_random_iv, generate_random_salt,
};
use crate::modules::encryption::{decrypt_data, encrypt_data};
use crate::USERS_FILE;

/// Define verification status enum
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum VerificationStatus {
    Unverified,
    Verified,
}

impl VerificationStatus {
    // Helper method to check if verified
    pub fn is_verified(&self) -> bool {
        matches!(self, VerificationStatus::Verified)
    }
}

/// Represents a single user with their authentication details and task file location
#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    pub username: String, // Original username as entered by user (for display)
    pub username_normalized: String, // Lowercase version for lookups and comparisons
    pub email: String,
    pub password_hash: String,
    pub created_at: u64,
    pub last_login: u64,
    pub failed_attempts: u32,
    pub last_failed_attempt: u64,
    pub tasks_file: String, // Each user gets their own encrypted tasks file
    pub last_activity: u64, // Timestamp of last user activity
    pub verification_status: VerificationStatus,
}

// Functions to handle password management
impl User {
    // Function to generate a secure, unique filename for user's tasks
    // This prevents information disclosure and filesystem security issues
    pub fn generate_task_filename(&self) -> io::Result<String> {
        // Create tasks directory if it doesn't exist
        std::fs::create_dir_all("tasks")?;

        // Create a unique identifier by combining username and creation timestamp
        // This ensures uniqueness even if usernames are reused
        let unique_id = format!("{}{}", self.username, self.created_at);

        // Use SHA-256 to create a secure hash of the unique identifier
        // This prevents directory traversal attacks and special character issues
        let filename_hash = sha2::Sha256::digest(unique_id.as_bytes());

        // Convert first 8 bytes of hash to hex for a shorter but still unique filename
        // Using 8 bytes (16 hex chars) gives us 2^64 possible filenames
        let safe_filename = hex::encode(&filename_hash[..8]);

        // Store in the tasks subdirectory with a consistent prefix and extension
        // The .dat extension obscures the file content type
        Ok(format!("tasks/user_{}.dat", safe_filename))
    }
}

// Container for all users with encryption metadata for secure storage, and a token store to track active reset tokens, plus registration verifications
#[derive(Serialize, Deserialize)]
pub struct UserStore {
    pub users: HashMap<String, User>,
    pub salt: Vec<u8>,
    pub iv: Vec<u8>,
    pub reset_tokens: HashMap<String, super::tokens::PasswordResetToken>,
    pub reset_attempts: HashMap<String, super::tokens::ResetAttemptTracker>, // Tracks reset attempts by email
    pub registration_verifications: HashMap<String, super::verification::RegistrationVerification>,
}

// Implementation block for UserStore to handle user management operations
impl UserStore {
    // Function to add a new user to the store
    // Takes ownership of username, email and password strings
    // Returns io::Result to handle potential errors
    pub fn add_user(
        &mut self,
        username: String,
        email: String,
        password: String,
    ) -> io::Result<()> {
        // Create tasks directory if it doesn't exist
        std::fs::create_dir_all("tasks")?;

        // Preserve original username and create normalized version for lookups
        let original_username = username.trim().to_string();
        let username_normalized = original_username.to_lowercase();

        // Check if normalized username already exists
        if self.users.contains_key(&username_normalized) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Username already exists",
            ));
        }

        // Get current timestamp for user creation and last login times
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Hash the user's password using PBKDF2 with the store's salt
        let password_hash = derive_key_from_passphrase(&password, &self.salt);
        let password_hash_hex = hex::encode(password_hash);

        // Create new User struct with initial values
        let mut user = User {
            username: original_username.clone(), // Store the original case
            username_normalized: username_normalized.clone(), // Store normalized version
            email,
            password_hash: password_hash_hex,
            created_at: current_time,
            last_login: current_time,
            failed_attempts: 0,
            last_failed_attempt: 0,
            tasks_file: String::new(),
            last_activity: current_time,
            verification_status: VerificationStatus::Unverified, // Initialize as unverified
        };

        // Generate secure filename for user's tasks
        match user.generate_task_filename() {
            Ok(secure_filename) => {
                user.tasks_file = secure_filename;
            }
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to generate secure filename: {}", e),
                ));
            }
        }

        // Insert the new user into the HashMap using normalized username as key
        self.users.insert(username_normalized, user);

        Ok(())
    }
}

// Function to create a new UserStore
pub fn create_user_store() -> UserStore {
    UserStore {
        users: HashMap::new(),
        salt: generate_random_salt(),
        iv: generate_random_iv(),
        reset_tokens: HashMap::new(),
        reset_attempts: HashMap::new(),
        registration_verifications: HashMap::new(), // Initialize verification
    }
}

// Function to save UserStore to file
// Modified function to save the user store to file using the secure master key
pub fn save_user_store(store: &UserStore) -> io::Result<()> {
    use crate::modules::security::SecureMasterKey;
    // use base64::{engine::general_purpose::STANDARD as base64, Engine as _};

    // Create an instance of secure key management and get the master key
    let secure_key = SecureMasterKey::new();

    // Retrieve the master key from secure storage
    let master_key = secure_key.get_key()?;

    // Convert the user store to a JSON string
    let data = serde_json::to_string_pretty(store).unwrap();

    // Encrypt the JSON data using the master key
    let encrypted_data = encrypt_data(&data, &master_key, &store.iv);

    // Prepare the file data with salt, IV, and encrypted data
    let mut file_data = Vec::new();
    file_data.extend_from_slice(&store.salt);
    file_data.extend_from_slice(&store.iv);
    file_data.extend_from_slice(&encrypted_data);

    // Write the complete data to the user store file
    std::fs::File::create(USERS_FILE)?.write_all(&file_data)?;
    Ok(())
}

// Modified function to load the user store from file using the secure master key
pub fn load_user_store() -> io::Result<UserStore> {
    use crate::modules::security::SecureMasterKey;
    use std::fs::File;
    use std::io::Read;

    // Create an instance of secure key management
    let secure_key = SecureMasterKey::new();

    // Ensure we have a master key available
    secure_key.initialize_if_needed()?;

    // Retrieve the master key from secure storage
    let master_key = secure_key.get_key()?;

    // Attempt to open the user store file
    match File::open(USERS_FILE) {
        Ok(mut file) => {
            // Read the entire file into a buffer
            let mut file_data = Vec::new();
            file.read_to_end(&mut file_data)?;

            // Check if file has minimum required data (salt + iv = 32 bytes)
            if file_data.len() >= 32 {
                let _salt = file_data[..16].to_vec();
                let iv = file_data[16..32].to_vec();
                let encrypted_data = &file_data[32..];

                // Attempt to decrypt and parse the user store data
                match decrypt_data(encrypted_data, &master_key, &iv) {
                    Ok(decrypted_data) => match serde_json::from_str(&decrypted_data) {
                        Ok(store) => Ok(store),
                        Err(_) => Ok(create_user_store()), // Create new store if parsing fails
                    },
                    Err(_) => Ok(create_user_store()), // Create new store if decryption fails
                }
            } else {
                // Create new store if file is too short
                Ok(create_user_store())
            }
        }
        Err(_) => Ok(create_user_store()), // Create new store if file doesn't exist
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    // Test fixture to create a temporary user store for testing
    fn setup_test_user_store() -> (UserStore, NamedTempFile) {
        // Create a temporary file for the user store
        let temp_file = NamedTempFile::new().unwrap();

        // Create a new UserStore with test data
        let store = UserStore {
            users: HashMap::new(),
            salt: generate_random_salt(),
            iv: generate_random_iv(),
            reset_tokens: HashMap::new(),
            reset_attempts: HashMap::new(),
            registration_verifications: HashMap::new(),
        };

        // Return the store and temp file (to keep it from being dropped)
        (store, temp_file)
    }

    #[test]
    /// Test user creation and verification
    fn test_user_creation() {
        let (mut store, _temp_file) = setup_test_user_store();

        // Add test user
        let result = store.add_user(
            "TestUser".to_string(),
            "test@example.com".to_string(),
            "Password123!".to_string(),
        );
        assert!(result.is_ok());

        // Verify user was added correctly
        assert!(store.users.contains_key("testuser")); // Should use normalized key
        let user = store.users.get("testuser").unwrap();
        assert_eq!(user.username, "TestUser"); // Should maintain original case
        assert_eq!(user.email, "test@example.com");

        // Test that password hash was created correctly
        let password_hash = hex::encode(derive_key_from_passphrase("Password123!", &store.salt));
        assert_eq!(user.password_hash, password_hash);
    }

    #[test]
    /// Test verification status management
    fn test_verification_status() {
        let (mut store, _temp_file) = setup_test_user_store();

        // Add to store
        store
            .add_user(
                "UnverifiedUser".to_string(),
                "unverified@example.com".to_string(),
                "Password123!".to_string(),
            )
            .unwrap();

        // Verify the user is unverified
        let user = store.users.get("unverifieduser").unwrap();
        assert!(!user.verification_status.is_verified());

        // Test verification status enum methods
        assert!(VerificationStatus::Verified.is_verified());
        assert!(!VerificationStatus::Unverified.is_verified());
    }

    #[test]
    /// Test user task file generation
    fn test_task_file_generation() {
        let (mut store, _temp_file) = setup_test_user_store();

        store
            .add_user(
                "FileTest".to_string(),
                "file@example.com".to_string(),
                "Password123!".to_string(),
            )
            .unwrap();

        let user = store.users.get("filetest").unwrap();

        // Verify filename format
        assert!(user.tasks_file.starts_with("tasks/user_"));
        assert!(user.tasks_file.ends_with(".dat"));

        // Verify it contains a hash component
        let hash_part = user
            .tasks_file
            .strip_prefix("tasks/user_")
            .unwrap()
            .strip_suffix(".dat")
            .unwrap();
        assert_eq!(hash_part.len(), 16);
        assert!(hash_part.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
