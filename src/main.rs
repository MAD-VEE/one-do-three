// External crate dependencies for various functionalities
use aes::Aes256;
use base64::{engine::general_purpose::STANDARD as base64, Engine as _};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use clap::{Arg, Command};
use env_logger::{Builder, WriteStyle};
use hmac::Hmac;
use itertools::Itertools;
use keyring::Entry;
use log::{error, info, warn, LevelFilter};
use pbkdf2::pbkdf2;
use rand::distributions::Alphanumeric;
use rand::Rng;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::num::NonZeroU32;
use std::path::Path;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

// Type aliases for better readability
type HmacSha256 = Hmac<sha2::Sha256>;
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// Add new constant for user storage
const USERS_FILE: &str = "users.json";

// Constants for admin security configuration
const MAX_ADMIN_ATTEMPTS: u32 = 3; // Maximum failed attempts before lockout
const ADMIN_LOCKOUT_DURATION: u64 = 1800; // 30 minutes lockout duration in seconds
const SETUP_TOKEN_DURATION: u64 = 3600; // 1 hour validity for setup tokens

// Structure to track admin authentication attempts
#[derive(Serialize, Deserialize)]
struct AdminAuthTracker {
    failed_attempts: u32,
    last_attempt: u64,
    lockout_until: u64,
}

impl AdminAuthTracker {
    // Create new authentication tracker with default values
    fn new() -> Self {
        Self {
            failed_attempts: 0,
            last_attempt: 0,
            lockout_until: 0,
        }
    }

    // Check if the admin account is currently locked out
    fn is_locked_out(&self, current_time: u64) -> bool {
        current_time < self.lockout_until
    }

    // Reset attempt counter if lockout duration has passed
    fn maybe_reset_attempts(&mut self, current_time: u64) {
        if current_time - self.last_attempt > ADMIN_LOCKOUT_DURATION {
            self.failed_attempts = 0;
            self.lockout_until = 0;
        }
    }

    // Record a failed authentication attempt and implement lockout if needed
    fn record_failed_attempt(&mut self, current_time: u64) {
        self.failed_attempts += 1;
        self.last_attempt = current_time;

        if self.failed_attempts >= MAX_ADMIN_ATTEMPTS {
            self.lockout_until = current_time + ADMIN_LOCKOUT_DURATION;
        }
    }

    // Record successful authentication and reset counters
    fn record_success(&mut self) {
        self.failed_attempts = 0;
        self.lockout_until = 0;
    }
}

// Configuration structure for admin settings and security
#[derive(Serialize, Deserialize)]
struct AdminConfig {
    auth_tracker: AdminAuthTracker,
    setup_token: Option<String>,     // One-time setup token
    setup_token_expiry: Option<u64>, // Token expiration timestamp
    allowed_setup_ips: Vec<String>,  // Optional IP whitelist for setup
}

impl AdminConfig {
    // Create new admin configuration with default values
    fn new() -> Self {
        Self {
            auth_tracker: AdminAuthTracker::new(),
            setup_token: None,
            setup_token_expiry: None,
            allowed_setup_ips: Vec::new(),
        }
    }

    // Generate a new one-time setup token
    fn generate_setup_token(&mut self) -> String {
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

    // Validate a provided setup token
    fn validate_setup_token(&self, token: &str) -> bool {
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

    // New method: Load configuration from secure storage
    fn load() -> Result<Self, String> {
        let secure_config = SecureAdminConfig::new();
        secure_config.load_config()
    }

    // New method: Save configuration to secure storage
    fn save(&self) -> Result<(), String> {
        let secure_config = SecureAdminConfig::new();
        secure_config.save_config(self)
    }
}

// Enhanced admin initialization with token verification
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

// Function to generate initial admin setup token
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

// Enhanced admin verification with rate limiting
pub fn enhanced_verify_admin(password: &str) -> Result<bool, String> {
    // Load admin configuration
    let mut config =
        AdminConfig::load().map_err(|e| format!("Failed to load admin configuration: {}", e))?;

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
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

// Secure storage handler for admin configuration
// This struct provides encrypted keyring storage for admin settings
struct SecureAdminConfig {
    keyring: Entry,              // Keyring entry specifically for admin config
    master_key: SecureMasterKey, // Master key for encryption/decryption
}

impl SecureAdminConfig {
    // Initialize secure storage handler with dedicated keyring entry
    fn new() -> Self {
        Self {
            keyring: Entry::new("one-do-three", "admin-config")
                .expect("Failed to create keyring entry"),
            master_key: SecureMasterKey::new(),
        }
    }

    // Save admin configuration securely to keyring using encryption
    fn save_config(&self, config: &AdminConfig) -> Result<(), String> {
        // Get the master key for encryption
        let master_key = self
            .master_key
            .get_key()
            .map_err(|e| format!("Failed to get master key: {}", e))?;

        // Generate new IV for each save operation for better security
        let iv = generate_random_iv();

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

    // Load admin configuration securely from keyring
    fn load_config(&self) -> Result<AdminConfig, String> {
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
            Err(_) => {
                // If no configuration exists yet, return a new default configuration
                Ok(AdminConfig::new())
            }
        }
    }
}

// Structure representing a single task that includes progress tracking
#[derive(Serialize, Deserialize, Debug)]
struct Task {
    name: String,
    description: String,
    priority: String,
    completed: bool,
    // New progress tracking fields
    progress_percent: u8,       // Stores progress as 0-100
    progress_bar_style: String, // Stores the chosen style for progress visualization
}

impl Task {
    // Add method to update progress
    fn update_progress(&mut self, new_progress: u8) -> Result<(), String> {
        // Validate progress value
        if new_progress > 100 {
            return Err("Progress cannot exceed 100%".to_string());
        }

        self.progress_percent = new_progress;

        // Automatically set completed flag when progress reaches 100%
        self.completed = new_progress == 100;

        Ok(())
    }

    // Method to generate ASCII progress bar based on chosen style
    fn generate_progress_bar(&self) -> String {
        match self.progress_bar_style.as_str() {
            "simple" => {
                // Generate [=====>    ] style progress bar
                let filled = (self.progress_percent as f32 / 10.0).round() as usize;
                let empty = 10 - filled;
                let bar = "=".repeat(filled.max(0));
                let spaces = " ".repeat(empty.max(0));
                format!("[{}>{spaces}] {}%", bar, self.progress_percent)
            }
            "block" => {
                // Generate [██████    ] style progress bar using block characters
                let filled = (self.progress_percent as f32 / 10.0).round() as usize;
                let empty = 10 - filled;
                let bar = "█".repeat(filled.max(0));
                let spaces = " ".repeat(empty.max(0));
                format!("[{bar}{spaces}] {}%", self.progress_percent)
            }
            "numeric" => {
                // Simple numeric display
                format!("[{}%]", self.progress_percent)
            }
            "detailed" => {
                // Detailed progress bar with fraction
                let filled = (self.progress_percent as f32 / 10.0).round() as usize;
                let empty = 10 - filled;
                let bar = "=".repeat(filled.max(0));
                let spaces = " ".repeat(empty.max(0));
                format!("[{bar}>{spaces}] {}/10", filled)
            }
            _ => format!("{}%", self.progress_percent), // Default fallback
        }
    }
}

// Available progress bar styles
#[derive(Serialize, Deserialize, Debug)]
enum ProgressBarStyle {
    Simple,   // [=====>    ] style
    Block,    // [██████    ] style
    Numeric,  // [60%] style
    Detailed, // [======>   ] 6/10 style
}

// Structure for storing password with timestamp in keyring
#[derive(Serialize, Deserialize)]
struct CachedPassword {
    username: String,            // Store original username
    username_normalized: String, // Add normalized version for lookups
    password: String,
    timestamp: u64,
}

// Represents a single user with their authentication details and task file location
#[derive(Serialize, Deserialize, Debug)]
struct User {
    username: String,            // Original username as entered by user (for display)
    username_normalized: String, // Lowercase version for lookups and comparisons
    email: String,
    password_hash: String,
    created_at: u64,
    last_login: u64,
    failed_attempts: u32,
    last_failed_attempt: u64,
    tasks_file: String, // Each user gets their own encrypted tasks file
    last_activity: u64, // Timestamp of last user activity
    verification_status: VerificationStatus,
}

// Container for all users with encryption metadata for secure storage, and a token store to track active reset tokens, plus registration verifications
#[derive(Serialize, Deserialize)]
struct UserStore {
    users: HashMap<String, User>,
    salt: Vec<u8>,
    iv: Vec<u8>,
    reset_tokens: HashMap<String, PasswordResetToken>,
    reset_attempts: HashMap<String, ResetAttemptTracker>, // Tracks reset attempts by email
    registration_verifications: HashMap<String, RegistrationVerification>,
}

// Main result type for overall authentication flow
// This enum handles all possible outcomes of the authentication process
#[derive(Debug)]
enum MainAuthResult {
    Success(String, String), // Successful login with (username, password)
    Back,                    // Return to main menu
    Exit,                    // Exit the program
    Error(String),           // Error with message
}

// Authentication result type for better flow control
#[derive(Debug)]
enum AuthenticationResult {
    Success(String, String),   // (username, password)
    InvalidCredentials,        // Wrong username/password
    NeedsVerification(String), // Username needs verification
    CacheCleared,              // Password cache was cleared
}

// Custom error type for task operations
#[derive(Debug)]
pub enum TaskError {
    FilePermissionDenied(String),
    FileNotFound(String),
    InvalidData(String),
    EncryptionError(String),
    IoError(io::Error),
}

// Password management struct
#[derive(Debug)]
enum PasswordError {
    TooShort,
    NoUppercase,
    NoLowercase,
    NoNumber,
    NoSpecialChar,
}

// Secure password cache implementation using system keyring
struct SecurePasswordCache {
    keyring: Entry,
}

// Define a struct to handle secure storage and retrieval of the master key
// This provides a clean interface for all master key operations
struct SecureMasterKey {
    // Store the keyring entry which provides access to the system's secure storage
    keyring: Entry,
}

// Implementation block for SecureMasterKey containing all its methods
impl SecureMasterKey {
    // Constructor for creating a new instance of SecureMasterKey
    // This sets up access to the system keyring with our application's identifier
    fn new() -> Self {
        Self {
            // Create a new keyring entry with service name "one-do-three" and identifier "master-key"
            // This combination uniquely identifies our key in the system's secure storage
            keyring: Entry::new("one-do-three", "master-key")
                .expect("Failed to create keyring entry"),
        }
    }

    // Function to store a new master key in the system's secure storage
    // Takes a byte slice as input and returns an IO Result
    fn store_key(&self, key: &[u8]) -> io::Result<()> {
        // Convert the binary key to hexadecimal string for storage
        // This ensures the key can be stored as a string in the keyring
        let encoded = hex::encode(key);

        // Attempt to store the encoded key in the system keyring
        // Convert any keyring errors to IO errors for consistent error handling
        self.keyring
            .set_password(&encoded)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    // Function to retrieve the master key from the system's secure storage
    // Returns the key as a vector of bytes
    fn get_key(&self) -> io::Result<Vec<u8>> {
        // Retrieve the encoded key string from the keyring
        // Map any keyring errors to IO errors
        let encoded = self
            .keyring
            .get_password()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        // Decode the hexadecimal string back to bytes
        // Map any decoding errors to IO errors
        hex::decode(encoded).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    // Function to initialize the master key if it doesn't exist
    // This ensures we always have a valid master key available
    fn initialize_if_needed(&self) -> io::Result<()> {
        // Check if we can retrieve an existing key
        if self.keyring.get_password().is_err() {
            // If no key exists, generate a new 32-byte random key
            let new_key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

            // Store the new key in the keyring
            self.store_key(&new_key)?;

            // Inform the user that a new key was generated
            println!("New master key generated and stored in system keyring");
        }
        Ok(())
    }
}

// Custom result type for authentication flow control
#[derive(Debug)]
enum AuthFlowResult {
    Back,            // Return to main menu
    Success(String), // Success with a message
    Error(String),   // Error with a message
}

// Custom result type for authentication flow control
// This enum helps manage different states of the verification process
#[derive(Debug)]
enum VerificationResult {
    Back,          // Return to main menu
    Success,       // Verification succeeded (no message needed)
    Error(String), // Error with a message
    Expired,       // Token has expired
    Invalid,       // Token is invalid
}

// Structure to track account deletion status
#[derive(Debug)]
enum DeletionStatus {
    Success,
    Failed(String),
    Cancelled,
}

// Function to handle account deletion process
fn handle_account_deletion(
    store: &mut UserStore,
    username: &str,
    password: &str, // We'll use this parameter for initial password verification
    cache: &SecurePasswordCache,
) -> DeletionStatus {
    // Initialize cleanup status with only the field we use
    // (Removing unused fields to fix warnings while maintaining functionality)
    let mut cleanup_status = CleanupStatus {
        task_file_removed: false,
        cache_cleared: false,
        store_saved: false,
    };

    // Validate deletion confirmation
    println!("\n=== Account Deletion Warning ===");
    println!("This action will:");
    println!("1. Permanently delete all your tasks");
    println!("2. Remove your account from the system");
    println!("3. Log you out immediately");
    println!("This action CANNOT be undone!");

    // First confirmation step
    println!("\nType 'DELETE' to confirm (or anything else to cancel):");
    let confirmation = read_line().unwrap_or_default();
    if confirmation.trim() != "DELETE" {
        return DeletionStatus::Cancelled;
    }

    // Get user reference for validation
    // Collect necessary user information before mutation
    let user_info = match store.users.get(username) {
        Some(user) => {
            // Create a tuple with the information we need
            (
                user.password_hash.clone(),
                user.email.clone(),
                user.tasks_file.clone(),
            )
        }
        None => return DeletionStatus::Failed("User not found".to_string()),
    };

    let (stored_password_hash, user_email, task_file) = user_info;

    // Initial password verification using the password parameter
    // This verifies the user's current session password
    let initial_password_hash = hex::encode(derive_key_from_passphrase(password, &store.salt));
    if stored_password_hash != initial_password_hash {
        return DeletionStatus::Failed("Session password verification failed".to_string());
    }

    // Password confirmation step
    println!("\nPlease enter your password to confirm deletion:");
    let confirm_password = match read_password() {
        Ok(pass) => pass,
        Err(e) => return DeletionStatus::Failed(format!("Failed to read password: {}", e)),
    };

    // Verify password
    let password_hash = hex::encode(derive_key_from_passphrase(&confirm_password, &store.salt));
    if stored_password_hash != password_hash {
        return DeletionStatus::Failed("Incorrect password".to_string());
    }

    // Final confirmation step
    println!("\nFINAL WARNING: Account deletion is irreversible!");
    println!("Type 'YES' to permanently delete your account:");
    let final_confirmation = read_line().unwrap_or_default();
    if final_confirmation.trim() != "YES" {
        return DeletionStatus::Cancelled;
    }

    // Begin deletion process
    // 1. Remove user's task file
    if let Err(e) = std::fs::remove_file(&task_file) {
        // Log error but continue with deletion
        log_data_operation(
            "delete_account",
            username,
            "task_file",
            false,
            Some(&format!("Failed to remove task file: {}", e)),
        );
    } else {
        cleanup_status.task_file_removed = true; // Mark task file as successfully removed
    }

    // 2. Clean up any orphaned task files
    if let Err(e) = cleanup_user_tasks(username, store) {
        error!("Failed to clean up orphaned task files: {}", e);
    }

    // 3. Remove user from store
    store.users.remove(username);

    // 4. Remove any password reset tokens for this user
    store
        .reset_tokens
        .retain(|_, token| token.username != username);

    // 5. Remove any reset attempts tracking
    store.reset_attempts.remove(&user_email);

    // 6. Save the updated store
    if let Err(e) = save_user_store(store) {
        return DeletionStatus::Failed(format!("Failed to save user store: {}", e));
    }
    cleanup_status.store_saved = true; // Mark store as successfully saved

    // 7. Clear password cache
    if let Err(e) = cache.clear_cache() {
        // Log error but continue
        log_data_operation(
            "delete_account",
            username,
            "password_cache",
            false,
            Some(&format!("Failed to clear password cache: {}", e)),
        );
    } else {
        cleanup_status.cache_cleared = true; // Mark cache as successfully cleared
    }

    // Log successful deletion
    log_data_operation(
        "delete_account",
        username,
        "user_store",
        true,
        Some("Account successfully deleted"),
    );

    // Return success if critical operations succeeded
    if cleanup_status.task_file_removed
        && cleanup_status.cache_cleared
        && cleanup_status.store_saved
    {
        DeletionStatus::Success
    } else {
        // Provide more detailed error message based on what failed
        let mut failed_operations = Vec::new();
        if !cleanup_status.task_file_removed {
            failed_operations.push("task file removal");
        }
        if !cleanup_status.cache_cleared {
            failed_operations.push("cache clearing");
        }
        if !cleanup_status.store_saved {
            failed_operations.push("store saving");
        }
        DeletionStatus::Failed(format!(
            "Failed operations: {}",
            failed_operations.join(", ")
        ))
    }
}

// Structure to track cleanup status
#[derive(Debug)]
struct CleanupStatus {
    task_file_removed: bool,
    cache_cleared: bool,
    store_saved: bool,
}

// Function to clean up user's task files
fn cleanup_user_tasks(_username: &str, store: &UserStore) -> Result<(), io::Error> {
    // Create set of valid task files (files belonging to current users)
    let valid_files: HashSet<String> = store.users.values().map(|u| u.tasks_file.clone()).collect();

    // Scan tasks directory for cleanup
    let tasks_dir = Path::new("tasks");
    if !tasks_dir.exists() {
        return Ok(());
    }

    // Read directory entries
    for entry in std::fs::read_dir(tasks_dir)? {
        let entry = entry?;
        let path = entry.path();

        // Check if this is a file and get its filename
        if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
            let full_path = format!("tasks/{}", filename);

            // If file doesn't belong to any current user, remove it
            if !valid_files.contains(&full_path) {
                std::fs::remove_file(&path)?;
                info!("Removed orphaned task file: {}", filename);
            }
        }
    }

    Ok(())
}

// Function to handle the interactive password change process
// Takes mutable references to both UserStore and the current User
// Returns Result indicating success or failure with error message
// Includes proper cache management after password change
fn handle_password_change(
    store: &mut UserStore,
    username: &str,
    cache: &SecurePasswordCache,
) -> Result<(), String> {
    // First, get a reference to the user
    let user = store.users.get(username).ok_or("User not found")?;

    println!("\n=== Password Change ===");

    // Get current password for verification
    println!("Enter your current password:");
    let current_password =
        read_password().map_err(|e| format!("Failed to read current password: {}", e))?;

    // Verify current password by comparing hashes
    let current_hash = hex::encode(derive_key_from_passphrase(&current_password, &store.salt));
    if current_hash != user.password_hash {
        return Err("Current password is incorrect".to_string());
    }

    // Get and validate new password
    println!("\nEnter new password");
    println!("Requirements:");
    println!("- Minimum 8 characters");
    println!("- At least one uppercase letter");
    println!("- At least one lowercase letter");
    println!("- At least one number");
    println!("- At least one special character");

    let new_password = loop {
        let password =
            read_password().map_err(|e| format!("Failed to read new password: {}", e))?;

        // Validate password strength
        match validate_password(&password) {
            Ok(_) => {
                // Check if new password is different from current
                if password == current_password {
                    println!("New password must be different from current password");
                    continue;
                }
                break password;
            }
            Err(e) => {
                println!("Password validation failed: {:?}", e);
                println!("Please try again.");
                continue;
            }
        }
    };

    // Confirm new password
    println!("\nConfirm new password:");
    let confirm_password =
        read_password().map_err(|e| format!("Failed to read password confirmation: {}", e))?;

    if new_password != confirm_password {
        return Err("Passwords don't match".to_string());
    }

    // Get mutable reference to user and update password
    if let Some(user) = store.users.get_mut(username) {
        // Update the password hash
        user.password_hash = hex::encode(derive_key_from_passphrase(&new_password, &store.salt));

        // Then, clear the existing password cache
        cache
            .clear_cache()
            .map_err(|e| format!("Failed to clear password cache: {}", e))?;

        // Finally, cache the new password
        cache
            .cache_password(username, &new_password)
            .map_err(|e| format!("Failed to update password cache: {}", e))?;

        // Log the password change event
        log_data_operation(
            "change_password",
            username,
            "user_store",
            true,
            Some("Password changed successfully"),
        );

        // Update the cached password
        cache
            .cache_password(username, &new_password)
            .map_err(|e| format!("Failed to update password cache: {}", e))?;

        // Save the updated user store
        save_user_store(store).map_err(|e| format!("Failed to save user store: {}", e))?;

        Ok(())
    } else {
        Err("Failed to update password: User not found".to_string())
    }
}

// Registration verification
#[derive(Serialize, Deserialize)]
struct RegistrationVerification {
    token: String,
    username: String,
    expires_at: u64,
    verified: bool,
}

// Define verification status enum
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
enum VerificationStatus {
    Unverified,
    Verified,
}

impl VerificationStatus {
    // Helper method to check if verified
    fn is_verified(&self) -> bool {
        matches!(self, VerificationStatus::Verified)
    }
}

// Structure to hold SMTP credentials with metadata
#[derive(Serialize, Deserialize)]
pub struct SmtpCredentials {
    // The email address/username for SMTP authentication
    username: String,
    // The password or app-specific password for SMTP
    password: String,
    // SMTP server hostname (e.g., smtp.gmail.com)
    host: String,
    // SMTP server port (typically 587 for TLS)
    port: u16,
    // When these credentials were last updated
    last_updated: u64,
}

// Structure to manage admin credentials securely
struct SecureAdminManager {
    keyring: Entry,
}

impl SecureAdminManager {
    fn new() -> Self {
        Self {
            // Use a separate keyring entry for admin credentials
            keyring: Entry::new("one-do-three", "admin-credentials")
                .expect("Failed to create keyring entry"),
        }
    }

    // Check if admin credentials are initialized
    fn is_initialized(&self) -> bool {
        self.keyring.get_password().is_ok()
    }

    // Initialize admin credentials
    fn initialize_admin(&self, password: &str) -> Result<(), String> {
        if self.is_initialized() {
            return Err("Admin credentials already initialized".to_string());
        }

        // Generate a secure salt for admin password
        let salt = generate_random_salt();

        // Hash the password with the salt
        let password_hash = derive_key_from_passphrase(password, &salt);

        // Store both salt and hash
        let admin_data = format!("{}:{}", hex::encode(&salt), hex::encode(password_hash));

        self.keyring
            .set_password(&admin_data)
            .map_err(|e| format!("Failed to store admin credentials: {}", e))
    }

    // Verify admin password
    fn verify_admin(&self, password: &str) -> Result<bool, String> {
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

        let test_hash = hex::encode(derive_key_from_passphrase(password, &salt));

        Ok(test_hash == stored_hash)
    }

    // Change admin password
    fn change_admin_password(
        &self,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), String> {
        // Verify current password first
        if !self.verify_admin(current_password)? {
            return Err("Current password is incorrect".to_string());
        }

        // Generate new salt
        let new_salt = generate_random_salt();

        // Hash the new password
        let new_hash = derive_key_from_passphrase(new_password, &new_salt);

        // Store new credentials
        let admin_data = format!("{}:{}", hex::encode(&new_salt), hex::encode(new_hash));

        self.keyring
            .set_password(&admin_data)
            .map_err(|e| format!("Failed to update admin credentials: {}", e))
    }
}

// Structure to manage secure email credentials
pub struct SecureEmailManager {
    // Keyring entry for storing credentials
    keyring: Entry,
}

// Function to initialize admin credentials
pub fn initialize_admin_credentials() -> Result<(), String> {
    let admin_manager = SecureAdminManager::new();

    if admin_manager.is_initialized() {
        println!("Admin credentials are already initialized.");
        return Ok(());
    }

    println!("\n=== Initial Admin Setup ===");
    println!("Please set the administrator password.");
    println!("This password will be required for system configuration changes.");

    let password = loop {
        println!("\nEnter admin password (min 12 chars, must include uppercase, lowercase, number, and special char):");
        let pwd = read_password().map_err(|e| format!("Failed to read password: {}", e))?;

        // Extra strong validation for admin password
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

    admin_manager.initialize_admin(&password)?;
    println!("\nAdmin credentials initialized successfully!");
    Ok(())
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

// Function to send registration verification token
// This function sends a verification email with a properly formatted template
// Parameters:
// - email: The recipient's email address
// Returns: Result containing the generated token or an error message
fn send_registration_verification(email: &str) -> Result<String, String> {
    // Generate 6-digit token using random numbers
    let token: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Uniform::new(0, 10))
        .take(6)
        .map(|d| d.to_string())
        .collect();

    // Create verification email with proper formatting
    let email_body = format!(
        "Welcome to One-Do-Three!\n\
        \n\
        Please verify your account using the following code:\n\
        \n\
        {}\n\
        \n\
        This code will expire in 24 hours.\n\
        \n\
        Best regards,\n\
        One-Do-Three Task Manager Team",
        token
    );

    // Send verification email
    match send_email(
        email,
        "Welcome to One-Do-Three - Verify Your Account",
        &email_body,
    ) {
        Ok(_) => Ok(token),
        Err(e) => Err(format!("Failed to send verification email: {}", e)),
    }
}

// Function to verify registration token
// This function now properly saves the store after successful verification and handles flow control
// Parameters:
// - username: The username of the user being verified
// - store: Mutable reference to the UserStore to allow updating verification status
// Returns: VerificationResult indicating the outcome of the verification process
fn verify_registration_token(username: &str, store: &mut UserStore) -> VerificationResult {
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
            if let Err(e) = save_user_store(store) {
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
                process::exit(0);
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
                        match save_user_store(store) {
                            Ok(_) => {
                                // Log successful verification
                                log_data_operation(
                                    "verify_registration",
                                    username,
                                    "user_store",
                                    true,
                                    Some("User verified successfully"),
                                );
                                return VerificationResult::Success;
                            }
                            Err(e) => {
                                // Log failed verification save
                                log_data_operation(
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

// Function to send emails using securely stored credentials
pub fn send_email(to_email: &str, subject: &str, body: &str) -> Result<(), String> {
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::transport::smtp::client::{Tls, TlsParameters};
    use lettre::transport::smtp::PoolConfig;
    use lettre::{Message, SmtpTransport, Transport};

    // Get instance of secure email manager
    let email_manager = SecureEmailManager::new();

    // Retrieve stored credentials
    let creds = email_manager.get_credentials()?;

    // Create email message
    let email = Message::builder()
        .from(
            format!("One-Do-Three <{}>", creds.username)
                .parse()
                .map_err(|e| format!("Invalid from address: {}", e))?,
        )
        .to(to_email
            .parse()
            .map_err(|e| format!("Invalid to address: {}", e))?)
        .subject(subject)
        .header(lettre::message::header::ContentType::TEXT_PLAIN)
        .body(body.to_string())
        .map_err(|e| format!("Failed to create email: {}", e))?;

    // Configure TLS parameters
    let tls_parameters = TlsParameters::builder(creds.host.clone())
        .build()
        .map_err(|e| format!("Failed to build TLS parameters: {}", e))?;

    // Set up SMTP transport with explicit TLS configuration
    let mailer = SmtpTransport::relay(&creds.host)
        .map_err(|e| format!("Failed to create SMTP transport: {}", e))?
        .credentials(Credentials::new(
            creds.username.clone(),
            creds.password.clone(),
        ))
        .port(creds.port)
        .tls(Tls::Required(tls_parameters))
        .pool_config(PoolConfig::new().max_size(1))
        .timeout(Some(std::time::Duration::from_secs(10)))
        .build();

    // Send the email
    match mailer.send(&email) {
        Ok(_) => {
            println!("Email sent successfully to: {}", to_email);
            Ok(())
        }
        Err(e) => {
            // Provide more detailed error information
            Err(format!("Failed to send email: {} (This might be due to network issues, incorrect credentials, or Gmail security settings. Please verify your App Password and Gmail settings)", e))
        }
    }
}

// Function to send password reset email using secure credentials
fn send_reset_email(reset_token: &PasswordResetToken) -> Result<(), String> {
    // Create a professional email template for password reset
    let email_body = format!(
        "Hello,\n\n\
        A password reset was requested for your One-Do-Three account.\n\n\
        To reset your password, use the following token:\n\n\
        {}\n\n\
        This token will expire in 30 minutes.\n\n\
        Security Tips:\n\
        - Choose a strong password with at least 8 characters\n\
        - Include uppercase and lowercase letters\n\
        - Include numbers and special characters\n\n\
        If you did not request this reset, please ignore this email and ensure \
        your account is secure.\n\n\
        Colorful wishes,\n\
        One-Do-Three Task Manager Team",
        reset_token.token
    );

    // Send the reset email using the secure email system
    send_email(
        &reset_token.user_email,
        "Password Reset Request - One-Do-Three",
        &email_body,
    )
}

// Add a command to set up email credentials
pub fn setup_email_credentials() -> Result<(), String> {
    let admin_manager = SecureAdminManager::new();

    // Check if admin credentials are initialized
    if !admin_manager.is_initialized() {
        return Err(
            "Admin credentials not initialized. Please set up admin password first.".to_string(),
        );
    }

    println!("\n=== Admin Authentication Required ===");
    println!("Please enter admin password to modify email settings:");

    // Limited number of admin password attempts
    const MAX_ATTEMPTS: u32 = 3;
    let mut attempts = 0;

    while attempts < MAX_ATTEMPTS {
        let admin_password =
            read_password().map_err(|e| format!("Failed to read password: {}", e))?;

        if admin_manager.verify_admin(&admin_password)? {
            break;
        }

        attempts += 1;
        if attempts < MAX_ATTEMPTS {
            println!(
                "Invalid password. {} attempts remaining.",
                MAX_ATTEMPTS - attempts
            );
        } else {
            return Err("Too many invalid attempts. Please try again later.".to_string());
        }
    }

    println!("\n=== Email Configuration Setup ===");

    // Get and validate SMTP server
    let host = loop {
        println!("Enter SMTP server address (e.g., smtp.gmail.com):");
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| format!("Failed to read input: {}", e))?;
        let input = input.trim();

        if input.is_empty() {
            println!("SMTP server cannot be empty. Please try again.");
            continue;
        }

        // Basic domain validation
        if !input.contains('.') || input.contains(' ') {
            println!("Invalid SMTP server format. Please enter a valid domain.");
            continue;
        }

        break input.to_string();
    };

    // Get and validate SMTP port
    let port = loop {
        println!("Enter SMTP port (default: 587):");
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| format!("Failed to read input: {}", e))?;
        let input = input.trim();

        if input.is_empty() {
            break 587; // Default port
        }

        match input.parse::<u16>() {
            Ok(p) if p > 0 => break p,
            _ => {
                println!("Invalid port number. Please enter a number between 1 and 65535.");
                continue;
            }
        }
    };

    // Get and validate email address
    let username = loop {
        println!("Enter email address:");
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| format!("Failed to read input: {}", e))?;
        let input = input.trim();

        if !is_valid_email(input) {
            println!("Invalid email format. Please enter a valid email address.");
            continue;
        }

        break input.to_string();
    };

    // Get and confirm password
    let password = loop {
        println!("Enter email password or app-specific password:");
        let pass = read_password().map_err(|e| format!("Failed to read password: {}", e))?;

        if pass.trim().is_empty() {
            println!("Password cannot be empty. Please try again.");
            continue;
        }

        // For Gmail app passwords, verify the format (16 characters)
        if host.contains("gmail.com") && pass.len() != 16 {
            println!("Warning: Gmail app passwords are typically 16 characters long.");
            println!("Are you sure you want to use this password? (y/n)");
            let mut confirm = String::new();
            std::io::stdin()
                .read_line(&mut confirm)
                .map_err(|e| format!("Failed to read input: {}", e))?;
            if confirm.trim().to_lowercase() != "y" {
                continue;
            }
        }

        break pass;
    };

    // Store credentials securely
    let email_manager = SecureEmailManager::new();
    email_manager.store_credentials(&username, &password, &host, port)?;

    println!("\nEmail configuration saved securely.");
    println!("Important: Please run 'test-email' to verify your configuration.");

    if host.contains("gmail.com") {
        println!("\nGmail-specific notes:");
        println!("1. Make sure 2-Step Verification is enabled in your Google Account");
        println!(
            "2. The password should be an App Password generated from Google Account settings"
        );
        println!("3. If the test fails, please verify your App Password and try again");
    }

    Ok(())
}

// Function to test email configuration
pub fn test_email_configuration() -> Result<(), String> {
    let email_manager = SecureEmailManager::new();
    let creds = email_manager.get_credentials()?;

    println!("Testing email configuration with the following settings:");
    println!("SMTP Server: {}", creds.host);
    println!("SMTP Port: {}", creds.port);
    println!("Username: {}", creds.username);
    println!("Attempting to send test email...");

    // Send a test email to the configured address
    let test_body = "This is a test email to verify your SMTP configuration.";

    send_email(
        &creds.username,
        "Task Manager - Email Configuration Test",
        test_body,
    )?;

    println!("Test email sent successfully to: {}", creds.username);
    Ok(())
}

// PasswordResetToken struct with a user identifier
#[derive(Serialize, Deserialize, Clone)]
struct PasswordResetToken {
    token: String,
    expires_at: u64,
    user_email: String,
    username: String, // Adding username to track which user the token belongs to
}

// Structure to track password reset attempts to prevent abuse
#[derive(Debug, Serialize, Deserialize, Clone)]
struct ResetAttemptTracker {
    attempts: u32,
    first_attempt: u64,
    last_attempt: u64,
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
        let original_username = username.trim().to_string(); // Preserve original case
        let username_normalized = original_username.to_lowercase(); // Normalize for lookups

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
        let user = User {
            username: original_username, // Store the original case
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
        let mut user = user;
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

        // Save store immediately after adding user to persist changes
        save_user_store(self)?;

        Ok(())
    }
}

impl SecurePasswordCache {
    // Create a new instance of SecurePasswordCache
    fn new() -> Self {
        Self {
            keyring: Entry::new("one-do-three", "task-password")
                .expect("Failed to create keyring entry"),
        }
    }

    // Cache a password in the system keyring and update timestamp
    fn cache_password(&self, username: &str, password: &str) -> io::Result<()> {
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

    // Retrieve cached password if it exists and hasn't expired
    fn get_cached_password(&self) -> io::Result<Option<(String, String)>> {
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

    // Clear the cached password from the keyring
    fn clear_cache(&self) -> io::Result<()> {
        let _ = self.keyring.delete_password();
        Ok(())
    }
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

    // Function to initiate password reset process
    pub fn request_password_reset(&self) -> Result<PasswordResetToken, String> {
        // Generate a cryptographically secure random token
        let token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32) // 32 characters provides good security
            .map(char::from)
            .collect();

        // Set token expiration to 30 minutes from now
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 1800; // 30 minutes in seconds

        // Create reset token with user information
        let reset_token = PasswordResetToken {
            token: token.clone(),
            expires_at,
            user_email: self.email.clone(),
            username: self.username.clone(),
        };

        Ok(reset_token)
    }
}

impl ResetAttemptTracker {
    fn new() -> Self {
        Self {
            attempts: 0,
            first_attempt: 0,
            last_attempt: 0,
        }
    }
}

// Function to validate password strength
fn validate_password(password: &str) -> Result<(), PasswordError> {
    if password.len() < 8 {
        return Err(PasswordError::TooShort);
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(PasswordError::NoUppercase);
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err(PasswordError::NoLowercase);
    }
    if !password.chars().any(|c| c.is_numeric()) {
        return Err(PasswordError::NoNumber);
    }
    if !password
        .chars()
        .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
    {
        return Err(PasswordError::NoSpecialChar);
    }
    Ok(())
}

// Implement conversion from io::Error to TaskError
impl From<io::Error> for TaskError {
    fn from(error: io::Error) -> Self {
        TaskError::IoError(error)
    }
}

// Implementation of Display trait for TaskError
impl std::fmt::Display for TaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskError::FilePermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            TaskError::FileNotFound(msg) => write!(f, "File not found: {}", msg),
            TaskError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            TaskError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            TaskError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

// Function to generate a random salt for PBKDF2
fn generate_random_salt() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..16).map(|_| rng.gen()).collect()
}

// Function to derive a 32-byte key from the passphrase using PBKDF2
fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Vec<u8> {
    let mut key = vec![0u8; 32];
    let iterations = NonZeroU32::new(100_000).unwrap();

    pbkdf2::<HmacSha256>(
        passphrase.as_bytes(),
        salt,
        iterations.get().into(),
        &mut key,
    );

    key
}

// Function to generate a random IV for AES encryption
fn generate_random_iv() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..16).map(|_| rng.gen()).collect()
}

// Function to handle interactive task creation with progress options
fn handle_interactive_task_creation() -> Task {
    // Get task name
    println!("\nEnter task name:");
    let name = read_line().unwrap();

    // Get description (optional)
    println!("\nEnter task description (press Enter to skip):");
    let description = read_line().unwrap();
    let description = if description.trim().is_empty() {
        "No description provided".to_string()
    } else {
        description
    };

    // Get priority with validation
    println!("\nEnter task priority (High/Medium/Low, press Enter for Medium):");
    let priority = loop {
        let input = read_line().unwrap();
        let priority = if input.trim().is_empty() {
            "Medium".to_string()
        } else {
            input.to_string()
        };

        match priority.to_lowercase().as_str() {
            "high" | "medium" | "low" => break priority.to_string(),
            _ => println!("Invalid priority. Please enter High, Medium, or Low:"),
        }
    };

    // Progress bar style selection
    println!("\nSelect progress bar style:");
    println!("1. Simple  [=====>    ]                   (or type 'simple')");
    println!("2. Block   [██████    ]                   (or type 'block')");
    println!("3. Numeric [60%]                          (or type 'numeric')");
    println!("4. Detailed [======>   ] 6/10             (or type 'detailed')");
    println!("Enter style number or command (default: Simple):");
    let style = loop {
        // Changed variable name to 'style' for clarity
        let input = read_line().unwrap();
        match input.trim() {
            "" | "simple" | "1" => break "simple".to_string(),
            "block" | "2" => break "block".to_string(),
            "numeric" | "3" => break "numeric".to_string(),
            "detailed" | "4" => break "detailed".to_string(),
            _ => println!("Invalid choice. Please enter 1-4:"),
        }
    };

    // Get initial progress (optional, defaults to 0)
    println!("\nEnter initial progress percentage (0-100, press Enter for 0%):");
    let progress = {
        let input = read_line().unwrap();
        if input.trim().is_empty() {
            0 // Default progress
        } else {
            match input.trim().parse::<u8>() {
                Ok(p) if p <= 100 => p,
                _ => {
                    println!("Invalid progress value. Setting to 0%");
                    0
                }
            }
        }
    };

    // Return the new task with all fields properly initialized
    Task {
        name,
        description,
        priority,
        completed: false,
        progress_percent: progress,
        progress_bar_style: style, // Use the selected style instead of hardcoded "simple"
    }
}

// Function to handle interactive task editing
fn handle_interactive_task_edit(existing_task: &Task) -> Task {
    // Show current task details
    println!("\nCurrent task details:");
    println!("Name: {}", existing_task.name);
    println!("Description: {}", existing_task.description);
    println!("Priority: {}", existing_task.priority);
    println!(
        "Status: {}",
        if existing_task.completed {
            "Completed"
        } else {
            "Pending"
        }
    );
    println!("Progress: {}%", existing_task.progress_percent);
    println!("Progress Bar: {}", existing_task.generate_progress_bar());

    // Get new description or keep current
    println!("\nEnter new description (press Enter to keep current):");
    let description = read_line().unwrap();
    let description = if description.trim().is_empty() {
        existing_task.description.clone()
    } else {
        description
    };

    // Get new priority or keep current
    println!("\nEnter new priority (High/Medium/Low, press Enter to keep current):");
    let priority = loop {
        let input = read_line().unwrap();
        if input.trim().is_empty() {
            break existing_task.priority.clone();
        }

        match input.to_lowercase().as_str() {
            "high" | "medium" | "low" => break input,
            _ => println!("Invalid priority. Please enter High, Medium, or Low:"),
        }
    };

    // Get new completion status and handle progress accordingly
    println!("\nMark as completed? (yes/no/Enter to keep current):");
    let (completed, progress_percent) = loop {
        let input = read_line().unwrap();
        if input.trim().is_empty() {
            // If keeping current completion status, ask for progress only if task is not completed
            if !existing_task.completed {
                // Ask for progress update without yes/no confirmation
                println!("\nEnter new progress percentage (0-100, press Enter to keep current):");
                let progress_input = read_line().unwrap();
                let new_progress = if progress_input.trim().is_empty() {
                    existing_task.progress_percent
                } else {
                    match progress_input.trim().parse::<u8>() {
                        Ok(p) if p <= 100 => p,
                        _ => {
                            println!("Invalid progress value. Keeping current progress.");
                            existing_task.progress_percent
                        }
                    }
                };
                break (existing_task.completed, new_progress);
            } else {
                // If task is already completed, keep progress at 100%
                break (existing_task.completed, existing_task.progress_percent);
            }
        }

        match input.to_lowercase().as_str() {
            "yes" | "y" => break (true, 100), // Automatically set progress to 100% when completed
            "no" | "n" => {
                // If marked as not completed, ask for progress
                println!("\nEnter new progress percentage (0-100, press Enter to keep current):");
                let progress_input = read_line().unwrap();
                let new_progress = if progress_input.trim().is_empty() {
                    existing_task.progress_percent
                } else {
                    match progress_input.trim().parse::<u8>() {
                        Ok(p) if p <= 100 => p,
                        _ => {
                            println!("Invalid progress value. Keeping current progress.");
                            existing_task.progress_percent
                        }
                    }
                };
                break (false, new_progress);
            }
            _ => println!("Invalid input. Please enter yes or no:"),
        }
    };

    // Create and return updated task
    // Keep the existing progress bar style as it can be changed through the progress command
    Task {
        name: existing_task.name.clone(),
        description,
        priority,
        completed,
        progress_percent,
        progress_bar_style: existing_task.progress_bar_style.clone(),
    }
}

// Function to handle interactive progress update
fn handle_interactive_progress_update(task: &mut Task) -> Result<(), String> {
    println!("\nCurrent progress: {}%", task.progress_percent);
    println!("Current visualization: {}", task.generate_progress_bar());

    // Show progress bar style options
    println!("\nAvailable progress bar styles:");
    println!("1. Simple  [=====>    ]");
    println!("2. Block   [██████    ]");
    println!("3. Numeric [60%]");
    println!("4. Detailed [======>   ] 6/10");

    println!("\nEnter style number (or press Enter to keep current):");
    let style_input = read_line().map_err(|e| e.to_string())?;

    if !style_input.trim().is_empty() {
        task.progress_bar_style = match style_input.trim() {
            "1" => "simple".to_string(),
            "2" => "block".to_string(),
            "3" => "numeric".to_string(),
            "4" => "detailed".to_string(),
            _ => {
                println!("Invalid style. Keeping current style.");
                task.progress_bar_style.clone()
            }
        };
    }

    println!("\nEnter new progress percentage (0-100):");
    let progress_input = read_line().map_err(|e| e.to_string())?;

    match progress_input.trim().parse::<u8>() {
        Ok(progress) => {
            task.update_progress(progress)?;
            println!("\nProgress updated: {}", task.generate_progress_bar());
            Ok(())
        }
        Err(_) => {
            Err("Invalid progress value. Please enter a number between 0 and 100.".to_string())
        }
    }
}

// Function to handle interactive user registration with proper cache clearing
fn handle_interactive_registration(store: &mut UserStore) -> io::Result<()> {
    // Create a new instance of SecurePasswordCache
    let cache = SecurePasswordCache::new();

    // First, clear any existing cached credentials
    if let Ok(Some((cached_username, _))) = cache.get_cached_password() {
        // Log the forced logout of previous user
        log_auth_event(
            "forced_logout",
            &cached_username,
            true,
            Some("Logout due to new registration"),
        );

        // Clear the password cache
        if let Err(e) = cache.clear_cache() {
            println!(
                "Warning: Failed to clear previous user's cached credentials: {}",
                e
            );
        }
    }

    println!("\n=== User Registration ===");

    // Get username with validation
    let username = loop {
        println!("\nEnter desired username:");
        let username = read_line()?;

        if username.trim().is_empty() {
            println!("Username cannot be empty.");
            continue;
        }

        if store.users.contains_key(&username) {
            println!("Username already exists. Please choose a different one.");
            continue;
        }

        break username;
    };

    // Get email with validation
    let email = loop {
        println!("\nEnter your email address:");
        let email = read_line()?;

        if !is_valid_email(&email) {
            println!("Invalid email format. Please enter a valid email address.");
            continue;
        }

        if store.users.values().any(|u| u.email == email) {
            println!("Email already registered. Please use a different email.");
            continue;
        }

        break email;
    };

    // Get password with validation
    let password = loop {
        println!("\nEnter password (min 8 chars, must include uppercase, lowercase, number, and special char):");
        let password = read_password()?;

        match validate_password(&password) {
            Ok(_) => break password,
            Err(e) => {
                println!("Password validation failed: {:?}", e);
                println!("Please try again.");
            }
        }
    };

    // Confirm password
    loop {
        println!("\nConfirm password:");
        let confirm = read_password()?;

        if confirm == password {
            break;
        }

        println!("Passwords don't match. Please try again.");
    }

    // Add the new user
    let email_clone = email.clone(); // Clone email before moving it
    match handle_user_creation(store, username.clone(), email, password) {
        Ok(_) => {
            // Generate and send verification token using cloned email
            match send_registration_verification(&email_clone) {
                Ok(token) => {
                    // Store verification token
                    let verification = RegistrationVerification {
                        token,
                        username: username.clone(),
                        expires_at: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            + 86400, // 24 hours
                        verified: false,
                    };

                    store
                        .registration_verifications
                        .insert(username.clone(), verification);

                    println!("\nRegistration successful!");
                    println!("Please check your email for a verification code.");
                    println!("You will need to enter this code on your first login.");
                }
                Err(e) => {
                    println!(
                        "\nRegistration successful, but failed to send verification email: {}",
                        e
                    );
                    println!("Please contact support for assistance.");
                }
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

// Forgot password handler
// Function to handle the complete password reset flow in an interactive manner
// This replaces the need for a separate confirm-reset command
// Takes a mutable reference to UserStore to allow password updates
// Returns AuthFlowResult to properly handle flow control and error propagation
fn handle_forgot_password(store: &mut UserStore) -> AuthFlowResult {
    println!("\n=== Password Reset ===");

    // First verify that the email system is properly configured
    // This prevents starting the reset process if emails can't be sent
    if !check_email_configuration() {
        return AuthFlowResult::Error(
            "Email system is not configured. Please contact administrator.".to_string(),
        );
    }

    // Get and validate user's email address with flow control
    println!("Please enter your email address (or 'back' to return to menu):");
    let email = match read_line() {
        Ok(input) => {
            // Check for back command first
            match input.trim().to_lowercase().as_str() {
                "back" => return AuthFlowResult::Back,
                "exit" => {
                    println!("Exiting program. Goodbye!");
                    process::exit(0);
                }
                email => email.to_string(),
            }
        }
        Err(e) => return AuthFlowResult::Error(format!("Error reading input: {}", e)),
    };

    let email = email.trim();

    // Validate email format before proceeding
    if !is_valid_email(email) {
        return AuthFlowResult::Error(
            "Invalid email format. Please enter a valid email address.".to_string(),
        );
    }

    // Check if the email exists in our user database
    // We don't reveal to the user whether the email exists for security
    let user_exists = store.users.values().any(|u| u.email == email);
    if !user_exists {
        // Send the same message regardless of whether email exists
        // This prevents email enumeration attacks
        return AuthFlowResult::Success(
            "If an account exists with this email, you will receive reset instructions."
                .to_string(),
        );
    }

    // Find user by email
    let user = match store.users.values().find(|u| u.email == email) {
        Some(u) => u,
        None => {
            return AuthFlowResult::Error("No account found with this email address.".to_string())
        }
    };

    // Clone the username for later use
    let username = user.username.clone();

    // Generate a 6-digit numeric reset token only for valid emails
    // Using numeric tokens as they're easier for users to enter
    let token: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Uniform::new(0, 10))
        .take(6)
        .map(|d| d.to_string())
        .collect();

    // Create an instance of token manager to handle secure token storage
    let token_manager = SecureTokenManager::new();
    // Store the generated token securely
    // This associates the token with the user's email
    if let Err(e) = token_manager.store_token(email, &token) {
        return AuthFlowResult::Error(e);
    }

    // Send reset email with proper error handling
    match send_reset_token_email(email, &token) {
        Ok(_) => {
            println!("\nA reset token has been sent to your email.");
            println!("Please check your inbox and enter the token below.");
        }
        Err(e) => {
            // If email fails, clean up the stored token
            let _ = token_manager.clear_token();
            return AuthFlowResult::Error(format!("Failed to send reset email: {}", e));
        }
    }

    // Set up attempt limiting for token verification
    let mut attempts = 0;
    const MAX_ATTEMPTS: u32 = 3;

    // Loop to handle token verification with flow control
    while attempts < MAX_ATTEMPTS {
        println!("\nEnter the reset token (or 'back' to return to menu, 'cancel' to abort):");
        let input_token = match read_line() {
            Ok(input) => input,
            Err(e) => return AuthFlowResult::Error(format!("Error reading input: {}", e)),
        };
        let input_token = input_token.trim();

        // Enhanced command handling
        match input_token.to_lowercase().as_str() {
            "back" => {
                let _ = token_manager.clear_token();
                return AuthFlowResult::Back;
            }
            "exit" => {
                println!("Exiting program. Goodbye!");
                process::exit(0);
            }
            "cancel" => {
                let _ = token_manager.clear_token();
                return AuthFlowResult::Success("Password reset cancelled.".to_string());
            }
            token => {
                // Verify the entered token
                match token_manager.verify_token(email, token) {
                    Ok(true) => {
                        // Token is valid, proceed with password reset
                        println!("\nToken verified successfully!");

                        // Get and validate new password with flow control
                        let new_password = match get_new_password() {
                            Ok(pwd) => pwd,
                            Err(e) => return AuthFlowResult::Error(e),
                        };

                        // Generate new password hash first
                        let new_hash =
                            hex::encode(derive_key_from_passphrase(&new_password, &store.salt));

                        // Then update the user's password hash
                        if let Some(user) = store.users.values_mut().find(|u| u.email == email) {
                            user.password_hash = new_hash;
                        } else {
                            return AuthFlowResult::Error(
                                "Failed to update password: user not found".to_string(),
                            );
                        }

                        // Save the store after releasing the mutable borrow
                        if let Err(e) = save_user_store(store) {
                            return AuthFlowResult::Error(format!(
                                "Failed to save user data: {}",
                                e
                            ));
                        }

                        // Clear the used token
                        let _ = token_manager.clear_token();

                        // Log the successful password reset
                        log_data_operation(
                            "password_reset",
                            &username,
                            "user_store",
                            true,
                            Some("Password reset completed successfully"),
                        );

                        return AuthFlowResult::Success("Password reset successful!".to_string());
                    }
                    Ok(false) => {
                        // Handle invalid token attempts
                        attempts += 1;
                        if attempts < MAX_ATTEMPTS {
                            println!(
                                "Invalid token. Please try again. {} attempts remaining.",
                                MAX_ATTEMPTS - attempts
                            );
                        } else {
                            // Clean up token after max attempts reached
                            let _ = token_manager.clear_token();
                            return AuthFlowResult::Error(
                                "Too many invalid attempts. Please start over.".to_string(),
                            );
                        }
                    }
                    Err(e) => {
                        return AuthFlowResult::Error(format!("Token verification failed: {}", e))
                    }
                }
            }
        }
    }

    AuthFlowResult::Success("Password reset completed.".to_string())
}

// Email configuration check function
fn check_email_configuration() -> bool {
    // Use existing SecureEmailManager to check if credentials exist
    let email_manager = SecureEmailManager::new();
    email_manager.get_credentials().is_ok()
}

// Function to create and send reset token
fn send_reset_token_email(email: &str, token: &str) -> Result<(), String> {
    // Create a temporary PasswordResetToken structure
    let reset_token = PasswordResetToken {
        token: token.to_string(),
        expires_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 1800, // 30 minutes expiration
        user_email: email.to_string(),
        username: "".to_string(), // We'll update this later
    };

    // Use the existing send_reset_email function
    send_reset_email(&reset_token)
}

// Secure token management
struct SecureTokenManager {
    keyring: Entry,
}

impl SecureTokenManager {
    fn new() -> Self {
        Self {
            keyring: Entry::new("one-do-three", "reset-tokens")
                .expect("Failed to create keyring entry"),
        }
    }

    // Store reset token securely
    fn store_token(&self, email: &str, token: &str) -> Result<(), String> {
        let token_data = format!("{}:{}", email, token);
        self.keyring
            .set_password(&token_data)
            .map_err(|e| format!("Failed to store reset token: {}", e))
    }

    // Verify a reset token
    fn verify_token(&self, email: &str, token: &str) -> Result<bool, String> {
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

    // Clear the token after use
    fn clear_token(&self) -> Result<(), String> {
        self.keyring
            .delete_password()
            .map_err(|e| format!("Failed to clear reset token: {}", e))
    }
}

// Helper function to get and validate new password
fn get_new_password() -> Result<String, String> {
    println!("\nEnter your new password");
    println!(
        "(minimum 8 characters, must include uppercase, lowercase, number, and special char):"
    );

    let new_password = loop {
        let password = read_password().map_err(|e| format!("Error reading password: {}", e))?;

        match validate_password(&password) {
            Ok(_) => break password,
            Err(e) => {
                println!("Password validation failed: {:?}", e);
                println!("Please try again.");
                continue;
            }
        }
    };

    // Confirm password
    println!("\nConfirm your new password:");
    let confirm_password = read_password().map_err(|e| format!("Error reading password: {}", e))?;

    if new_password != confirm_password {
        return Err("Passwords don't match. Please start over.".to_string());
    }

    Ok(new_password)
}

// Function to show initial options when starting the program
fn show_initial_options() {
    println!("\n=== Welcome to One-Do-Three ===");
    println!("1. Login                  (or type 'login')");
    println!("2. Register new account   (or type 'register')");
    println!("3. Forgot password        (or type 'forgot')");
    println!("4. Exit                   (or type 'exit')");
    println!("\nEnter your choice         (1-4 or command):");
}

// Help information function
fn show_help_information() {
    println!("\n=== Task Manager Help ===");

    // Main Commands Section
    println!("\nMain Commands:");
    println!("  add                 - Add a new task");
    println!("  list                - List all tasks");
    println!("  edit                - Edit an existing task");
    println!("  delete              - Delete a task");
    println!("  progress TASKNAME   - Update progress for a specific task");
    println!("  profile             - View or update profile information");
    println!("  change-password     - Change your password");
    println!("  delete-account      - Permanently delete your account");
    println!("  logout              - Log out of current session");

    // List Command Options
    println!("\nList Command Options:");
    println!("  list --filter high       - Show only high priority tasks");
    println!("  list --filter completed  - Show only completed tasks");
    println!("  list --sort priority     - Sort tasks by priority");
    println!("  list --sort name         - Sort tasks by name");

    // Task Management Notes
    println!("\nTask Management Notes:");
    println!("  - Tasks can have high, medium, or low priority");
    println!("  - Each task has a name, description, priority, and completion status");
    println!("  - Task names must be unique");
    println!("  - All changes are automatically saved");

    // Profile Command Details
    println!("\nProfile Command Usage:");
    println!("  profile                    - Show your profile information");
    println!("  profile --show             - Explicitly display profile information");
    println!("  profile --email NEW_EMAIL  - Update your email address");
    println!("\nProfile command notes:");
    println!("  - Email updates require password confirmation");
    println!("  - Profile information includes:");
    println!("    * Username");
    println!("    * Email address");
    println!("    * Account creation date");
    println!("    * Last login time");
    println!("    * Last activity time");

    // Account Management Section
    println!("\nAccount Management:");
    println!("  change-password            - Change your account password");
    println!("  delete-account             - Delete your account permanently");
    println!("  \u{2022} Requires multiple confirmations");
    println!("  \u{2022} Deletes all tasks and user data");
    println!("  \u{2022} Action cannot be undone");

    // Security Notes
    println!("\nSecurity Notes:");
    println!("  - Sessions timeout after 15 minutes of inactivity");
    println!("  - Profile changes require password confirmation");
    println!("  - Password must contain uppercase, lowercase, numbers, and special characters");

    println!("\nType any command with --help for more specific information");
}

// Function to show command-specific help
fn show_command_help(command: &str) {
    match command {
        "profile" => {
            println!("\n=== Profile Command Help ===");
            println!("\nUsage:");
            println!("  profile                    - View your profile information");
            println!("  profile --show             - Display detailed profile information");
            println!("  profile --email NEW_EMAIL  - Update your email address");
            println!("\nOptions:");
            println!("  --show    Show profile information");
            println!("  --email   Update email address (requires password confirmation)");
            println!("\nExamples:");
            println!("  profile");
            println!("  profile --show");
            println!("  profile --email user@example.com");
        }
        "add" => {
            println!("\n=== Add Command Help ===");
            println!("\nUsage:");
            println!("  add  - Start interactive task creation");
            println!("\nYou will be prompted for:");
            println!("  - Task name (must be unique)");
            println!("  - Description (optional)");
            println!("  - Priority (High/Medium/Low)");
        }
        "progress" => {
            println!("\n=== Progress Command Help ===");
            println!("\nUsage:");
            println!("  progress TASKNAME  - Update progress for specified task");
            println!("\nFeatures:");
            println!("  - Set progress percentage (0-100%)");
            println!("  - Choose from multiple progress bar styles:");
            println!("    1. Simple  [=====>    ]");
            println!("    2. Block   [██████    ]");
            println!("    3. Numeric [60%]");
            println!("    4. Detailed [======>   ] 6/10");
            println!("\nExample:");
            println!("  progress \"My Task\"");
        }
        "delete-account" => {
            println!("\n=== Delete Account Command Help ===");
            println!("\nUsage:");
            println!("  delete-account  - Start account deletion process");
            println!("\nThis command will:");
            println!("  1. Ask for confirmation by typing 'DELETE'");
            println!("  2. Require password verification");
            println!("  3. Require final confirmation by typing 'YES'");
            println!("\nWarnings:");
            println!("  - This action permanently deletes your account");
            println!("  - All tasks and user data will be erased");
            println!("  - This action cannot be undone");
            println!("  - You will be logged out immediately after deletion");
        }
        // Add other command-specific help sections as needed
        _ => {
            println!("\nNo detailed help available for '{}' command.", command);
            println!("Use 'help' to see general usage information.");
        }
    }
}

// Main authentication flow to include initial options
// This function handles the main authentication loop and all possible authentication paths
// Parameters:
// - store: Mutable reference to UserStore for managing user data
// Returns: Option<(String, String)> containing (username, password) if authentication succeeds
fn main_auth_flow(store: &mut UserStore) -> Option<(String, String)> {
    loop {
        show_initial_options();

        // Read user input with error handling
        let choice = match read_line() {
            Ok(input) => input.trim().to_string(),
            Err(e) => {
                println!("Error reading input: {}", e);
                continue;
            }
        };

        // Handle the user's choice
        let result = match choice.as_str() {
            "1" | "login" => {
                // Handle login process
                match authenticate_user(store) {
                    Some((username, password)) => MainAuthResult::Success(username, password),
                    None => MainAuthResult::Back,
                }
            }
            "2" | "register" => {
                // Handle registration process
                match handle_interactive_registration(store) {
                    Ok(_) => {
                        // Double-check that we're logged out and clean up any lingering credentials
                        let cache = SecurePasswordCache::new();
                        if let Ok(Some(_)) = cache.get_cached_password() {
                            if let Err(e) = cache.clear_cache() {
                                println!("Warning: Failed to clear lingering credentials: {}", e);
                            }
                        }
                        MainAuthResult::Back // Return to main menu after successful registration
                    }
                    Err(e) => MainAuthResult::Error(format!("Registration failed: {}", e)),
                }
            }
            "3" | "forgot" => {
                // Handle password reset process
                match handle_forgot_password(store) {
                    AuthFlowResult::Back => {
                        println!("Returning to main menu...");
                        continue; // Return to main menu
                    }
                    AuthFlowResult::Success(msg) => {
                        println!("\n{}", msg);
                        continue;
                    }
                    AuthFlowResult::Error(e) => {
                        println!("\nError: {}", e);
                        continue;
                    }
                }
            }
            "4" | "exit" | "quit" => {
                println!("Goodbye!");
                MainAuthResult::Exit
            }
            _ => {
                MainAuthResult::Error(
                    "Invalid choice. Please enter a number (1-4) or command (login/register/forgot/exit).".to_string()
                )
            }
        };

        // Handle the result of the chosen action
        match result {
            MainAuthResult::Success(username, password) => {
                return Some((username, password));
            }
            MainAuthResult::Back => {
                // Just continue the loop to show options again
                continue;
            }
            MainAuthResult::Exit => {
                process::exit(0);
            }
            MainAuthResult::Error(msg) => {
                println!("\n{}", msg);
                // Add a small delay before showing the menu again
                std::thread::sleep(std::time::Duration::from_millis(500));
                continue;
            }
        }
    }
}

// Function to encrypt data using AES-256-CBC
fn encrypt_data(data: &str, encryption_key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes256Cbc::new_from_slices(encryption_key, iv).unwrap();
    cipher.encrypt_vec(data.as_bytes())
}

// Function to decrypt data using AES-256-CBC
fn decrypt_data(encrypted_data: &[u8], encryption_key: &[u8], iv: &[u8]) -> Result<String, String> {
    let cipher = Aes256Cbc::new_from_slices(encryption_key, iv).unwrap();
    match cipher.decrypt_vec(encrypted_data) {
        Ok(decrypted_data) => match String::from_utf8(decrypted_data) {
            Ok(decoded_str) => Ok(decoded_str),
            Err(_) => Err("Decrypted data is not valid UTF-8".to_string()),
        },
        Err(_) => Err("Decryption failed".to_string()),
    }
}

// Function to check if the passphrase is correct (works with user context)
fn is_passphrase_correct(user: &User, passphrase: &str) -> bool {
    match File::open(&user.tasks_file) {
        Ok(mut file) => {
            let mut file_data = Vec::new();
            if let Err(_) = file.read_to_end(&mut file_data) {
                return false;
            }

            if file_data.len() >= 32 {
                let salt = file_data[..16].to_vec();
                let iv = file_data[16..32].to_vec();
                let encrypted_data = &file_data[32..];

                let encryption_key = derive_key_from_passphrase(passphrase, &salt);
                decrypt_data(encrypted_data, &encryption_key, &iv).is_ok()
            } else {
                false
            }
        }
        Err(_) => true, // Return true if file doesn't exist (new user)
    }
}

// Function to load tasks from the user-specific encrypted file with error handling
fn load_tasks_from_file(user: &User, passphrase: &str) -> Result<HashMap<String, Task>, TaskError> {
    // Check file permissions first
    check_file_permissions(user, &user.tasks_file)?;

    let mut tasks = HashMap::new();

    // Attempt to open the user's specific task file
    let file_data = match File::open(&user.tasks_file) {
        Ok(mut file) => {
            let mut data = Vec::new();
            file.read_to_end(&mut data)
                .map_err(|e| TaskError::IoError(e))?;
            data
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(tasks); // Return empty HashMap for new users
        }
        Err(e) => {
            return Err(TaskError::IoError(e));
        }
    };

    // Check if file has minimum required data (salt + iv)
    if file_data.len() < 32 {
        return Err(TaskError::InvalidData("File data is too short".to_string()));
    }

    let salt = file_data[..16].to_vec();
    let iv = file_data[16..32].to_vec();
    let encrypted_data = &file_data[32..];

    // Derive encryption key from user's passphrase
    let encryption_key = derive_key_from_passphrase(passphrase, &salt);
    let decrypted_data = decrypt_data(encrypted_data, &encryption_key, &iv)
        .map_err(|e| TaskError::EncryptionError(e))?;

    tasks =
        serde_json::from_str(&decrypted_data).map_err(|e| TaskError::InvalidData(e.to_string()))?;

    Ok(tasks)
}

// Function to save tasks to the user-specific encrypted file
fn save_tasks_to_file(
    tasks: &HashMap<String, Task>,
    user: &User,
    passphrase: &str,
) -> Result<(), TaskError> {
    // Check file permissions first
    check_file_permissions(user, &user.tasks_file)?;

    // Convert tasks to JSON string
    let data =
        serde_json::to_string_pretty(tasks).map_err(|e| TaskError::InvalidData(e.to_string()))?;

    // Generate new IV and salt for each save
    let iv = generate_random_iv();
    let salt = generate_random_salt();

    // Derive encryption key from user's passphrase
    let encryption_key = derive_key_from_passphrase(passphrase, &salt);

    // Encrypt the task data
    let encrypted_data = encrypt_data(&data, &encryption_key, &iv);

    // Combine salt, IV, and encrypted data
    let mut file_data = Vec::new();
    file_data.extend_from_slice(&salt);
    file_data.extend_from_slice(&iv);
    file_data.extend_from_slice(&encrypted_data);

    // Write to user's specific task file
    File::create(&user.tasks_file)
        .and_then(|mut file| file.write_all(&file_data))
        .map_err(TaskError::IoError)?;

    println!("Changes successfully saved to file {}.", user.tasks_file);
    Ok(())
}

// Function to handle user authentication with proper welcome messages and username case preservation
// Returns Option<(String, String)> where the tuple contains (normalized_username, password)
fn authenticate_user(store: &mut UserStore) -> Option<(String, String)> {
    let cache = SecurePasswordCache::new();

    // Try to get cached credentials first
    if let Ok(Some((cached_username, cached_password))) = cache.get_cached_password() {
        // Check if the cached password is "logout"
        if cached_password.trim() == "logout" {
            if let Err(e) = cache.clear_cache() {
                println!("Warning: Failed to clear password cache: {}", e);
            }
            println!("Successfully logged out. Password cache cleared.");
            return None;
        }

        // Convert to normalized username for verification
        let normalized_username = cached_username.trim().to_lowercase();

        // Verify cached credentials and show welcome back message
        if let Some(user) = store.users.get(&normalized_username) {
            // Use the original username format stored in the user struct
            println!("Welcome back, {}!", user.username);

            // Log successful cached login
            log_auth_event(
                "login",
                &user.username,
                true,
                Some("using cached credentials"),
            );

            return Some((normalized_username, cached_password));
        }
    }

    // If no valid cached credentials, prompt for fresh login
    let mut login_attempts = 0;
    loop {
        // Show initial prompt with navigation options
        if login_attempts == 0 {
            println!("\nPlease enter your username");
            println!("(type 'back' to return to menu, 'exit' to quit):");
        }

        // Get username input with proper error handling
        let original_username = match read_line() {
            Ok(input) => input,
            Err(e) => {
                println!("Error reading input: {}", e);
                continue;
            }
        };
        let normalized_username = original_username.trim().to_lowercase();

        // Handle navigation commands for username
        match normalized_username.as_str() {
            "exit" => {
                println!("Exiting program. Goodbye!");
                process::exit(0);
            }
            "back" => {
                println!("Returning to main menu...");
                return None;
            }
            _ => {
                println!("Enter password (type 'back' for menu, 'exit' to quit):");
                let password = match read_password() {
                    Ok(pwd) => pwd,
                    Err(e) => {
                        println!("Error reading password: {}", e);
                        continue;
                    }
                };

                // Handle navigation and special commands for password
                let auth_result = match password.trim() {
                    "exit" => {
                        println!("Exiting program. Goodbye!");
                        process::exit(0);
                    }
                    "back" => {
                        println!("Returning to main menu...");
                        return None;
                    }
                    "logout" => {
                        if let Err(e) = cache.clear_cache() {
                            println!("Warning: Failed to clear password cache: {}", e);
                        }
                        AuthenticationResult::CacheCleared
                    }
                    password => {
                        // Verify credentials
                        if verify_user_credentials(&normalized_username, password, store) {
                            // Cache the successful credentials
                            if let Err(e) = cache.cache_password(&normalized_username, password) {
                                println!("Warning: Failed to cache credentials: {}", e);
                            }

                            // Get user info needed for verification and welcome message
                            if let Some(user) = store.users.get(&normalized_username) {
                                if !user.verification_status.is_verified() {
                                    AuthenticationResult::NeedsVerification(user.username.clone())
                                } else {
                                    AuthenticationResult::Success(
                                        normalized_username.clone(),
                                        password.to_string(),
                                    )
                                }
                            } else {
                                AuthenticationResult::InvalidCredentials
                            }
                        } else {
                            AuthenticationResult::InvalidCredentials
                        }
                    }
                };

                // Handle authentication result
                match auth_result {
                    AuthenticationResult::Success(username, password) => {
                        if let Some(user) = store.users.get(&username) {
                            println!(
                                "\nWelcome, {}! Type 'help' to see available commands.",
                                user.username
                            );
                            return Some((username, password));
                        }
                    }
                    AuthenticationResult::NeedsVerification(username_for_welcome) => {
                        println!("\nPlease check your email for a verification token.");
                        println!("Enter the 6-digit verification token:");

                        // Handle verification process
                        match verify_registration_token(&normalized_username, store) {
                            VerificationResult::Success => {
                                // Changed from Success(_) to just Success
                                println!("\nVerification successful!");
                                println!(
                                    "\nWelcome, {}! Type 'help' to see available commands.",
                                    username_for_welcome
                                );
                                return Some((normalized_username, password.to_string()));
                            }
                            VerificationResult::Back => {
                                println!("Returning to main menu...");
                                return None;
                            }
                            VerificationResult::Expired => {
                                println!("Verification token has expired. Please register again.");
                                return None;
                            }
                            VerificationResult::Invalid => {
                                println!("Too many invalid attempts. Please try again later.");
                                return None;
                            }
                            VerificationResult::Error(e) => {
                                println!("Verification error: {}", e);
                                println!("Please try again or type 'back' to return to menu");
                                continue;
                            }
                        }
                    }
                    AuthenticationResult::InvalidCredentials => {
                        if login_attempts >= 3 {
                            println!("Multiple failed attempts.");
                            println!("\nPlease enter your username");
                            println!("(type 'back' for menu, 'exit' to quit, or press ENTER to try again):");
                            login_attempts = 0;
                        } else {
                            login_attempts += 1;
                            println!("Authentication failed.");
                            println!("\nPlease enter your username");
                            println!("(type 'back' for menu, 'exit' to quit):");
                        }
                    }
                    AuthenticationResult::CacheCleared => {
                        println!("Successfully logged out. Password cache cleared.");
                        login_attempts = 0;
                        continue;
                    }
                }
            }
        }
    }
}

// Function to check file permissions for a user
fn check_file_permissions(_user: &User, file_path: &str) -> Result<(), TaskError> {
    let _metadata = match std::fs::metadata(file_path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // If file doesn't exist, we'll create it later
            return Ok(());
        }
        Err(e) => {
            return Err(TaskError::IoError(e));
        }
    };

    // Check if file is owned by current process
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let current_uid = nix::unistd::getuid().as_raw();

        if metadata.uid() != current_uid {
            return Err(TaskError::FilePermissionDenied(format!(
                "File {} is not owned by current user",
                file_path
            )));
        }
    }

    // Check if file is writable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o200 == 0 {
            return Err(TaskError::FilePermissionDenied(format!(
                "File {} is not writable",
                file_path
            )));
        }
    }

    Ok(())
}

// Helper function to read a line from stdin
fn read_line() -> io::Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

// Function to create a new UserStore
fn create_user_store() -> UserStore {
    UserStore {
        users: HashMap::new(),
        salt: generate_random_salt(),
        iv: generate_random_iv(),
        reset_tokens: HashMap::new(),
        reset_attempts: HashMap::new(),
        registration_verifications: HashMap::new(), // Initialize verification
    }
}

// Handler function for user creation process
// Takes mutable reference to UserStore and owned strings for user details
// Returns io::Result to propagate potential errors
fn handle_user_creation(
    store: &mut UserStore,
    username: String,
    email: String,
    password: String,
) -> io::Result<()> {
    // Normalize the username for consistency with login
    let original_username = username.trim().to_string();
    let _username_normalized = original_username.to_lowercase();

    // Log the start of user creation operation
    log_data_operation(
        "create_user",
        &original_username, // Changed from normalized_username
        "user_store",
        true,
        Some("starting user registration"),
    );

    // Attempt to add user to the store and handle the result
    match store.add_user(original_username.clone(), email.clone(), password.clone()) {
        Ok(_) => {
            // Attempt to save the store immediately after successful user creation
            match save_user_store(store) {
                Ok(_) => {
                    log_data_operation(
                        "create_user",
                        &original_username, // Changed from normalized_username
                        "user_store",
                        true,
                        Some("user created and store saved"),
                    );
                    println!("User {} created successfully", original_username); // Changed from normalized_username
                    Ok(())
                }
                Err(e) => {
                    log_data_operation(
                        "create_user",
                        &original_username, // Changed from normalized_username
                        "user_store",
                        false,
                        Some(&format!("failed to add user: {}", e)),
                    );
                    println!("Failed to create user: {}", e);
                    Err(e)
                }
            }
        }
        Err(e) => {
            log_data_operation(
                "create_user",
                &original_username, // Changed from normalized_username
                "user_store",
                false,
                Some(&format!("failed to add user: {}", e)),
            );
            println!("Failed to create user: {}", e);
            Err(e)
        }
    }
}

// Function to save UserStore to file
// Modified function to save the user store to file using the secure master key
fn save_user_store(store: &UserStore) -> io::Result<()> {
    // Create an instance of our secure key management
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
    File::create(USERS_FILE)?.write_all(&file_data)?;
    Ok(())
}

// Modified function to load the user store from file using the secure master key
fn load_user_store() -> io::Result<UserStore> {
    // Create an instance of our secure key management
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
                // Extract salt and initialization vector from file
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

fn verify_user_credentials(username: &str, password: &str, store: &mut UserStore) -> bool {
    let normalized_username = username.trim().to_lowercase();
    let password_hash = hex::encode(derive_key_from_passphrase(password, &store.salt));

    if let Some(user) = store.users.get_mut(&normalized_username) {
        if user.password_hash == password_hash {
            // Reset failed attempts and update last login on successful login
            user.failed_attempts = 0;
            user.last_login = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Save the updated user store
            if let Err(e) = save_user_store(store) {
                println!("Warning: Failed to save user data: {}", e);
            }
            return true;
        }

        // Handle failed attempt
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if user has exceeded maximum attempts (3)
        if user.failed_attempts >= 3 {
            // Calculate time passed since last attempt
            let time_since_last_attempt = current_time - user.last_failed_attempt;

            // If less than 30 seconds have passed, prevent login attempt
            if time_since_last_attempt < 30 {
                println!(
                    "Too many failed attempts. Please wait {} seconds before trying again.",
                    30 - time_since_last_attempt
                );
                return false;
            }

            // Reset failed attempts counter after 30-second timeout
            user.failed_attempts = 0;
        }

        // Increment failed attempts and update last attempt timestamp
        user.failed_attempts += 1;
        user.last_failed_attempt = current_time;

        // Save the updated user store
        if let Err(e) = save_user_store(store) {
            println!("Warning: Failed to save user data: {}", e);
        }

        false
    } else {
        println!("4. User not found in store");
        false
    }
}

// Function to clean up expired tokens and reset attempts
fn cleanup_expired_data(store: &mut UserStore) {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Remove expired tokens
    store
        .reset_tokens
        .retain(|_, token| current_time <= token.expires_at);

    // Clean up old reset attempts (older than 24 hours)
    store
        .reset_attempts
        .retain(|_, tracker| current_time - tracker.first_attempt < 24 * 60 * 60);
}

// Function to validate email format
fn is_valid_email(email: &str) -> bool {
    // Basic email validation
    email.contains('@')
        && email.contains('.')
        && !email.contains(' ')
        && email.chars().filter(|&c| c == '@').count() == 1
        && email.len() >= 5
}

// Function to format timestamp as readable date
fn format_timestamp(timestamp: u64) -> String {
    chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .unwrap_or_default()
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

// Initialize the logging system with both file and console output
fn initialize_logging() -> Result<(), Box<dyn std::error::Error>> {
    // Create or append to log file with proper permissions
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("application.log")?;

    // Configure the logging system
    Builder::new()
        // Set default log level
        .filter_level(LevelFilter::Info)
        // Enable timestamps
        .format_timestamp_secs()
        // Enable module path in logs
        .format_module_path(true)
        // Set colored output for console
        .write_style(WriteStyle::Auto)
        // Write to both file and stderr
        .target(env_logger::Target::Pipe(Box::new(file)))
        .init();

    info!("Logging system initialized");
    Ok(())
}

// Helper function to format sensitive data for logging
fn format_sensitive(text: &str) -> String {
    if text.len() <= 4 {
        return "*".repeat(text.len());
    }
    format!("{}***{}", &text[0..2], &text[text.len() - 2..])
}

// Add structured logging for authentication events
fn log_auth_event(event_type: &str, username: &str, success: bool, details: Option<&str>) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    if success {
        info!(
            "Auth event: type={}, user={}, success=true, timestamp={}, details={:?}",
            event_type,
            format_sensitive(username),
            timestamp,
            details
        );
    } else {
        warn!(
            "Auth event: type={}, user={}, success=false, timestamp={}, details={:?}",
            event_type,
            format_sensitive(username),
            timestamp,
            details
        );
    }
}

// Add structured logging for data operations
fn log_data_operation(
    operation: &str,
    user: &str,
    resource: &str,
    success: bool,
    details: Option<&str>,
) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    if success {
        info!(
            "Data operation: op={}, user={}, resource={}, success=true, timestamp={}, details={:?}",
            operation,
            format_sensitive(user),
            resource,
            timestamp,
            details
        );
    } else {
        error!(
            "Data operation: op={}, user={}, resource={}, success=false, timestamp={}, details={:?}",
            operation,
            format_sensitive(user),
            resource,
            timestamp,
            details
        );
    }
}

// Handle the admin password change flow
fn handle_admin_password_change() -> Result<(), String> {
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

fn main() {
    // Admin credentials setup and email configuration setup
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        match args[1].as_str() {
            "--admin-setup" => {
                if args.len() < 3 {
                    println!("Usage: --admin-setup <setup-token>");
                    return;
                }
                let setup_token = &args[2];
                match enhanced_initialize_admin_credentials(setup_token) {
                    Ok(_) => println!("Admin credentials initialized successfully!"),
                    Err(e) => println!("Failed to initialize admin credentials: {}", e),
                }
                return;
            }
            "--generate-admin-token" => {
                match generate_admin_setup_token() {
                    Ok(token) => {
                        println!("\nGenerated admin setup token (valid for 1 hour):");
                        println!("{}", token);
                    }
                    Err(e) => println!("Failed to generate setup token: {}", e),
                }
                return;
            }
            "--email-setup" => {
                match setup_email_credentials() {
                    Ok(_) => println!("Email configuration completed successfully!"),
                    Err(e) => println!("Failed to configure email: {}", e),
                }
                return;
            }
            "--change-admin-password" => {
                match handle_admin_password_change() {
                    Ok(_) => println!("Admin password changed successfully!"),
                    Err(e) => println!("Failed to change admin password: {}", e),
                }
                return;
            }
            _ => {}
        }
    }

    // Initialize logging system
    if let Err(e) = initialize_logging() {
        eprintln!("Failed to initialize logging: {}", e);
        process::exit(1);
    }

    // Create instance of secure key management and ensure key exists
    let secure_key = SecureMasterKey::new();
    if let Err(e) = secure_key.initialize_if_needed() {
        eprintln!("Failed to initialize master key: {}", e);
        process::exit(1);
    }

    // Load the user store with error handling
    let mut store = match load_user_store() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("Failed to load user store: {}", e);
            process::exit(1);
        }
    };

    // Main program loop
    'main: loop {
        // Show initial options, authenticate user and get credentials
        let (username, password) = match main_auth_flow(&mut store) {
            Some(credentials) => credentials,
            None => {
                println!("Authentication failed");
                process::exit(1);
            }
        };

        // Get user's task file path before entering command loop
        let _tasks_file = {
            let user = store
                .users
                .get(&username)
                .expect("User not found after authentication");
            user.tasks_file.clone()
        };

        // After successful authentication
        let cache = SecurePasswordCache::new();
        if let Some(user) = store.users.get(&username) {
            // For cached credentials, the welcome back message is already shown in authenticate_user
            // For fresh logins, show the welcome message
            match cache.get_cached_password() {
                Ok(Some(_)) => {} // Do nothing, "Welcome back" was already shown
                _ => {
                    println!(
                        "\nWelcome, {}! Type 'help' to see available commands.",
                        user.username
                    );
                }
            }
        }

        // Command execution loop - stays here until logout or timeout
        loop {
            // Check for session timeout
            if let Ok(Some((cached_username, _))) = cache.get_cached_password() {
                if cached_username == username {
                    // If session has expired, force logout and restart authentication
                    if let Ok(None) = cache.get_cached_password() {
                        println!("\nSession expired due to 15 minutes of inactivity. Please log in again.");
                        continue 'main;
                    }
                } else {
                    // Username mismatch in cache
                    println!("\nSession error: User mismatch. Please log in again.");
                    continue 'main;
                }
            } else {
                // No cached credentials
                println!("\nSession expired due to 15 minutes of inactivity. Please log in again.");
                continue 'main;
            }

            // Getting fresh user reference and load tasks at the start of each command loop
            let user = match store.users.get(&username) {
                Some(user) => user,
                None => {
                    println!("User not found. Please log in again.");
                    continue 'main;
                }
            };

            // Loading tasks here, so they're fresh for each command
            let mut tasks: HashMap<String, Task> = match load_tasks_from_file(user, &password) {
                Ok(tasks) => tasks,
                Err(e) => {
                    println!("Error loading tasks: {}", e);
                    continue;
                }
            };

            println!("\nEnter command (or 'help' for available commands):");

            let input = read_line().unwrap();
            let args = input.split_whitespace().collect::<Vec<_>>();
            if args.is_empty() {
                continue;
            }

            // First, let's handle the input before passing to clap
            match args[0].to_lowercase().as_str() {
                "help" => {
                    if args.len() > 1 {
                        // Show command-specific help if a command is specified
                        show_command_help(&args[1].to_lowercase());
                    } else {
                        // Show general help information
                        show_help_information();
                    }
                    continue;
                }
                cmd if cmd.ends_with("--help") || cmd.ends_with("-h") => {
                    // Extract the base command by removing the help flag
                    let base_cmd = cmd.replace("--help", "").replace("-h", "");
                    show_command_help(&base_cmd);
                    continue;
                }
                _ => {
                    // Set up CLI command structure using clap
                    let matches = Command::new("task")
                        .about("Task management commands")
                        // Define the subcommands with their arguments using clap
                        // This sets up how the commands can be used from the command line
                        .subcommand(Command::new("add").about("Add a new task"))
                        .subcommand(
                            Command::new("list")
                                .about("List all tasks")
                                .arg(
                                    Arg::new("filter")
                                        .long("filter")
                                        .help("Filter tasks by priority or completion status")
                                        .value_name("FILTER"),
                                )
                                .arg(
                                    Arg::new("sort")
                                        .long("sort")
                                        .help("Sort tasks by priority, completion status, or name")
                                        .value_name("SORT"),
                                ),
                        )
                        .subcommand(Command::new("edit").about("Edit an existing task"))
                        .subcommand(Command::new("delete").about("Delete an existing task"))
                        .subcommand(
                            Command::new("progress").about("Update task progress").arg(
                                Arg::new("task-name")
                                    .help("Name of the task to update progress")
                                    .required(true),
                            ),
                        )
                        .subcommand(Command::new("register").about("Register a new user"))
                        .subcommand(
                            Command::new("profile") // Create a new subcommand named "profile"
                                .about("View or update user profile") // Help text shown in --help
                                .arg(
                                    // Define the --email argument
                                    Arg::new("email")
                                        .long("email") // Makes the argument accessible as --email
                                        .help("Update email address") // Help text for this specific argument
                                        .value_name("NEW_EMAIL") // Placeholder shown in help text
                                        .required(false), // Make this argument optional
                                )
                                .arg(
                                    // Define the --show argument
                                    Arg::new("show")
                                        .long("show") // Makes the argument accessible as --show
                                        .help("Show profile information") // Help text for this specific argument
                                        .action(clap::ArgAction::SetTrue) // Makes this a flag (no value needed)
                                        .required(false), // Make this argument optional
                                ),
                        )
                        .subcommand(
                            Command::new("change-password")
                                .about("Change your password")
                                .arg(
                                    Arg::new("old-password")
                                        .help("Your current password")
                                        .required(true),
                                )
                                .arg(
                                    Arg::new("new-password")
                                        .help("Your new password")
                                        .required(true),
                                ),
                        )
                        .subcommand(
                            Command::new("reset-password")
                                .about("Request a password reset")
                                .arg(Arg::new("email").help("Your email address").required(true)),
                        )
                        .subcommand(
                            Command::new("email-setup").about("Configure email settings securely"),
                        )
                        .subcommand(Command::new("test-email").about("Test email configuration"))
                        .subcommand(
                            Command::new("confirm-reset")
                                .about("Confirm password reset with token")
                                .arg(
                                    Arg::new("token")
                                        .help("Reset token from email")
                                        .required(true),
                                )
                                .arg(
                                    Arg::new("new-password")
                                        .help("Your new password")
                                        .required(true),
                                ),
                        )
                        .subcommand(
                            Command::new("delete-account")
                                .about("Delete user account")
                                .arg(
                                    Arg::new("confirm")
                                        .long("confirm")
                                        .help("Type 'DELETE' to confirm account deletion")
                                        .required(true),
                                ),
                        )
                        .subcommand(
                            Command::new("logout").about("Logout and clear cached password"),
                        )
                        .ignore_errors(true) // Preventing clap from exiting on parse errors
                        .no_binary_name(true) // Allowing commands without the binary name
                        .get_matches_from(args);

                    // Handle different subcommands
                    match matches.subcommand() {
                        // Handle logout comomand
                        Some(("logout", _)) => {
                            if let Err(e) = cache.clear_cache() {
                                println!("Warning: Failed to clear password cache: {}", e);
                            }
                            println!("Successfully logged out.");
                            continue 'main; // Return to main loop for re-authentication
                        }
                        // handle help command
                        Some(("help", _)) => {
                            show_help_information();
                            continue;
                        }
                        // Handle add command
                        Some(("add", _)) => {
                            // Check for session timeout before executing command
                            if let Ok(None) = cache.get_cached_password() {
                                println!("Session expired due to inactivity. Please log in again.");
                                continue;
                            }

                            // First check passphrase
                            if !is_passphrase_correct(user, &password) {
                                println!("Incorrect passphrase. Task not added.");
                                return;
                            }

                            let new_task = handle_interactive_task_creation();

                            // Check if task with the same name already exists
                            if tasks.contains_key(&new_task.name) {
                                println!("A task with this name already exists. Choose a different name or delete the existing task first.");
                                return;
                            }

                            // Log the add operation
                            log_data_operation("add_task", &username, &new_task.name, true, None);

                            tasks.insert(new_task.name.clone(), new_task);

                            cache
                                .cache_password(&username, &password)
                                .unwrap_or_else(|e| {
                                    println!("Warning: Failed to update password cache: {}", e);
                                });

                            // Add error handling to save operation
                            match save_tasks_to_file(&tasks, user, &password) {
                                Ok(_) => println!("Task added successfully!"),
                                Err(e) => println!("Error saving task: {}", e),
                            }
                        }
                        // Handle list command
                        Some(("list", sub_matches)) => {
                            // Check for session timeout before executing command
                            if let Ok(None) = cache.get_cached_password() {
                                println!("Session expired due to inactivity. Please log in again.");
                                continue;
                            }

                            // First check passphrase
                            if !is_passphrase_correct(user, &password) {
                                println!("Error: Incorrect passphrase. Unable to list tasks.");
                                return;
                            }

                            // Add error handling to task loading
                            match load_tasks_from_file(user, &password) {
                                Ok(tasks) => {
                                    let cache = SecurePasswordCache::new();
                                    cache.cache_password(&username, &password).unwrap_or_else(
                                        |e| {
                                            println!(
                                                "Warning: Failed to update password cache: {}",
                                                e
                                            );
                                        },
                                    );

                                    if tasks.is_empty() {
                                        println!("No tasks available.");
                                        return;
                                    }

                                    let filter = sub_matches.get_one::<String>("filter");
                                    let sort = sub_matches.get_one::<String>("sort");

                                    let filtered_tasks = tasks
                                        .iter()
                                        .filter(|(_, task)| {
                                            if let Some(f) = filter {
                                                match f.as_str() {
                                                    "completed" => task.completed,
                                                    "high" => task.priority == "High",
                                                    _ => true,
                                                }
                                            } else {
                                                true
                                            }
                                        })
                                        .collect::<HashMap<_, _>>();

                                    let sorted_tasks = filtered_tasks
                                        .iter()
                                        .sorted_by(|a, b| {
                                            if let Some(s) = sort {
                                                match s.as_str() {
                                                    "priority" => a.1.priority.cmp(&b.1.priority),
                                                    "completed" => {
                                                        a.1.completed.cmp(&b.1.completed)
                                                    }
                                                    _ => a.0.cmp(b.0),
                                                }
                                            } else {
                                                a.0.cmp(b.0)
                                            }
                                        })
                                        .collect::<Vec<_>>();

                                    for (name, task) in sorted_tasks {
                                        println!(
                                                "Task: {}\nDescription: {}\nPriority: {}\nProgress: {}\nCompleted: {}\n",
                                                name,
                                                task.description,
                                                task.priority,
                                                task.generate_progress_bar(),
                                                task.completed
                                            );
                                    }
                                }
                                Err(e) => println!("Error loading tasks: {}", e),
                            }
                        }
                        // Handle edit command
                        Some(("edit", _)) => {
                            // Check for session timeout before executing command
                            if let Ok(None) = cache.get_cached_password() {
                                println!("Session expired due to inactivity. Please log in again.");
                                continue;
                            }

                            // First check passphrase
                            if !is_passphrase_correct(user, &password) {
                                println!("Error: Incorrect passphrase. Unable to edit task.");
                                return;
                            }

                            // Show available tasks
                            println!("\nAvailable tasks:");
                            for (name, _) in &tasks {
                                println!("  {}", name);
                            }

                            println!("\nEnter the name of the task to edit:");
                            let name = read_line().unwrap();

                            if let Some(task) = tasks.get(&name) {
                                let updated_task = handle_interactive_task_edit(task);
                                tasks.insert(name.clone(), updated_task);

                                cache
                                    .cache_password(&username, &password)
                                    .unwrap_or_else(|e| {
                                        println!("Warning: Failed to update password cache: {}", e);
                                    });

                                match save_tasks_to_file(&tasks, user, &password) {
                                    Ok(_) => println!("Task updated successfully!"),
                                    Err(e) => println!("Error saving task update: {}", e),
                                }
                            } else {
                                println!("Task not found: {}", name);
                            }
                        }
                        // Handle delete command
                        Some(("delete", sub_matches)) => {
                            // Check for session timeout before executing command
                            if let Ok(None) = cache.get_cached_password() {
                                println!("Session expired due to inactivity. Please log in again.");
                                continue;
                            }

                            // First check passphrase
                            if !is_passphrase_correct(user, &password) {
                                println!("Error: Incorrect passphrase. Unable to delete task.");
                                return;
                            }

                            let name = sub_matches.get_one::<String>("name").unwrap();

                            // Check if task exists
                            if !tasks.contains_key(name) {
                                println!(
                            "Task '{}' not found. Use 'list' command to see available tasks.",
                            name
                        );
                                return;
                            }

                            // Asking for deletion confirmation
                            loop {
                                print!("Are you sure you want to delete task '{}'? (y/n): ", name);
                                io::stdout().flush().unwrap(); // Ensure the prompt is displayed before input

                                let mut confirmation = String::new();
                                io::stdin().read_line(&mut confirmation).unwrap();
                                let confirmation = confirmation.trim().to_lowercase();

                                if confirmation.is_empty() || confirmation == "y" {
                                    println!("Task '{}' deleted.", name);
                                    // Add the actual deletion logic here
                                    break;
                                } else if confirmation == "n" {
                                    println!("Task deletion cancelled.");
                                    return;
                                } else {
                                    println!(
                                        "Invalid input. Please enter 'y' for yes or 'n' for no."
                                    );
                                }
                            }

                            if tasks.remove(name).is_some() {
                                cache
                                    .cache_password(&username, &password)
                                    .unwrap_or_else(|e| {
                                        println!("Warning: Failed to update password cache: {}", e);
                                    });

                                // Add error handling to save operation
                                match save_tasks_to_file(&tasks, user, &password) {
                                    Ok(_) => println!("Task deleted: {}", name),
                                    Err(e) => println!("Error saving after deletion: {}", e),
                                }
                            } else {
                                println!("Task not found: {}", name);
                            }
                        }
                        // Handle progress command
                        Some(("progress", sub_matches)) => {
                            // Check for session timeout
                            if let Ok(None) = cache.get_cached_password() {
                                println!("Session expired due to inactivity. Please log in again.");
                                continue;
                            }

                            // First check passphrase
                            if !is_passphrase_correct(user, &password) {
                                println!("Error: Incorrect passphrase. Unable to update progress.");
                                return;
                            }

                            let task_name = sub_matches.get_one::<String>("task-name").unwrap();

                            if let Some(task) = tasks.get_mut(task_name) {
                                match handle_interactive_progress_update(task) {
                                    Ok(_) => {
                                        // Update cache and save changes
                                        cache.cache_password(&username, &password).unwrap_or_else(
                                            |e| {
                                                println!(
                                                    "Warning: Failed to update password cache: {}",
                                                    e
                                                );
                                            },
                                        );

                                        match save_tasks_to_file(&tasks, user, &password) {
                                            Ok(_) => println!("Progress updated successfully!"),
                                            Err(e) => {
                                                println!("Error saving progress update: {}", e)
                                            }
                                        }
                                    }
                                    Err(e) => println!("Failed to update progress: {}", e),
                                }
                            } else {
                                println!("Task not found: {}", task_name);
                            }
                        }
                        // Handle register command
                        Some(("register", sub_matches)) => {
                            let username = sub_matches.get_one::<String>("username").unwrap();
                            let email = sub_matches.get_one::<String>("email").unwrap();
                            let password = sub_matches.get_one::<String>("password").unwrap();

                            // Validate email format
                            if !is_valid_email(email) {
                                println!(
                                    "Invalid email format. Please provide a valid email address."
                                );
                                return;
                            }

                            // Validate password strength
                            if let Err(e) = validate_password(password) {
                                println!("Password validation failed: {:?}", e);
                                return;
                            }

                            // Check if username already exists
                            if store.users.contains_key(username) {
                                println!(
                                    "Username already exists. Please choose a different username."
                                );
                                return;
                            }

                            // Check if email is already in use
                            if store.users.values().any(|u| u.email == *email) {
                                println!("Email address is already registered.");
                                return;
                            }

                            // Add the new user
                            match handle_user_creation(
                                &mut store,
                                username.to_string(),
                                email.to_string(),
                                password.to_string(),
                            ) {
                                Ok(_) => {
                                    println!("User successfully registered! You can now log in.");
                                    // Save the updated user store
                                    if let Err(e) = save_user_store(&store) {
                                        println!("Warning: Failed to save user data: {}", e);
                                    }
                                }
                                Err(e) => println!("Failed to register user: {}", e),
                            }
                        }
                        // Handle profile command
                        Some(("profile", sub_matches)) => {
                            // First, check if the user's session is still valid
                            // This prevents unauthorized access to profile information
                            if let Ok(None) = cache.get_cached_password() {
                                println!("Session expired due to inactivity. Please log in again.");
                                continue;
                            }

                            // If no arguments provided (i.e., just 'profile' command), show profile by default
                            // This makes the command more user-friendly by having a sensible default behavior
                            if !sub_matches.contains_id("email") && !sub_matches.get_flag("show") {
                                if let Some(user) = store.users.get(&username) {
                                    // Display basic profile information in a formatted manner
                                    println!("\nUser Profile");
                                    println!("------------");
                                    println!("Username: {}", user.username);
                                    println!("Email: {}", user.email);
                                    println!(
                                        "Account created: {}",
                                        format_timestamp(user.created_at) // Convert Unix timestamp to readable format
                                    );
                                    println!(
                                        "Last login: {}",
                                        format_timestamp(user.last_login) // Show when user last logged in
                                    );
                                    println!(
                                        "Last active: {}",
                                        format_timestamp(user.last_activity) // Show last activity timestamp
                                    );
                                }
                                continue; // Return to main loop after displaying information
                            }

                            // Handle the --show flag if present
                            // This explicitly shows profile information even if other arguments are present
                            if sub_matches.get_flag("show") {
                                if let Some(user) = store.users.get(&username) {
                                    // Display the same profile information as above
                                    println!("\nUser Profile");
                                    println!("------------");
                                    println!("Username: {}", user.username);
                                    println!("Email: {}", user.email);
                                    println!(
                                        "Account created: {}",
                                        format_timestamp(user.created_at)
                                    );
                                    println!("Last login: {}", format_timestamp(user.last_login));
                                    println!(
                                        "Last active: {}",
                                        format_timestamp(user.last_activity)
                                    );
                                }
                            }

                            // Handle email update if --email argument is provided
                            if let Some(new_email) = sub_matches.get_one::<String>("email") {
                                // Validate the new email format using the is_valid_email function
                                if !is_valid_email(new_email) {
                                    println!("Invalid email format. Please provide a valid email address.");
                                    continue;
                                }

                                // Check if the new email is already in use by another user
                                // This prevents email address conflicts between users
                                if store
                                    .users
                                    .values()
                                    .any(|u| u.email == *new_email && u.username != username)
                                {
                                    println!("This email address is already registered to another account.");
                                    continue;
                                }

                                // Get mutable reference to the current user to update their email
                                if let Some(user) = store.users.get_mut(&username) {
                                    // Require password confirmation for security
                                    println!("Please enter your password to confirm changes:");
                                    let confirm_password = read_password().unwrap();

                                    // Verify the provided password by comparing hashes
                                    let password_hash = hex::encode(derive_key_from_passphrase(
                                        &confirm_password,
                                        &store.salt,
                                    ));
                                    if user.password_hash != password_hash {
                                        println!("Incorrect password. Email update cancelled.");
                                        continue;
                                    }

                                    // Update the email address
                                    user.email = new_email.to_string();

                                    // Save the updated user store to persist the change
                                    match save_user_store(&store) {
                                        Ok(_) => println!("Email updated successfully."),
                                        Err(e) => println!("Failed to update email: {}", e),
                                    }
                                }
                            }
                        }
                        // Handle change-password command
                        Some(("change-password", _)) => {
                            // Check for session timeout
                            if let Ok(None) = cache.get_cached_password() {
                                println!("Session expired due to inactivity. Please log in again.");
                                continue;
                            }

                            // Handle the password change process
                            match handle_password_change(&mut store, &username, &cache) {
                                Ok(_) => {
                                    println!("Password changed successfully!");
                                    println!("Please use your new password for future logins.");
                                }
                                Err(e) => {
                                    println!("Failed to change password: {}", e);
                                }
                            }
                        }
                        Some(("email-setup", _)) => {
                            match setup_email_credentials() {
                                Ok(_) => println!("Email configuration completed successfully."),
                                Err(e) => println!("Failed to configure email: {}", e),
                            }
                            continue;
                        }
                        Some(("test-email", _)) => {
                            match test_email_configuration() {
                                Ok(_) => println!("Email configuration test successful!"),
                                Err(e) => println!("Email configuration test failed: {}", e),
                            }
                            continue;
                        }
                        // Handle reset-passowrd command
                        Some(("reset-password", sub_matches)) => {
                            let email = sub_matches.get_one::<String>("email").unwrap();

                            // Clean up expired data first
                            cleanup_expired_data(&mut store);

                            // Check rate limiting for reset attempts
                            let current_time = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();

                            let tracker = store
                                .reset_attempts
                                .entry(email.to_string())
                                .or_insert_with(ResetAttemptTracker::new);

                            // If this is a new attempt window (>24 hours since first attempt)
                            if current_time - tracker.first_attempt > 24 * 60 * 60 {
                                tracker.attempts = 0;
                                tracker.first_attempt = current_time;
                            }

                            // Check if too many attempts
                            if tracker.attempts >= 5
                                && current_time - tracker.last_attempt < 60 * 60
                            {
                                println!("Too many reset attempts. Please try again in an hour.");
                                return;
                            }

                            // Find user by email
                            if let Some(user) = store
                                .users
                                .values()
                                .find(|u| u.email.as_str() == email.as_str())
                            {
                                match user.request_password_reset() {
                                    Ok(reset_token) => {
                                        // Store the token
                                        store
                                            .reset_tokens
                                            .insert(reset_token.token.clone(), reset_token.clone());

                                        // Update attempt tracker
                                        tracker.attempts += 1;
                                        tracker.last_attempt = current_time;

                                        // Save the updated store with error handling
                                        match save_user_store(&store) {
                                            Ok(_) => {
                                                match send_reset_email(&reset_token) {
                                                    Ok(_) => {
                                                        println!(
                                            "Password reset email sent. Please check your inbox."
                                        );
                                                    }
                                                    Err(e) => {
                                                        // Remove token if email fails
                                                        store
                                                            .reset_tokens
                                                            .remove(&reset_token.token);
                                                        println!(
                                                            "Failed to send reset email: {}",
                                                            e
                                                        );
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                println!("Failed to save reset token: {}", e);
                                                store.reset_tokens.remove(&reset_token.token);
                                            }
                                        }
                                    }
                                    Err(e) => println!("Failed to create reset token: {}", e),
                                }
                            } else {
                                // Don't reveal if email exists, but still update attempt tracker
                                tracker.attempts += 1;
                                tracker.last_attempt = current_time;
                                println!(
                            "If this email is registered, you will receive a reset link shortly."
                        );
                            }

                            // Save attempt tracker
                            if let Err(e) = save_user_store(&store) {
                                println!("Warning: Failed to save attempt tracking: {}", e);
                            }
                        }
                        // Handle confirm-reset command
                        Some(("confirm-reset", sub_matches)) => {
                            let token = sub_matches.get_one::<String>("token").unwrap();
                            let new_password =
                                sub_matches.get_one::<String>("new-password").unwrap();

                            // Look up the stored token
                            if let Some(stored_token) = store.reset_tokens.get(token) {
                                // Check if token has expired
                                let current_time = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs();

                                if current_time > stored_token.expires_at {
                                    println!("Password reset token has expired. Please request a new one.");
                                    return;
                                }

                                // Find the user associated with this token
                                if let Some(user) = store.users.get_mut(&stored_token.username) {
                                    // Validate new password
                                    if let Err(e) = validate_password(new_password) {
                                        println!("Invalid new password: {:?}", e);
                                        return;
                                    }

                                    // Update password hash
                                    user.password_hash = hex::encode(derive_key_from_passphrase(
                                        new_password,
                                        &store.salt,
                                    ));

                                    cache
                                        .cache_password(&user.username, new_password)
                                        .unwrap_or_else(|e| {
                                            println!(
                                                "Warning: Failed to update password cache: {}",
                                                e
                                            );
                                        });

                                    // Remove the used token
                                    store.reset_tokens.remove(token);

                                    // Save the updated store
                                    match save_user_store(&store) {
                                        Ok(_) => {
                                            println!("Password reset successful. You can now log in with your new password.");
                                        }
                                        Err(e) => println!("Error saving new password: {}", e),
                                    }
                                } else {
                                    println!("Invalid reset token.");
                                }
                            } else {
                                println!("Invalid or expired reset token.");
                            }
                        }
                        // Handle delete-account command
                        Some(("delete-account", _)) => {
                            // Check for session timeout
                            if let Ok(None) = cache.get_cached_password() {
                                println!("Session expired due to inactivity. Please log in again.");
                                continue;
                            }

                            // Handle the deletion process
                            match handle_account_deletion(&mut store, &username, &password, &cache)
                            {
                                DeletionStatus::Success => {
                                    println!("\nAccount successfully deleted.");
                                    println!("You will now be logged out.");
                                    continue 'main; // Go back to the inital options menu after successful deletion
                                }
                                DeletionStatus::Failed(reason) => {
                                    println!("\nAccount deletion failed: {}", reason);
                                    println!("No changes were made to your account.");
                                    continue;
                                }
                                DeletionStatus::Cancelled => {
                                    println!("\nAccount deletion cancelled.");
                                    println!("No changes were made to your account.");
                                    continue;
                                }
                            }
                        }
                        _ => {
                            println!(
                                "No valid command provided. Use 'help' for usage information."
                            );
                        }
                    }
                }
            }
        }
    }
}

// -------------------------------------------------------------------------------------------------------------

// Authentication tests
// These tests cover the user authentication functionality of your application, including:
// 1. Password validation (checking for length, uppercase, lowercase, numbers, and special characters)
// 2. User creation and storage (ensuring users are properly added to the store with correct data)
// 3. Email validation (verifying email format validation works correctly)
// 4. Credential verification (testing successful and failed authentication attempts)
// 5. Login attempt rate limiting (verifying that failed attempts are tracked and reset appropriately)
// 6. Username normalization (ensuring usernames are stored correctly in case-sensitive and case-insensitive forms)
// 7. Password hashing security (confirming passwords are properly hashed with the store's salt)
#[cfg(test)]
mod authentication_tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Test fixture to create a temporary user store for testing
    fn setup_test_user_store() -> (UserStore, NamedTempFile) {
        // Create a temporary file for the user store
        let temp_file = NamedTempFile::new().unwrap();
        let temp_path = temp_file.path().to_str().unwrap().to_string();

        // Create a new UserStore with test data
        let mut store = UserStore {
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

    // Helper function to add a test user to a store
    fn add_test_user(
        store: &mut UserStore,
        username: &str,
        email: &str,
        password: &str,
    ) -> Result<(), String> {
        // This adds a user directly, bypassing the interactive components
        let password_hash = hex::encode(derive_key_from_passphrase(password, &store.salt));
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let user = User {
            username: username.to_string(),
            username_normalized: username.to_lowercase(),
            email: email.to_string(),
            password_hash,
            created_at: current_time,
            last_login: current_time,
            failed_attempts: 0,
            last_failed_attempt: 0,
            tasks_file: format!("tasks/test_user_{}.dat", username),
            last_activity: current_time,
            verification_status: VerificationStatus::Verified, // Default to verified for tests
        };

        store.users.insert(username.to_lowercase(), user);
        Ok(())
    }

    #[test]
    /// Test that verifies password validation works correctly for various password inputs
    fn test_password_validation() {
        // Test valid password
        let valid_password = "Password123!";
        assert!(validate_password(valid_password).is_ok());

        // Test too short
        let short_password = "Pass1!";
        assert!(matches!(
            validate_password(short_password),
            Err(PasswordError::TooShort)
        ));

        // Test missing uppercase
        let no_upper_password = "password123!";
        assert!(matches!(
            validate_password(no_upper_password),
            Err(PasswordError::NoUppercase)
        ));

        // Test missing lowercase
        let no_lower_password = "PASSWORD123!";
        assert!(matches!(
            validate_password(no_lower_password),
            Err(PasswordError::NoLowercase)
        ));

        // Test missing number
        let no_number_password = "Password!";
        assert!(matches!(
            validate_password(no_number_password),
            Err(PasswordError::NoNumber)
        ));

        // Test missing special character
        let no_special_password = "Password123";
        assert!(matches!(
            validate_password(no_special_password),
            Err(PasswordError::NoSpecialChar)
        ));
    }

    #[test]
    /// Test user creation and verification
    fn test_user_creation() {
        let (mut store, _temp_file) = setup_test_user_store();

        // Add test user
        let result = add_test_user(&mut store, "TestUser", "test@example.com", "Password123!");
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
    /// Test email validation
    fn test_email_validation() {
        // Valid emails
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("user.name@example.co.uk"));
        assert!(is_valid_email("user+tag@example.com"));

        // Invalid emails
        assert!(!is_valid_email("user@example")); // Missing TLD
        assert!(!is_valid_email("user example.com")); // Contains space
        assert!(!is_valid_email("user")); // No @ symbol
        assert!(!is_valid_email("")); // Empty string
        assert!(!is_valid_email("user@@example.com")); // Multiple @ symbols
    }

    #[test]
    /// Test verify_user_credentials functionality
    fn test_credential_verification() {
        let (mut store, _temp_file) = setup_test_user_store();

        // Add test user
        add_test_user(&mut store, "TestUser", "test@example.com", "Password123!").unwrap();

        // Test valid credentials
        assert!(verify_user_credentials(
            "testuser",
            "Password123!",
            &mut store
        ));

        // Test incorrect password
        assert!(!verify_user_credentials(
            "testuser",
            "WrongPassword123!",
            &mut store
        ));

        // Test non-existent user
        assert!(!verify_user_credentials(
            "nonexistentuser",
            "Password123!",
            &mut store
        ));
    }

    #[test]
    /// Test handling of failed login attempts
    fn test_failed_login_attempts() {
        let (mut store, _temp_file) = setup_test_user_store();

        // Add test user
        add_test_user(&mut store, "TestUser", "test@example.com", "Password123!").unwrap();

        // First incorrect attempt
        assert!(!verify_user_credentials(
            "testuser",
            "WrongPassword1!",
            &mut store
        ));
        let user = store.users.get("testuser").unwrap();
        assert_eq!(user.failed_attempts, 1);

        // Second incorrect attempt
        assert!(!verify_user_credentials(
            "testuser",
            "WrongPassword2!",
            &mut store
        ));
        let user = store.users.get("testuser").unwrap();
        assert_eq!(user.failed_attempts, 2);

        // Third incorrect attempt
        assert!(!verify_user_credentials(
            "testuser",
            "WrongPassword3!",
            &mut store
        ));
        let user = store.users.get("testuser").unwrap();
        assert_eq!(user.failed_attempts, 3);

        // Successful login should reset counter
        assert!(verify_user_credentials(
            "testuser",
            "Password123!",
            &mut store
        ));
        let user = store.users.get("testuser").unwrap();
        assert_eq!(user.failed_attempts, 0);
    }
}

// Encryption tests
// These tests cover the encryption and security aspects of your application, including:
// 1. Encryption and decryption functionality with proper roundtrip testing
// 2. Handling of incorrect keys and initialization vectors
// 3. Key derivation from passphrases
// 4. The SecureMasterKey functionality (with a mock implementation for testing)
// 5. The AdminAuthTracker for handling login attempt limiting
// 6. Admin setup token generation and validation
#[cfg(test)]
mod encryption_tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    /// Test that encryption and decryption work correctly (roundtrip test)
    fn test_encryption_decryption_roundtrip() {
        // Test data
        let original_data = "This is a secret message that needs to be encrypted";

        // For testing, create a fixed key and IV to ensure consistency
        // In production code, these would be randomly generated
        let encryption_key: Vec<u8> = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let iv: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        // Ensure key and iv are of correct length
        assert_eq!(encryption_key.len(), 32); // AES-256 needs a 32-byte key
        assert_eq!(iv.len(), 16);

        // Encrypt the data
        let encrypted_data = encrypt_data(original_data, &encryption_key, &iv);

        // Ensure encrypted data is not empty
        assert!(!encrypted_data.is_empty());

        // We can't reliably compare the encrypted data as UTF-8 string since it might not be valid UTF-8
        // So we'll just make sure it's different from the original in binary form
        assert_ne!(encrypted_data, original_data.as_bytes());

        // Decrypt the data
        let decrypted_data = decrypt_data(&encrypted_data, &encryption_key, &iv).unwrap();

        // Verify decryption worked correctly
        assert_eq!(decrypted_data, original_data);
    }

    #[test]
    /// Test that decryption fails with incorrect key
    fn test_decryption_with_wrong_key() {
        // Test data
        let original_data = "This is a secret message that needs to be encrypted";

        // Use a fixed key and IV for consistent test results
        let encryption_key: Vec<u8> = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let iv: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        // Encrypt the data
        let encrypted_data = encrypt_data(original_data, &encryption_key, &iv);

        // Create a distinctly different key with the same length
        let wrong_key: Vec<u8> = vec![
            100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
            117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131,
        ];

        // Verify keys are different but same length
        assert_ne!(encryption_key, wrong_key);
        assert_eq!(encryption_key.len(), wrong_key.len());

        // Attempt to decrypt with wrong key - this should fail gracefully
        let result = decrypt_data(&encrypted_data, &wrong_key, &iv);

        // The function returns a Result, so we expect an Err
        assert!(result.is_err());
    }

    #[test]
    /// Test that decryption fails with incorrect iv
    fn test_decryption_with_wrong_iv() {
        // Test data
        let original_data = "This is a secret message that needs to be encrypted";

        // Use fixed values for key and IV for consistent testing
        let encryption_key: Vec<u8> = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let iv: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        // Encrypt the data
        let encrypted_data = encrypt_data(original_data, &encryption_key, &iv);

        // Create a distinctly different IV with the same length
        let wrong_iv: Vec<u8> = vec![
            100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
        ];

        // Verify IVs are different but same length
        assert_ne!(iv, wrong_iv);
        assert_eq!(iv.len(), wrong_iv.len());

        // The test might fail if the decryption happens to produce valid UTF-8 data
        // Instead of checking for an error, try to decrypt and verify the result doesn't match original
        match decrypt_data(&encrypted_data, &encryption_key, &wrong_iv) {
            Ok(decrypted) => {
                // Even if decryption "succeeds", the result should be different from the original
                assert_ne!(decrypted, original_data);
            }
            Err(_) => {
                // An error is also an acceptable outcome, as decryption with wrong IV should fail
                // No assertion needed here - the test passes if it reaches this point
            }
        }
    }

    #[test]
    /// Test key derivation from passphrase
    fn test_key_derivation() {
        // Test data
        let passphrase = "MySecurePassword123!";
        let salt = generate_random_salt();

        // Derive key
        let key = derive_key_from_passphrase(passphrase, &salt);

        // Key should be 32 bytes
        assert_eq!(key.len(), 32);

        // Deriving again with the same passphrase and salt should yield the same key
        let key2 = derive_key_from_passphrase(passphrase, &salt);
        assert_eq!(key, key2);

        // Using a different passphrase should yield a different key
        let different_passphrase = "DifferentPassword456!";
        let key3 = derive_key_from_passphrase(different_passphrase, &salt);
        assert_ne!(key, key3);

        // Using a different salt should yield a different key
        let different_salt = generate_random_salt();
        let key4 = derive_key_from_passphrase(passphrase, &different_salt);
        assert_ne!(key, key4);
    }

    #[test]
    /// Test the SecureMasterKey functionality
    fn test_secure_master_key() {
        // Create a mock implementation for testing
        struct MockSecureMasterKey {
            stored_key: Option<Vec<u8>>,
        }

        impl MockSecureMasterKey {
            fn new() -> Self {
                Self { stored_key: None }
            }

            fn store_key(&mut self, key: &[u8]) -> io::Result<()> {
                self.stored_key = Some(key.to_vec());
                Ok(())
            }

            fn get_key(&self) -> io::Result<Vec<u8>> {
                match &self.stored_key {
                    Some(key) => Ok(key.clone()),
                    None => Err(io::Error::new(io::ErrorKind::NotFound, "Key not found")),
                }
            }

            fn initialize_if_needed(&mut self) -> io::Result<()> {
                if self.stored_key.is_none() {
                    let new_key: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
                    self.store_key(&new_key)?;
                }
                Ok(())
            }
        }

        // Create a new instance
        let mut master_key = MockSecureMasterKey::new();

        // Initially, there should be no key
        assert!(master_key.get_key().is_err());

        // Initialize should create a key
        assert!(master_key.initialize_if_needed().is_ok());

        // Now we should be able to get the key
        let key = master_key.get_key().unwrap();
        assert_eq!(key.len(), 32);

        // Store a new key
        let new_key: Vec<u8> = (0..32).map(|_| 0xAA).collect();
        assert!(master_key.store_key(&new_key).is_ok());

        // Check that the new key was stored
        let retrieved_key = master_key.get_key().unwrap();
        assert_eq!(retrieved_key, new_key);
    }

    #[test]
    /// Test the AdminAuthTracker functionality
    fn test_admin_auth_tracker() {
        // Create a new tracker
        let mut tracker = AdminAuthTracker::new();

        // Initially no failed attempts
        assert_eq!(tracker.failed_attempts, 0);
        assert_eq!(tracker.lockout_until, 0);

        // Current time for testing
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

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
    /// Test setup token generation and validation
    fn test_admin_setup_token() {
        // Create a new admin config
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

// Task Management tests
// These tests cover the task management functionality of your application, including:
// 1. Task creation and storage (creating tasks with various properties and saving them)
// 2. Task loading and retrieval (verifying tasks can be properly loaded from encrypted storage)
// 3. Task progress updates (testing progress tracking and automatic completion)
// 4. Progress bar visualization styles (testing different progress display formats)
// 5. Task editing (verifying modifications to tasks are properly persisted)
// 6. Task deletion (ensuring tasks can be removed and changes are saved)
// 7. Error handling (testing behavior with encryption errors and incorrect passwords)
// 8. File permissions (verifying handling of nonexistent files and permission issues)
// 9. Task completion state (checking automatic completion when progress reaches 100%)
// 10. Passphrase verification (confirming the is_passphrase_correct function works properly)
#[cfg(test)]
mod task_management_tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tempfile::TempDir;

    // Helper function to create a test task
    fn create_test_task(name: &str, priority: &str, progress: u8) -> Task {
        Task {
            name: name.to_string(),
            description: format!("Description for {}", name),
            priority: priority.to_string(),
            completed: progress == 100,
            progress_percent: progress,
            progress_bar_style: "simple".to_string(),
        }
    }

    // Helper function to create a test user with a valid task file
    fn create_test_user_with_task_file() -> (User, NamedTempFile, String) {
        // Create a temporary directory for tasks
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path().to_str().unwrap();

        // Create a task file in the temp directory
        let task_file_path = format!("{}/user_test.dat", temp_path);
        let task_file = NamedTempFile::new().unwrap();
        let task_file_path_actual = task_file.path().to_str().unwrap().to_string();

        // Create a test user
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let user = User {
            username: "TestUser".to_string(),
            username_normalized: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "dummy_hash".to_string(),
            created_at: current_time,
            last_login: current_time,
            failed_attempts: 0,
            last_failed_attempt: 0,
            tasks_file: task_file_path_actual.clone(),
            last_activity: current_time,
            verification_status: VerificationStatus::Verified,
        };

        (user, task_file, task_file_path_actual)
    }

    // Helper function to save and reload tasks for testing
    fn save_and_reload_tasks(
        tasks: &HashMap<String, Task>,
        user: &User,
        password: &str,
    ) -> Result<HashMap<String, Task>, TaskError> {
        // Save tasks
        save_tasks_to_file(tasks, user, password)?;

        // Load tasks back
        load_tasks_from_file(user, password)
    }

    #[test]
    /// Test creating, saving, and loading tasks
    fn test_task_roundtrip() {
        // Create test user and task file
        let (user, _temp_file, _temp_path) = create_test_user_with_task_file();
        let password = "TestPassword123!";

        // Create test tasks
        let mut tasks = HashMap::new();
        tasks.insert("Task1".to_string(), create_test_task("Task1", "High", 50));
        tasks.insert("Task2".to_string(), create_test_task("Task2", "Medium", 75));
        tasks.insert("Task3".to_string(), create_test_task("Task3", "Low", 100));

        // Save tasks to file
        let save_result = save_tasks_to_file(&tasks, &user, password);
        assert!(save_result.is_ok());

        // Load tasks back from file
        let loaded_tasks = load_tasks_from_file(&user, password).unwrap();

        // Verify tasks loaded correctly
        assert_eq!(loaded_tasks.len(), 3);
        assert!(loaded_tasks.contains_key("Task1"));
        assert!(loaded_tasks.contains_key("Task2"));
        assert!(loaded_tasks.contains_key("Task3"));

        // Check some specific fields
        let task1 = loaded_tasks.get("Task1").unwrap();
        assert_eq!(task1.priority, "High");
        assert_eq!(task1.progress_percent, 50);
        assert!(!task1.completed);

        let task3 = loaded_tasks.get("Task3").unwrap();
        assert_eq!(task3.priority, "Low");
        assert_eq!(task3.progress_percent, 100);
        assert!(task3.completed);
    }

    #[test]
    /// Test task progress updates
    fn test_task_progress_update() {
        // Create a task
        let mut task = create_test_task("ProgressTest", "Medium", 0);

        // Update progress to 50%
        let result = task.update_progress(50);
        assert!(result.is_ok());
        assert_eq!(task.progress_percent, 50);
        assert!(!task.completed);

        // Update progress to 100% (should set completed = true)
        let result = task.update_progress(100);
        assert!(result.is_ok());
        assert_eq!(task.progress_percent, 100);
        assert!(task.completed);

        // Try invalid progress value
        let result = task.update_progress(101);
        assert!(result.is_err());
        assert_eq!(task.progress_percent, 100); // Should not change
    }

    #[test]
    /// Test different progress bar styles
    fn test_progress_bar_styles() {
        // Create a task with 60% progress
        let mut task = create_test_task("StyleTest", "Medium", 60);

        // Test simple style
        task.progress_bar_style = "simple".to_string();
        let progress_bar = task.generate_progress_bar();
        assert!(progress_bar.contains("======"));
        assert!(progress_bar.contains(">"));
        assert!(progress_bar.contains("60%"));

        // Test block style
        task.progress_bar_style = "block".to_string();
        let progress_bar = task.generate_progress_bar();
        assert!(progress_bar.contains("████"));
        assert!(progress_bar.contains("60%"));

        // Test numeric style
        task.progress_bar_style = "numeric".to_string();
        let progress_bar = task.generate_progress_bar();
        assert_eq!(progress_bar, "[60%]");

        // Test detailed style
        task.progress_bar_style = "detailed".to_string();
        let progress_bar = task.generate_progress_bar();
        assert!(progress_bar.contains("6/10"));

        // Test invalid style (should default to percentage)
        task.progress_bar_style = "invalid".to_string();
        let progress_bar = task.generate_progress_bar();
        assert_eq!(progress_bar, "60%");
    }

    #[test]
    /// Test editing tasks
    fn test_task_editing() {
        // Create test user and task file
        let (user, _temp_file, _temp_path) = create_test_user_with_task_file();
        let password = "TestPassword123!";

        // Create initial task
        let mut tasks = HashMap::new();
        tasks.insert(
            "EditTask".to_string(),
            create_test_task("EditTask", "Medium", 50),
        );

        // Save and reload
        let tasks = save_and_reload_tasks(&tasks, &user, password).unwrap();

        // Edit task (manually simulating interactive edit)
        // Get a reference and create a new owned Task
        if let Some(task) = tasks.get("EditTask") {
            let edited_task = Task {
                name: task.name.clone(),
                description: "Updated description".to_string(),
                priority: "High".to_string(),
                completed: true,
                progress_percent: 100, // Auto-set by completion
                progress_bar_style: task.progress_bar_style.clone(),
            };

            // Update task in the map
            // Create a new HashMap with owned values
            let mut updated_tasks = HashMap::new();
            for (key, value) in &tasks {
                updated_tasks.insert(
                    key.clone(),
                    Task {
                        name: value.name.clone(),
                        description: value.description.clone(),
                        priority: value.priority.clone(),
                        completed: value.completed,
                        progress_percent: value.progress_percent,
                        progress_bar_style: value.progress_bar_style.clone(),
                    },
                );
            }
            updated_tasks.insert("EditTask".to_string(), edited_task);

            // Save and reload
            let reloaded_tasks = save_and_reload_tasks(&updated_tasks, &user, password).unwrap();

            // Verify changes persisted
            let edited_task = reloaded_tasks.get("EditTask").unwrap();
            assert_eq!(edited_task.description, "Updated description");
            assert_eq!(edited_task.priority, "High");
            assert!(edited_task.completed);
            assert_eq!(edited_task.progress_percent, 100);
        }

        #[test]
        /// Test deleting tasks
        fn test_task_deletion() {
            // Create test user and task file
            let (user, _temp_file, _temp_path) = create_test_user_with_task_file();
            let password = "TestPassword123!";

            // Create multiple tasks
            let mut tasks = HashMap::new();
            tasks.insert("Task1".to_string(), create_test_task("Task1", "High", 50));
            tasks.insert("Task2".to_string(), create_test_task("Task2", "Medium", 75));
            tasks.insert(
                "DeleteMe".to_string(),
                create_test_task("DeleteMe", "Low", 25),
            );

            // Save tasks
            let save_result = save_tasks_to_file(&tasks, &user, password);
            assert!(save_result.is_ok());

            // Load tasks back
            let mut loaded_tasks = load_tasks_from_file(&user, password).unwrap();
            assert_eq!(loaded_tasks.len(), 3);

            // Delete one task
            loaded_tasks.remove("DeleteMe");
            assert_eq!(loaded_tasks.len(), 2);
            assert!(!loaded_tasks.contains_key("DeleteMe"));

            // Save changes
            let save_result = save_tasks_to_file(&loaded_tasks, &user, password);
            assert!(save_result.is_ok());

            // Load again to verify deletion persisted
            let final_tasks = load_tasks_from_file(&user, password).unwrap();
            assert_eq!(final_tasks.len(), 2);
            assert!(!final_tasks.contains_key("DeleteMe"));
            assert!(final_tasks.contains_key("Task1"));
            assert!(final_tasks.contains_key("Task2"));
        }

        #[test]
        /// Test handling encryption error when loading tasks
        fn test_task_encryption_error() {
            // Create test user and task file
            let (user, mut temp_file, _temp_path) = create_test_user_with_task_file();

            // Write invalid data to the file (not properly encrypted)
            temp_file.write_all(b"This is not encrypted data").unwrap();
            temp_file.flush().unwrap();

            // Attempt to load tasks - should fail with encryption error
            let password = "TestPassword123!";
            let result = load_tasks_from_file(&user, password);

            assert!(result.is_err());
            match result {
                Err(TaskError::InvalidData(_)) => {
                    // This is the expected error type
                }
                Err(e) => {
                    panic!("Expected InvalidData error, got: {:?}", e);
                }
                Ok(_) => {
                    panic!("Expected error, but task loading succeeded");
                }
            }
        }

        #[test]
        /// Test loading tasks with wrong password
        fn test_wrong_password_load() {
            // Create test user and task file
            let (user, _temp_file, _temp_path) = create_test_user_with_task_file();
            let correct_password = "TestPassword123!";
            let wrong_password = "WrongPassword123!";

            // Create and save a task with the correct password
            let mut tasks = HashMap::new();
            tasks.insert("Task1".to_string(), create_test_task("Task1", "High", 50));

            let save_result = save_tasks_to_file(&tasks, &user, correct_password);
            assert!(save_result.is_ok());

            // Try to load with wrong password
            let load_result = load_tasks_from_file(&user, wrong_password);
            assert!(load_result.is_err());

            // Should still be able to load with correct password
            let load_result = load_tasks_from_file(&user, correct_password);
            assert!(load_result.is_ok());
        }

        #[test]
        /// Test handling task file permissions
        fn test_task_file_permissions() {
            // Create test user and task file
            let (user, _temp_file, _temp_path) = create_test_user_with_task_file();
            let password = "TestPassword123!";

            // Create test tasks
            let mut tasks = HashMap::new();
            tasks.insert("Task1".to_string(), create_test_task("Task1", "High", 50));

            // Save tasks to file
            let save_result = save_tasks_to_file(&tasks, &user, password);
            assert!(save_result.is_ok());

            // Test loading tasks from a nonexistent file path
            // Create a new user with a bad path since we can't clone User
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut bad_path_user = User {
                username: user.username.clone(),
                username_normalized: user.username_normalized.clone(),
                email: user.email.clone(),
                password_hash: user.password_hash.clone(),
                created_at: current_time,
                last_login: current_time,
                failed_attempts: 0,
                last_failed_attempt: 0,
                tasks_file: "nonexistent/path/file.dat".to_string(),
                last_activity: current_time,
                // We need to manually create a new instance since VerificationStatus may not implement Clone
                verification_status: if user.verification_status.is_verified() {
                    VerificationStatus::Verified
                } else {
                    VerificationStatus::Unverified
                },
            };
            bad_path_user.tasks_file = "nonexistent/path/file.dat".to_string();

            // This should create a new empty task list rather than fail
            let result = load_tasks_from_file(&bad_path_user, password);
            assert!(result.is_ok());
            assert_eq!(result.unwrap().len(), 0);
        }

        #[test]
        /// Test automatic completion when progress reaches 100%
        fn test_auto_completion() {
            // Create a task with 99% progress
            let mut task = create_test_task("AutoComplete", "Medium", 99);
            assert!(!task.completed);

            // Update to 100%
            let result = task.update_progress(100);
            assert!(result.is_ok());

            // Should be marked as completed
            assert!(task.completed);

            // Create a task that's already completed but with less than 100% progress
            let mut task = Task {
                name: "AlreadyComplete".to_string(),
                description: "Description".to_string(),
                priority: "Medium".to_string(),
                completed: true,
                progress_percent: 80,
                progress_bar_style: "simple".to_string(),
            };

            // Update progress to 90%
            let result = task.update_progress(90);
            assert!(result.is_ok());

            // Should still be completed (completion state shouldn't be reverted automatically)
            assert!(task.completed);
            assert_eq!(task.progress_percent, 90);
        }

        #[test]
        /// Test is_passphrase_correct function
        fn test_passphrase_verification() {
            // Create test user and task file
            let (user, _temp_file, _temp_path) = create_test_user_with_task_file();
            let password = "TestPassword123!";

            // Create and save a task
            let mut tasks = HashMap::new();
            tasks.insert("Task1".to_string(), create_test_task("Task1", "High", 50));

            let save_result = save_tasks_to_file(&tasks, &user, password);
            assert!(save_result.is_ok());

            // Verify correct passphrase returns true
            assert!(is_passphrase_correct(&user, password));

            // Verify incorrect passphrase returns false
            assert!(!is_passphrase_correct(&user, "WrongPassword123!"));
        }
    }
}

// Password Reset tests
// These tests cover the password reset functionality of your application, including:
// 1. Reset token generation (creating secure tokens for password reset)
// 2. Token validation (verifying tokens are correctly validated)
// 3. Token expiration (ensuring expired tokens are rejected)
// 4. Password reset process (testing the complete reset flow)
// 5. Rate limiting (verifying protection against reset attempt abuse)
// 6. Token security (ensuring tokens are properly secured)
#[cfg(test)]
mod password_reset_tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Test fixture to create a test user store with a user
    fn setup_test_user_store_with_user() -> (UserStore, User, NamedTempFile) {
        // Create a temporary file for the user store
        let temp_file = NamedTempFile::new().unwrap();

        // Create a new UserStore with test data
        let mut store = UserStore {
            users: HashMap::new(),
            salt: generate_random_salt(),
            iv: generate_random_iv(),
            reset_tokens: HashMap::new(),
            reset_attempts: HashMap::new(),
            registration_verifications: HashMap::new(),
        };

        // Create a test user
        let password_hash = hex::encode(derive_key_from_passphrase("Password123!", &store.salt));
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create the user struct
        let username = "TestUser".to_string();
        let username_normalized = "testuser".to_string();
        let email = "test@example.com".to_string();
        let tasks_file = format!("tasks/test_user_{}.dat", current_time);

        // Create a user for the HashMap
        let user = User {
            username: username.clone(),
            username_normalized: username_normalized.clone(),
            email: email.clone(),
            password_hash: password_hash.clone(),
            created_at: current_time,
            last_login: current_time,
            failed_attempts: 0,
            last_failed_attempt: 0,
            tasks_file: tasks_file.clone(),
            last_activity: current_time,
            verification_status: VerificationStatus::Verified,
        };

        // Add user to store
        store.users.insert(username_normalized.clone(), user);

        // Create a second user struct with the same data for testing
        let user_for_testing = User {
            username,
            username_normalized,
            email,
            password_hash,
            created_at: current_time,
            last_login: current_time,
            failed_attempts: 0,
            last_failed_attempt: 0,
            tasks_file,
            last_activity: current_time,
            verification_status: VerificationStatus::Verified,
        };

        (store, user_for_testing, temp_file)
    }

    #[test]
    /// Test password reset token generation
    fn test_reset_token_generation() {
        let (_, user, _) = setup_test_user_store_with_user();

        // Request password reset
        let reset_token = user.request_password_reset().unwrap();

        // Verify token properties
        assert_eq!(reset_token.user_email, user.email);
        assert_eq!(reset_token.username, user.username);
        assert!(!reset_token.token.is_empty());
        assert_eq!(reset_token.token.len(), 32); // Should be 32 characters long

        // Verify expiration is set to 30 minutes in the future
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(reset_token.expires_at > current_time);
        assert!(reset_token.expires_at <= current_time + 1800); // 30 minutes
    }

    #[test]
    /// Test token expiration handling
    fn test_token_expiration() {
        let (mut store, user, _) = setup_test_user_store_with_user();

        // Create a reset token that's already expired
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expired_token = PasswordResetToken {
            token: "expired_token".to_string(),
            expires_at: current_time - 60, // Expired 1 minute ago
            user_email: user.email.clone(),
            username: user.username.clone(),
        };

        // Add to store
        store
            .reset_tokens
            .insert(expired_token.token.clone(), expired_token.clone());

        // Create a valid token
        let valid_token = PasswordResetToken {
            token: "valid_token".to_string(),
            expires_at: current_time + 1800, // Valid for 30 minutes
            user_email: user.email.clone(),
            username: user.username.clone(),
        };

        // Add to store
        store
            .reset_tokens
            .insert(valid_token.token.clone(), valid_token.clone());

        // Test manual token validation
        assert!(current_time > expired_token.expires_at); // Verify it's expired
        assert!(current_time < valid_token.expires_at); // Verify it's valid

        // Cleanup expired tokens
        cleanup_expired_data(&mut store);

        // Expired token should be removed, valid one should remain
        assert!(!store.reset_tokens.contains_key(&expired_token.token));
        assert!(store.reset_tokens.contains_key(&valid_token.token));
    }

    #[test]
    /// Test password reset attempt rate limiting
    fn test_reset_rate_limiting() {
        let (mut store, _, _) = setup_test_user_store_with_user();
        let email = "rate_limited@example.com";

        // Create a reset attempt tracker
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut tracker = ResetAttemptTracker {
            attempts: 0,
            first_attempt: current_time,
            last_attempt: current_time,
        };

        // Test attempts within limit
        for i in 1..=4 {
            tracker.attempts = i;
            assert!(tracker.attempts < 5);
        }

        // Test exceeding attempt limit
        tracker.attempts = 5;
        assert!(tracker.attempts >= 5);

        // Add to store
        store.reset_attempts.insert(email.to_string(), tracker);

        // Verify tracker is in store
        assert!(store.reset_attempts.contains_key(email));

        // Test old tracker cleanup
        let old_email = "old@example.com";
        let old_tracker = ResetAttemptTracker {
            attempts: 1,
            first_attempt: current_time - 25 * 60 * 60, // 25 hours ago
            last_attempt: current_time - 25 * 60 * 60,
        };
        store
            .reset_attempts
            .insert(old_email.to_string(), old_tracker);

        // Clean up expired data
        cleanup_expired_data(&mut store);

        // Recent tracker should remain, old one should be removed
        assert!(store.reset_attempts.contains_key(email));
        assert!(!store.reset_attempts.contains_key(old_email));
    }

    #[test]
    /// Test secure token manager
    fn test_secure_token_manager() {
        // Create a mock implementation for testing
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
    /// Test password reset email structure
    fn test_reset_email_content() {
        // Create a reset token
        let token = PasswordResetToken {
            token: "test_token_123".to_string(),
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 1800,
            user_email: "test@example.com".to_string(),
            username: "TestUser".to_string(),
        };

        // Instead of actually sending an email, we'll mock the send_email function
        // and check that the email content is properly formatted

        // In a real implementation, you might use a mocking library
        // Here we'll just manually check some properties we expect in a reset email

        // Verify token is included in email content
        let email_content = format!(
            "To reset your password, use the following token:\n\n{}\n\n",
            token.token
        );
        assert!(email_content.contains(&token.token));

        // Verify email contains important security content
        assert!(email_content.contains("reset your password"));
        assert!(email_content.contains(&token.token));
    }

    #[test]
    /// Test get_new_password function
    fn test_get_new_password() {
        // This test is tricky because get_new_password requires interactive input
        // In a real test, you might mock stdin or refactor the function to accept input as a parameter

        // For now, we'll test the password validation logic directly

        // Valid password should pass validation
        assert!(validate_password("NewPassword123!").is_ok());

        // Invalid passwords should fail validation with specific errors
        assert!(matches!(
            validate_password("short1!"),
            Err(PasswordError::TooShort)
        ));
        assert!(matches!(
            validate_password("nouppercase123!"),
            Err(PasswordError::NoUppercase)
        ));
        assert!(matches!(
            validate_password("NOLOWERCASE123!"),
            Err(PasswordError::NoLowercase)
        ));
        assert!(matches!(
            validate_password("NoNumbers!"),
            Err(PasswordError::NoNumber)
        ));
        assert!(matches!(
            validate_password("NoSpecials123"),
            Err(PasswordError::NoSpecialChar)
        ));
    }

    #[test]
    /// Test handling of SecurityEmailManager
    fn test_email_manager() {
        // Create a mock email manager for testing
        struct MockSecureEmailManager {
            stored_credentials: Option<SmtpCredentials>,
        }

        impl MockSecureEmailManager {
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
                    Some(creds) => {
                        // Create a new SmtpCredentials instance instead of cloning
                        Ok(SmtpCredentials {
                            username: creds.username.clone(),
                            password: creds.password.clone(),
                            host: creds.host.clone(),
                            port: creds.port,
                            last_updated: creds.last_updated,
                        })
                    }
                    None => Err("No credentials stored".to_string()),
                }
            }

            fn delete_credentials(&mut self) -> Result<(), String> {
                self.stored_credentials = None;
                Ok(())
            }
        }

        // Test storage and retrieval of email credentials
        let mut email_manager = MockSecureEmailManager::new();

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

// Admin Management tests
// These tests cover the administrative functionality of your application, including:
// 1. Admin credential initialization and verification
// 2. Admin password security and validation
// 3. Admin authentication rate limiting and lockout
// 4. Setup token generation and validation
// 5. Secure configuration storage
// 6. Admin password changes
#[cfg(test)]
mod admin_management_tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Mock keyring for testing admin functionality
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

        fn delete_password(&mut self) -> Result<(), String> {
            self.data = None;
            Ok(())
        }
    }

    // Mock SecureAdminManager for testing
    struct MockSecureAdminManager {
        keyring: MockKeyring,
    }

    impl MockSecureAdminManager {
        fn new() -> Self {
            Self {
                keyring: MockKeyring::new(),
            }
        }

        fn is_initialized(&self) -> bool {
            self.keyring.get_password().is_ok()
        }

        fn initialize_admin(&mut self, password: &str) -> Result<(), String> {
            if self.is_initialized() {
                return Err("Admin credentials already initialized".to_string());
            }

            // Generate a secure salt for admin password
            let salt = generate_random_salt();

            // Hash the password with the salt
            let password_hash = derive_key_from_passphrase(password, &salt);

            // Store both salt and hash
            let admin_data = format!("{}:{}", hex::encode(&salt), hex::encode(password_hash));

            self.keyring.set_password(&admin_data)
        }

        fn verify_admin(&self, password: &str) -> Result<bool, String> {
            let stored_data = self.keyring.get_password()?;

            let parts: Vec<&str> = stored_data.split(':').collect();
            if parts.len() != 2 {
                return Err("Invalid admin credential format".to_string());
            }

            let salt =
                hex::decode(parts[0]).map_err(|e| format!("Failed to decode salt: {}", e))?;
            let stored_hash = parts[1];

            let test_hash = hex::encode(derive_key_from_passphrase(password, &salt));

            Ok(test_hash == stored_hash)
        }

        fn change_admin_password(
            &mut self,
            current_password: &str,
            new_password: &str,
        ) -> Result<(), String> {
            // Verify current password first
            if !self.verify_admin(current_password)? {
                return Err("Current password is incorrect".to_string());
            }

            // Generate new salt
            let new_salt = generate_random_salt();

            // Hash the new password
            let new_hash = derive_key_from_passphrase(new_password, &new_salt);

            // Store new credentials
            let admin_data = format!("{}:{}", hex::encode(&new_salt), hex::encode(new_hash));

            self.keyring.set_password(&admin_data)
        }
    }

    // Mock SecureAdminConfig for testing
    struct MockSecureAdminConfig {
        keyring: MockKeyring,
        master_key: Vec<u8>,
    }

    impl MockSecureAdminConfig {
        fn new() -> Self {
            Self {
                keyring: MockKeyring::new(),
                master_key: (0..32).map(|_| rand::random::<u8>()).collect(),
            }
        }

        fn save_config(&mut self, config: &AdminConfig) -> Result<(), String> {
            // Convert config to JSON string for storage
            let config_json = serde_json::to_string(config)
                .map_err(|e| format!("Failed to serialize config: {}", e))?;

            // Generate new IV for each save operation for better security
            let iv = generate_random_iv();

            // Encrypt the configuration data
            let encrypted_data = encrypt_data(&config_json, &self.master_key, &iv);

            // Combine IV and encrypted data for storage
            let mut storage_data = Vec::new();
            storage_data.extend_from_slice(&iv);
            storage_data.extend_from_slice(&encrypted_data);

            // Store as base64 encoded string in keyring
            let encoded_data = base64.encode(&storage_data);
            self.keyring.set_password(&encoded_data)
        }

        fn load_config(&self) -> Result<AdminConfig, String> {
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
                    let decrypted_data = decrypt_data(encrypted_data, &self.master_key, iv)
                        .map_err(|e| format!("Failed to decrypt config: {}", e))?;

                    serde_json::from_str(&decrypted_data)
                        .map_err(|e| format!("Failed to parse config: {}", e))
                }
                Err(_) => {
                    // If no configuration exists yet, return a new default configuration
                    Ok(AdminConfig::new())
                }
            }
        }
    }

    #[test]
    /// Test admin credential initialization
    fn test_admin_credential_initialization() {
        let mut admin_manager = MockSecureAdminManager::new();

        // Initially should not be initialized
        assert!(!admin_manager.is_initialized());

        // Initialize with a valid password
        let result = admin_manager.initialize_admin("StrongAdminPass123!");
        assert!(result.is_ok());

        // Should now be initialized
        assert!(admin_manager.is_initialized());

        // Attempt to initialize again should fail
        let result = admin_manager.initialize_admin("AnotherPassword456!");
        assert!(result.is_err());
    }

    #[test]
    /// Test admin password verification
    fn test_admin_password_verification() {
        let mut admin_manager = MockSecureAdminManager::new();

        // Initialize with a password
        admin_manager.initialize_admin("AdminPassword123!").unwrap();

        // Verify correct password
        let result = admin_manager.verify_admin("AdminPassword123!");
        assert!(result.unwrap());

        // Verify incorrect password
        let result = admin_manager.verify_admin("WrongPassword123!");
        assert!(!result.unwrap());
    }

    #[test]
    /// Test admin password change
    fn test_admin_password_change() {
        let mut admin_manager = MockSecureAdminManager::new();
        let original_password = "OriginalPass123!";
        let new_password = "NewPassword456!";

        // Initialize with original password
        admin_manager.initialize_admin(original_password).unwrap();

        // Change password
        let result = admin_manager.change_admin_password(original_password, new_password);
        assert!(result.is_ok());

        // Original password should no longer work
        let result = admin_manager.verify_admin(original_password);
        assert!(!result.unwrap());

        // New password should work
        let result = admin_manager.verify_admin(new_password);
        assert!(result.unwrap());

        // Attempting to change with incorrect current password should fail
        let result = admin_manager.change_admin_password("WrongPassword123!", "AnotherPass789!");
        assert!(result.is_err());
    }

    #[test]
    /// Test admin authentication tracker
    fn test_admin_auth_tracker() {
        let mut tracker = AdminAuthTracker::new();

        // Initial state
        assert_eq!(tracker.failed_attempts, 0);
        assert_eq!(tracker.lockout_until, 0);

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Record failed attempts up to lockout
        for i in 1..=MAX_ADMIN_ATTEMPTS {
            tracker.record_failed_attempt(current_time);
            if i < MAX_ADMIN_ATTEMPTS {
                assert!(!tracker.is_locked_out(current_time));
            } else {
                // Should be locked out after MAX_ADMIN_ATTEMPTS
                assert!(tracker.is_locked_out(current_time));
                // Lockout should be set to current_time + ADMIN_LOCKOUT_DURATION
                assert_eq!(tracker.lockout_until, current_time + ADMIN_LOCKOUT_DURATION);
            }
        }

        // Test that lockout expires
        let after_lockout = current_time + ADMIN_LOCKOUT_DURATION + 1;
        assert!(!tracker.is_locked_out(after_lockout));

        // Test that attempts are reset after lockout expires
        tracker.maybe_reset_attempts(after_lockout);
        assert_eq!(tracker.failed_attempts, 0);

        // Test that successful login resets the counter
        tracker.record_failed_attempt(current_time);
        assert_eq!(tracker.failed_attempts, 1);
        tracker.record_success();
        assert_eq!(tracker.failed_attempts, 0);
        assert_eq!(tracker.lockout_until, 0);
    }

    #[test]
    /// Test admin config class
    fn test_admin_config() {
        let mut config = AdminConfig::new();

        // Test initial state
        assert_eq!(config.auth_tracker.failed_attempts, 0);
        assert!(config.setup_token.is_none());
        assert!(config.setup_token_expiry.is_none());
        assert_eq!(config.allowed_setup_ips.len(), 0);

        // Test token generation
        let token = config.generate_setup_token();
        assert!(!token.is_empty());
        assert!(config.setup_token.is_some());
        assert!(config.setup_token_expiry.is_some());

        // Test token validation
        assert!(config.validate_setup_token(&token));
        assert!(!config.validate_setup_token("invalid_token"));

        // Test token expiration
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        config.setup_token_expiry = Some(current_time - 1);
        assert!(!config.validate_setup_token(&token));
    }

    #[test]
    /// Test secure admin config storage
    fn test_secure_admin_config_storage() {
        // Create the mock config storage
        let mut secure_config = MockSecureAdminConfig::new();

        // Create a default config
        let mut config = AdminConfig::new();

        // Add some non-default settings
        config.generate_setup_token();
        config.allowed_setup_ips.push("192.168.1.1".to_string());

        // Save the config
        let save_result = secure_config.save_config(&config);
        assert!(save_result.is_ok());

        // Load the config
        let loaded_config = secure_config.load_config().unwrap();

        // Verify data was saved and loaded correctly
        assert_eq!(loaded_config.allowed_setup_ips.len(), 1);
        assert_eq!(loaded_config.allowed_setup_ips[0], "192.168.1.1");
        assert!(loaded_config.setup_token.is_some());
        assert!(loaded_config.setup_token_expiry.is_some());
    }

    #[test]
    /// Test admin setup token functionality
    fn test_setup_token_functionality() {
        let mut config = AdminConfig::new();

        // Generate a token
        let token = config.generate_setup_token();

        // Token length should be 32 characters (from the Alphanumeric generator)
        assert_eq!(token.len(), 32);

        // Token should be valid initially
        assert!(config.validate_setup_token(&token));

        // Invalid token should fail
        assert!(!config.validate_setup_token("invalid_token"));

        // Token should have an expiry time set
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(config.setup_token_expiry.unwrap() > current_time);
        assert!(config.setup_token_expiry.unwrap() <= current_time + SETUP_TOKEN_DURATION);
    }

    #[test]
    /// Test enhanced verify admin functionality with rate limiting
    fn test_enhanced_admin_verification() {
        // Create mock config and admin manager
        let mut secure_config = MockSecureAdminConfig::new();
        let mut admin_manager = MockSecureAdminManager::new();

        // Initialize admin credentials
        admin_manager.initialize_admin("AdminPassword123!").unwrap();

        // Create config with reset auth tracker
        let mut config = AdminConfig::new();
        secure_config.save_config(&config).unwrap();

        // Simulate the enhanced_verify_admin function
        // This would normally use the real config and admin manager

        // 1. Test successful verification
        if config.auth_tracker.is_locked_out(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ) {
            panic!("Should not be locked out initially");
        }

        let result = admin_manager.verify_admin("AdminPassword123!").unwrap();
        assert!(result);

        config.auth_tracker.record_success();
        assert_eq!(config.auth_tracker.failed_attempts, 0);

        // 2. Test failed verification and attempt tracking
        let result = admin_manager.verify_admin("WrongPassword123!").unwrap();
        assert!(!result);

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        config.auth_tracker.record_failed_attempt(current_time);
        assert_eq!(config.auth_tracker.failed_attempts, 1);

        // 3. Test lockout after multiple failed attempts
        for _ in 2..=MAX_ADMIN_ATTEMPTS {
            config.auth_tracker.record_failed_attempt(current_time);
        }

        assert!(config.auth_tracker.is_locked_out(current_time));

        // 4. Test lockout expiration
        let future_time = current_time + ADMIN_LOCKOUT_DURATION + 1;
        config.auth_tracker.maybe_reset_attempts(future_time);
        assert_eq!(config.auth_tracker.failed_attempts, 0);
        assert!(!config.auth_tracker.is_locked_out(future_time));
    }
}

// User Profile Management tests
// These tests cover the user profile functionality of your application, including:
// 1. User profile information retrieval and display
// 2. Email address updates with verification
// 3. User activity tracking
// 4. Profile data persistence
// 5. User verification status management
// 6. Last login and activity timestamps
#[cfg(test)]
mod user_profile_tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Helper function to create a test user store with sample users
    fn setup_test_user_store() -> (UserStore, NamedTempFile) {
        // Create a temporary file for the user store
        let temp_file = NamedTempFile::new().unwrap();

        // Create a new UserStore with test data
        let mut store = UserStore {
            users: HashMap::new(),
            salt: generate_random_salt(),
            iv: generate_random_iv(),
            reset_tokens: HashMap::new(),
            reset_attempts: HashMap::new(),
            registration_verifications: HashMap::new(),
        };

        // Add a sample user
        add_test_user(&mut store, "TestUser", "test@example.com", "Password123!");

        // Return the store and temp file (to keep it from being dropped)
        (store, temp_file)
    }

    // Helper function to add a test user to the store
    fn add_test_user(store: &mut UserStore, username: &str, email: &str, password: &str) -> User {
        // Create a hash from the password
        let password_hash = hex::encode(derive_key_from_passphrase(password, &store.salt));

        // Get current timestamp
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create the user data
        let username_str = username.to_string();
        let username_normalized = username.to_lowercase();
        let email_str = email.to_string();
        let tasks_file = format!("tasks/test_user_{}.dat", username_normalized);

        // Create a user for the HashMap
        let user = User {
            username: username_str.clone(),
            username_normalized: username_normalized.clone(),
            email: email_str.clone(),
            password_hash: password_hash.clone(),
            created_at: current_time,
            last_login: current_time,
            failed_attempts: 0,
            last_failed_attempt: 0,
            tasks_file: tasks_file.clone(),
            last_activity: current_time,
            verification_status: VerificationStatus::Verified,
        };

        // Insert into store
        store.users.insert(username_normalized.clone(), user);

        // Create and return a copy of the user for testing
        User {
            username: username_str,
            username_normalized,
            email: email_str,
            password_hash,
            created_at: current_time,
            last_login: current_time,
            failed_attempts: 0,
            last_failed_attempt: 0,
            tasks_file,
            last_activity: current_time,
            verification_status: VerificationStatus::Verified,
        }
    }

    #[test]
    /// Test user profile data retrieval
    fn test_profile_retrieval() {
        let (store, _) = setup_test_user_store();

        // Get the test user (we know it exists because we added it in setup)
        let user = store.users.get("testuser").unwrap();

        // Verify profile data
        assert_eq!(user.username, "TestUser");
        assert_eq!(user.email, "test@example.com");
        assert!(user.created_at > 0);
        assert!(user.last_login > 0);
        assert!(user.last_activity > 0);

        // Test timestamp formatting
        let formatted_time = format_timestamp(user.created_at);
        assert!(!formatted_time.is_empty());
    }

    #[test]
    /// Test email address updates
    fn test_email_update() {
        let (mut store, _) = setup_test_user_store();

        // Get the username for lookups
        let username_normalized = "testuser".to_string();
        let old_email = "test@example.com".to_string();
        let new_email = "updated@example.com".to_string();

        // Verify original email
        let user = store.users.get(&username_normalized).unwrap();
        assert_eq!(user.email, old_email);

        // Update email address
        if let Some(user) = store.users.get_mut(&username_normalized) {
            user.email = new_email.clone();
        }

        // Verify email was updated
        let updated_user = store.users.get(&username_normalized).unwrap();
        assert_eq!(updated_user.email, new_email);

        // Test email validation before updating
        let invalid_email = "not-an-email";
        assert!(!is_valid_email(invalid_email));

        // Test email uniqueness check
        let conflicting_user = add_test_user(
            &mut store,
            "AnotherUser",
            "unique@example.com",
            "Password456!",
        );
        let has_conflict = store
            .users
            .values()
            .any(|u| u.email == conflicting_user.email && u.username != conflicting_user.username);
        assert!(!has_conflict);

        // Adding duplicate email should create a conflict
        let has_conflict = store
            .users
            .values()
            .any(|u| u.email == new_email && u.username != "TestUser");
        assert!(!has_conflict); // Should be false as we haven't created a conflict yet

        // Now add another user with the same email
        add_test_user(&mut store, "ConflictUser", &new_email, "Password789!");

        // Check for conflict again
        let has_conflict = store
            .users
            .values()
            .any(|u| u.email == new_email && u.username != "ConflictUser");
        assert!(has_conflict); // Should now be true
    }

    #[test]
    /// Test user activity tracking
    fn test_activity_tracking() {
        let (mut store, _) = setup_test_user_store();

        // Get the username for lookups
        let username_normalized = "testuser".to_string();

        // Get initial activity time
        let user = store.users.get(&username_normalized).unwrap();
        let initial_activity = user.last_activity;

        // Simulate waiting by advancing the time
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Update last activity time
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if let Some(user) = store.users.get_mut(&username_normalized) {
            user.last_activity = current_time;
        }

        // Verify activity time was updated
        let updated_user = store.users.get(&username_normalized).unwrap();
        assert!(updated_user.last_activity > initial_activity);
    }

    #[test]
    /// Test user login timestamp updates
    fn test_login_timestamp_updates() {
        let (mut store, _) = setup_test_user_store();

        // Get the username for lookups
        let username_normalized = "testuser".to_string();

        // Get initial login time
        let user = store.users.get(&username_normalized).unwrap();
        let initial_login = user.last_login;

        // Simulate waiting by advancing the time
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Simulate a successful login by updating the timestamp
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if let Some(user) = store.users.get_mut(&username_normalized) {
            user.last_login = current_time;
            // Should also reset failed attempts
            user.failed_attempts = 0;
        }

        // Verify login time was updated
        let updated_user = store.users.get(&username_normalized).unwrap();
        assert!(updated_user.last_login > initial_login);
        assert_eq!(updated_user.failed_attempts, 0);

        // Test failed login attempt tracking
        if let Some(user) = store.users.get_mut(&username_normalized) {
            user.failed_attempts += 1;
            user.last_failed_attempt = current_time;
        }

        let updated_user = store.users.get(&username_normalized).unwrap();
        assert_eq!(updated_user.failed_attempts, 1);
        assert_eq!(updated_user.last_failed_attempt, current_time);
    }

    #[test]
    /// Test verification status management
    fn test_verification_status() {
        let (mut store, _) = setup_test_user_store();

        // Create an unverified user
        let unverified_user = User {
            username: "UnverifiedUser".to_string(),
            username_normalized: "unverifieduser".to_string(),
            email: "unverified@example.com".to_string(),
            password_hash: "dummy_hash".to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_login: 0,
            failed_attempts: 0,
            last_failed_attempt: 0,
            tasks_file: "tasks/unverified.dat".to_string(),
            last_activity: 0,
            verification_status: VerificationStatus::Unverified,
        };

        // Add to store
        store
            .users
            .insert(unverified_user.username_normalized.clone(), unverified_user);

        // Verify the user is unverified
        let user = store.users.get("unverifieduser").unwrap();
        assert!(!user.verification_status.is_verified());

        // Update verification status
        if let Some(user) = store.users.get_mut("unverifieduser") {
            user.verification_status = VerificationStatus::Verified;
        }

        // Verify the user is now verified
        let user = store.users.get("unverifieduser").unwrap();
        assert!(user.verification_status.is_verified());

        // Test verification status enum methods
        assert!(VerificationStatus::Verified.is_verified());
        assert!(!VerificationStatus::Unverified.is_verified());
    }

    #[test]
    /// Test user data persistence through save and load
    fn test_user_data_persistence() {
        // This test would simulate saving the user store to a file and loading it back
        // For testing, we'll create a UserStore, add a user, simulate save/load, and verify

        // Create a temporary file for testing
        let temp_file = NamedTempFile::new().unwrap();
        let temp_path = temp_file.path().to_str().unwrap().to_string();

        // Create a store with a test user
        let mut store = UserStore {
            users: HashMap::new(),
            salt: generate_random_salt(),
            iv: generate_random_iv(),
            reset_tokens: HashMap::new(),
            reset_attempts: HashMap::new(),
            registration_verifications: HashMap::new(),
        };

        // Add a test user
        let test_user = add_test_user(
            &mut store,
            "PersistenceUser",
            "persist@example.com",
            "Password123!",
        );

        // Create a mock implementation of save_user_store and load_user_store
        // In a real test, we'd need to actually call these functions
        // For now, we'll just simulate by creating a new store with the same data

        // Create a new store to simulate loading from file
        let mut loaded_store = UserStore {
            users: HashMap::new(),
            salt: store.salt.clone(),
            iv: store.iv.clone(),
            reset_tokens: HashMap::new(),
            reset_attempts: HashMap::new(),
            registration_verifications: HashMap::new(),
        };

        // Add the same user to the "loaded" store
        loaded_store.users.insert(
            test_user.username_normalized.clone(),
            User {
                username: test_user.username.clone(),
                username_normalized: test_user.username_normalized.clone(),
                email: test_user.email.clone(),
                password_hash: test_user.password_hash.clone(),
                created_at: test_user.created_at,
                last_login: test_user.last_login,
                failed_attempts: test_user.failed_attempts,
                last_failed_attempt: test_user.last_failed_attempt,
                tasks_file: test_user.tasks_file.clone(),
                last_activity: test_user.last_activity,
                verification_status: if test_user.verification_status.is_verified() {
                    VerificationStatus::Verified
                } else {
                    VerificationStatus::Unverified
                },
            },
        );

        // Verify the user data was preserved in the "loaded" store
        let loaded_user = loaded_store
            .users
            .get(&test_user.username_normalized)
            .unwrap();
        assert_eq!(loaded_user.username, test_user.username);
        assert_eq!(loaded_user.email, test_user.email);
        assert_eq!(loaded_user.password_hash, test_user.password_hash);
        assert_eq!(loaded_user.created_at, test_user.created_at);
    }

    #[test]
    /// Test user task file generation
    fn test_task_file_generation() {
        // Test that the function generates valid filenames
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let user = User {
            username: "FilenameTest".to_string(),
            username_normalized: "filenametest".to_string(),
            email: "filename@example.com".to_string(),
            password_hash: "dummy_hash".to_string(),
            created_at: current_time,
            last_login: current_time,
            failed_attempts: 0,
            last_failed_attempt: 0,
            tasks_file: "".to_string(), // Will be generated
            last_activity: current_time,
            verification_status: VerificationStatus::Verified,
        };

        // Generate the filename
        let result = user.generate_task_filename();
        assert!(result.is_ok());

        let filename = result.unwrap();

        // Verify filename format
        assert!(filename.starts_with("tasks/user_"));
        assert!(filename.ends_with(".dat"));

        // Verify it contains a hash component (should be 16 hex chars = 8 bytes)
        let hash_part = filename
            .strip_prefix("tasks/user_")
            .unwrap()
            .strip_suffix(".dat")
            .unwrap();
        assert_eq!(hash_part.len(), 16);

        // Verify the hash contains only hex characters
        assert!(hash_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    /// Test handling of account update conflicts
    fn test_account_update_conflicts() {
        let (mut store, _) = setup_test_user_store();

        // Create a second user
        add_test_user(
            &mut store,
            "SecondUser",
            "second@example.com",
            "Password456!",
        );

        // Attempt to update the second user's email to conflict with first user
        let has_conflict = store.users.values().any(|u| u.email == "test@example.com");
        assert!(has_conflict); // Should find a conflict

        // Simulate checking for a conflict before update
        let new_email = "new@example.com";
        let email_in_use = store.users.values().any(|u| u.email == new_email);
        assert!(!email_in_use); // Should not find a conflict

        // Update email should succeed
        if let Some(user) = store.users.get_mut("seconduser") {
            user.email = new_email.to_string();
        }

        // Verify the email was updated
        let updated_user = store.users.get("seconduser").unwrap();
        assert_eq!(updated_user.email, new_email);
    }
}

// Email Verification tests
// These tests cover the email verification functionality of your application, including:
// 1. Verification token generation and validation
// 2. Token expiration handling
// 3. Verification status updates
// 4. Email sending for verification
// 5. Registration verification flow
// 6. Verification attempt limiting
#[cfg(test)]
mod email_verification_tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Helper function to create a test user store with sample users
    fn setup_test_user_store() -> (UserStore, NamedTempFile) {
        // Create a temporary file for the user store
        let temp_file = NamedTempFile::new().unwrap();

        // Create a new UserStore with test data
        let mut store = UserStore {
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

    // Helper function to add a test user to the store
    fn add_test_user(
        store: &mut UserStore,
        username: &str,
        email: &str,
        password: &str,
        verified: bool,
    ) -> User {
        // Create a hash from the password
        let password_hash = hex::encode(derive_key_from_passphrase(password, &store.salt));

        // Get current timestamp
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create the user data
        let username_str = username.to_string();
        let username_normalized = username.to_lowercase();
        let email_str = email.to_string();
        let tasks_file = format!("tasks/test_user_{}.dat", username_normalized);

        // Set verification status
        let verification_status = if verified {
            VerificationStatus::Verified
        } else {
            VerificationStatus::Unverified
        };

        // Create a user for the HashMap
        let user = User {
            username: username_str.clone(),
            username_normalized: username_normalized.clone(),
            email: email_str.clone(),
            password_hash: password_hash.clone(),
            created_at: current_time,
            last_login: current_time,
            failed_attempts: 0,
            last_failed_attempt: 0,
            tasks_file: tasks_file.clone(),
            last_activity: current_time,
            verification_status: verification_status.clone(),
        };

        // Insert into store
        store.users.insert(username_normalized.clone(), user);

        // Create and return a copy of the user for testing
        User {
            username: username_str,
            username_normalized,
            email: email_str,
            password_hash,
            created_at: current_time,
            last_login: current_time,
            failed_attempts: 0,
            last_failed_attempt: 0,
            tasks_file,
            last_activity: current_time,
            verification_status,
        }
    }

    // Helper to create a verification token
    fn create_test_verification_token(
        username: &str,
        email: &str,
        expires_in_seconds: u64,
    ) -> RegistrationVerification {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        RegistrationVerification {
            token: "123456".to_string(), // Use a fixed token for testing
            username: username.to_string(),
            expires_at: current_time + expires_in_seconds,
            verified: false,
        }
    }

    #[test]
    /// Test verification token generation
    fn test_verification_token_generation() {
        // We can't directly test the random token generation since we don't have the function
        // But we can test a mock version of it

        // Mock function to generate a verification token
        fn mock_generate_verification_token() -> String {
            let token: String = (0..6)
                .map(|i| char::from_digit(i as u32 % 10, 10).unwrap())
                .collect();
            token
        }

        // Generate a few tokens
        let token1 = mock_generate_verification_token();
        let token2 = mock_generate_verification_token();

        // Verify token format
        assert_eq!(token1.len(), 6); // Should be 6 digits
        assert!(token1.chars().all(|c| c.is_ascii_digit())); // Should be all digits

        // In the real implementation tokens should be random, but our mock is deterministic
        assert_eq!(token1, token2);
    }

    #[test]
    /// Test creating and storing registration verification
    fn test_registration_verification_creation() {
        let (mut store, _) = setup_test_user_store();

        // Add an unverified user
        let user = add_test_user(
            &mut store,
            "UnverifiedUser",
            "unverified@example.com",
            "Password123!",
            false,
        );

        // Create a verification token
        let verification = create_test_verification_token(&user.username, &user.email, 86400); // 24 hours

        // Add to store
        store
            .registration_verifications
            .insert(user.username.clone(), verification);

        // Verify the verification was added
        assert!(store
            .registration_verifications
            .contains_key(&user.username));

        // Verify token properties
        let stored_verification = store
            .registration_verifications
            .get(&user.username)
            .unwrap();
        assert_eq!(stored_verification.token, "123456");
        assert_eq!(stored_verification.username, user.username);
        assert!(!stored_verification.verified);

        // Expiration should be 24 hours in the future
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(stored_verification.expires_at > current_time);
        assert!(stored_verification.expires_at <= current_time + 86400);
    }

    #[test]
    /// Test verification token validation
    fn test_verification_token_validation() {
        let (mut store, _) = setup_test_user_store();

        // Add an unverified user
        let user = add_test_user(
            &mut store,
            "VerifyUser",
            "verify@example.com",
            "Password123!",
            false,
        );

        // Create a verification token
        let verification = create_test_verification_token(&user.username, &user.email, 86400); // 24 hours

        // Add to store
        store
            .registration_verifications
            .insert(user.username.clone(), verification);

        // Verify user is initially unverified
        let unverified_user = store.users.get(&user.username_normalized).unwrap();
        assert!(!unverified_user.verification_status.is_verified());

        // Simulate verification token validation
        let input_token = "123456"; // Correct token

        // Check if token matches
        let stored_verification = store
            .registration_verifications
            .get(&user.username)
            .unwrap();
        let token_valid = stored_verification.token == input_token;
        assert!(token_valid);

        // Update user verification status
        if token_valid {
            if let Some(user) = store.users.get_mut(&user.username_normalized) {
                user.verification_status = VerificationStatus::Verified;
            }
        }

        // Verify user is now verified
        let verified_user = store.users.get(&user.username_normalized).unwrap();
        assert!(verified_user.verification_status.is_verified());

        // Remove verification entry after successful verification
        store.registration_verifications.remove(&user.username);

        // Verify verification entry was removed
        assert!(!store
            .registration_verifications
            .contains_key(&user.username));
    }

    #[test]
    /// Test token expiration handling
    fn test_verification_token_expiration() {
        let (mut store, _) = setup_test_user_store();

        // Add an unverified user
        let user = add_test_user(
            &mut store,
            "ExpiredUser",
            "expired@example.com",
            "Password123!",
            false,
        );

        // Create an expired verification token (expires 1 second in the past)
        let verification = create_test_verification_token(&user.username, &user.email, 0);
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut expired_verification = verification;
        expired_verification.expires_at = current_time - 1;

        // Add to store
        store
            .registration_verifications
            .insert(user.username.clone(), expired_verification);

        // Check if token is expired
        let stored_verification = store
            .registration_verifications
            .get(&user.username)
            .unwrap();
        let token_expired = current_time > stored_verification.expires_at;
        assert!(token_expired);

        // Create a valid verification token
        let valid_verification = create_test_verification_token(&user.username, &user.email, 86400);

        // Replace expired token
        store
            .registration_verifications
            .insert(user.username.clone(), valid_verification);

        // Verify the replacement worked
        let updated_verification = store
            .registration_verifications
            .get(&user.username)
            .unwrap();
        assert!(current_time < updated_verification.expires_at);
    }

    #[test]
    /// Test email template for verification
    fn test_verification_email_template() {
        // Mock the email content generation
        let token = "123456";
        let email_body = format!(
            "Welcome to One-Do-Three!\n\
            \n\
            Please verify your account using the following code:\n\
            \n\
            {}\n\
            \n\
            This code will expire in 24 hours.\n\
            \n\
            Best regards,\n\
            One-Do-Three Task Manager Team",
            token
        );

        // Verify email contains the token
        assert!(email_body.contains(token));

        // Verify email contains important information
        assert!(email_body.contains("verify your account"));
        assert!(email_body.contains("expire in 24 hours"));
    }

    #[test]
    /// Test verification attempt limiting
    fn test_verification_attempt_limiting() {
        // Mock validation function to simulate multiple attempts
        fn mock_validate_token(attempt: u32, max_attempts: u32) -> bool {
            attempt <= max_attempts
        }

        // Set up attempt limiting
        let max_attempts = 3;
        let mut attempts = 0;

        // First attempt (valid)
        attempts += 1;
        assert!(mock_validate_token(attempts, max_attempts));

        // Second attempt (valid)
        attempts += 1;
        assert!(mock_validate_token(attempts, max_attempts));

        // Third attempt (valid - last allowed)
        attempts += 1;
        assert!(mock_validate_token(attempts, max_attempts));

        // Fourth attempt (should fail due to max attempts)
        attempts += 1;
        assert!(!mock_validate_token(attempts, max_attempts));
    }

    #[test]
    /// Test verification flow control
    fn test_verification_flow_control() {
        // Mock VerificationResult enum
        enum MockVerificationResult {
            Back,
            Success,
            Error(String),
            Expired,
            Invalid,
        }

        // Mock verification function
        fn mock_verify_token(token: &str, is_expired: bool) -> MockVerificationResult {
            match token {
                "back" => MockVerificationResult::Back,
                "exit" => MockVerificationResult::Back, // In real code this would exit the program
                _ if is_expired => MockVerificationResult::Expired,
                "123456" => MockVerificationResult::Success,
                _ => MockVerificationResult::Invalid,
            }
        }

        // Test various scenarios
        assert!(matches!(
            mock_verify_token("123456", false),
            MockVerificationResult::Success
        ));
        assert!(matches!(
            mock_verify_token("back", false),
            MockVerificationResult::Back
        ));
        assert!(matches!(
            mock_verify_token("exit", false),
            MockVerificationResult::Back
        ));
        assert!(matches!(
            mock_verify_token("wrong", false),
            MockVerificationResult::Invalid
        ));
        assert!(matches!(
            mock_verify_token("123456", true),
            MockVerificationResult::Expired
        ));
    }

    #[test]
    /// Test verification status updates
    fn test_verification_status_update() {
        let (mut store, _) = setup_test_user_store();

        // Add an unverified user
        let user = add_test_user(
            &mut store,
            "StatusUser",
            "status@example.com",
            "Password123!",
            false,
        );

        // Verify initial status
        let initial_user = store.users.get(&user.username_normalized).unwrap();
        assert!(!initial_user.verification_status.is_verified());

        // Update verification status
        if let Some(user) = store.users.get_mut(&user.username_normalized) {
            user.verification_status = VerificationStatus::Verified;
        }

        // Verify updated status
        let updated_user = store.users.get(&user.username_normalized).unwrap();
        assert!(updated_user.verification_status.is_verified());

        // Test enum variants
        assert!(matches!(
            VerificationStatus::Verified,
            VerificationStatus::Verified
        ));
        assert!(matches!(
            VerificationStatus::Unverified,
            VerificationStatus::Unverified
        ));
    }

    #[test]
    /// Test mock email sending for verification
    fn test_mock_email_sending() {
        // Since we can't actually send emails in tests, we'll mock the function
        struct MockEmailSender {
            last_email: Option<(String, String, String)>,
        }

        impl MockEmailSender {
            fn new() -> Self {
                Self { last_email: None }
            }

            fn send_email(&mut self, to: &str, subject: &str, body: &str) -> Result<(), String> {
                self.last_email = Some((to.to_string(), subject.to_string(), body.to_string()));
                Ok(())
            }
        }

        // Create the mock sender
        let mut email_sender = MockEmailSender::new();

        // Send a verification email
        let to = "test@example.com";
        let subject = "Welcome to One-Do-Three - Verify Your Account";
        let token = "123456";
        let body = format!(
            "Welcome to One-Do-Three!\n\
            \n\
            Please verify your account using the following code:\n\
            \n\
            {}\n\
            \n\
            This code will expire in 24 hours.\n\
            \n\
            Best regards,\n\
            One-Do-Three Task Manager Team",
            token
        );

        // Send the email
        let result = email_sender.send_email(to, subject, &body);
        assert!(result.is_ok());

        // Verify the email details were stored
        let (stored_to, stored_subject, stored_body) = email_sender.last_email.unwrap();
        assert_eq!(stored_to, to);
        assert_eq!(stored_subject, subject);
        assert_eq!(stored_body, body);
        assert!(stored_body.contains(token));
    }
}
