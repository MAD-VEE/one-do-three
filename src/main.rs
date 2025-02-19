// External crate dependencies for various functionalities
use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use clap::{Arg, Command};
use env_logger::{Builder, WriteStyle};
use hmac::Hmac;
use itertools::Itertools;
use keyring::Entry;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use log::{error, info, warn, LevelFilter};
use pbkdf2::pbkdf2;
use rand::distributions::Alphanumeric;
use rand::Rng;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
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

// Constant for the tasks storage file
const STORAGE_FILE: &str = "tasks.json";

// Add new constant for user storage
const USERS_FILE: &str = "users.json";

// Structure representing a single task
#[derive(Serialize, Deserialize, Debug)]
struct Task {
    name: String,
    description: String,
    priority: String,
    completed: bool,
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
}

// Container for all users with encryption metadata for secure storage, and a token store to track active reset tokens
#[derive(Serialize, Deserialize)]
struct UserStore {
    users: HashMap<String, User>,
    salt: Vec<u8>,
    iv: Vec<u8>,
    reset_tokens: HashMap<String, PasswordResetToken>,
    reset_attempts: HashMap<String, ResetAttemptTracker>, // Tracks reset attempts by email
}

// Custom error type for task operations
#[derive(Debug)]
enum TaskError {
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
    MatchesOld,
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
    password: &str,
    cache: &SecurePasswordCache,
) -> DeletionStatus {
    // Initialize cleanup status
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
    cleanup_status.store_saved = true;

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
    if cleanup_status.store_saved {
        DeletionStatus::Success
    } else {
        DeletionStatus::Failed("Critical cleanup operations failed".to_string())
    }
}

// Structure to track cleanup status
#[derive(Debug)]
struct CleanupStatus {
    task_file_removed: bool,
    cache_cleared: bool,
    store_saved: bool,
}

// Function to handle graceful program exit with cleanup
fn handle_program_exit(cleanup_status: &CleanupStatus) -> i32 {
    // Log any cleanup failures
    if !cleanup_status.task_file_removed {
        error!("Failed to remove all task files during cleanup");
    }
    if !cleanup_status.cache_cleared {
        error!("Failed to clear password cache during cleanup");
    }
    if !cleanup_status.store_saved {
        error!("Failed to save user store during cleanup");
    }

    // Determine exit code based on cleanup status
    if cleanup_status.task_file_removed
        && cleanup_status.cache_cleared
        && cleanup_status.store_saved
    {
        0 // Successful cleanup
    } else {
        1 // Cleanup had some failures
    }
}

// Function to clean up user's task files
fn cleanup_user_tasks(username: &str, store: &UserStore) -> Result<(), io::Error> {
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

// Structure to hold SMTP credentials with metadata
#[derive(Serialize, Deserialize)]
struct SmtpCredentials {
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
    // Service name for identifying the application
    service_name: String,
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
            service_name,
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
pub fn send_reset_email(reset_token: &PasswordResetToken) -> Result<(), String> {
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

    // Function to retrieve a user from the store
    // Takes a reference to username and returns an Option containing a reference to the User
    // Returns None if user doesn't exist
    pub fn get_user(&self, username: &str) -> Option<&User> {
        let normalized_username = username.trim().to_lowercase();
        self.users.get(&normalized_username)
    }

    // Function to clean up orphaned task files
    // This removes any task files that don't belong to current users
    pub fn cleanup_task_files(&self) -> io::Result<()> {
        let tasks_dir = std::path::Path::new("tasks");
        if !tasks_dir.exists() {
            return Ok(());
        }

        // Collect all valid task files from current users
        let valid_files: HashSet<String> = self
            .users
            .values()
            .map(|user| user.tasks_file.clone())
            .collect();

        // Remove any files that don't belong to current users
        for entry in std::fs::read_dir(tasks_dir)? {
            let entry = entry?;
            let path = entry.path();
            if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
                let full_path = format!("tasks/{}", filename);
                if !valid_files.contains(&full_path) {
                    std::fs::remove_file(path)?;
                }
            }
        }

        Ok(())
    }

    // Function to migrate all existing users to secure filenames
    // This should be called when upgrading an existing system
    pub fn migrate_all_to_secure_filenames(&mut self) -> io::Result<()> {
        // Create tasks directory if it doesn't exist
        std::fs::create_dir_all("tasks")?;

        // Collect usernames first to avoid borrow checker issues
        let usernames: Vec<String> = self.users.keys().cloned().collect();

        // Migrate each user's task file
        for username in usernames {
            if let Some(user) = self.users.get_mut(&username) {
                user.migrate_to_secure_filename()?;
            }
        }

        // Save store to persist changes
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

    // Function to change user's password with existing functionality
    pub fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
        store_salt: &[u8],
    ) -> Result<(), String> {
        // Verify old password by comparing hashes
        let old_hash = hex::encode(derive_key_from_passphrase(old_password, store_salt));
        if self.password_hash != old_hash {
            return Err("Current password is incorrect".to_string());
        }

        // Validate new password using password policy
        if let Err(e) = validate_password(new_password) {
            return Err(format!("Invalid new password: {:?}", e));
        }

        // Ensure new password is different from the old one
        if old_password == new_password {
            return Err("New password must be different from current password".to_string());
        }

        // Update password hash with the new password
        self.password_hash = hex::encode(derive_key_from_passphrase(new_password, store_salt));

        Ok(())
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

    // Function to reset password using a valid token
    pub fn reset_password_with_token(
        &mut self,
        token: &str,
        new_password: &str,
        stored_token: &PasswordResetToken,
        store: &UserStore,
    ) -> Result<(), String> {
        // Verify token matches the stored one
        if token != stored_token.token {
            return Err("Invalid reset token".to_string());
        }

        // Check token expiration
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if current_time > stored_token.expires_at {
            return Err("Reset token has expired".to_string());
        }

        // Validate new password strength
        if let Err(e) = validate_password(new_password) {
            return Err(format!("Invalid new password: {:?}", e));
        }

        // Update password hash using store's salt
        self.password_hash = hex::encode(derive_key_from_passphrase(new_password, &store.salt));

        Ok(())
    }

    // Function to migrate existing task file to secure filename
    // This should be called when upgrading existing users
    pub fn migrate_to_secure_filename(&mut self) -> io::Result<()> {
        // Generate new secure filename
        let new_filename = self.generate_task_filename()?;

        // If old file exists, move it to new location
        if Path::new(&self.tasks_file).exists() {
            std::fs::rename(&self.tasks_file, &new_filename)?;
        }

        // Update user's task file path
        self.tasks_file = new_filename;

        Ok(())
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

// Function to handle interactive task creation
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

    Task {
        name,
        description,
        priority,
        completed: false,
    }
}

// Function to handle interactive task editing
fn handle_interactive_task_edit(existing_task: &Task) -> Task {
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

    println!("\nEnter new description (press Enter to keep current):");
    let description = read_line().unwrap();
    let description = if description.trim().is_empty() {
        existing_task.description.clone()
    } else {
        description
    };

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

    println!("\nMark as completed? (yes/no/Enter to keep current):");
    let completed = loop {
        let input = read_line().unwrap();
        if input.trim().is_empty() {
            break existing_task.completed;
        }

        match input.to_lowercase().as_str() {
            "yes" | "y" => break true,
            "no" | "n" => break false,
            _ => println!("Invalid input. Please enter yes or no:"),
        }
    };

    Task {
        name: existing_task.name.clone(),
        description,
        priority,
        completed,
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
    match handle_user_creation(store, username.clone(), email, password) {
        Ok(_) => {
            // Log successful registration
            log_auth_event(
                "registration",
                &username,
                true,
                Some("New user registered successfully"),
            );

            // Ensure we're in a logged-out state after registration
            if let Err(e) = cache.clear_cache() {
                println!(
                    "Warning: Failed to clear credentials after registration: {}",
                    e
                );
            }

            println!("\nRegistration successful!");
            println!("Please log in with your new account.");
            Ok(())
        }
        Err(e) => {
            // Log failed registration
            log_auth_event(
                "registration",
                &username,
                false,
                Some(&format!("Registration failed: {}", e)),
            );

            // Clear cache on failure as well for consistency
            if let Err(ce) = cache.clear_cache() {
                println!(
                    "Warning: Failed to clear credentials after failed registration: {}",
                    ce
                );
            }

            Err(e)
        }
    }
}

// Forgot password handler
// Function to handle the complete password reset flow in an interactive manner
// This replaces the need for a separate confirm-reset command
// Takes a mutable reference to UserStore to allow password updates
// Returns Result to properly handle and propagate errors
fn handle_forgot_password(store: &mut UserStore) -> Result<(), String> {
    println!("\n=== Password Reset ===");

    // First verify that the email system is properly configured
    // This prevents starting the reset process if emails can't be sent
    if !check_email_configuration() {
        return Err("Email system is not configured. Please contact administrator.".to_string());
    }

    // Get and validate user's email address
    println!("Please enter your email address:");
    let email = read_line().map_err(|e| format!("Error reading input: {}", e))?;
    let email = email.trim();

    // Validate email format before proceeding
    if !is_valid_email(email) {
        return Err("Invalid email format. Please enter a valid email address.".to_string());
    }

    // Check if the email exists in our user database
    // We don't reveal to the user whether the email exists for security
    let user_exists = store.users.values().any(|u| u.email == email);
    if !user_exists {
        // Send the same message regardless of whether email exists
        // This prevents email enumeration attacks
        println!("If an account exists with this email, you will receive reset instructions.");
        return Ok(());
    }

    // Find user by email
    let user = store
        .users
        .values()
        .find(|u| u.email == email)
        .ok_or("No account found with this email address.")?;

    // Clone the username for later use
    let username = user.username.clone();

    // Generate a 6-digit numeric reset token onlt for valid emails
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
    token_manager.store_token(email, &token)?;

    // Send reset email with proper error handling
    match send_reset_token_email(email, &token) {
        Ok(_) => {
            println!("\nA reset token has been sent to your email.");
            println!("Please check your inbox and enter the token below.");
        }
        Err(e) => {
            // If email fails, clean up the stored token
            token_manager.clear_token()?;
            return Err(format!("Failed to send reset email: {}", e));
        }
    }

    // Set up attempt limiting for token verification
    let mut attempts = 0;
    const MAX_ATTEMPTS: u32 = 3;

    // Loop to handle token verification
    while attempts < MAX_ATTEMPTS {
        println!("\nEnter the reset token (or 'cancel' to abort):");
        let input_token = read_line().map_err(|e| format!("Error reading input: {}", e))?;
        let input_token = input_token.trim();

        // Allow user to cancel the reset process
        if input_token.to_lowercase() == "cancel" {
            token_manager.clear_token()?;
            return Ok(());
        }

        // Verify the entered token
        if token_manager.verify_token(email, input_token)? {
            // Token is valid, proceed with password reset
            println!("\nToken verified successfully!");

            // Get and validate new password
            let new_password = get_new_password()?;

            // Generate new password hash first
            let new_hash = hex::encode(derive_key_from_passphrase(&new_password, &store.salt));

            // Then update the user's password hash
            if let Some(user) = store.users.values_mut().find(|u| u.email == email) {
                user.password_hash = new_hash;
            } else {
                return Err("Failed to update password: user not found".to_string());
            }

            // Save the store after releasing the mutable borrow
            save_user_store(store).map_err(|e| format!("Failed to save user data: {}", e))?;

            // Clear the used token
            token_manager.clear_token()?;

            // Log the successful password reset
            log_data_operation(
                "password_reset",
                &username,
                "user_store",
                true,
                Some("Password reset completed successfully"),
            );

            println!("\nPassword reset successful!");
            return Ok(());
        }

        // Handle invalid token attempts
        attempts += 1;
        if attempts < MAX_ATTEMPTS {
            println!(
                "Invalid token. Please try again. {} attempts remaining.",
                MAX_ATTEMPTS - attempts
            );
        } else {
            // Clean up token after max attempts reached
            token_manager.clear_token()?;
            return Err("Too many invalid attempts. Please start over.".to_string());
        }
    }

    Ok(())
}

// Helper function for converting io::Error to String
fn io_err_to_string(e: io::Error) -> String {
    format!("IO error: {}", e)
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
    println!("  add              - Add a new task");
    println!("  list             - List all tasks");
    println!("  edit             - Edit an existing task");
    println!("  delete           - Delete a task");
    println!("  profile          - View or update profile information");
    println!("  change-password  - Change your password");
    println!("  delete-account   - Permanently delete your account");
    println!("  logout           - Log out of current session");

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
fn main_auth_flow(store: &mut UserStore) -> Option<(String, String)> {
    loop {
        show_initial_options();

        match read_line().unwrap().trim() {
            "1" | "login" => {
                return authenticate_user(store);
            }
            "2" | "register" => {
                match handle_interactive_registration(store) {
                    Ok(_) => {
                        // Double-check that we're logged out
                        let cache = SecurePasswordCache::new();
                        if let Ok(Some(_)) = cache.get_cached_password() {
                            if let Err(e) = cache.clear_cache() {
                                println!("Warning: Failed to clear lingering credentials: {}", e);
                            }
                        }
                        continue;
                    }
                    Err(e) => {
                        println!("Registration failed: {}", e);
                        continue;
                    }
                }
            }
            "3" | "forgot" => match handle_forgot_password(store) {
                Ok(_) => {
                    println!("You may now log in with your new password.");
                    continue;
                }
                Err(e) => {
                    println!("Password reset failed: {}", e);
                    continue;
                }
            },
            "4" | "exit" | "quit" => {
                println!("Goodbye!");
                process::exit(0);
            }
            _ => {
                println!("Invalid choice. Please enter a number (1-4) or command (login/register/forgot/exit).");
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

// This function handles failed login attempts and implements the 30-second delay
fn handle_failed_login_attempt(user: &mut User, store: &mut UserStore) -> bool {
    // Log the failed login attempt
    log_auth_event(
        "login_attempt",
        &user.username,
        false,
        Some("failed login attempt"),
    );
    // Get current time since UNIX epoch
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

    // Save the updated user store to persist the failed attempt count
    if let Err(e) = save_user_store(store) {
        println!("Warning: Failed to save user data: {}", e);
    }

    true
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
            println!("Welcome back, {}!", user.username); // This uses the preserved original case

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
    let mut attempts = 0;
    loop {
        if attempts == 0 {
            println!("\nPlease enter your username (type 'exit' to quit):");
        }

        // Get username input and preserve original case
        let original_username = read_line().unwrap();
        let normalized_username = original_username.trim().to_lowercase(); // Normalize for lookup

        match normalized_username.as_str() {
            "exit" => {
                println!("Operation cancelled by user.");
                process::exit(0);
            }
            _ => {
                println!("Enter password:");
                let password = read_password().unwrap();

                match password.trim() {
                    "exit" => {
                        println!("Operation cancelled by user.");
                        process::exit(0);
                    }
                    "logout" => {
                        if let Err(e) = cache.clear_cache() {
                            println!("Warning: Failed to clear password cache: {}", e);
                        }
                        println!("Successfully logged out. Password cache cleared.");
                        attempts = 0;
                        continue;
                    }
                    password => {
                        // Verify credentials
                        if verify_user_credentials(&normalized_username, password, store) {
                            // Cache the successful credentials with the normalized username
                            if let Err(e) = cache.cache_password(&normalized_username, password) {
                                println!("Warning: Failed to cache credentials: {}", e);
                            }

                            // Show welcome message for fresh login using original case from stored user
                            if let Some(user) = store.users.get(&normalized_username) {
                                println!(
                                    "\nWelcome, {}! Type 'help' to see available commands.",
                                    user.username
                                );
                            }

                            return Some((normalized_username, password.to_string()));
                        }

                        // Handle failed login attempts
                        if attempts >= 3 {
                            println!("Multiple failed attempts.");
                            println!("Press ENTER to try again, type 'exit' to quit, or 'logout' to clear cache.");
                            read_password().unwrap();
                            attempts = 0;
                        } else {
                            attempts += 1;
                            println!("Authentication failed. Please try again.");
                        }
                    }
                }
            }
        }
    }
}

// Function to check file permissions for a user
fn check_file_permissions(user: &User, file_path: &str) -> Result<(), TaskError> {
    let metadata = match std::fs::metadata(file_path) {
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
    let username_normalized = original_username.to_lowercase();

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
                let salt = file_data[..16].to_vec();
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

pub fn verify_user_credentials(username: &str, password: &str, store: &mut UserStore) -> bool {
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
    chrono::NaiveDateTime::from_timestamp_opt(timestamp as i64, 0)
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

// Activity tracking function
fn update_user_activity(user: &mut User) {
    user.last_activity = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
}

// Inactivity check function
fn check_session_timeout(user: &User) -> bool {
    const SESSION_TIMEOUT: u64 = 15 * 60; // 15 minutes in seconds

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    current_time - user.last_activity > SESSION_TIMEOUT
}

// Command handling loop to check for timeout
fn handle_command(
    store: &mut UserStore,
    user: &mut User,
    cache: &SecurePasswordCache,
) -> io::Result<bool> {
    if check_session_timeout(user) {
        println!("Session expired due to inactivity. Please log in again.");
        cache.clear_cache()?;
        return Ok(false);
    }

    update_user_activity(user);
    Ok(true)
}

fn main() {
    // Admin credentials setup and email configuration setup
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        match args[1].as_str() {
            "--admin-setup" => {
                match initialize_admin_credentials() {
                    Ok(_) => println!("Admin credentials initialized successfully!"),
                    Err(e) => println!("Failed to initialize admin credentials: {}", e),
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
        let tasks_file = {
            let user = store
                .users
                .get(&username)
                .expect("User not found after authentication");
            user.tasks_file.clone()
        };

        // Load tasks from user-specific encrypted file with error handling
        let mut tasks: HashMap<String, Task> = {
            let user = store
                .users
                .get(&username)
                .expect("User not found after authentication");
            match load_tasks_from_file(user, &password) {
                Ok(tasks) => tasks,
                Err(e) => {
                    println!("Error loading tasks: {}", e);
                    process::exit(1);
                }
            }
        };

        let cache = SecurePasswordCache::new();
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
        'command: loop {
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
                                    "Task: {}\nDescription: {}\nPriority: {}\nCompleted: {}\n",
                                    name, task.description, task.priority, task.completed
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Helper function to create a test UserStore
    fn create_test_store() -> UserStore {
        UserStore {
            users: HashMap::new(),
            salt: generate_random_salt(),
            iv: generate_random_iv(),
            reset_tokens: HashMap::new(),
            reset_attempts: HashMap::new(),
        }
    }

    // Helper function to create a test user
    fn create_test_user(store: &mut UserStore) -> (String, String, String) {
        let username = "testuser".to_string();
        let email = "test@example.com".to_string();
        let password = "TestPassword123!".to_string();

        store
            .add_user(username.clone(), email.clone(), password.clone())
            .expect("Failed to add test user");

        (username, email, password)
    }

    #[test]
    fn test_user_registration() {
        let mut store = create_test_store();
        let (username, email, password) = create_test_user(&mut store);

        assert!(store.users.contains_key(&username));
        let user = store.users.get(&username).unwrap();
        assert_eq!(user.email, email);
        assert!(!user.password_hash.is_empty());
    }

    #[test]
    fn test_password_hashing_consistency() {
        let mut store = create_test_store();
        let password = "TestPassword123!";

        // Generate two hashes with the same salt
        let hash1 = hex::encode(derive_key_from_passphrase(password, &store.salt));
        let hash2 = hex::encode(derive_key_from_passphrase(password, &store.salt));

        // Verify hashes are identical
        assert_eq!(hash1, hash2, "Password hashing is not consistent");
    }

    #[test]
    fn test_successful_login() {
        let mut store = create_test_store();
        let (username, _, password) = create_test_user(&mut store);

        assert!(verify_user_credentials(&username, &password, &mut store));
    }

    #[test]
    fn test_failed_login_wrong_password() {
        let mut store = create_test_store();
        let (username, _, _) = create_test_user(&mut store);

        assert!(!verify_user_credentials(
            &username,
            "WrongPassword123!",
            &mut store
        ));
    }

    #[test]
    fn test_failed_login_nonexistent_user() {
        let mut store = create_test_store();
        assert!(!verify_user_credentials(
            "nonexistent",
            "TestPassword123!",
            &mut store
        ));
    }

    #[test]
    fn test_login_rate_limiting() {
        let mut store = create_test_store();
        let (username, _, _) = create_test_user(&mut store);

        // Attempt multiple failed logins
        for _ in 0..3 {
            assert!(!verify_user_credentials(
                &username,
                "WrongPassword123!",
                &mut store
            ));
        }

        // Fourth attempt should be rate limited
        let user = store.users.get(&username).unwrap();
        assert_eq!(user.failed_attempts, 3);
    }

    #[test]
    fn test_password_hash_verification() {
        let mut store = create_test_store();
        let (username, _, password) = create_test_user(&mut store);

        // Get the stored hash
        let stored_hash = store.users.get(&username).unwrap().password_hash.clone();

        // Generate a new hash with the same password and salt
        let new_hash = hex::encode(derive_key_from_passphrase(&password, &store.salt));

        // Verify hashes match
        assert_eq!(stored_hash, new_hash, "Password hash verification failed");
    }

    #[test]
    fn test_user_store_persistence() {
        let mut store = create_test_store();
        let (username, email, _) = create_test_user(&mut store);

        // Save the store
        save_user_store(&store).expect("Failed to save user store");

        // Load the store
        let loaded_store = load_user_store().expect("Failed to load user store");

        // Verify user data persisted correctly
        assert!(loaded_store.users.contains_key(&username));
        let loaded_user = loaded_store.users.get(&username).unwrap();
        assert_eq!(loaded_user.email, email);
    }

    #[test]
    fn test_username_normalization() {
        let mut store = create_test_store();
        let (_, _, password) = create_test_user(&mut store);

        // Try logging in with different case/spacing
        assert!(verify_user_credentials("TestUser  ", &password, &mut store));
        assert!(verify_user_credentials("testUser", &password, &mut store));
        assert!(verify_user_credentials("TESTUSER", &password, &mut store));
    }

    #[test]
    fn test_salt_consistency() {
        let mut store = create_test_store();
        let original_salt = store.salt.clone();

        // Add a user
        let (username, _, password) = create_test_user(&mut store);

        // Verify salt hasn't changed
        assert_eq!(
            store.salt, original_salt,
            "Store salt changed during user creation"
        );

        // Save and reload store
        save_user_store(&store).expect("Failed to save store");
        let mut loaded_store = load_user_store().expect("Failed to load store"); // Changed this line

        // Verify salt persisted correctly
        assert_eq!(
            loaded_store.salt, original_salt,
            "Store salt changed during persistence"
        );

        // Verify login still works with loaded store
        assert!(verify_user_credentials(
            &username,
            &password,
            &mut loaded_store
        ));
    }
}
