// External crate dependencies for various functionalities
use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use clap::{Arg, Command};
use hmac::Hmac;
use itertools::Itertools;
use keyring::Entry;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use pbkdf2::pbkdf2;
use rand::distributions::Alphanumeric;
use rand::Rng;
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::num::NonZeroU32;
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
    username: String,
    password: String,
    timestamp: u64,
}

// Represents a single user with their authentication details and task file location
#[derive(Serialize, Deserialize, Debug)]
struct User {
    username: String,
    email: String,
    password_hash: String,
    created_at: u64,
    last_login: u64,
    failed_attempts: u32,
    last_failed_attempt: u64,
    tasks_file: String, // Each user gets their own encrypted tasks file
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
        // Get current timestamp for user creation and last login times
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Hash the user's password using PBKDF2 with the store's salt
        // Convert the resulting hash to hexadecimal string for storage
        let password_hash = derive_key_from_passphrase(&password, &self.salt);
        let password_hash = hex::encode(password_hash);

        // Create new User struct with initial values
        let user = User {
            username: username.clone(), // Clone username as we need it for HashMap key
            email,
            password_hash,
            created_at: current_time, // Set creation timestamp
            last_login: current_time, // Initially same as creation time
            failed_attempts: 0,       // Initialize login attempt counter
            last_failed_attempt: 0,   // Initialize failed attempt timestamp
            tasks_file: format!("tasks_{}.json", username), // Create unique task file name
        };

        // Insert the new user into the HashMap
        self.users.insert(username, user);
        Ok(())
    }

    // Function to retrieve a user from the store
    // Takes a reference to username and returns an Option containing a reference to the User
    // Returns None if user doesn't exist
    pub fn get_user(&self, username: &str) -> Option<&User> {
        self.users.get(username)
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

    // Cache a password in the system keyring
    fn cache_password(&self, username: &str, password: &str) -> io::Result<()> {
        let cached = CachedPassword {
            username: username.to_string(),
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

                if current_time - cached.timestamp > 15 * 60 {
                    // Password expired, clear it
                    self.clear_cache()?;
                    Ok(None)
                } else {
                    Ok(Some((cached.username, cached.password)))
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
    // Function to change user's password
    pub fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
        store_salt: &[u8],
    ) -> Result<(), String> {
        // Verify old password
        let old_hash = hex::encode(derive_key_from_passphrase(old_password, store_salt));
        if self.password_hash != old_hash {
            return Err("Current password is incorrect".to_string());
        }

        // Validate new password
        if let Err(e) = validate_password(new_password) {
            return Err(format!("Invalid new password: {:?}", e));
        }

        // Check if new password matches old password
        if old_password == new_password {
            return Err("New password must be different from current password".to_string());
        }

        // Update password hash
        self.password_hash = hex::encode(derive_key_from_passphrase(new_password, store_salt));

        Ok(())
    }

    // Function to initiate password reset
    pub fn request_password_reset(&self) -> Result<PasswordResetToken, String> {
        // Generate random token
        let token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        // Set expiration time (30 minutes from now)
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 1800;

        let reset_token = PasswordResetToken {
            token: token.clone(),
            expires_at,
            user_email: self.email.clone(),
            username: self.username.clone(),
        };

        Ok(reset_token)
    }

    // Function to reset password using token
    pub fn reset_password_with_token(
        &mut self,
        token: &str,
        new_password: &str,
        stored_token: &PasswordResetToken,
        store: &UserStore,
    ) -> Result<(), String> {
        // Check if token matches
        if token != stored_token.token {
            return Err("Invalid reset token".to_string());
        }

        // Check if token has expired
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if current_time > stored_token.expires_at {
            return Err("Reset token has expired".to_string());
        }

        // Validate new password
        if let Err(e) = validate_password(new_password) {
            return Err(format!("Invalid new password: {:?}", e));
        }

        // Update password hash
        self.password_hash = hex::encode(derive_key_from_passphrase(new_password, &store.salt));

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

// Function to send password reset email
fn send_reset_email(reset_token: &PasswordResetToken) -> Result<(), String> {
    // Configure email settings from environment or config file
    let smtp_host =
        std::env::var("SMTP_HOST").unwrap_or_else(|_| "smtp.yourdomain.com".to_string());
    let smtp_username =
        std::env::var("SMTP_USERNAME").unwrap_or_else(|_| "smtp_username".to_string());
    let smtp_password =
        std::env::var("SMTP_PASSWORD").unwrap_or_else(|_| "smtp_password".to_string());

    // Create email message with better formatting
    let email_body = format!(
        "Hello,\n\n\
        A password reset was requested for your account.\n\n\
        Your password reset token is: {}\n\n\
        This token will expire in 30 minutes.\n\n\
        If you did not request this reset, please ignore this email.\n\n\
        Best regards,\n\
        Your Application Team",
        reset_token.token
    );

    let email = Message::builder()
        .from(
            "noreply@yourdomain.com"
                .parse()
                .map_err(|e| format!("Invalid from address: {}", e))?,
        )
        .to(reset_token
            .user_email
            .parse()
            .map_err(|e| format!("Invalid to address: {}", e))?)
        .subject("Password Reset Request")
        .header(ContentType::TEXT_PLAIN)
        .body(email_body)
        .map_err(|e| format!("Failed to create email: {}", e))?;

    // Create SMTP transport with proper error handling
    let creds = Credentials::new(smtp_username, smtp_password);

    let mailer = SmtpTransport::relay(&smtp_host)
        .map_err(|e| format!("Failed to create SMTP transport: {}", e))?
        .credentials(creds)
        .timeout(Some(std::time::Duration::from_secs(10))) // Add timeout
        .build();

    // Send email with detailed error handling
    match mailer.send(&email) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!(
            "Failed to send email: {}. Please check your SMTP configuration.",
            e
        )),
    }
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
    if let Err(e) = save_user_store(
        store,
        &derive_key_from_passphrase("master_key", &store.salt),
    ) {
        println!("Warning: Failed to save user data: {}", e);
    }

    true
}

// Authentication function
fn authenticate_user(store: &mut UserStore) -> Option<(String, String)> {
    let cache = SecurePasswordCache::new();

    // Try to get cached credentials
    if let Ok(Some((cached_username, cached_password))) = cache.get_cached_password() {
        // Check if the cached password is "logout"
        if cached_password.trim().to_lowercase() == "logout" {
            if let Err(e) = cache.clear_cache() {
                println!("Warning: Failed to clear password cache: {}", e);
            }
            println!("Successfully logged out. Password cache cleared.");
            return None;
        }

        // Verify cached credentials
        if verify_user_credentials(&cached_username, &cached_password, store) {
            println!("Using cached credentials (type 'logout' for a new session).");
            return Some((cached_username, cached_password));
        }
    }

    // If no valid cached credentials, prompt for login
    let mut attempts = 0;
    loop {
        if attempts == 0 {
            println!("\nPlease enter your username (type 'exit' to quit):");
        }

        let username = read_line().unwrap().trim().to_string();
        match username.trim().to_lowercase().as_str() {
            "exit" => {
                println!("Operation cancelled by user.");
                process::exit(0);
            }
            username => {
                println!("Enter password:");
                let password = read_password().unwrap();

                match password.trim().to_lowercase().as_str() {
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
                        if verify_user_credentials(username, password, store) {
                            // Cache the successful credentials
                            if let Err(e) = cache.cache_password(username, password) {
                                println!("Warning: Failed to cache credentials: {}", e);
                            }
                            return Some((username.to_string(), password.to_string()));
                        }

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
    // Attempt to add user to the store and handle the result
    match store.add_user(username.clone(), email, password) {
        Ok(_) => {
            // If successful, print confirmation message
            println!("User {} created successfully", username);
            Ok(())
        }
        Err(e) => {
            // If failed, print error message and propagate error
            println!("Failed to create user: {}", e);
            Err(e)
        }
    }
}

// Function to save UserStore to file
fn save_user_store(store: &UserStore, master_key: &[u8]) -> io::Result<()> {
    let data = serde_json::to_string_pretty(store).unwrap();
    let encrypted_data = encrypt_data(&data, master_key, &store.iv);

    let mut file_data = Vec::new();
    file_data.extend_from_slice(&store.salt);
    file_data.extend_from_slice(&store.iv);
    file_data.extend_from_slice(&encrypted_data);

    File::create(USERS_FILE)?.write_all(&file_data)?;
    Ok(())
}

// Function to load UserStore from file
fn load_user_store(master_key: &[u8]) -> io::Result<UserStore> {
    match File::open(USERS_FILE) {
        Ok(mut file) => {
            let mut file_data = Vec::new();
            file.read_to_end(&mut file_data)?;

            if file_data.len() >= 32 {
                let salt = file_data[..16].to_vec();
                let iv = file_data[16..32].to_vec();
                let encrypted_data = &file_data[32..];

                match decrypt_data(encrypted_data, master_key, &iv) {
                    Ok(decrypted_data) => match serde_json::from_str(&decrypted_data) {
                        Ok(store) => Ok(store),
                        Err(_) => Ok(create_user_store()),
                    },
                    Err(_) => Ok(create_user_store()),
                }
            } else {
                Ok(create_user_store())
            }
        }
        Err(_) => Ok(create_user_store()),
    }
}

fn verify_user_credentials(username: &str, password: &str, store: &mut UserStore) -> bool {
    // Generate password hash using store's salt
    let password_hash = hex::encode(derive_key_from_passphrase(password, &store.salt));

    // Get mutable reference to user (if exists)
    if let Some(user) = store.users.get_mut(username) {
        // Compare with stored hash
        if user.password_hash == password_hash {
            // Reset failed attempts and update last login on successful login
            user.failed_attempts = 0;
            user.last_login = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Save the updated user store
            if let Err(e) = save_user_store(
                store,
                &derive_key_from_passphrase("master_key", &store.salt),
            ) {
                println!("Warning: Failed to save user data: {}", e);
            }
            return true;
        }

        // Handle failed attempt inline instead of calling the separate function
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
        if let Err(e) = save_user_store(
            store,
            &derive_key_from_passphrase("master_key", &store.salt),
        ) {
            println!("Warning: Failed to save user data: {}", e);
        }

        return false;
    }

    false
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

fn main() {
    // Load user store
    let mut store = load_user_store(&derive_key_from_passphrase(
        "master_key",
        &generate_random_salt(),
    ))
    .expect("Failed to load user store");

    // Authenticate user and get credentials
    let (username, password) = match authenticate_user(&mut store) {
        Some(credentials) => credentials,
        None => {
            println!("Authentication failed");
            process::exit(1);
        }
    };

    // Get the authenticated user
    let user = store
        .users
        .get(&username)
        .expect("User not found after authentication");

    // Load tasks from user-specific encrypted file with error handling
    let mut tasks: HashMap<String, Task> = match load_tasks_from_file(user, &password) {
        Ok(tasks) => tasks,
        Err(e) => {
            println!("Error loading tasks: {}", e);
            process::exit(1);
        }
    };

    // Set up CLI command structure using clap
    let matches = Command::new("one-do-three")
        .about("A simple task management CLI")
        .subcommand(
            Command::new("add")
                .about("Add a new task")
                .arg(Arg::new("name").help("The name of the task").required(true))
                .arg(
                    Arg::new("description")
                        .help("The task description")
                        .required(true),
                )
                .arg(
                    Arg::new("priority")
                        .help("The priority of the task")
                        .required(true),
                ),
        )
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
        .subcommand(
            Command::new("edit")
                .about("Edit an existing task")
                .arg(
                    Arg::new("name")
                        .help("The name of the task to edit")
                        .required(true),
                )
                .arg(
                    Arg::new("description")
                        .help("The new description of the task")
                        .long("description")
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("priority")
                        .help("The new priority of the task")
                        .long("priority")
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("completed")
                        .help("Set the task as completed (true/false)")
                        .long("completed")
                        .value_parser(clap::value_parser!(String)),
                ),
        )
        .subcommand(
            Command::new("delete").about("Delete an existing task").arg(
                Arg::new("name")
                    .help("The name of the task to delete")
                    .required(true),
            ),
        )
        .subcommand(
            Command::new("profile")
                .about("View or update user profile")
                .arg(
                    Arg::new("email")
                        .long("email")
                        .help("Update email address")
                        .value_name("NEW_EMAIL"),
                )
                .arg(
                    Arg::new("show")
                        .long("show")
                        .help("Show profile information")
                        .action(clap::ArgAction::SetTrue),
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
        .subcommand(Command::new("logout").about("Logout and clear cached password"))
        .get_matches();

    // Handle different subcommands
    match matches.subcommand() {
        Some(("logout", _)) => {
            // Handle logout command
            let cache = SecurePasswordCache::new();
            if let Err(e) = cache.clear_cache() {
                println!("Warning: Failed to clear password cache: {}", e);
            } else {
                println!("Successfully logged out. Password cache cleared.");
            }
            process::exit(0);
        }
        Some(("add", sub_matches)) => {
            // First check passphrase
            if !is_passphrase_correct(user, &password) {
                println!("Incorrect passphrase. Task not added.");
                return;
            }

            let name = sub_matches.get_one::<String>("name").unwrap();
            let description = sub_matches.get_one::<String>("description").unwrap();
            let priority = sub_matches.get_one::<String>("priority").unwrap();

            let new_task = Task {
                name: name.to_string(),
                description: description.to_string(),
                priority: priority.to_string(),
                completed: false,
            };

            tasks.insert(name.clone(), new_task);

            // Add error handling to save operation
            match save_tasks_to_file(&tasks, user, &password) {
                Ok(_) => println!("Task added: {}", name),
                Err(e) => println!("Error saving task: {}", e),
            }
        }
        // Handle list command
        Some(("list", sub_matches)) => {
            // First check passphrase
            if !is_passphrase_correct(user, &password) {
                println!("Error: Incorrect passphrase. Unable to list tasks.");
                return;
            }

            // Add error handling to task loading
            match load_tasks_from_file(user, &password) {
                Ok(tasks) => {
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
                                    "completed" => a.1.completed.cmp(&b.1.completed),
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
        Some(("edit", sub_matches)) => {
            // First check passphrase
            if !is_passphrase_correct(user, &password) {
                println!("Error: Incorrect passphrase. Unable to edit task.");
                return;
            }

            let name = sub_matches.get_one::<String>("name").unwrap();

            if let Some(task) = tasks.get_mut(name) {
                if let Some(description) = sub_matches.get_one::<String>("description") {
                    task.description = description.clone();
                }
                if let Some(priority) = sub_matches.get_one::<String>("priority") {
                    task.priority = priority.clone();
                }
                if let Some(completed) = sub_matches.get_one::<String>("completed") {
                    task.completed = completed == "true";
                }

                // Add error handling to save operation
                match save_tasks_to_file(&tasks, user, &password) {
                    Ok(_) => println!("Task updated: {}", name),
                    Err(e) => println!("Error saving task update: {}", e),
                }
            } else {
                println!("Task not found: {}", name);
            }
        }
        // Handle delete command
        Some(("delete", sub_matches)) => {
            // First check passphrase
            if !is_passphrase_correct(user, &password) {
                println!("Error: Incorrect passphrase. Unable to delete task.");
                return;
            }

            let name = sub_matches.get_one::<String>("name").unwrap();

            if tasks.remove(name).is_some() {
                // Add error handling to save operation
                match save_tasks_to_file(&tasks, user, &password) {
                    Ok(_) => println!("Task deleted: {}", name),
                    Err(e) => println!("Error saving after deletion: {}", e),
                }
            } else {
                println!("Task not found: {}", name);
            }
        }
        // Handle profile command
        Some(("profile", sub_matches)) => {
            // Show profile information
            if sub_matches.get_flag("show") {
                if let Some(user) = store.users.get(&username) {
                    println!("\nUser Profile");
                    println!("------------");
                    println!("Username: {}", user.username);
                    println!("Email: {}", user.email);
                    println!(
                        "Account created: {}",
                        chrono::NaiveDateTime::from_timestamp_opt(user.created_at as i64, 0)
                            .unwrap_or_default()
                            .format("%Y-%m-%d %H:%M:%S")
                    );
                    println!(
                        "Last login: {}",
                        chrono::NaiveDateTime::from_timestamp_opt(user.last_login as i64, 0)
                            .unwrap_or_default()
                            .format("%Y-%m-%d %H:%M:%S")
                    );
                }
            }

            // Update email if provided
            if let Some(new_email) = sub_matches.get_one::<String>("email") {
                // Validate email format
                if !new_email.contains('@') || !new_email.contains('.') {
                    println!("Invalid email format. Please provide a valid email address.");
                    return;
                }

                if let Some(user) = store.users.get_mut(&username) {
                    // Verify current password before making changes
                    println!("Please enter your password to confirm changes:");
                    let confirm_password = read_password().unwrap();

                    let password_hash =
                        hex::encode(derive_key_from_passphrase(&confirm_password, &store.salt));
                    if user.password_hash != password_hash {
                        println!("Incorrect password. Email update cancelled.");
                        return;
                    }

                    user.email = new_email.to_string();
                    match save_user_store(
                        &store,
                        &derive_key_from_passphrase("master_key", &store.salt),
                    ) {
                        Ok(_) => println!("Email updated successfully."),
                        Err(e) => println!("Failed to update email: {}", e),
                    }
                }
            }
        }
        // Handle change-password command
        Some(("change-password", sub_matches)) => {
            let old_password = sub_matches.get_one::<String>("old-password").unwrap();
            let new_password = sub_matches.get_one::<String>("new-password").unwrap();

            // Get store's salt before mutable borrow
            let store_salt = store.salt.clone();

            if let Some(user) = store.users.get_mut(&username) {
                match user.change_password(old_password, new_password, &store_salt) {
                    Ok(_) => {
                        match save_user_store(
                            &store,
                            &derive_key_from_passphrase("master_key", &store.salt),
                        ) {
                            Ok(_) => println!("Password changed successfully."),
                            Err(e) => println!("Error saving password change: {}", e),
                        }
                    }
                    Err(e) => println!("Failed to change password: {}", e),
                }
            } else {
                println!("User not found.");
            }
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
            if tracker.attempts >= 5 && current_time - tracker.last_attempt < 60 * 60 {
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
                        match save_user_store(
                            &store,
                            &derive_key_from_passphrase("master_key", &store.salt),
                        ) {
                            Ok(_) => {
                                match send_reset_email(&reset_token) {
                                    Ok(_) => {
                                        println!(
                                            "Password reset email sent. Please check your inbox."
                                        );
                                    }
                                    Err(e) => {
                                        // Remove token if email fails
                                        store.reset_tokens.remove(&reset_token.token);
                                        println!("Failed to send reset email: {}", e);
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
                println!("If this email is registered, you will receive a reset link shortly.");
            }

            // Save attempt tracker
            if let Err(e) = save_user_store(
                &store,
                &derive_key_from_passphrase("master_key", &store.salt),
            ) {
                println!("Warning: Failed to save attempt tracking: {}", e);
            }
        }
        // Handle confirm-reset command
        Some(("confirm-reset", sub_matches)) => {
            let token = sub_matches.get_one::<String>("token").unwrap();
            let new_password = sub_matches.get_one::<String>("new-password").unwrap();

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
                    user.password_hash =
                        hex::encode(derive_key_from_passphrase(new_password, &store.salt));

                    // Remove the used token
                    store.reset_tokens.remove(token);

                    // Save the updated store
                    match save_user_store(
                        &store,
                        &derive_key_from_passphrase("master_key", &store.salt),
                    ) {
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
        Some(("delete-account", sub_matches)) => {
            let confirmation = sub_matches.get_one::<String>("confirm").unwrap();

            if confirmation != "DELETE" {
                println!("Account deletion cancelled. You must type 'DELETE' to confirm.");
                return;
            }

            println!("Please enter your password to confirm account deletion:");
            let confirm_password = read_password().unwrap();

            if let Some(user) = store.users.get(&username) {
                let password_hash =
                    hex::encode(derive_key_from_passphrase(&confirm_password, &store.salt));
                if user.password_hash != password_hash {
                    println!("Incorrect password. Account deletion cancelled.");
                    return;
                }

                // Add final confirmation
                println!("\nWARNING: This action cannot be undone!");
                println!("All your tasks and data will be permanently deleted.");
                println!("Type 'YES' to proceed with account deletion:");

                let final_confirmation = read_line().unwrap();
                if final_confirmation.trim() != "YES" {
                    println!("Account deletion cancelled.");
                    return;
                }

                // Remove user's task file
                if let Err(e) = std::fs::remove_file(&user.tasks_file) {
                    println!("Warning: Failed to remove task file: {}", e);
                }

                // Remove user from store
                store.users.remove(&username);

                // Remove any reset tokens for this user
                store
                    .reset_tokens
                    .retain(|_, token| token.username != username);

                // Save the updated store
                match save_user_store(
                    &store,
                    &derive_key_from_passphrase("master_key", &store.salt),
                ) {
                    Ok(_) => {
                        // Clear password cache
                        let cache = SecurePasswordCache::new();
                        let _ = cache.clear_cache();

                        println!("Account successfully deleted.");
                        process::exit(0);
                    }
                    Err(e) => println!("Error saving changes: {}", e),
                }
            }
        }
        _ => {
            println!("No valid command provided. Use --help for usage information.");
        }
    }
}
