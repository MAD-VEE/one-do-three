// External crate dependencies for various functionalities
use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use clap::{Arg, Command};
use hmac::Hmac;
use itertools::Itertools;
use keyring::Entry;
use pbkdf2::pbkdf2;
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

// Container for all users with encryption metadata for secure storage
#[derive(Serialize, Deserialize)]
struct UserStore {
    users: HashMap<String, User>,
    salt: Vec<u8>,
    iv: Vec<u8>,
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

// Secure password cache implementation using system keyring
struct SecurePasswordCache {
    keyring: Entry,
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

// Implement conversion from io::Error to TaskError
impl From<io::Error> for TaskError {
    fn from(error: io::Error) -> Self {
        TaskError::IoError(error)
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

// Function to load tasks from the user-specific encrypted file
fn load_tasks_from_file(user: &User, passphrase: &str) -> HashMap<String, Task> {
    let mut tasks = HashMap::new();

    // Attempt to open the user's specific task file
    match File::open(&user.tasks_file) {
        Ok(mut file) => {
            let mut file_data = Vec::new();
            if let Err(e) = file.read_to_end(&mut file_data) {
                println!("Error reading from file {}: {}", user.tasks_file, e);
                return tasks;
            }

            // Check if file has minimum required data (salt + iv)
            if file_data.len() >= 32 {
                let salt = file_data[..16].to_vec();
                let iv = file_data[16..32].to_vec();
                let encrypted_data = &file_data[32..];

                // Derive encryption key from user's passphrase
                let encryption_key = derive_key_from_passphrase(passphrase, &salt);

                // Attempt to decrypt and parse the data
                match decrypt_data(encrypted_data, &encryption_key, &iv) {
                    Ok(decrypted_data) => {
                        if let Ok(parsed) = serde_json::from_str(&decrypted_data) {
                            tasks = parsed;
                        } else {
                            println!("Error deserializing task data for user {}.", user.username);
                        }
                    }
                    Err(e) => {
                        println!("Error decrypting data for user {}: {}", user.username, e);
                    }
                }
            }
        }
        Err(e) => {
            // If file doesn't exist, just return empty HashMap
            if e.kind() != io::ErrorKind::NotFound {
                println!("Error opening task file for user {}: {}", user.username, e);
            }
        }
    }

    tasks
}

// Function to save tasks to the user-specific encrypted file
fn save_tasks_to_file(
    tasks: &HashMap<String, Task>,
    user: &User,
    passphrase: &str,
) -> io::Result<()> {
    // Convert tasks to JSON string
    let data = serde_json::to_string_pretty(tasks).unwrap();

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
    File::create(&user.tasks_file)?.write_all(&file_data)?;
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

    // Load tasks from user-specific encrypted file
    let mut tasks: HashMap<String, Task> = load_tasks_from_file(user, &password);

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
            let name = sub_matches.get_one::<String>("name").unwrap();
            let description = sub_matches.get_one::<String>("description").unwrap();
            let priority = sub_matches.get_one::<String>("priority").unwrap();

            if !is_passphrase_correct(user, &password) {
                println!("Incorrect passphrase. Task not added.");
                return;
            }

            let new_task = Task {
                name: name.to_string(),
                description: description.to_string(),
                priority: priority.to_string(),
                completed: false,
            };

            tasks.insert(name.clone(), new_task);
            save_tasks_to_file(&tasks, user, &password).expect("Failed to save tasks to file");
            println!("Task added: {}", name);
        }
        Some(("list", sub_matches)) => {
            // Handle list command
            if !is_passphrase_correct(user, &password) {
                println!("Error: Incorrect passphrase. Unable to list tasks.");
                return;
            }

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
        Some(("edit", sub_matches)) => {
            // Handle edit command
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

                save_tasks_to_file(&tasks, user, &password).expect("Failed to save tasks to file");
                println!("Task updated: {}", name);
            } else {
                println!("Task not found: {}", name);
            }
        }
        Some(("delete", sub_matches)) => {
            // Handle delete command
            if !is_passphrase_correct(user, &password) {
                println!("Error: Incorrect passphrase. Unable to delete task.");
                return;
            }

            let name = sub_matches.get_one::<String>("name").unwrap();

            if tasks.remove(name).is_some() {
                save_tasks_to_file(&tasks, user, &password).expect("Failed to save tasks to file");
                println!("Task deleted: {}", name);
            } else {
                println!("Task not found: {}", name);
            }
        }
        _ => {
            println!("No valid command provided. Use --help for usage information.");
        }
    }
}
