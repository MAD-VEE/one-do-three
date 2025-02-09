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

// Secure password cache implementation using system keyring
struct SecurePasswordCache {
    keyring: Entry,
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
    fn cache_password(&self, password: &str) -> io::Result<()> {
        let cached = CachedPassword {
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
    fn get_cached_password(&self) -> io::Result<Option<String>> {
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
                    Ok(Some(cached.password))
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

// Function to check if the passphrase is correct
fn is_passphrase_correct(passphrase: &str) -> bool {
    match File::open(STORAGE_FILE) {
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
        Err(_) => false,
    }
}

// Function to load tasks from the encrypted file
fn load_tasks_from_file(passphrase: &str) -> HashMap<String, Task> {
    let mut tasks = HashMap::new();

    match File::open(STORAGE_FILE) {
        Ok(mut file) => {
            let mut file_data = Vec::new();
            if let Err(e) = file.read_to_end(&mut file_data) {
                println!("Error reading from file: {}", e);
                return tasks;
            }

            if file_data.len() >= 32 {
                let salt = file_data[..16].to_vec();
                let iv = file_data[16..32].to_vec();
                let encrypted_data = &file_data[32..];

                let encryption_key = derive_key_from_passphrase(passphrase, &salt);

                match decrypt_data(encrypted_data, &encryption_key, &iv) {
                    Ok(decrypted_data) => {
                        if let Ok(parsed) = serde_json::from_str(&decrypted_data) {
                            tasks = parsed;
                        } else {
                            println!("Error deserializing task data.");
                        }
                    }
                    Err(e) => {
                        println!("Error decrypting data: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            println!("Error opening file: {}", e);
        }
    }

    tasks
}

// Function to save tasks to the encrypted file
fn save_tasks_to_file(tasks: &HashMap<String, Task>, passphrase: &str) -> io::Result<()> {
    let data = serde_json::to_string_pretty(tasks).unwrap();
    let iv = generate_random_iv();
    let salt = generate_random_salt();
    let encryption_key = derive_key_from_passphrase(passphrase, &salt);
    let encrypted_data = encrypt_data(&data, &encryption_key, &iv);

    let mut file_data = Vec::new();
    file_data.extend_from_slice(&salt);
    file_data.extend_from_slice(&iv);
    file_data.extend_from_slice(&encrypted_data);

    File::create(STORAGE_FILE)?.write_all(&file_data)?;
    println!("Changes successfully saved to file.");
    Ok(())
}

// The get_password function needs to be modified to verify passwords before caching
// The get_password function with cancel option
fn get_password() -> String {
    // Try to get cached password from keyring
    let cache = SecurePasswordCache::new();
    if let Ok(Some(password)) = cache.get_cached_password() {
        // Only show cached password message if we're actually using it
        if !password.trim().to_lowercase().eq("logout") {
            println!("Using cached password (type 'logout' for a new session).");
            return password;
        }
    }

    // If no valid cached password, prompt for new one
    let mut attempts = 0;
    loop {
        if attempts == 0 {
            println!("\nPlease enter your passphrase (type 'exit' to quit):");
        }

        attempts += 1;
        let password = read_password().unwrap();

        match password.trim().to_lowercase().as_str() {
            "exit" => {
                println!("Operation cancelled by user.");
                process::exit(0);
            }
            "logout" => {
                if let Err(e) = cache.clear_cache() {
                    println!("Warning: Failed to clear password cache: {}", e);
                } else {
                    println!("Successfully logged out. Password cache cleared.");
                    attempts = 0;
                    continue;
                }
            }
            password => {
                // Only cache and return the password if it's correct
                if is_passphrase_correct(password) {
                    // Store in keyring
                    if let Err(e) = cache.cache_password(password) {
                        println!("Warning: Failed to cache password: {}", e);
                    }
                    return password.to_string();
                }

                if attempts >= 3 {
                    println!("Incorrect passphrase. Multiple failed attempts.");
                    println!("Press ENTER to try again, type 'exit' to quit, or 'logout' to clear cache.");
                    read_password().unwrap(); // Wait for user input
                    attempts = 0; // Reset attempts after user acknowledgment
                } else {
                    println!("Incorrect passphrase. Pleasee try again.");
                }
            }
        }
    }
}

// Function to create a new UserStore
fn create_user_store() -> UserStore {
    UserStore {
        users: HashMap::new(),
        salt: generate_random_salt(),
        iv: generate_random_iv(),
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

fn main() {
    // Get password using secure caching mechanism
    let passphrase = get_password();

    // Load tasks from encrypted file
    let mut tasks: HashMap<String, Task> = load_tasks_from_file(&passphrase);

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
            // Handle add command
            let name = sub_matches.get_one::<String>("name").unwrap();
            let description = sub_matches.get_one::<String>("description").unwrap();
            let priority = sub_matches.get_one::<String>("priority").unwrap();

            if !is_passphrase_correct(&passphrase) {
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
            save_tasks_to_file(&tasks, &passphrase).expect("Failed to save tasks to file");
            println!("Task added: {}", name);
        }
        Some(("list", sub_matches)) => {
            // Handle list command
            if !is_passphrase_correct(&passphrase) {
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
            if !is_passphrase_correct(&passphrase) {
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

                save_tasks_to_file(&tasks, &passphrase).expect("Failed to save tasks to file");
                println!("Task updated: {}", name);
            } else {
                println!("Task not found: {}", name);
            }
        }
        Some(("delete", sub_matches)) => {
            // Handle delete command
            if !is_passphrase_correct(&passphrase) {
                println!("Error: Incorrect passphrase. Unable to delete task.");
                return;
            }

            let name = sub_matches.get_one::<String>("name").unwrap();

            if tasks.remove(name).is_some() {
                save_tasks_to_file(&tasks, &passphrase).expect("Failed to save tasks to file");
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
