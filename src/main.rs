use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use clap::{Arg, Command};
use hmac::Hmac;
type HmacSha256 = Hmac<sha2::Sha256>;
use itertools::Itertools;
use lazy_static::lazy_static;
use pbkdf2::pbkdf2;
use rand::Rng; // For generating random values
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::num::NonZeroU32;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt; // For Unix-like systems
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

use std::ffi::CString;
use std::ptr::null_mut;
use winapi::um::accctrl::{EXPLICIT_ACCESS_A, TRUSTEE_A};
use winapi::um::accctrl::{NO_INHERITANCE, SET_ACCESS};
use winapi::um::accctrl::{SE_FILE_OBJECT, TRUSTEE_IS_NAME, TRUSTEE_IS_USER};
use winapi::um::aclapi::SetNamedSecurityInfoA;
use winapi::um::fileapi::SetFileAttributesA;
use winapi::um::winbase::LocalFree;
use winapi::um::winnt::PACL;
use winapi::um::winnt::{
    DACL_SECURITY_INFORMATION, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM, GENERIC_READ,
    GENERIC_WRITE,
};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

#[derive(Serialize, Deserialize, Debug)]
struct Task {
    name: String,
    description: String,
    priority: String,
    completed: bool,
}

lazy_static! {
    static ref PASSWORD_CACHE: Mutex<Option<PasswordCache>> = Mutex::new(None);
}
struct PasswordCache {
    password: String,
    timestamp: Instant,
    temp_file_path: String,
}

impl PasswordCache {
    fn new(password: String, temp_file_path: String) -> Self {
        PasswordCache {
            password,
            timestamp: Instant::now(),
            temp_file_path,
        }
    }

    fn is_valid(&self) -> bool {
        self.timestamp.elapsed() < Duration::from_secs(15 * 60)
    }
}

const STORAGE_FILE: &str = "tasks.json";

// Function to generate a random salt for PBKDF2
fn generate_random_salt() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..16).map(|_| rng.gen()).collect() // Generate 16 bytes of random data
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

// Function to generate a random IV (16 bytes for AES-256-CBC)
fn generate_random_iv() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..16).map(|_| rng.gen()).collect() // Generate 16 bytes of random data
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

// Function to check if the passphrase is correct by attempting to load tasks
fn is_passphrase_correct(passphrase: &str) -> bool {
    match File::open(STORAGE_FILE) {
        Ok(mut file) => {
            let mut file_data = Vec::new();

            if let Err(_) = file.read_to_end(&mut file_data) {
                return false;
            }

            if file_data.len() >= 16 + 16 {
                let salt = file_data[..16].to_vec(); // Extract the salt
                let iv = file_data[16..32].to_vec(); // Extract the IV
                let encrypted_data = &file_data[32..]; // The rest is the encrypted data

                let encryption_key = derive_key_from_passphrase(passphrase, &salt);

                match decrypt_data(encrypted_data, &encryption_key, &iv) {
                    Ok(_) => true,
                    Err(_) => false,
                }
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

// Function to load tasks from an encrypted file
fn load_tasks_from_file(passphrase: &str) -> HashMap<String, Task> {
    let mut tasks = HashMap::new();

    // Attempt to open the file for reading
    match File::open(STORAGE_FILE) {
        Ok(mut file) => {
            let mut file_data = Vec::new();

            // Attempt to read all the file data
            if let Err(e) = file.read_to_end(&mut file_data) {
                println!("Error reading from file: {}", e);
                return tasks; // Return empty tasks on error
            }

            if file_data.len() >= 16 + 16 {
                // Ensure we have salt and IV
                let salt = file_data[..16].to_vec(); // Extract the salt
                let iv = file_data[16..32].to_vec(); // Extract the IV
                let encrypted_data = &file_data[32..]; // The rest is the encrypted data

                // Derive the encryption key from the passphrase and salt
                let encryption_key = derive_key_from_passphrase(passphrase, &salt);

                match decrypt_data(encrypted_data, &encryption_key, &iv) {
                    Ok(decrypted_data) => {
                        // Try to deserialize the decrypted data into a HashMap
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
            } else {
                println!("Invalid file format: File does not contain enough data.");
            }
        }
        Err(e) => {
            println!("Error opening file: {}", e);
        }
    }

    tasks
}

// Function to save tasks to an encrypted file
fn save_tasks_to_file(tasks: &HashMap<String, Task>, passphrase: &str) -> io::Result<()> {
    let data = serde_json::to_string_pretty(tasks).unwrap();
    let iv = generate_random_iv(); // Generate random IV for encryption
    let salt = generate_random_salt(); // Generate a new salt for each file

    // Derive the encryption key from the passphrase and salt
    let encryption_key = derive_key_from_passphrase(passphrase, &salt);

    // Encrypt the task data
    let encrypted_data = encrypt_data(&data, &encryption_key, &iv);

    // Prepend the salt and IV to the encrypted data before saving
    let mut file_data = Vec::new();
    file_data.extend_from_slice(&salt); // Save the salt
    file_data.extend_from_slice(&iv); // Save the IV
    file_data.extend_from_slice(&encrypted_data); // Save the encrypted data

    // Attempt to open the file for writing
    match File::create(STORAGE_FILE) {
        Ok(mut file) => {
            // Attempt to write the data to the file
            if let Err(e) = file.write_all(&file_data) {
                println!("Error writing to file: {}", e);
            } else {
                println!("Changes successfully saved to file.");
            }
        }
        Err(e) => {
            println!("Error creating file: {}", e);
        }
    }

    Ok(())
}

fn get_password() -> String {
    // Check if we have a valid cached password
    if let Ok(cache) = PASSWORD_CACHE.lock() {
        if let Some(ref cached) = *cache {
            if cached.is_valid() {
                println!("Using cached password.");
                return cached.password.clone();
            } else {
                println!("Cached password expired.");
                // Delete the temporary file
                let _ = fs::remove_file(&cached.temp_file_path);
            }
        } else {
            println!("No cached password found.");
        }
    } else {
        println!("Failed to lock PASSWORD_CACHE.");
    }

    // If no valid cached password, check if a temporary file exists
    if let Ok(mut temp_file) = File::open("password_cache.tmp") {
        let mut password = String::new();
        if temp_file.read_to_string(&mut password).is_ok() {
            let timestamp = fs::metadata("password_cache.tmp")
                .and_then(|metadata| metadata.modified())
                .unwrap_or(SystemTime::now())
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::new(0, 0))
                .as_secs();

            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if current_time - timestamp < 15 * 60 {
                println!("Using password from temporary file.");
                return password;
            } else {
                println!("Temporary file password expired.");
                let _ = fs::remove_file("password_cache.tmp");
            }
        }
    } else {
        println!("No cached password found.");
    }

    // If no valid cached password, prompt for new password
    println!("Please enter your passphrase:");
    let password = read_password().unwrap();

    // Create a temporary file to store the password
    let mut temp_file = NamedTempFile::new().expect("Failed to create temporary file");
    let temp_file_path = temp_file.path().to_str().unwrap().to_string();
    temp_file
        .write_all(password.as_bytes())
        .expect("Failed to write to temporary file");

    // Set restricted permissions for the temporary file (Unix-like systems)
    #[cfg(unix)]
    {
        let permissions = fs::Permissions::from_mode(0o600); // Owner read/write only
        fs::set_permissions(temp_file.path(), permissions).expect("Failed to set permissions");
    }

    // Set hidden and system attributes for the temporary file (Windows)
    #[cfg(windows)]
    {
        let path = CString::new(temp_file.path().to_str().unwrap()).unwrap();
        unsafe {
            // Set file attributes to hidden and system
            SetFileAttributesA(path.as_ptr(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

            // Set file permissions to restrict access
            let mut ea: EXPLICIT_ACCESS_A = std::mem::zeroed();
            let trustee = CString::new("CURRENT_USER").unwrap();
            ea.grfAccessPermissions = GENERIC_READ | GENERIC_WRITE;
            ea.grfAccessMode = SET_ACCESS;
            ea.grfInheritance = NO_INHERITANCE;
            ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
            ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
            ea.Trustee.ptstrName = trustee.as_ptr() as *mut i8;

            let mut acl: PACL = null_mut();
            let result = SetNamedSecurityInfoA(
                path.as_ptr() as *mut i8,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl,
                null_mut(),
            );

            if result != 0 {
                println!("Failed to set file permissions.");
            }

            if !acl.is_null() {
                LocalFree(acl as *mut _);
            }
        }
    }

    // Cache the new password
    if let Ok(mut cache) = PASSWORD_CACHE.lock() {
        *cache = Some(PasswordCache::new(password.clone(), temp_file_path.clone()));
        println!("Password cached.");
    } else {
        println!("Failed to lock PASSWORD_CACHE for writing.");
    }

    // Persist the temporary file
    temp_file
        .persist("password_cache.tmp")
        .expect("Failed to persist temporary file");

    password
}

fn main() {
    let passphrase = get_password();

    let mut tasks: HashMap<String, Task> = load_tasks_from_file(&passphrase);

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
        .get_matches();

    // Handle the "add" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("add") {
        let name = sub_matches.get_one::<String>("name").unwrap();
        let description = sub_matches.get_one::<String>("description").unwrap();
        let priority = sub_matches.get_one::<String>("priority").unwrap();

        // Validate the passphrase before adding a task
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

    // Handle the "list" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("list") {
        // Validate the passphrase before listing tasks
        if !is_passphrase_correct(&passphrase) {
            println!("Error: Incorrect passphrase. Unable to list tasks.");
            println!("Please ensure you've entered the correct passphrase to access your tasks.");
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

    // Handle the "edit" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("edit") {
        // Validate the passphrase before any task operations
        if !is_passphrase_correct(&passphrase) {
            println!("Error: Incorrect passphrase. Unable to edit task.");
            println!("Please ensure you've entered the correct passphrase to modify tasks.");
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

    // Handle the "delete" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("delete") {
        // Validate the passphrase before deleting a task
        if !is_passphrase_correct(&passphrase) {
            println!("Error: Incorrect passphrase. Unable to delete task.");
            println!("Please ensure you've entered the correct passphrase to modify tasks.");
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
}
