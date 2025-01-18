use clap::{Arg, Command}; // Import necessary modules from clap for command-line argument parsing
use serde::{Deserialize, Serialize}; // Import Serde to serialize and deserialize task data to/from JSON
use std::collections::HashMap; // Import HashMap to store tasks in memory
use std::fs::File; // For file operations such as opening and writing files
use std::io::{self, Read, Write}; // For reading from and writing to files

use aes::Aes256; // AES-256 encryption
use block_modes::block_padding::Pkcs7; // Use PKCS7 padding for block cipher
use block_modes::{BlockMode, Cbc}; // Import block modes, specifically CBC mode

use hmac::Hmac; // HMAC for PBKDF2
use itertools::Itertools;
use pbkdf2::pbkdf2; // For PBKDF2 key derivation
use rpassword::read_password; // For securely reading the passphrase

use sha2::Sha256; // SHA-256 for HMAC

use std::num::NonZeroU32; // To handle iteration count // Import Itertools for the `.sorted_by` met in PBKDF2

// Define encryption and decryption types using AES-256-CBC
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

#[derive(Serialize, Deserialize, Debug)] // Derive Serde traits for Task struct to enable serialization/deserialization
struct Task {
    name: String,        // Name of the task
    description: String, // Description of the task
    priority: String,    // Priority of the task (e.g., "High", "Medium", "Low")
    completed: bool,     // Status of the task: true if completed, false otherwise
}

const STORAGE_FILE: &str = "tasks.json"; // Define the path to the file where tasks are stored

// Function to derive a 32-byte key from the passphrase using PBKDF2
fn derive_key_from_passphrase(passphrase: &str) -> Vec<u8> {
    let mut key = vec![0u8; 32]; // Create a vector of 32 bytes for the key
    let salt = b"some_unique_salt"; // Ideally, this should be unique per user or session

    let iterations = NonZeroU32::new(100_000).unwrap(); // Set the iteration count for PBKDF2

    pbkdf2::<Hmac<Sha256>>(
        passphrase.as_bytes(),
        salt,
        iterations.get().into(),
        &mut key,
    ); // Derive the key

    key // Return the 32-byte derived key
}

// Function to encrypt data using AES-256-CBC
fn encrypt_data(data: &str, encryption_key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes256Cbc::new_from_slices(encryption_key, iv).unwrap(); // Initialize AES-256-CBC cipher
    cipher.encrypt_vec(data.as_bytes()) // Encrypt the input data and return the ciphertext
}

// Function to decrypt data using AES-256-CBC
fn decrypt_data(encrypted_data: &[u8], encryption_key: &[u8], iv: &[u8]) -> Result<String, String> {
    let cipher = Aes256Cbc::new_from_slices(encryption_key, iv).unwrap(); // Initialize AES-256-CBC cipher
    match cipher.decrypt_vec(encrypted_data) {
        Ok(decrypted_data) => match String::from_utf8(decrypted_data) {
            Ok(decoded_str) => Ok(decoded_str),
            Err(_) => Err("Decrypted data is not valid UTF-8".to_string()), // Handle invalid UTF-8 data
        },
        Err(_) => Err("Decryption failed".to_string()), // Handle decryption failure
    }
}

// Function to load tasks from an encrypted file
fn load_tasks_from_file(encryption_key: &[u8]) -> HashMap<String, Task> {
    let mut tasks = HashMap::new(); // Create an empty HashMap to store tasks
    if let Ok(mut file) = File::open(STORAGE_FILE) {
        // Attempt to open the encrypted file
        let mut encrypted_data = Vec::new(); // Create a buffer for the encrypted data
        if file.read_to_end(&mut encrypted_data).is_ok() {
            // Read the file content into the buffer
            match decrypt_data(&encrypted_data, encryption_key, &vec![0u8; 16]) {
                Ok(decrypted_data) => {
                    if let Ok(parsed) = serde_json::from_str(&decrypted_data) {
                        tasks = parsed; // If successful, assign the parsed HashMap to `tasks`
                    }
                }
                Err(err) => {
                    println!("Error decrypting data: {}", err); // Handle decryption error
                }
            }
        }
    }
    tasks // Return the loaded tasks (could be empty if the file couldn't be read or decrypted)
}

// Function to save tasks to an encrypted file
fn save_tasks_to_file(tasks: &HashMap<String, Task>, encryption_key: &[u8]) -> io::Result<()> {
    let data = serde_json::to_string_pretty(tasks).unwrap(); // Serialize the tasks to a pretty JSON format
    let encrypted_data = encrypt_data(&data, encryption_key, &vec![0u8; 16]); // Encrypt the serialized JSON string
    let mut file = File::create(STORAGE_FILE)?; // Create or overwrite the file for writing
    file.write_all(&encrypted_data) // Write the encrypted data to the file
}

// Main function to handle command-line arguments and task operations
fn main() {
    // Get the passphrase securely from the user
    println!("Please enter your passphrase:");
    let passphrase = read_password().unwrap(); // Securely read the passphrase

    // Derive the 32-byte key from the passphrase
    let encryption_key = derive_key_from_passphrase(&passphrase);

    let mut tasks: HashMap<String, Task> = load_tasks_from_file(&encryption_key); // Load tasks from the encrypted file into a HashMap

    // Define the command-line interface using clap
    let matches = Command::new("one-do-three") // Create a new Clap command with the name "one-do-three"
        .about("A simple task management CLI") // Set the description for the command-line tool
        .subcommand(
            Command::new("add")
                .about("Add a new task") // Description for the "add" subcommand
                .arg(Arg::new("name").help("The name of the task").required(true)) // Define the "name" argument (required)
                .arg(
                    Arg::new("description")
                        .help("The task description")
                        .required(true),
                ) // Define the "description" argument (required)
                .arg(
                    Arg::new("priority")
                        .help("The priority of the task")
                        .required(true),
                ), // Define the "priority" argument (required)
        )
        .subcommand(
            Command::new("list")
                .about("List all tasks") // Description for the "list" subcommand
                .arg(
                    Arg::new("filter")
                        .long("filter") // Define a filter argument to filter tasks
                        .help("Filter tasks by priority or completion status")
                        .value_name("FILTER"),
                )
                .arg(
                    Arg::new("sort")
                        .long("sort") // Define a sort argument to sort tasks
                        .help("Sort tasks by priority, completion status, or name")
                        .value_name("SORT"),
                ),
        )
        .subcommand(
            Command::new("edit")
                .about("Edit an existing task") // Description for the "edit" subcommand
                .arg(
                    Arg::new("name")
                        .help("The name of the task to edit") // Define the "name" argument (required)
                        .required(true),
                )
                .arg(
                    Arg::new("description")
                        .help("The new description of the task") // Define the "description" argument
                        .long("description")
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("priority")
                        .help("The new priority of the task") // Define the "priority" argument
                        .long("priority")
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("completed")
                        .help("Set the task as completed (true/false)") // Define the "completed" argument
                        .long("completed")
                        .value_parser(clap::value_parser!(String)),
                ),
        )
        .subcommand(
            Command::new("delete")
                .about("Delete an existing task") // Description for the "delete" subcommand
                .arg(
                    Arg::new("name")
                        .help("The name of the task to delete") // Define the "name" argument (required)
                        .required(true),
                ),
        )
        .get_matches(); // Parse the command-line arguments

    // Handle the "add" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("add") {
        let name = sub_matches.get_one::<String>("name").unwrap(); // Get the task name
        let description = sub_matches.get_one::<String>("description").unwrap(); // Get the task description
        let priority = sub_matches.get_one::<String>("priority").unwrap(); // Get the task priority

        let new_task = Task {
            name: name.to_string(),
            description: description.to_string(),
            priority: priority.to_string(),
            completed: false, // New tasks are incomplete by default
        };

        tasks.insert(name.clone(), new_task); // Add the new task to the HashMap
        save_tasks_to_file(&tasks, &encryption_key).expect("Failed to save tasks to file"); // Save tasks to the encrypted file
        println!("Task added: {}", name); // Confirmation message
    }

    // Handle the "list" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("list") {
        if tasks.is_empty() {
            println!("No tasks available."); // If there are no tasks, notify the user
            return;
        }

        let filter = sub_matches.get_one::<String>("filter"); // Get the filter argument
        let sort = sub_matches.get_one::<String>("sort"); // Get the sort argument

        // Filter tasks if the "filter" argument is provided
        let filtered_tasks = tasks
            .iter()
            .filter(|(_, task)| {
                if let Some(f) = filter {
                    match f.as_str() {
                        "completed" => task.completed,
                        "high" => task.priority == "High",
                        _ => true, // Default to no filtering
                    }
                } else {
                    true
                }
            })
            .collect::<HashMap<_, _>>(); // Collect filtered tasks into a new HashMap

        // Sort tasks if the "sort" argument is provided
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
                    a.0.cmp(b.0) // Default to sorting by task name
                }
            })
            .collect::<Vec<_>>(); // Sort tasks and collect them in a vector

        // Display sorted tasks
        for (name, task) in sorted_tasks {
            println!(
                "Task: {}\nDescription: {}\nPriority: {}\nCompleted: {}\n",
                name, task.description, task.priority, task.completed
            );
        }
    }

    // Handle the "edit" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("edit") {
        let name = sub_matches.get_one::<String>("name").unwrap(); // Get the task name to edit

        if let Some(task) = tasks.get_mut(name) {
            if let Some(description) = sub_matches.get_one::<String>("description") {
                task.description = description.clone(); // Update the task description
            }
            if let Some(priority) = sub_matches.get_one::<String>("priority") {
                task.priority = priority.clone(); // Update the task priority
            }
            if let Some(completed) = sub_matches.get_one::<String>("completed") {
                task.completed = completed == "true"; // Update the task completion status
            }

            save_tasks_to_file(&tasks, &encryption_key).expect("Failed to save tasks to file"); // Save the updated tasks to the file
            println!("Task updated: {}", name); // Confirmation message
        } else {
            println!("Task not found: {}", name); // If task doesn't exist
        }
    }

    // Handle the "delete" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("delete") {
        let name = sub_matches.get_one::<String>("name").unwrap(); // Get the task name to delete

        if tasks.remove(name).is_some() {
            save_tasks_to_file(&tasks, &encryption_key).expect("Failed to save tasks to file"); // Save the updated tasks to the file
            println!("Task deleted: {}", name); // Confirmation message
        } else {
            println!("Task not found: {}", name); // If task doesn't exist
        }
    }
}
