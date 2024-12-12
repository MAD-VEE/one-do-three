use clap::{Arg, Command}; // Import necessary modules from clap for command-line argument parsing
use serde::{Deserialize, Serialize}; // Import Serde to serialize and deserialize task data to/from JSON
use std::collections::HashMap; // Import HashMap to store tasks in memory
use std::fs::{self, File}; // For file operations such as opening and writing files
use std::io::{self, Read, Write}; // For reading from and writing to files

#[derive(Serialize, Deserialize, Debug)] // Derive Serde traits for Task struct to enable serialization/deserialization
struct Task {
    name: String,
    description: String,
    priority: String,
    completed: bool,
}

const STORAGE_FILE: &str = "tasks.json"; // Define the path to the file where tasks are stored

// Function to load tasks from a file
fn load_tasks_from_file() -> HashMap<String, Task> {
    let mut tasks = HashMap::new(); // Create an empty HashMap to store tasks
    if let Ok(mut file) = File::open(STORAGE_FILE) {
        // Attempt to open the file
        let mut data = String::new();
        if file.read_to_string(&mut data).is_ok() {
            // Read the file content into a string
            if let Ok(parsed) = serde_json::from_str(&data) {
                // Parse the JSON data into HashMap
                tasks = parsed;
            }
        }
    }
    tasks // Return the loaded tasks
}

// Function to save tasks to a file
fn save_tasks_to_file(tasks: &HashMap<String, Task>) -> io::Result<()> {
    let data = serde_json::to_string_pretty(tasks).unwrap(); // Serialize tasks into a pretty JSON format
    let mut file = File::create(STORAGE_FILE)?; // Create or overwrite the file
    file.write_all(data.as_bytes()) // Write the serialized tasks into the file
}

// Main function to handle command-line arguments and task operations
fn main() {
    let mut tasks: HashMap<String, Task> = load_tasks_from_file(); // Load tasks from the file

    // Define the command-line interface using clap
    let matches = Command::new("one-do-three")
        .about("A simple task management CLI")
        .subcommand(
            // Define the "add" subcommand for adding tasks
            Command::new("add")
                .about("Add a new task")
                .arg(Arg::new("name").help("The name of the task").required(true)) // Name is required
                .arg(
                    Arg::new("description")
                        .help("The task description")
                        .required(true),
                ) // Description is required
                .arg(
                    Arg::new("priority")
                        .help("The priority of the task")
                        .required(true),
                ), // Priority is required
        )
        .subcommand(
            // Define the "list" subcommand for listing tasks
            Command::new("list").about("List all tasks").arg(
                Arg::new("filter")
                    .long("filter")
                    .help("Filter tasks by priority or completion status")
                    .value_name("FILTER"),
            ), // Optional filter
        )
        .subcommand(
            // Define the "edit" subcommand for editing tasks
            Command::new("edit")
                .about("Edit an existing task")
                .arg(
                    Arg::new("name")
                        .help("The name of the task to edit")
                        .required(true),
                ) // Name of the task to edit
                .arg(
                    Arg::new("description")
                        .help("The new description of the task")
                        .long("description")
                        .value_parser(clap::value_parser!(String)),
                ) // New description
                .arg(
                    Arg::new("priority")
                        .help("The new priority of the task")
                        .long("priority")
                        .value_parser(clap::value_parser!(String)),
                ) // New priority
                .arg(
                    Arg::new("completed")
                        .help("Set the task as completed (true/false)")
                        .long("completed")
                        .value_parser(clap::value_parser!(String)),
                ), // Task completion status
        )
        .subcommand(
            // Define the "delete" subcommand for deleting tasks
            Command::new("delete").about("Delete an existing task").arg(
                Arg::new("name")
                    .help("The name of the task to delete")
                    .required(true),
            ), // Name of the task to delete
        )
        .get_matches(); // Parse the command-line arguments

    // Handle the "add" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("add") {
        let name = sub_matches.get_one::<String>("name").unwrap(); // Get task name
        let description = sub_matches.get_one::<String>("description").unwrap(); // Get task description
        let priority = sub_matches.get_one::<String>("priority").unwrap(); // Get task priority

        let new_task = Task {
            // Create a new task
            name: name.to_string(),
            description: description.to_string(),
            priority: priority.to_string(),
            completed: false, // New tasks are incomplete by default
        };

        tasks.insert(name.clone(), new_task); // Insert the new task into the tasks HashMap
        save_tasks_to_file(&tasks).expect("Failed to save tasks to file"); // Save the tasks to the file
        println!("Task added: {}", name);
    }

    // Handle the "list" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("list") {
        if tasks.is_empty() {
            println!("No tasks available."); // If no tasks, display a message
            return;
        }

        let filter = sub_matches.get_one::<String>("filter"); // Get filter argument
        for (name, task) in &tasks {
            // Iterate through tasks
            if let Some(filter) = filter {
                if filter.eq_ignore_ascii_case("completed") && !task.completed {
                    continue; // Skip incomplete tasks if filtered for completed tasks
                } else if filter.eq_ignore_ascii_case("incomplete") && task.completed {
                    continue; // Skip completed tasks if filtered for incomplete tasks
                } else if filter.eq_ignore_ascii_case(&task.priority) {
                    // Match task by priority
                } else {
                    continue; // Skip tasks that don't match filter
                }
            }
            println!(
                // Print task details
                "Task: {}\nDescription: {}\nPriority: {}\nCompleted: {}\n",
                name, task.description, task.priority, task.completed
            );
        }
    }

    // Handle the "edit" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("edit") {
        let name = sub_matches.get_one::<String>("name").unwrap(); // Get task name to edit

        if let Some(task) = tasks.get_mut(name) {
            // If task exists
            // Optional editing: Update fields if provided
            if let Some(description) = sub_matches.get_one::<String>("description") {
                task.description = description.to_string();
            }
            if let Some(priority) = sub_matches.get_one::<String>("priority") {
                task.priority = priority.to_string();
            }
            if let Some(completed) = sub_matches.get_one::<String>("completed") {
                task.completed = completed == "true";
            }

            save_tasks_to_file(&tasks).expect("Failed to save tasks to file"); // Save changes to file
            println!("Task updated: {}", name);
        } else {
            println!("Task not found: {}", name); // If task not found
        }
    }

    // Handle the "delete" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("delete") {
        let name = sub_matches.get_one::<String>("name").unwrap(); // Get task name to delete

        if tasks.remove(name).is_some() {
            // Remove the task if it exists
            save_tasks_to_file(&tasks).expect("Failed to save tasks to file"); // Save the changes to the file
            println!("Task deleted: {}", name);
        } else {
            println!("Task not found: {}", name); // If task not found
        }
    }
}
