use clap::{Arg, Command}; // Import necessary modules from clap for command-line argument parsing
use serde::{Deserialize, Serialize}; // Import Serde to serialize and deserialize task data to/from JSON
use std::collections::HashMap; // Import HashMap to store tasks in memory
use std::fs::{self, File}; // For file operations such as opening and writing files
use std::io::{self, Read, Write}; // For reading from and writing to files

#[derive(Serialize, Deserialize, Debug)] // Derive Serde traits for Task struct to enable serialization/deserialization
struct Task {
    name: String,        // Name of the task
    description: String, // Description of the task
    priority: String,    // Priority of the task (e.g., "High", "Medium", "Low")
    completed: bool,     // Status of the task: true if completed, false otherwise
}

const STORAGE_FILE: &str = "tasks.json"; // Define the path to the file where tasks are stored

// Function to load tasks from a file
fn load_tasks_from_file() -> HashMap<String, Task> {
    let mut tasks = HashMap::new(); // Create an empty HashMap to store tasks
    if let Ok(mut file) = File::open(STORAGE_FILE) {
        // Attempt to open the file for reading
        let mut data = String::new(); // Create a mutable string to store the file contents
        if file.read_to_string(&mut data).is_ok() {
            // Read the file content into the string
            if let Ok(parsed) = serde_json::from_str(&data) {
                // Try parsing the JSON string into a HashMap
                tasks = parsed; // If successful, assign the parsed HashMap to `tasks`
            }
        }
    }
    tasks // Return the loaded tasks (could be empty if the file couldn't be read)
}

// Function to save tasks to a file
fn save_tasks_to_file(tasks: &HashMap<String, Task>) -> io::Result<()> {
    let data = serde_json::to_string_pretty(tasks).unwrap(); // Serialize the tasks to a pretty JSON format
    let mut file = File::create(STORAGE_FILE)?; // Create or overwrite the file for writing
    file.write_all(data.as_bytes()) // Write the serialized tasks data to the file as bytes
}

// Main function to handle command-line arguments and task operations
fn main() {
    let mut tasks: HashMap<String, Task> = load_tasks_from_file(); // Load tasks from the file into a HashMap

    // Define the command-line interface using clap
    let matches = Command::new("one-do-three") // Create a new Clap command with the name "one-do-three"
        .about("A simple task management CLI") // Set the description for the command-line tool
        .subcommand(
            // Define the "add" subcommand for adding tasks
            Command::new("add")
                .about("Add a new task") // Description for the "add" subcommand
                .arg(Arg::new("name").help("The name of the task").required(true)) // Define the "name" argument for the task (required)
                .arg(
                    Arg::new("description")
                        .help("The task description") // Define the "description" argument (required)
                        .required(true),
                )
                .arg(
                    Arg::new("priority")
                        .help("The priority of the task") // Define the "priority" argument (required)
                        .required(true),
                ),
        )
        .subcommand(
            // Define the "list" subcommand for listing tasks
            Command::new("list")
                .about("List all tasks") // Description for the "list" subcommand
                .arg(
                    Arg::new("filter")
                        .long("filter") // Define a filter argument to filter tasks by priority or completion status
                        .help("Filter tasks by priority or completion status")
                        .value_name("FILTER"),
                )
                .arg(
                    Arg::new("sort")
                        .long("sort") // Define a sort argument to sort tasks by different criteria
                        .help("Sort tasks by priority, completion status, or name")
                        .value_name("SORT"),
                ),
        )
        .subcommand(
            // Define the "edit" subcommand for editing tasks
            Command::new("edit")
                .about("Edit an existing task") // Description for the "edit" subcommand
                .arg(
                    Arg::new("name")
                        .help("The name of the task to edit") // Define the "name" argument for the task to edit (required)
                        .required(true),
                )
                .arg(
                    Arg::new("description")
                        .help("The new description of the task") // Define the "description" argument to update task description
                        .long("description") // Long option name for description
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("priority")
                        .help("The new priority of the task") // Define the "priority" argument to update task priority
                        .long("priority")
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("completed")
                        .help("Set the task as completed (true/false)") // Define the "completed" argument to update task completion status
                        .long("completed")
                        .value_parser(clap::value_parser!(String)),
                ),
        )
        .subcommand(
            // Define the "delete" subcommand for deleting tasks
            Command::new("delete")
                .about("Delete an existing task") // Description for the "delete" subcommand
                .arg(
                    Arg::new("name")
                        .help("The name of the task to delete") // Define the "name" argument to specify the task to delete
                        .required(true),
                ),
        )
        .get_matches(); // Parse the command-line arguments based on the defined structure

    // Handle the "add" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("add") {
        // If the "add" subcommand was used
        let name = sub_matches.get_one::<String>("name").unwrap(); // Get the task name from the argument
        let description = sub_matches.get_one::<String>("description").unwrap(); // Get the task description from the argument
        let priority = sub_matches.get_one::<String>("priority").unwrap(); // Get the task priority from the argument

        let new_task = Task {
            // Create a new task with the provided arguments
            name: name.to_string(),
            description: description.to_string(),
            priority: priority.to_string(),
            completed: false, // New tasks are incomplete by default
        };

        tasks.insert(name.clone(), new_task); // Insert the new task into the tasks HashMap with name as the key
        save_tasks_to_file(&tasks).expect("Failed to save tasks to file"); // Save the tasks to the file after adding the new task
        println!("Task added: {}", name); // Output confirmation message
    }

    // Handle the "list" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("list") {
        // If the "list" subcommand was used
        if tasks.is_empty() {
            // Check if there are no tasks to display
            println!("No tasks available."); // Output message if no tasks are present
            return;
        }

        let filter = sub_matches.get_one::<String>("filter"); // Get the filter argument (if any)
        let mut tasks_vec: Vec<&Task> = tasks.values().collect(); // Collect the tasks into a vector for sorting

        if let Some(sort) = sub_matches.get_one::<String>("sort") {
            // If the sort argument was provided
            match sort.as_str() {
                // Match against the provided sort value
                "priority" => tasks_vec.sort_by(|a, b| {
                    // Sort by priority (High > Medium > Low)
                    let priority_value = |priority: &str| match priority {
                        "High" => 3,
                        "Medium" => 2,
                        "Low" => 1,
                        _ => 0,
                    };
                    priority_value(&b.priority).cmp(&priority_value(&a.priority))
                    // Sort descending by priority
                }),
                "completed" => tasks_vec.sort_by(|a, b| a.completed.cmp(&b.completed)), // Sort by completion status
                "name" => tasks_vec.sort_by(|a, b| a.name.cmp(&b.name)), // Sort by name alphabetically
                _ => println!("Unknown sort option: {}", sort), // If an unknown sort option is provided
            }
        }

        // Iterate over the sorted tasks and apply the filter if needed
        for task in tasks_vec {
            // For each task in the sorted list
            if let Some(filter) = filter {
                // If a filter is provided
                match filter.to_lowercase().as_str() {
                    // Apply the filter to tasks
                    "completed" if !task.completed => continue, // Skip incomplete tasks for "completed" filter
                    "incomplete" if task.completed => continue, // Skip completed tasks for "incomplete" filter
                    "high" | "medium" | "low"
                        if task.priority.to_lowercase() != filter.to_lowercase() =>
                    {
                        continue; // Skip tasks that don't match the priority filter
                    }
                    _ => {} // Handle other cases (e.g., unknown filter)
                }
            }

            // Print the task details
            println!(
                "Task: {}\nDescription: {}\nPriority: {}\nCompleted: {}\n",
                task.name, task.description, task.priority, task.completed
            );
        }
    }

    // Handle the "edit" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("edit") {
        // If the "edit" subcommand was used
        let name = sub_matches.get_one::<String>("name").unwrap(); // Get the task name to edit

        if let Some(task) = tasks.get_mut(name) {
            // If the task exists in the HashMap
            // Update the task's fields with the new values if provided
            if let Some(description) = sub_matches.get_one::<String>("description") {
                task.description = description.to_string(); // Update description
            }
            if let Some(priority) = sub_matches.get_one::<String>("priority") {
                task.priority = priority.to_string(); // Update priority
            }
            if let Some(completed) = sub_matches.get_one::<String>("completed") {
                task.completed = completed == "true"; // Update completion status (true/false)
            }

            save_tasks_to_file(&tasks).expect("Failed to save tasks to file"); // Save the updated tasks to the file
            println!("Task updated: {}", name); // Output confirmation message
        } else {
            println!("Task not found: {}", name); // If the task does not exist in the HashMap
        }
    }

    // Handle the "delete" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("delete") {
        // If the "delete" subcommand was used
        let name = sub_matches.get_one::<String>("name").unwrap(); // Get the task name to delete

        if tasks.remove(name).is_some() {
            // If the task was found and removed
            save_tasks_to_file(&tasks).expect("Failed to save tasks to file"); // Save the updated tasks to the file
            println!("Task deleted: {}", name); // Output confirmation message
        } else {
            println!("Task not found: {}", name); // If the task was not found to delete
        }
    }
}
