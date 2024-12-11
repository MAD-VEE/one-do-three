use clap::{Command, Arg}; // Updated import for clap 3.x
use serde::{Serialize, Deserialize}; // Import only what you need
use serde_json; // Import serde_json for later use

#[derive(Serialize, Deserialize, Debug)] // Deriving serialization and deserialization for Task
struct Task {
    id: u32, // Task ID, unique identifier
    name: String, // Name of the task
    category: String, // Category of the task (e.g., "work", "personal")
    priority: u8, // Priority of the task (1-5 scale)
}

fn add_task(name: &str, category: &str, priority: u8) {
    // Create a Task struct and print it to the console
    let task = Task {
        id: 1, // Static ID for now (in a real app, it should be dynamic)
        name: name.to_string(), // Convert the name parameter to String
        category: category.to_string(), // Convert the category parameter to String
        priority, // Directly use the priority passed in
    };

    println!("Task added: {:?}", task); // Print the task to the console in debug format
}

fn list_tasks() {
    // Placeholder function to list tasks
    println!("Listing all tasks...");
    // In a real application, you would fetch and print tasks from storage
}

fn main() {
    // Create the main command-line interface (CLI) using clap
    let matches = Command::new("One-Do-Three") // Name of the app
        .version("1.0") // Version of the app
        .author("MAD-VEE") // Author's name
        .about("A secure, encrypted CLI todo app with progress visualization") // Description of the app
        .subcommand(Command::new("add") // Subcommand to add a task
            .about("Add a new task") // Description of the add task subcommand
            .arg(Arg::new("name") // Argument for task name
                .short('n') // Short flag for the name
                .long("name") // Long flag for the name
                .value_parser(clap::value_parser!(String)) // Parse the name as a String
                .help("The name of the task")) // Help message for the name argument
            .arg(Arg::new("category") // Argument for task category
                .short('c') // Short flag for category
                .long("category") // Long flag for category
                .value_parser(clap::value_parser!(String)) // Parse the category as a String
                .help("Category of the task")) // Help message for the category argument
            .arg(Arg::new("priority") // Argument for task priority
                .short('p') // Short flag for priority
                .long("priority") // Long flag for priority
                .value_parser(clap::value_parser!(u8)) // Parse the priority as a u8 (integer)
                .help("Priority of the task")) // Help message for the priority argument
        )
        .subcommand(Command::new("list") // Subcommand to list tasks
            .about("List all tasks")) // Description of the list tasks subcommand
        .get_matches(); // Parse the command-line arguments

    // Handle the "add" subcommand
    if let Some(matches) = matches.subcommand_matches("add") {
        // If the "add" subcommand is used, get the argument values
        if let Some(name) = matches.get_one::<String>("name") { // Get the task name
            if let Some(category) = matches.get_one::<String>("category") { // Get the task category
                if let Some(priority_str) = matches.get_one::<u8>("priority") { // Get the task priority
                    add_task(name, category, *priority_str); // Call add_task function with the provided arguments
                }
            }
        }
    }

    // Handle the "list" subcommand
    if let Some(_) = matches.subcommand_matches("list") {
        list_tasks(); // Call the list_tasks function to list all tasks
    }
}
