use clap::{Arg, Command};  // Importing clap to handle command-line argument parsing
use serde::{Serialize, Deserialize};  // Importing Serde traits for serializing and deserializing data
use std::collections::HashMap;  // Importing HashMap to store tasks in memory with key-value pairs

#[derive(Serialize, Deserialize, Debug)]  // The Task struct will represent individual tasks
struct Task {
    name: String,             // Name of the task (unique identifier)
    description: String,      // A brief description of what the task entails
    priority: String,         // Priority level (e.g., High, Medium, Low)
    completed: bool,          // Whether the task is completed or not
}

fn main() {
    // Create an in-memory storage for tasks using a HashMap, where task names are keys
    let mut tasks: HashMap<String, Task> = HashMap::new();

    // Define the structure of the CLI application using clap
    let matches = Command::new("one-do-three")  // Name of the application
        .about("A simple task management CLI")  // Short description of the app
        .subcommand(                            // Adding a subcommand for "add"
            Command::new("add")
                .about("Add a new task")        // Description of the "add" command
                .arg(Arg::new("name")           // Argument for the task name
                    .help("The name of the task")  // Explanation for the user
                    .required(true))           // This argument is mandatory
                .arg(Arg::new("description")    // Argument for the task description
                    .help("The task description")  // Explanation for the user
                    .required(true))           // This argument is mandatory
                .arg(Arg::new("priority")       // Argument for the task priority
                    .help("The priority of the task")  // Explanation for the user
                    .required(true)),          // This argument is mandatory
        )
        .subcommand(                            // Adding a subcommand for "list"
            Command::new("list")
                .about("List all tasks")        // Description of the "list" command
                .arg(Arg::new("filter")         // Optional argument to filter tasks
                    .long("filter")             // Prefix for using this argument (--filter)
                    .help("Filter tasks by priority or completion status")  // Explanation
                    .value_name("FILTER")),     // Name of the value expected for filtering
        )
        .get_matches();  // Parse the command-line arguments provided by the user

    // Check if the "add" subcommand was called
    if let Some(sub_matches) = matches.subcommand_matches("add") {
        let name = sub_matches.get_one::<String>("name").unwrap();  // Retrieve the task name
        let description = sub_matches.get_one::<String>("description").unwrap();  // Task description
        let priority = sub_matches.get_one::<String>("priority").unwrap();  // Task priority

        // Create a new Task instance with the provided data
        let new_task = Task {
            name: name.to_string(),
            description: description.to_string(),
            priority: priority.to_string(),
            completed: false,  // Tasks are marked incomplete by default
        };

        // Add the task to the in-memory HashMap, using its name as the key
        tasks.insert(name.clone(), new_task);

        // Print a confirmation message to the user
        println!("Task added: {}", name);
    }

    // Check if the "list" subcommand was called
    if let Some(sub_matches) = matches.subcommand_matches("list") {
        if tasks.is_empty() {
            // If no tasks exist in the HashMap, notify the user
            println!("No tasks available.");
            return;  // Exit the program after showing this message
        }

        // Check if a filter was provided
        let filter = sub_matches.get_one::<String>("filter");
        for (name, task) in &tasks {
            if let Some(filter) = filter {
                // Skip tasks based on the filter criteria
                if filter.eq_ignore_ascii_case("completed") && !task.completed {
                    continue;  // Skip if the filter is "completed" and the task is not completed
                } else if filter.eq_ignore_ascii_case("incomplete") && task.completed {
                    continue;  // Skip if the filter is "incomplete" and the task is completed
                } else if filter.eq_ignore_ascii_case(&task.priority) {
                    // Matches priority (e.g., High, Medium, Low)
                } else {
                    continue;  // Skip tasks that don't match any filter
                }
            }

            // Display the task details
            println!(
                "Task: {}\nDescription: {}\nPriority: {}\nCompleted: {}\n",
                name, task.description, task.priority, task.completed
            );
        }
    }
}
