use clap::{Arg, Command};  // Importing necessary clap modules for command-line argument parsing
use serde::{Serialize, Deserialize};  // Importing Serde for serializing and deserializing data
use serde_json;  // Importing Serde JSON library for working with JSON
use std::collections::HashMap;  // Importing HashMap for storing tasks (optional)

#[derive(Serialize, Deserialize, Debug)]  // Deriving Serialize and Deserialize traits for Task struct to be converted to and from JSON
struct Task {
    name: String,
    description: String,
    priority: String,
    completed: bool,
}

fn main() {
    // Defining the command-line interface using clap
    let matches = Command::new("one-do-three")  // The name of the application
        .about("A simple task management CLI")  // A short description of the application
        .subcommand(
            Command::new("add")  // Adding the "add" subcommand to allow users to add a task
                .about("Add a new task")  // A short description of the "add" subcommand
                .arg(Arg::new("name")  // Defining the "name" positional argument
                    .help("The name of the task")  // Help text for this argument
                    .required(true))  // Marking this argument as required
                .arg(Arg::new("description")  // Defining the "description" positional argument
                    .help("The task description")  // Help text for this argument
                    .required(true))  // Marking this argument as required
                .arg(Arg::new("priority")  // Defining the "priority" positional argument
                    .help("The priority of the task")  // Help text for this argument
                    .required(true)),  // Marking this argument as required
        )
        .get_matches();  // Parsing the command-line arguments

    // Handling the "add" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("add") {
        let name = sub_matches.get_one::<String>("name").unwrap();  // Using get_one to retrieve the "name" argument
        let description = sub_matches.get_one::<String>("description").unwrap();  // Using get_one to retrieve the "description" argument
        let priority = sub_matches.get_one::<String>("priority").unwrap();  // Using get_one to retrieve the "priority" argument

        // Creating a new task with the given arguments
        let new_task = Task {
            name: name.to_string(),
            description: description.to_string(),
            priority: priority.to_string(),
            completed: false,  // The task is initially marked as not completed
        };

        // In a real application, tasks would be stored in memory or saved to a file/database.
        // For now, we're just printing the created task to the console.
        println!("Task created: {:#?}", new_task);
    }
}
