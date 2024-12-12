use clap::{Arg, Command};  // Importing necessary clap modules for command-line argument parsing
use serde::{Serialize, Deserialize};  // Importing Serde for serializing and deserializing data
use std::collections::HashMap;  // Importing HashMap for in-memory task storage
use std::fs::{self, File};  // For file operations
use std::io::{self, Read, Write};  // For reading and writing to files

#[derive(Serialize, Deserialize, Debug)]  // Deriving Serialize and Deserialize traits for Task struct
struct Task {
    name: String,
    description: String,
    priority: String,
    completed: bool,
}

const STORAGE_FILE: &str = "tasks.json";  // File where tasks will be stored

fn load_tasks_from_file() -> HashMap<String, Task> {
    let mut tasks = HashMap::new();

    if let Ok(mut file) = File::open(STORAGE_FILE) {
        let mut data = String::new();
        if file.read_to_string(&mut data).is_ok() {
            if let Ok(parsed) = serde_json::from_str(&data) {
                tasks = parsed;
            }
        }
    }

    tasks
}

fn save_tasks_to_file(tasks: &HashMap<String, Task>) -> io::Result<()> {
    let data = serde_json::to_string_pretty(tasks).unwrap();
    let mut file = File::create(STORAGE_FILE)?;
    file.write_all(data.as_bytes())
}

fn main() {
    let mut tasks: HashMap<String, Task> = load_tasks_from_file();  // Load tasks from file

    // Defining the command-line interface using clap
    let matches = Command::new("one-do-three")
        .about("A simple task management CLI")
        .subcommand(
            Command::new("add")
                .about("Add a new task")
                .arg(Arg::new("name")
                    .help("The name of the task")
                    .required(true))
                .arg(Arg::new("description")
                    .help("The task description")
                    .required(true))
                .arg(Arg::new("priority")
                    .help("The priority of the task")
                    .required(true)),
        )
        .subcommand(
            Command::new("list")
                .about("List all tasks")
                .arg(Arg::new("filter")
                    .long("filter")
                    .help("Filter tasks by priority or completion status")
                    .value_name("FILTER")),
        )
        .get_matches();

    // Handling the "add" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("add") {
        let name = sub_matches.get_one::<String>("name").unwrap();
        let description = sub_matches.get_one::<String>("description").unwrap();
        let priority = sub_matches.get_one::<String>("priority").unwrap();

        let new_task = Task {
            name: name.to_string(),
            description: description.to_string(),
            priority: priority.to_string(),
            completed: false,
        };

        tasks.insert(name.clone(), new_task);  // Add the task to the in-memory storage
        save_tasks_to_file(&tasks).expect("Failed to save tasks to file");  // Save tasks to file
        println!("Task added: {}", name);
    }

    // Handling the "list" subcommand
    if let Some(sub_matches) = matches.subcommand_matches("list") {
        if tasks.is_empty() {
            println!("No tasks available.");
            return;
        }

        let filter = sub_matches.get_one::<String>("filter");
        for (name, task) in &tasks {
            if let Some(filter) = filter {
                if filter.eq_ignore_ascii_case("completed") && !task.completed {
                    continue;
                } else if filter.eq_ignore_ascii_case("incomplete") && task.completed {
                    continue;
                } else if filter.eq_ignore_ascii_case(&task.priority) {
                    // Match priority
                } else {
                    continue;
                }
            }
            println!(
                "Task: {}\nDescription: {}\nPriority: {}\nCompleted: {}\n",
                name, task.description, task.priority, task.completed
            );
        }
    }
}
