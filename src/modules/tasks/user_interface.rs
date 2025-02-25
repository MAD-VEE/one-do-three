// src/modules/tasks/user_interface.rs
use clap::ArgMatches;
use itertools::Itertools;
use std::collections::HashMap;
use std::io::Write;

use super::{load_tasks_from_file, save_tasks_to_file, storage::is_passphrase_correct, Task};
use crate::auth::store::User;
use crate::auth::tokens::SecurePasswordCache;
use crate::modules::utils::io::read_line;
use crate::modules::utils::logging::log_data_operation;

/// Function to handle interactive task creation
pub fn handle_interactive_task_creation() -> Task {
    // Get task name
    println!("\nEnter task name:");
    let name = read_line().unwrap();

    // Get description (optional)
    println!("\nEnter task description (press Enter to skip):");
    let description = read_line().unwrap();
    let description = if description.trim().is_empty() {
        "No description provided".to_string()
    } else {
        description
    };

    // Get priority with validation
    println!("\nEnter task priority (High/Medium/Low, press Enter for Medium):");
    let priority = loop {
        let input = read_line().unwrap();
        let priority = if input.trim().is_empty() {
            "Medium".to_string()
        } else {
            input.to_string()
        };

        match priority.to_lowercase().as_str() {
            "high" | "medium" | "low" => break priority.to_string(),
            _ => println!("Invalid priority. Please enter High, Medium, or Low:"),
        }
    };

    // Progress bar style selection
    println!("\nSelect progress bar style:");
    println!("1. Simple  [=====>    ]                   (or type 'simple')");
    println!("2. Block   [██████    ]                   (or type 'block')");
    println!("3. Numeric [60%]                          (or type 'numeric')");
    println!("4. Detailed [======>   ] 6/10             (or type 'detailed')");
    println!("Enter style number or command (default: Simple):");
    let style = loop {
        let input = read_line().unwrap();
        match input.trim() {
            "" | "simple" | "1" => break "simple".to_string(),
            "block" | "2" => break "block".to_string(),
            "numeric" | "3" => break "numeric".to_string(),
            "detailed" | "4" => break "detailed".to_string(),
            _ => println!("Invalid choice. Please enter 1-4:"),
        }
    };

    // Get initial progress (optional, defaults to 0)
    println!("\nEnter initial progress percentage (0-100, press Enter for 0%):");
    let progress = {
        let input = read_line().unwrap();
        if input.trim().is_empty() {
            0 // Default progress
        } else {
            match input.trim().parse::<u8>() {
                Ok(p) if p <= 100 => p,
                _ => {
                    println!("Invalid progress value. Setting to 0%");
                    0
                }
            }
        }
    };

    // Return the new task with all fields properly initialized
    Task {
        name,
        description,
        priority,
        completed: false,
        progress_percent: progress,
        progress_bar_style: style,
    }
}

/// Function to handle interactive task editing
pub fn handle_interactive_task_edit(existing_task: &Task) -> Task {
    // Show current task details
    println!("\nCurrent task details:");
    println!("Name: {}", existing_task.name);
    println!("Description: {}", existing_task.description);
    println!("Priority: {}", existing_task.priority);
    println!(
        "Status: {}",
        if existing_task.completed {
            "Completed"
        } else {
            "Pending"
        }
    );
    println!("Progress: {}%", existing_task.progress_percent);
    println!("Progress Bar: {}", existing_task.generate_progress_bar());

    // Get new description or keep current
    println!("\nEnter new description (press Enter to keep current):");
    let description = read_line().unwrap();
    let description = if description.trim().is_empty() {
        existing_task.description.clone()
    } else {
        description
    };

    // Get new priority or keep current
    println!("\nEnter new priority (High/Medium/Low, press Enter to keep current):");
    let priority = loop {
        let input = read_line().unwrap();
        if input.trim().is_empty() {
            break existing_task.priority.clone();
        }

        match input.to_lowercase().as_str() {
            "high" | "medium" | "low" => break input,
            _ => println!("Invalid priority. Please enter High, Medium, or Low:"),
        }
    };

    // Get new completion status and handle progress accordingly
    println!("\nMark as completed? (yes/no/Enter to keep current):");
    let (completed, progress_percent) = loop {
        let input = read_line().unwrap();
        if input.trim().is_empty() {
            // If keeping current completion status, ask for progress only if task is not completed
            if !existing_task.completed {
                // Ask for progress update without yes/no confirmation
                println!("\nEnter new progress percentage (0-100, press Enter to keep current):");
                let progress_input = read_line().unwrap();
                let new_progress = if progress_input.trim().is_empty() {
                    existing_task.progress_percent
                } else {
                    match progress_input.trim().parse::<u8>() {
                        Ok(p) if p <= 100 => p,
                        _ => {
                            println!("Invalid progress value. Keeping current progress.");
                            existing_task.progress_percent
                        }
                    }
                };
                break (existing_task.completed, new_progress);
            } else {
                // If task is already completed, keep progress at 100%
                break (existing_task.completed, existing_task.progress_percent);
            }
        }

        match input.to_lowercase().as_str() {
            "yes" | "y" => break (true, 100), // Automatically set progress to 100% when completed
            "no" | "n" => {
                // If marked as not completed, ask for progress
                println!("\nEnter new progress percentage (0-100, press Enter to keep current):");
                let progress_input = read_line().unwrap();
                let new_progress = if progress_input.trim().is_empty() {
                    existing_task.progress_percent
                } else {
                    match progress_input.trim().parse::<u8>() {
                        Ok(p) if p <= 100 => p,
                        _ => {
                            println!("Invalid progress value. Keeping current progress.");
                            existing_task.progress_percent
                        }
                    }
                };
                break (false, new_progress);
            }
            _ => println!("Invalid input. Please enter yes or no:"),
        }
    };

    // Create and return updated task
    // Keep the existing progress bar style as it can be changed through the progress command
    Task {
        name: existing_task.name.clone(),
        description,
        priority,
        completed,
        progress_percent,
        progress_bar_style: existing_task.progress_bar_style.clone(),
    }
}

/// Function to handle interactive progress update
pub fn handle_interactive_progress_update(task: &mut Task) -> Result<(), String> {
    println!("\nCurrent progress: {}%", task.progress_percent);
    println!("Current visualization: {}", task.generate_progress_bar());

    // Show progress bar style options
    println!("\nAvailable progress bar styles:");
    println!("1. Simple  [=====>    ]");
    println!("2. Block   [██████    ]");
    println!("3. Numeric [60%]");
    println!("4. Detailed [======>   ] 6/10");

    println!("\nEnter style number (or press Enter to keep current):");
    let style_input = read_line().map_err(|e| e.to_string())?;

    if !style_input.trim().is_empty() {
        task.progress_bar_style = match style_input.trim() {
            "1" => "simple".to_string(),
            "2" => "block".to_string(),
            "3" => "numeric".to_string(),
            "4" => "detailed".to_string(),
            _ => {
                println!("Invalid style. Keeping current style.");
                task.progress_bar_style.clone()
            }
        };
    }

    println!("\nEnter new progress percentage (0-100):");
    let progress_input = read_line().map_err(|e| e.to_string())?;

    match progress_input.trim().parse::<u8>() {
        Ok(progress) => {
            task.update_progress(progress)?;
            println!("\nProgress updated: {}", task.generate_progress_bar());
            Ok(())
        }
        Err(_) => {
            Err("Invalid progress value. Please enter a number between 0 and 100.".to_string())
        }
    }
}

/// Handle the 'add' command
pub fn handle_add_command(
    tasks: &mut HashMap<String, Task>,
    user: &User,
    username: &str,
    password: &str,
    cache: &SecurePasswordCache,
) {
    // Check for session timeout
    if let Ok(None) = cache.get_cached_password() {
        println!("Session expired due to inactivity. Please log in again.");
        return;
    }

    // First check passphrase
    if !is_passphrase_correct(user, password) {
        println!("Incorrect passphrase. Task not added.");
        return;
    }

    let new_task = handle_interactive_task_creation();

    // Check if task with the same name already exists
    if tasks.contains_key(&new_task.name) {
        println!("A task with this name already exists. Choose a different name or delete the existing task first.");
        return;
    }

    // Log the add operation
    log_data_operation("add_task", username, &new_task.name, true, None);

    tasks.insert(new_task.name.clone(), new_task);

    cache
        .cache_password(username, password)
        .unwrap_or_else(|e| {
            println!("Warning: Failed to update password cache: {}", e);
        });

    // Add error handling to save operation
    match save_tasks_to_file(tasks, user, password) {
        Ok(_) => println!("Task added successfully!"),
        Err(e) => println!("Error saving task: {}", e),
    }
}

/// Handle the 'list' command
pub fn handle_list_command(
    sub_matches: &ArgMatches,
    _tasks: &HashMap<String, Task>,
    user: &User,
    username: &str,
    password: &str,
    cache: &SecurePasswordCache,
) {
    // Check for session timeout
    if let Ok(None) = cache.get_cached_password() {
        println!("Session expired due to inactivity. Please log in again.");
        return;
    }

    // First check passphrase
    if !is_passphrase_correct(user, password) {
        println!("Error: Incorrect passphrase. Unable to list tasks.");
        return;
    }

    // Add error handling to task loading
    match load_tasks_from_file(user, password) {
        Ok(tasks) => {
            cache
                .cache_password(username, password)
                .unwrap_or_else(|e| {
                    println!("Warning: Failed to update password cache: {}", e);
                });

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
                    "Task: {}\nDescription: {}\nPriority: {}\nProgress: {}\nCompleted: {}\n",
                    name,
                    task.description,
                    task.priority,
                    task.generate_progress_bar(),
                    task.completed
                );
            }
        }
        Err(e) => println!("Error loading tasks: {}", e),
    }
}

/// Handle the 'edit' command
pub fn handle_edit_command(
    tasks: &mut HashMap<String, Task>,
    user: &User,
    username: &str,
    password: &str,
    cache: &SecurePasswordCache,
) {
    // Check for session timeout
    if let Ok(None) = cache.get_cached_password() {
        println!("Session expired due to inactivity. Please log in again.");
        return;
    }

    // First check passphrase
    if !is_passphrase_correct(user, password) {
        println!("Error: Incorrect passphrase. Unable to edit task.");
        return;
    }

    // Show available tasks
    println!("\nAvailable tasks:");
    for (name, _) in tasks.iter() {
        println!("  {}", name);
    }

    println!("\nEnter the name of the task to edit:");
    let name = read_line().unwrap();

    if let Some(task) = tasks.get(&name) {
        let updated_task = handle_interactive_task_edit(task);
        tasks.insert(name.clone(), updated_task);

        cache
            .cache_password(username, password)
            .unwrap_or_else(|e| {
                println!("Warning: Failed to update password cache: {}", e);
            });

        match save_tasks_to_file(tasks, user, password) {
            Ok(_) => println!("Task updated successfully!"),
            Err(e) => println!("Error saving task update: {}", e),
        }
    } else {
        println!("Task not found: {}", name);
    }
}

/// Handle the 'delete' command
pub fn handle_delete_command(
    tasks: &mut HashMap<String, Task>,
    user: &User,
    username: &str,
    password: &str,
    cache: &SecurePasswordCache,
) {
    // Check for session timeout
    if let Ok(None) = cache.get_cached_password() {
        println!("Session expired due to inactivity. Please log in again.");
        return;
    }

    // First check passphrase
    if !is_passphrase_correct(user, password) {
        println!("Error: Incorrect passphrase. Unable to delete task.");
        return;
    }

    // Show available tasks
    println!("\nAvailable tasks:");
    for (name, _) in tasks.iter() {
        println!("  {}", name);
    }

    println!("\nEnter the name of the task to delete:");
    let name = read_line().unwrap();

    if !tasks.contains_key(&name) {
        println!(
            "Task '{}' not found. Use 'list' command to see available tasks.",
            name
        );
        return;
    }

    // Asking for deletion confirmation
    loop {
        print!("Are you sure you want to delete task '{}'? (y/n): ", name);
        std::io::stdout().flush().unwrap(); // Ensure the prompt is displayed before input

        let mut confirmation = String::new();
        std::io::stdin().read_line(&mut confirmation).unwrap();
        let confirmation = confirmation.trim().to_lowercase();

        if confirmation.is_empty() || confirmation == "y" {
            println!("Task '{}' deleted.", name);
            break;
        } else if confirmation == "n" {
            println!("Task deletion cancelled.");
            return;
        } else {
            println!("Invalid input. Please enter 'y' for yes or 'n' for no.");
        }
    }

    tasks.remove(&name);

    cache
        .cache_password(username, password)
        .unwrap_or_else(|e| {
            println!("Warning: Failed to update password cache: {}", e);
        });

    // Add error handling to save operation
    match save_tasks_to_file(tasks, user, password) {
        Ok(_) => println!("Task deleted: {}", name),
        Err(e) => println!("Error saving after deletion: {}", e),
    }
}

/// Handle the 'progress' command
pub fn handle_progress_command(
    sub_matches: &ArgMatches,
    tasks: &mut HashMap<String, Task>,
    user: &User,
    username: &str,
    password: &str,
    cache: &SecurePasswordCache,
) {
    // Check for session timeout
    if let Ok(None) = cache.get_cached_password() {
        println!("Session expired due to inactivity. Please log in again.");
        return;
    }

    // First check passphrase
    if !is_passphrase_correct(user, password) {
        println!("Error: Incorrect passphrase. Unable to update progress.");
        return;
    }

    let task_name = sub_matches.get_one::<String>("task-name").unwrap();

    if let Some(task) = tasks.get_mut(task_name) {
        match handle_interactive_progress_update(task) {
            Ok(_) => {
                // Update cache and save changes
                cache
                    .cache_password(username, password)
                    .unwrap_or_else(|e| {
                        println!("Warning: Failed to update password cache: {}", e);
                    });

                match save_tasks_to_file(tasks, user, password) {
                    Ok(_) => println!("Progress updated successfully!"),
                    Err(e) => println!("Error saving progress update: {}", e),
                }
            }
            Err(e) => println!("Failed to update progress: {}", e),
        }
    } else {
        println!("Task not found: {}", task_name);
    }
}
