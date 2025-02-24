use clap::{Arg, Command};
use std::process;

// Import from our lib.rs re-exports
use one_do_three::{
    admin::{
        enhanced_initialize_admin_credentials, enhanced_verify_admin, generate_admin_setup_token,
        handle_admin_password_change,
    },
    auth::{
        store::{load_user_store, save_user_store, User, UserStore},
        verification::verify_registration_token,
    },
    email::{send_registration_verification, SecureEmailManager},
    tasks::{handle_interactive_progress_update, load_tasks_from_file, save_tasks_to_file, Task},
    utils::{
        io::{read_line},
        logging::{initialize_logging, log_auth_event, log_data_operation},
        time::format_timestamp,
    },
};

// Main entry point
fn main() {
    // Initialize logging system
    if let Err(e) = initialize_logging() {
        eprintln!("Failed to initialize logging: {}", e);
        process::exit(1);
    }

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    if handle_command_line_args(&args) {
        return;
    }

    // Main application loop
    run_application();
}

// Handle command line arguments for admin and email setup
fn handle_command_line_args(args: &[String]) -> bool {
    if args.len() > 1 {
        match args[1].as_str() {
            "--admin-setup" => {
                if args.len() < 3 {
                    println!("Usage: --admin-setup <setup-token>");
                    return true;
                }
                let setup_token = &args[2];
                match enhanced_initialize_admin_credentials(setup_token) {
                    Ok(_) => println!("Admin credentials initialized successfully!"),
                    Err(e) => println!("Failed to initialize admin credentials: {}", e),
                }
                return true;
            }
            "--generate-admin-token" => {
                match generate_admin_setup_token() {
                    Ok(token) => {
                        println!("\nGenerated admin setup token (valid for 1 hour):");
                        println!("{}", token);
                    }
                    Err(e) => println!("Failed to generate setup token: {}", e),
                }
                return true;
            }
            "--email-setup" => {
                match setup_email_credentials() {
                    Ok(_) => println!("Email configuration completed successfully!"),
                    Err(e) => println!("Failed to configure email: {}", e),
                }
                return true;
            }
            "--change-admin-password" => {
                match handle_admin_password_change() {
                    Ok(_) => println!("Admin password changed successfully!"),
                    Err(e) => println!("Failed to change admin password: {}", e),
                }
                return true;
            }
            _ => {}
        }
    }
    false
}

// Main application loop
fn run_application() {
}

// Placeholder for main_auth_flow function
fn main_auth_flow(store: &mut UserStore) -> Option<(String, String)> {
    // Implement the authentication flow here
    Some(("username".to_string(), "password".to_string()))
}

fn run_application() {
    // Load the user store
    let mut store = match load_user_store() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("Failed to load user store: {}", e);
            process::exit(1);
        }
    };

    // Main program loop
    'main: loop {
        // Show initial options and authenticate user
        let (username, password) = match main_auth_flow(&mut store).as_ref().map(|(u, p)| (u.clone(), p.clone())) {
            Some(credentials) => credentials,
            None => {
                println!("Authentication failed");
                process::exit(1);
            }
        };

        // Command execution loop for authenticated user
        handle_authenticated_session(&mut store, &username, &password);
    }
}

// Function to set up email credentials securely
pub fn setup_email_credentials() -> Result<(), String> {
    // Get admin credentials verification first
    let admin_manager = one_do_three::admin::SecureAdminManager::new();

    // Check if admin credentials are initialized
    if !admin_manager.is_initialized() {
        return Err(
            "Admin credentials not initialized. Please set up admin password first.".to_string(),
        );
    }

    println!("\n=== Admin Authentication Required ===");
    println!("Please enter admin password to modify email settings:");

    // Limited admin password attempts
    const MAX_ATTEMPTS: u32 = 3;
    let mut attempts = 0;

    while attempts < MAX_ATTEMPTS {
        let admin_password =
            read_password().map_err(|e| format!("Failed to read password: {}", e))?;

        if admin_manager.verify_admin(&admin_password)? {
            break;
        }

        attempts += 1;
        if attempts < MAX_ATTEMPTS {
            println!(
                "Invalid password. {} attempts remaining.",
                MAX_ATTEMPTS - attempts
            );
        } else {
            return Err("Too many invalid attempts. Please try again later.".to_string());
        }
    }

    // Get SMTP configuration interactively
    let email_manager = SecureEmailManager::new();
    get_smtp_configuration(&email_manager)?;

    println!("\nEmail configuration saved securely.");
    println!("Important: Please run 'test-email' to verify your configuration.");
    Ok(())
}

// Get SMTP configuration from user
fn get_smtp_configuration(email_manager: &SecureEmailManager) -> Result<(), String> {
    println!("\n=== Email Configuration Setup ===");

    // Get and validate SMTP server
    let host = loop {
        println!("Enter SMTP server address (e.g., smtp.gmail.com):");
        let input = read_line().map_err(|e| format!("Failed to read input: {}", e))?;
        let input = input.trim();

        if input.is_empty() {
            println!("SMTP server cannot be empty. Please try again.");
            continue;
        }

        if !input.contains('.') || input.contains(' ') {
            println!("Invalid SMTP server format. Please enter a valid domain.");
            continue;
        }

        break input.to_string();
    };

    // Get and validate SMTP port
    let port = loop {
        println!("Enter SMTP port (default: 587):");
        let input = read_line().map_err(|e| format!("Failed to read input: {}", e))?;
        let input = input.trim();

        if input.is_empty() {
            break 587;
        }

        match input.parse::<u16>() {
            Ok(p) if p > 0 => break p,
            _ => {
                println!("Invalid port number. Please enter a number between 1 and 65535.");
                continue;
            }
        }
    };

    // Get and validate email address
    let username = loop {
        println!("Enter email address:");
        let input = read_line().map_err(|e| format!("Failed to read input: {}", e))?;
        let input = input.trim();

        if !one_do_three::utils::io::is_valid_email(input) {
            println!("Invalid email format. Please enter a valid email address.");
            continue;
        }

        break input.to_string();
    };

    // Get and confirm password
    let password = loop {
        println!("Enter email password or app-specific password:");
        let pass = read_password().map_err(|e| format!("Failed to read password: {}", e))?;

        if pass.trim().is_empty() {
            println!("Password cannot be empty. Please try again.");
            continue;
        }

        if host.contains("gmail.com") && pass.len() != 16 {
            println!("Warning: Gmail app passwords are typically 16 characters long.");
            println!("Are you sure you want to use this password? (y/n)");
            let mut confirm = String::new();
            std::io::stdin()
                .read_line(&mut confirm)
                .map_err(|e| format!("Failed to read input: {}", e))?;
            if confirm.trim().to_lowercase() != "y" {
                continue;
            }
        }

        break pass;
    };

    // Store credentials securely
    email_manager.store_credentials(&username, &password, &host, port)?;

    if host.contains("gmail.com") {
        println!("\nGmail-specific notes:");
        println!("1. Make sure 2-Step Verification is enabled in your Google Account");
        println!(
            "2. The password should be an App Password generated from Google Account settings"
        );
        println!("3. If the test fails, please verify your App Password and try again");
    }

    Ok(())
}

// Authentication session management
fn handle_authenticated_session(store: &mut UserStore, username: &str, password: &str) {
    let cache = one_do_three::auth::SecurePasswordCache::new();

    // Get user's task file path before entering command loop
    let _tasks_file = {
        let user = store
            .users
            .get(username)
            .expect("User not found after authentication");
        user.tasks_file.clone()
    };

    // After successful authentication
    if let Some(user) = store.users.get(username) {
        // For cached credentials, the welcome back message is already shown in authenticate_user
        // For fresh logins, show the welcome message
        match cache.get_cached_password() {
            Ok(Some(_)) => {} // Do nothing, "Welcome back" was already shown
            _ => {
                println!(
                    "\nWelcome, {}! Type 'help' to see available commands.",
                    user.username
                );
            }
        }
    }

    // Command execution loop - stays here until logout or timeout
    loop {
        // Check for session timeout
        if let Ok(Some((cached_username, _))) = cache.get_cached_password() {
            if cached_username == username {
                // If session has expired, force logout and restart authentication
                if let Ok(None) = cache.get_cached_password() {
                    println!(
                        "\nSession expired due to 15 minutes of inactivity. Please log in again."
                    );
                    return;
                }
            } else {
                // Username mismatch in cache
                println!("\nSession error: User mismatch. Please log in again.");
                return;
            }
        } else {
            // No cached credentials
            println!("\nSession expired due to 15 minutes of inactivity. Please log in again.");
            return;
        }

        // Getting fresh user reference and load tasks at the start of each command loop
        let user = match store.users.get(username) {
            Some(user) => user,
            None => {
                println!("User not found. Please log in again.");
                return;
            }
        };

        // Loading tasks here, so they're fresh for each command
        let mut tasks = match load_tasks_from_file(user, password) {
            Ok(tasks) => tasks,
            Err(e) => {
                println!("Error loading tasks: {}", e);
                continue;
            }
        };

        println!("\nEnter command (or 'help' for available commands):");

        let input = read_line().unwrap();
        let args = input.split_whitespace().collect::<Vec<_>>();
        if args.is_empty() {
            continue;
        }

        // First, handle the built-in commands
        match args[0].to_lowercase().as_str() {
            "help" => {
                if args.len() > 1 {
                    show_command_help(&args[1].to_lowercase());
                } else {
                    show_help_information();
                }
                continue;
            }
            cmd if cmd.ends_with("--help") || cmd.ends_with("-h") => {
                let base_cmd = cmd.replace("--help", "").replace("-h", "");
                show_command_help(&base_cmd);
                continue;
            }
            _ => {
                // Set up CLI command structure using clap
                let matches = Command::new("task")
                    .about("Task management commands")
                    .subcommand(Command::new("add").about("Add a new task"))
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
                    .subcommand(Command::new("edit").about("Edit an existing task"))
                    .subcommand(Command::new("delete").about("Delete an existing task"))
                    .subcommand(
                        Command::new("progress").about("Update task progress").arg(
                            Arg::new("task-name")
                                .help("Name of the task to update progress")
                                .required(true),
                        ),
                    )
                    .subcommand(Command::new("logout").about("Logout and clear cached password"))
                    .ignore_errors(true)
                    .no_binary_name(true)
                    .get_matches_from(args);

                // Handle different subcommands
                handle_command(matches, store, username, password, &mut tasks, user, &cache)?;
            }
        }
    }
}

// Command handling function
fn handle_command(
    matches: clap::ArgMatches,
    store: &mut UserStore,
    username: &str,
    password: &str,
    tasks: &mut HashMap<String, Task>,
    user: &User,
    cache: &one_do_three::auth::SecurePasswordCache,
) -> Result<(), Box<dyn std::error::Error>> {
    match matches.subcommand() {
        Some(("logout", _)) => {
            if let Err(e) = cache.clear_cache() {
                println!("Warning: Failed to clear password cache: {}", e);
            }
            println!("Successfully logged out.");
            return Ok(());
        }
        Some(("add", _)) => {
            // Check for session timeout
            if let Ok(None) = cache.get_cached_password() {
                println!("Session expired due to inactivity. Please log in again.");
                return Ok(());
            }

            // First check passphrase
            if !one_do_three::tasks::storage::is_passphrase_correct(user, password) {
                println!("Incorrect passphrase. Task not added.");
                return Ok(());
            }

            let new_task = one_do_three::tasks::handle_interactive_task_creation();

            // Check if task with the same name already exists
            if tasks.contains_key(&new_task.name) {
                println!("A task with this name already exists. Choose a different name or delete the existing task first.");
                return Ok(());
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
        Some(("list", sub_matches)) => {
            // Check for session timeout
            if let Ok(None) = cache.get_cached_password() {
                println!("Session expired due to inactivity. Please log in again.");
                return Ok(());
            }

            // First check passphrase
            if !one_do_three::tasks::storage::is_passphrase_correct(user, password) {
                println!("Error: Incorrect passphrase. Unable to list tasks.");
                return Ok(());
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
                        return Ok(());
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
        Some(("edit", _)) => {
            // Check for session timeout
            if let Ok(None) = cache.get_cached_password() {
                println!("Session expired due to inactivity. Please log in again.");
                return Ok(());
            }

            // First check passphrase
            if !one_do_three::tasks::storage::is_passphrase_correct(user, password) {
                println!("Error: Incorrect passphrase. Unable to edit task.");
                return Ok(());
            }

            // Show available tasks
            println!("\nAvailable tasks:");
            for (name, _) in tasks {
                println!("  {}", name);
            }

            println!("\nEnter the name of the task to edit:");
            let name = read_line().unwrap();

            if let Some(task) = tasks.get(&name) {
                let updated_task = one_do_three::tasks::handle_interactive_task_edit(task);
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
        Some(("delete", _)) => {
            // Check for session timeout
            if let Ok(None) = cache.get_cached_password() {
                println!("Session expired due to inactivity. Please log in again.");
                return Ok(());
            }

            // First check passphrase
            if !one_do_three::tasks::storage::is_passphrase_correct(user, password) {
                println!("Error: Incorrect passphrase. Unable to delete task.");
                return Ok(());
            }

            // Show available tasks and get task name
            println!("\nAvailable tasks:");
            for (name, _) in tasks {
                println!("  {}", name);
            }

            println!("\nEnter the name of the task to delete:");
            let name = read_line().unwrap();

            if !tasks.contains_key(&name) {
                println!(
                    "Task '{}' not found. Use 'list' command to see available tasks.",
                    name
                );
                return Ok(());
            }

            // Ask for confirmation
            println!("Are you sure you want to delete task '{}'? (y/n): ", name);
            let confirmation = read_line().unwrap().trim().to_lowercase();

            if confirmation == "y" || confirmation == "yes" {
                tasks.remove(&name);

                cache
                    .cache_password(username, password)
                    .unwrap_or_else(|e| {
                        println!("Warning: Failed to update password cache: {}", e);
                    });

                match save_tasks_to_file(tasks, user, password) {
                    Ok(_) => println!("Task deleted: {}", name),
                    Err(e) => println!("Error saving after deletion: {}", e),
                }
            } else {
                println!("Task deletion cancelled.");
            }
        }
        Some(("progress", sub_matches)) => {
            // Check for session timeout
            if let Ok(None) = cache.get_cached_password() {
                println!("Session expired due to inactivity. Please log in again.");
                return Ok(());
            }

            // First check passphrase
            if !one_do_three::tasks::storage::is_passphrase_correct(user, password) {
                println!("Error: Incorrect passphrase. Unable to update progress.");
                return Ok(());
            }

            let task_name = sub_matches.get_one::<String>("task-name").unwrap();

            if let Some(task) = tasks.get_mut(task_name) {
                match handle_interactive_progress_update(task) {
                    Ok(_) => {
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
        _ => {
            println!("Unknown command. Use 'help' for usage information.");
        }
    }
    Ok(())
}

// Help information display functions
fn show_help_information() {
    println!("\n=== Task Manager Help ===");

    // Main Commands Section
    println!("\nMain Commands:");
    println!("  add                 - Add a new task");
    println!("  list                - List all tasks");
    println!("  edit                - Edit an existing task");
    println!("  delete              - Delete a task");
    println!("  progress TASKNAME   - Update progress for a specific task");
    println!("  profile             - View or update profile information");
    println!("  change-password     - Change your password");
    println!("  delete-account      - Permanently delete your account");
    println!("  logout              - Log out of current session");

    // List Command Options
    println!("\nList Command Options:");
    println!("  list --filter high       - Show only high priority tasks");
    println!("  list --filter completed  - Show only completed tasks");
    println!("  list --sort priority     - Sort tasks by priority");
    println!("  list --sort name         - Sort tasks by name");

    // Task Management Notes
    println!("\nTask Management Notes:");
    println!("  - Tasks can have high, medium, or low priority");
    println!("  - Each task has a name, description, priority, and completion status");
    println!("  - Task names must be unique");
    println!("  - All changes are automatically saved");

    // Security Notes
    println!("\nSecurity Notes:");
    println!("  - Sessions timeout after 15 minutes of inactivity");
    println!("  - Profile changes require password confirmation");
    println!("  - Password must contain uppercase, lowercase, numbers, and special characters");

    println!("\nType any command with --help for more specific information");
}

fn show_command_help(command: &str) {
    match command {
        "profile" => {
            println!("\n=== Profile Command Help ===");
            println!("\nUsage:");
            println!("  profile                    - View your profile information");
            println!("  profile --show             - Display detailed profile information");
            println!("  profile --email NEW_EMAIL  - Update your email address");
            println!("\nOptions:");
            println!("  --show    Show profile information");
            println!("  --email   Update email address (requires password confirmation)");
            println!("\nExamples:");
            println!("  profile");
            println!("  profile --show");
            println!("  profile --email user@example.com");
        }
        "add" => {
            println!("\n=== Add Command Help ===");
            println!("\nUsage:");
            println!("  add  - Start interactive task creation");
            println!("\nYou will be prompted for:");
            println!("  - Task name (must be unique)");
            println!("  - Description (optional)");
            println!("  - Priority (High/Medium/Low)");
        }
        "progress" => {
            println!("\n=== Progress Command Help ===");
            println!("\nUsage:");
            println!("  progress TASKNAME  - Update progress for specified task");
            println!("\nFeatures:");
            println!("  - Set progress percentage (0-100%)");
            println!("  - Choose from multiple progress bar styles:");
            println!("    1. Simple  [=====>    ]");
            println!("    2. Block   [██████    ]");
            println!("    3. Numeric [60%]");
            println!("    4. Detailed [======>   ] 6/10");
            println!("\nExample:");
            println!("  progress \"My Task\"");
        }
        "delete-account" => {
            println!("\n=== Delete Account Command Help ===");
            println!("\nUsage:");
            println!("  delete-account  - Start account deletion process");
            println!("\nThis command will:");
            println!("  1. Ask for confirmation by typing 'DELETE'");
            println!("  2. Require password verification");
            println!("  3. Require final confirmation by typing 'YES'");
            println!("\nWarnings:");
            println!("  - This action permanently deletes your account");
            println!("  - All tasks and user data will be erased");
            println!("  - This action cannot be undone");
            println!("  - You will be logged out immediately after deletion");
        }
        _ => {
            println!("\nNo detailed help available for '{}' command.", command);
            println!("Use 'help' to see general usage information.");
        }
    }
}
