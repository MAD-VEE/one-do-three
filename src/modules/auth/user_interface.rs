// src/modules/auth/user_interface.rs
use rand::prelude::*;
use std::io::{self};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH}; // This will import SampleRange and other useful traits

use super::password::{read_password, validate_password};
use super::store::{save_user_store, UserStore};
use super::tokens::SecurePasswordCache;
use super::verification::{verify_registration_token, VerificationResult};
use crate::modules::utils::io::read_line;
use crate::modules::utils::logging::{log_auth_event, log_data_operation};
use crate::modules::utils::time::format_timestamp;

/// Main result type for overall authentication flow
#[derive(Debug)]
pub enum MainAuthResult {
    Success(String, String), // Successful login with (username, password)
    Back,                    // Return to main menu
    Exit,                    // Exit the program
    Error(String),           // Error with message
}

/// Authentication result type for better flow control
#[derive(Debug)]
pub enum AuthenticationResult {
    Success(String, String),   // (username, password)
    InvalidCredentials,        // Wrong username/password
    NeedsVerification(String), // Username needs verification
    CacheCleared,              // Password cache was cleared
}

/// Structure to track account deletion status
#[derive(Debug)]
pub enum DeletionStatus {
    Success,
    Failed(String),
    Cancelled,
}

/// Structure to track cleanup status
#[derive(Debug)]
pub struct CleanupStatus {
    pub task_file_removed: bool,
    pub cache_cleared: bool,
    pub store_saved: bool,
}

/// Function to show initial options when starting the program
pub fn show_initial_options() {
    println!("\n=== Welcome to One-Do-Three ===");
    println!("1. Login                  (or type 'login')");
    println!("2. Register new account   (or type 'register')");
    println!("3. Forgot password        (or type 'forgot')");
    println!("4. Exit                   (or type 'exit')");
    println!("\nEnter your choice         (1-4 or command):");
}

// Main authentication flow to include initial options
// This function handles the main authentication loop and all possible authentication paths
// Parameters:
// - store: Mutable reference to UserStore for managing user data
// Returns: Option<(String, String)> containing (username, password) if authentication succeeds
pub fn main_auth_flow(store: &mut UserStore) -> Option<(String, String)> {
    loop {
        show_initial_options();

        // Read user input with error handling
        let choice = match read_line() {
            Ok(input) => input.trim().to_string(),
            Err(e) => {
                println!("Error reading input: {}", e);
                continue;
            }
        };

        // Handle the user's choice
        let result = match choice.as_str() {
            "1" | "login" => {
                // Handle login process
                match authenticate_user(store) {
                    Some((username, password)) => MainAuthResult::Success(username, password),
                    None => MainAuthResult::Back,
                }
            }
            "2" | "register" => {
                // Handle registration process
                match handle_interactive_registration(store) {
                    Ok(_) => {
                        // Double-check that we're logged out and clean up any lingering credentials
                        let cache = SecurePasswordCache::new();
                        if let Ok(Some(_)) = cache.get_cached_password() {
                            if let Err(e) = cache.clear_cache() {
                                println!("Warning: Failed to clear lingering credentials: {}", e);
                            }
                        }
                        MainAuthResult::Back // Return to main menu after successful registration
                    }
                    Err(e) => MainAuthResult::Error(format!("Registration failed: {}", e)),
                }
            }
            "3" | "forgot" => {
                // Handle password reset process
                match handle_forgot_password(store) {
                    AuthFlowResult::Back => {
                        println!("Returning to main menu...");
                        continue; // Return to main menu
                    }
                    AuthFlowResult::Success(msg) => {
                        println!("\n{}", msg);
                        continue;
                    }
                    AuthFlowResult::Error(e) => {
                        println!("\nError: {}", e);
                        continue;
                    }
                }
            }
            "4" | "exit" | "quit" => {
                println!("Goodbye!");
                MainAuthResult::Exit
            }
            _ => {
                MainAuthResult::Error(
                    "Invalid choice. Please enter a number (1-4) or command (login/register/forgot/exit).".to_string()
                )
            }
        };

        // Handle the result of the chosen action
        match result {
            MainAuthResult::Success(username, password) => {
                return Some((username, password));
            }
            MainAuthResult::Back => {
                // Just continue the loop to show options again
                continue;
            }
            MainAuthResult::Exit => {
                process::exit(0);
            }
            MainAuthResult::Error(msg) => {
                println!("\n{}", msg);
                // Add a small delay before showing the menu again
                std::thread::sleep(std::time::Duration::from_millis(500));
                continue;
            }
        }
    }
}

/// Handle the authenticated user session
pub fn handle_authenticated_session(store: &mut UserStore, username: &str, password: &str) {
    let cache = SecurePasswordCache::new();

    // Welcome the user
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
        // Check for session timeout or user mismatch
        match cache.get_cached_password() {
            Ok(Some((cached_username, _))) => {
                if cached_username != *username {
                    println!("\nSession error: User mismatch. Please log in again.");
                    return; // Return to login
                }
            }
            _ => {
                println!("\nSession expired due to 15 minutes of inactivity. Please log in again.");
                return; // Return to login
            }
        }

        // Get user and load tasks
        let user = match store.users.get(username) {
            Some(user) => user,
            None => {
                println!("User not found. Please log in again.");
                return; // Return to login
            }
        };

        // Load tasks for this session
        let mut tasks = match crate::tasks::load_tasks_from_file(user, password) {
            Ok(tasks) => tasks,
            Err(e) => {
                println!("Error loading tasks: {}", e);
                continue; // Try again
            }
        };

        // Prompt for command
        println!("\nEnter command (or 'help' for available commands):");

        // Get user input
        let input = match crate::utils::io::read_line() {
            Ok(input) => input,
            Err(_) => continue,
        };

        let args = input.split_whitespace().collect::<Vec<_>>();
        if args.is_empty() {
            continue;
        }

        // Handle special help commands first
        if args[0].to_lowercase() == "help" {
            if args.len() > 1 {
                show_command_help(&args[1].to_lowercase());
            } else {
                show_help_information();
            }
            continue;
        } else if args[0].ends_with("--help") || args[0].ends_with("-h") {
            let base_cmd = args[0].replace("--help", "").replace("-h", "");
            show_command_help(&base_cmd);
            continue;
        }

        // Create clap command matcher
        use clap::{Arg, Command};
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
            .subcommand(
                Command::new("profile")
                    .about("View or update profile information")
                    .arg(
                        Arg::new("email")
                            .long("email")
                            .help("Update email address")
                            .value_name("NEW_EMAIL"),
                    )
                    .arg(
                        Arg::new("show")
                            .long("show")
                            .help("Show profile information")
                            .action(clap::ArgAction::SetTrue),
                    ),
            )
            .subcommand(Command::new("change-password").about("Change your password"))
            .subcommand(Command::new("delete-account").about("Delete your account"))
            .ignore_errors(true)
            .no_binary_name(true)
            .get_matches_from(args);

        // Handle different subcommands
        match matches.subcommand() {
            Some(("logout", _)) => {
                if let Err(e) = cache.clear_cache() {
                    println!("Warning: Failed to clear password cache: {}", e);
                }
                println!("Successfully logged out.");
                return; // Return to login
            }
            Some(("add", _)) => {
                crate::tasks::user_interface::handle_add_command(
                    &mut tasks, user, username, password, &cache,
                );
            }
            Some(("list", sub_matches)) => {
                crate::tasks::user_interface::handle_list_command(
                    sub_matches,
                    &tasks,
                    user,
                    username,
                    password,
                    &cache,
                );
            }
            Some(("edit", _)) => {
                crate::tasks::user_interface::handle_edit_command(
                    &mut tasks, user, username, password, &cache,
                );
            }
            Some(("delete", _)) => {
                crate::tasks::user_interface::handle_delete_command(
                    &mut tasks, user, username, password, &cache,
                );
            }
            Some(("progress", sub_matches)) => {
                crate::tasks::user_interface::handle_progress_command(
                    sub_matches,
                    &mut tasks,
                    user,
                    username,
                    password,
                    &cache,
                );
            }
            Some(("profile", sub_matches)) => {
                handle_profile_command(sub_matches, store, username, password, &cache);
            }
            Some(("change-password", _)) => {
                match crate::auth::password::handle_password_change(store, username, &cache) {
                    Ok(_) => println!("Password changed successfully!"),
                    Err(e) => println!("Failed to change password: {}", e),
                }
            }
            Some(("delete-account", _)) => {
                match handle_account_deletion(store, username, password, &cache) {
                    DeletionStatus::Success => return, // Return to login
                    _ => {}                            // Continue session
                }
            }
            _ => {
                println!("Unknown command. Use 'help' for usage information.");
            }
        }
    }
}

// Function to handle user authentication with proper welcome messages and username case preservation
// Returns Option<(String, String)> where the tuple contains (normalized_username, password)
pub fn authenticate_user(store: &mut UserStore) -> Option<(String, String)> {
    let cache = SecurePasswordCache::new();

    // Try to get cached credentials first
    if let Ok(Some((cached_username, cached_password))) = cache.get_cached_password() {
        // Check if the cached password is "logout"
        if cached_password.trim() == "logout" {
            if let Err(e) = cache.clear_cache() {
                println!("Warning: Failed to clear password cache: {}", e);
            }
            println!("Successfully logged out. Password cache cleared.");
            return None;
        }

        // Convert to normalized username for verification
        let normalized_username = cached_username.trim().to_lowercase();

        // Verify cached credentials and show welcome back message
        if let Some(user) = store.users.get(&normalized_username) {
            // Use the original username format stored in the user struct
            println!("Welcome back, {}!", user.username);

            // Log successful cached login
            log_auth_event(
                "login",
                &user.username,
                true,
                Some("using cached credentials"),
            );

            return Some((normalized_username, cached_password));
        }
    }

    // If no valid cached credentials, prompt for fresh login
    let mut login_attempts = 0;
    loop {
        // Show initial prompt with navigation options
        if login_attempts == 0 {
            println!("\nPlease enter your username");
            println!("(type 'back' to return to menu, 'exit' to quit):");
        }

        // Get username input with proper error handling
        let original_username = match read_line() {
            Ok(input) => input,
            Err(e) => {
                println!("Error reading input: {}", e);
                continue;
            }
        };
        let normalized_username = original_username.trim().to_lowercase();

        // Handle navigation commands for username
        match normalized_username.as_str() {
            "exit" => {
                println!("Exiting program. Goodbye!");
                process::exit(0);
            }
            "back" => {
                println!("Returning to main menu...");
                return None;
            }
            _ => {
                println!("Enter password (type 'back' for menu, 'exit' to quit):");
                let password = match read_password() {
                    Ok(pwd) => pwd,
                    Err(e) => {
                        println!("Error reading password: {}", e);
                        continue;
                    }
                };

                // Handle navigation and special commands for password
                let auth_result = match password.trim() {
                    "exit" => {
                        println!("Exiting program. Goodbye!");
                        process::exit(0);
                    }
                    "back" => {
                        println!("Returning to main menu...");
                        return None;
                    }
                    "logout" => {
                        if let Err(e) = cache.clear_cache() {
                            println!("Warning: Failed to clear password cache: {}", e);
                        }
                        AuthenticationResult::CacheCleared
                    }
                    password => {
                        // Verify credentials
                        if verify_user_credentials(&normalized_username, password, store) {
                            // Cache the successful credentials
                            if let Err(e) = cache.cache_password(&normalized_username, password) {
                                println!("Warning: Failed to cache credentials: {}", e);
                            }

                            // Get user info needed for verification and welcome message
                            if let Some(user) = store.users.get(&normalized_username) {
                                if !user.verification_status.is_verified() {
                                    AuthenticationResult::NeedsVerification(user.username.clone())
                                } else {
                                    AuthenticationResult::Success(
                                        normalized_username.clone(),
                                        password.to_string(),
                                    )
                                }
                            } else {
                                AuthenticationResult::InvalidCredentials
                            }
                        } else {
                            AuthenticationResult::InvalidCredentials
                        }
                    }
                };

                // Handle authentication result
                match auth_result {
                    AuthenticationResult::Success(username, password) => {
                        if let Some(user) = store.users.get(&username) {
                            println!(
                                "\nWelcome, {}! Type 'help' to see available commands.",
                                user.username
                            );
                            return Some((username, password));
                        }
                    }
                    AuthenticationResult::NeedsVerification(username_for_welcome) => {
                        println!("\nPlease check your email for a verification token.");
                        println!("Enter the 6-digit verification token:");

                        // Handle verification process
                        match verify_registration_token(&normalized_username, store) {
                            VerificationResult::Success => {
                                println!("\nVerification successful!");
                                println!(
                                    "\nWelcome, {}! Type 'help' to see available commands.",
                                    username_for_welcome
                                );
                                return Some((normalized_username, password.to_string()));
                            }
                            VerificationResult::Back => {
                                println!("Returning to main menu...");
                                return None;
                            }
                            VerificationResult::Expired => {
                                println!("Verification token has expired. Please register again.");
                                return None;
                            }
                            VerificationResult::Invalid => {
                                println!("Too many invalid attempts. Please try again later.");
                                return None;
                            }
                            VerificationResult::Error(e) => {
                                println!("Verification error: {}", e);
                                println!("Please try again or type 'back' to return to menu");
                                continue;
                            }
                        }
                    }
                    AuthenticationResult::InvalidCredentials => {
                        if login_attempts >= 3 {
                            println!("Multiple failed attempts.");
                            println!("\nPlease enter your username");
                            println!("(type 'back' for menu, 'exit' to quit, or press ENTER to try again):");
                            login_attempts = 0;
                        } else {
                            login_attempts += 1;
                            println!("Authentication failed.");
                            println!("\nPlease enter your username");
                            println!("(type 'back' for menu, 'exit' to quit):");
                        }
                    }
                    AuthenticationResult::CacheCleared => {
                        println!("Successfully logged out. Password cache cleared.");
                        login_attempts = 0;
                        continue;
                    }
                }
            }
        }
    }
}

/// Function to clean up user's task files
pub fn cleanup_user_tasks(_username: &str, store: &UserStore) -> Result<(), io::Error> {
    // Create set of valid task files (files belonging to current users)
    let valid_files: std::collections::HashSet<String> =
        store.users.values().map(|u| u.tasks_file.clone()).collect();

    // Scan tasks directory for cleanup
    let tasks_dir = std::path::Path::new("tasks");
    if !tasks_dir.exists() {
        return Ok(());
    }

    // Read directory entries
    for entry in std::fs::read_dir(tasks_dir)? {
        let entry = entry?;
        let path = entry.path();

        // Check if this is a file and get its filename
        if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
            let full_path = format!("tasks/{}", filename);

            // If file doesn't belong to any current user, remove it
            if !valid_files.contains(&full_path) {
                std::fs::remove_file(&path)?;
                log::info!("Removed orphaned task file: {}", filename);
            }
        }
    }

    Ok(())
}

/// Function to verify user credentials
pub fn verify_user_credentials(username: &str, password: &str, store: &mut UserStore) -> bool {
    let normalized_username = username.trim().to_lowercase();
    let password_hash = hex::encode(
        crate::modules::encryption::keys::derive_key_from_passphrase(password, &store.salt),
    );

    if let Some(user) = store.users.get_mut(&normalized_username) {
        if user.password_hash == password_hash {
            // Reset failed attempts and update last login on successful login
            user.failed_attempts = 0;
            user.last_login = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Save the updated user store
            if let Err(e) = save_user_store(store) {
                println!("Warning: Failed to save user data: {}", e);
            }
            return true;
        }

        // Handle failed attempt
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if user has exceeded maximum attempts (3)
        if user.failed_attempts >= 3 {
            // Calculate time passed since last attempt
            let time_since_last_attempt = current_time - user.last_failed_attempt;

            // If less than 30 seconds have passed, prevent login attempt
            if time_since_last_attempt < 30 {
                println!(
                    "Too many failed attempts. Please wait {} seconds before trying again.",
                    30 - time_since_last_attempt
                );
                return false;
            }

            // Reset failed attempts counter after 30-second timeout
            user.failed_attempts = 0;
        }

        // Increment failed attempts and update last attempt timestamp
        user.failed_attempts += 1;
        user.last_failed_attempt = current_time;

        // Save the updated user store
        if let Err(e) = save_user_store(store) {
            println!("Warning: Failed to save user data: {}", e);
        }

        false
    } else {
        false
    }
}

/// Function to handle account deletion process
pub fn handle_account_deletion(
    store: &mut UserStore,
    username: &str,
    password: &str,
    cache: &SecurePasswordCache,
) -> DeletionStatus {
    // Initialize cleanup status with only the field we use
    // (Removing unused fields to fix warnings while maintaining functionality)
    let mut cleanup_status = CleanupStatus {
        task_file_removed: false,
        cache_cleared: false,
        store_saved: false,
    };

    // Validate deletion confirmation
    println!("\n=== Account Deletion Warning ===");
    println!("This action will:");
    println!("1. Permanently delete all your tasks");
    println!("2. Remove your account from the system");
    println!("3. Log you out immediately");
    println!("This action CANNOT be undone!");

    // First confirmation step
    println!("\nType 'DELETE' to confirm (or anything else to cancel):");
    let confirmation = read_line().unwrap_or_default();
    if confirmation.trim() != "DELETE" {
        return DeletionStatus::Cancelled;
    }

    // Get user reference for validation
    // Collect necessary user information before mutation
    let user_info = match store.users.get(username) {
        Some(user) => {
            // Create a tuple with the information we need
            (
                user.password_hash.clone(),
                user.email.clone(),
                user.tasks_file.clone(),
            )
        }
        None => return DeletionStatus::Failed("User not found".to_string()),
    };

    let (stored_password_hash, user_email, task_file) = user_info;

    // Initial password verification using the password parameter
    // This verifies the user's current session password
    let initial_password_hash = hex::encode(
        crate::modules::encryption::keys::derive_key_from_passphrase(password, &store.salt),
    );
    if stored_password_hash != initial_password_hash {
        return DeletionStatus::Failed("Session password verification failed".to_string());
    }

    // Password confirmation step
    println!("\nPlease enter your password to confirm deletion:");
    let confirm_password = match read_password() {
        Ok(pass) => pass,
        Err(e) => return DeletionStatus::Failed(format!("Failed to read password: {}", e)),
    };

    // Verify password
    let password_hash = hex::encode(
        crate::modules::encryption::keys::derive_key_from_passphrase(
            &confirm_password,
            &store.salt,
        ),
    );
    if stored_password_hash != password_hash {
        return DeletionStatus::Failed("Incorrect password".to_string());
    }

    // Final confirmation step
    println!("\nFINAL WARNING: Account deletion is irreversible!");
    println!("Type 'YES' to permanently delete your account:");
    let final_confirmation = read_line().unwrap_or_default();
    if final_confirmation.trim() != "YES" {
        return DeletionStatus::Cancelled;
    }

    // Begin deletion process
    // 1. Remove user's task file
    if let Err(e) = std::fs::remove_file(&task_file) {
        // Log error but continue with deletion
        log_data_operation(
            "delete_account",
            username,
            "task_file",
            false,
            Some(&format!("Failed to remove task file: {}", e)),
        );
    } else {
        cleanup_status.task_file_removed = true; // Mark task file as successfully removed
    }

    // 2. Clean up any orphaned task files
    if let Err(e) = cleanup_user_tasks(username, store) {
        log::error!("Failed to clean up orphaned task files: {}", e);
    }

    // 3. Remove user from store
    store.users.remove(username);

    // 4. Remove any password reset tokens for this user
    store
        .reset_tokens
        .retain(|_, token| token.username != username);

    // 5. Remove any reset attempts tracking
    store.reset_attempts.remove(&user_email);

    // 6. Save the updated store
    if let Err(e) = save_user_store(store) {
        return DeletionStatus::Failed(format!("Failed to save user store: {}", e));
    }
    cleanup_status.store_saved = true; // Mark store as successfully saved

    // 7. Clear password cache
    if let Err(e) = cache.clear_cache() {
        // Log error but continue
        log_data_operation(
            "delete_account",
            username,
            "password_cache",
            false,
            Some(&format!("Failed to clear password cache: {}", e)),
        );
    } else {
        cleanup_status.cache_cleared = true; // Mark cache as successfully cleared
    }

    // Log successful deletion
    log_data_operation(
        "delete_account",
        username,
        "user_store",
        true,
        Some("Account successfully deleted"),
    );

    // Return success if critical operations succeeded
    if cleanup_status.task_file_removed
        && cleanup_status.cache_cleared
        && cleanup_status.store_saved
    {
        DeletionStatus::Success
    } else {
        // Provide more detailed error message based on what failed
        let mut failed_operations = Vec::new();
        if !cleanup_status.task_file_removed {
            failed_operations.push("task file removal");
        }
        if !cleanup_status.cache_cleared {
            failed_operations.push("cache clearing");
        }
        if !cleanup_status.store_saved {
            failed_operations.push("store saving");
        }
        DeletionStatus::Failed(format!(
            "Failed operations: {}",
            failed_operations.join(", ")
        ))
    }
}

/// Function to handle interactive user registration with proper cache clearing
pub fn handle_interactive_registration(store: &mut UserStore) -> io::Result<()> {
    // Create a new instance of SecurePasswordCache
    let cache = SecurePasswordCache::new();

    // First, clear any existing cached credentials
    if let Ok(Some((cached_username, _))) = cache.get_cached_password() {
        // Log the forced logout of previous user
        log_auth_event(
            "forced_logout",
            &cached_username,
            true,
            Some("Logout due to new registration"),
        );

        // Clear the password cache
        if let Err(e) = cache.clear_cache() {
            println!(
                "Warning: Failed to clear previous user's cached credentials: {}",
                e
            );
        }
    }

    println!("\n=== User Registration ===");

    // Get username with validation
    let username = loop {
        println!("\nEnter desired username:");
        let username = read_line()?;

        if username.trim().is_empty() {
            println!("Username cannot be empty.");
            continue;
        }

        // Check if username already exists - use normalized username
        let normalized = username.trim().to_lowercase();
        if store.users.contains_key(&normalized) {
            println!("Username already exists. Please choose a different one.");
            continue;
        }

        break username;
    };

    // Get email with validation
    let email = loop {
        println!("\nEnter your email address:");
        let email = read_line()?;

        if !crate::modules::utils::io::is_valid_email(&email) {
            println!("Invalid email format. Please enter a valid email address.");
            continue;
        }

        if store.users.values().any(|u| u.email == email) {
            println!("Email already registered. Please use a different email.");
            continue;
        }

        break email;
    };

    // Get password with validation
    let password = loop {
        println!("\nEnter password (min 8 chars, must include uppercase, lowercase, number, and special char):");
        let password = read_password()?;

        match validate_password(&password) {
            Ok(_) => break password,
            Err(e) => {
                println!("Password validation failed: {:?}", e);
                println!("Please try again.");
            }
        }
    };

    // Confirm password
    loop {
        println!("\nConfirm password:");
        let confirm = read_password()?;

        if confirm == password {
            break;
        }

        println!("Passwords don't match. Please try again.");
    }

    // Add the new user
    let email_clone = email.clone(); // Clone email before moving it
    match handle_user_creation(store, username.clone(), email, password) {
        Ok(_) => {
            // Generate and send verification token using cloned email
            match crate::modules::email::send_registration_verification(&email_clone) {
                Ok(token) => {
                    // Store verification token
                    let verification = super::verification::RegistrationVerification {
                        token,
                        username: username.clone(),
                        expires_at: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs()
                            + 86400, // 24 hours
                        verified: false,
                    };

                    store
                        .registration_verifications
                        .insert(username.clone(), verification);

                    println!("\nRegistration successful!");
                    println!("Please check your email for a verification code.");
                    println!("You will need to enter this code on your first login.");
                }
                Err(e) => {
                    println!(
                        "\nRegistration successful, but failed to send verification email: {}",
                        e
                    );
                    println!("Please contact support for assistance.");
                }
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Handler function for user creation process
pub fn handle_user_creation(
    store: &mut UserStore,
    username: String,
    email: String,
    password: String,
) -> io::Result<()> {
    // Normalize the username for consistency with login
    let original_username = username.trim().to_string();

    // Log the start of user creation operation
    log_data_operation(
        "create_user",
        &original_username,
        "user_store",
        true,
        Some("starting user registration"),
    );

    // Attempt to add user to the store and handle the result
    match store.add_user(original_username.clone(), email.clone(), password.clone()) {
        Ok(_) => {
            // Attempt to save the store immediately after successful user creation
            match save_user_store(store) {
                Ok(_) => {
                    log_data_operation(
                        "create_user",
                        &original_username,
                        "user_store",
                        true,
                        Some("user created and store saved"),
                    );
                    println!("User {} created successfully", original_username);
                    Ok(())
                }
                Err(e) => {
                    log_data_operation(
                        "create_user",
                        &original_username,
                        "user_store",
                        false,
                        Some(&format!("failed to add user: {}", e)),
                    );
                    println!("Failed to create user: {}", e);
                    Err(e)
                }
            }
        }
        Err(e) => {
            log_data_operation(
                "create_user",
                &original_username,
                "user_store",
                false,
                Some(&format!("failed to add user: {}", e)),
            );
            println!("Failed to create user: {}", e);
            Err(e)
        }
    }
}

// Custom result type for authentication flow control
#[derive(Debug)]
pub enum AuthFlowResult {
    Back,            // Return to main menu
    Success(String), // Success with a message
    Error(String),   // Error with a message
}

/// Forgot password handler
pub fn handle_forgot_password(store: &mut UserStore) -> AuthFlowResult {
    println!("\n=== Password Reset ===");

    // First verify that the email system is properly configured
    // This prevents starting the reset process if emails can't be sent
    if !check_email_configuration() {
        return AuthFlowResult::Error(
            "Email system is not configured. Please contact administrator.".to_string(),
        );
    }

    // Get and validate user's email address with flow control
    println!("Please enter your email address (or 'back' to return to menu):");
    let email = match read_line() {
        Ok(input) => {
            // Check for back command first
            match input.trim().to_lowercase().as_str() {
                "back" => return AuthFlowResult::Back,
                "exit" => {
                    println!("Exiting program. Goodbye!");
                    process::exit(0);
                }
                email => email.to_string(),
            }
        }
        Err(e) => return AuthFlowResult::Error(format!("Error reading input: {}", e)),
    };

    let email = email.trim();

    // Validate email format before proceeding
    if !crate::modules::utils::io::is_valid_email(email) {
        return AuthFlowResult::Error(
            "Invalid email format. Please enter a valid email address.".to_string(),
        );
    }

    // Check if the email exists in our user database
    // We don't reveal to the user whether the email exists for security
    let user_exists = store.users.values().any(|u| u.email == email);
    if !user_exists {
        // Send the same message regardless of whether email exists
        // This prevents email enumeration attacks
        return AuthFlowResult::Success(
            "If an account exists with this email, you will receive reset instructions."
                .to_string(),
        );
    }

    // Find user by email
    let user = match store.users.values().find(|u| u.email == email) {
        Some(u) => u,
        None => {
            return AuthFlowResult::Error("No account found with this email address.".to_string())
        }
    };

    // Clone the username for later use
    let username = user.username.clone();

    // Generate a 6-digit numeric reset token only for valid emails
    // Using numeric tokens as they're easier for users to enter
    let token: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Uniform::new(0, 10))
        .take(6)
        .map(|d| d.to_string())
        .collect();

    // Create an instance of token manager to handle secure token storage
    let token_manager = super::tokens::SecureTokenManager::new();
    // Store the generated token securely
    // This associates the token with the user's email
    if let Err(e) = token_manager.store_token(email, &token) {
        return AuthFlowResult::Error(e);
    }

    // Send reset email with proper error handling
    match send_reset_token_email(email, &token) {
        Ok(_) => {
            println!("\nA reset token has been sent to your email.");
            println!("Please check your inbox and enter the token below.");
        }
        Err(e) => {
            // If email fails, clean up the stored token
            let _ = token_manager.clear_token();
            return AuthFlowResult::Error(format!("Failed to send reset email: {}", e));
        }
    }

    // Set up attempt limiting for token verification
    let mut attempts = 0;
    const MAX_ATTEMPTS: u32 = 3;

    // Loop to handle token verification with flow control
    while attempts < MAX_ATTEMPTS {
        println!("\nEnter the reset token (or 'back' to return to menu, 'cancel' to abort):");
        let input_token = match read_line() {
            Ok(input) => input,
            Err(e) => return AuthFlowResult::Error(format!("Error reading input: {}", e)),
        };
        let input_token = input_token.trim();

        // Enhanced command handling
        match input_token.to_lowercase().as_str() {
            "back" => {
                let _ = token_manager.clear_token();
                return AuthFlowResult::Back;
            }
            "exit" => {
                println!("Exiting program. Goodbye!");
                process::exit(0);
            }
            "cancel" => {
                let _ = token_manager.clear_token();
                return AuthFlowResult::Success("Password reset cancelled.".to_string());
            }
            token => {
                // Verify the entered token
                match token_manager.verify_token(email, token) {
                    Ok(true) => {
                        // Token is valid, proceed with password reset
                        println!("\nToken verified successfully!");

                        // Get and validate new password with flow control
                        let new_password = match get_new_password() {
                            Ok(pwd) => pwd,
                            Err(e) => return AuthFlowResult::Error(e),
                        };

                        // Generate new password hash first
                        let new_hash = hex::encode(
                            crate::modules::encryption::keys::derive_key_from_passphrase(
                                &new_password,
                                &store.salt,
                            ),
                        );

                        // Then update the user's password hash
                        if let Some(user) = store.users.values_mut().find(|u| u.email == email) {
                            user.password_hash = new_hash;
                        } else {
                            return AuthFlowResult::Error(
                                "Failed to update password: user not found".to_string(),
                            );
                        }

                        // Save the store after releasing the mutable borrow
                        if let Err(e) = save_user_store(store) {
                            return AuthFlowResult::Error(format!(
                                "Failed to save user data: {}",
                                e
                            ));
                        }

                        // Clear the used token
                        let _ = token_manager.clear_token();

                        // Log the successful password reset
                        log_data_operation(
                            "password_reset",
                            &username,
                            "user_store",
                            true,
                            Some("Password reset completed successfully"),
                        );

                        return AuthFlowResult::Success("Password reset successful!".to_string());
                    }
                    Ok(false) => {
                        // Handle invalid token attempts
                        attempts += 1;
                        if attempts < MAX_ATTEMPTS {
                            println!(
                                "Invalid token. Please try again. {} attempts remaining.",
                                MAX_ATTEMPTS - attempts
                            );
                        } else {
                            // Clean up token after max attempts reached
                            let _ = token_manager.clear_token();
                            return AuthFlowResult::Error(
                                "Too many invalid attempts. Please start over.".to_string(),
                            );
                        }
                    }
                    Err(e) => {
                        return AuthFlowResult::Error(format!("Token verification failed: {}", e))
                    }
                }
            }
        }
    }

    AuthFlowResult::Success("Password reset completed.".to_string())
}

/// Function to create and send reset token
fn send_reset_token_email(email: &str, token: &str) -> Result<(), String> {
    // Create a temporary PasswordResetToken structure
    let reset_token = super::tokens::PasswordResetToken {
        token: token.to_string(),
        expires_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 1800, // 30 minutes expiration
        user_email: email.to_string(),
        username: "".to_string(), // We'll update this later
    };

    // Use the existing send_reset_email function
    crate::modules::email::send_reset_email(&reset_token)
}

/// Email configuration check function
fn check_email_configuration() -> bool {
    // Use existing SecureEmailManager to check if credentials exist
    let email_manager = crate::modules::email::SecureEmailManager::new();
    email_manager.get_credentials().is_ok()
}

/// Helper function to get and validate new password
fn get_new_password() -> Result<String, String> {
    println!("\nEnter your new password");
    println!(
        "(minimum 8 characters, must include uppercase, lowercase, number, and special char):"
    );

    let new_password = loop {
        let password = read_password().map_err(|e| format!("Error reading password: {}", e))?;

        match validate_password(&password) {
            Ok(_) => break password,
            Err(e) => {
                println!("Password validation failed: {:?}", e);
                println!("Please try again.");
                continue;
            }
        }
    };

    // Confirm password
    println!("\nConfirm your new password:");
    let confirm_password = read_password().map_err(|e| format!("Error reading password: {}", e))?;

    if new_password != confirm_password {
        return Err("Passwords don't match. Please start over.".to_string());
    }

    Ok(new_password)
}

/// Handle the 'profile' command
pub fn handle_profile_command(
    sub_matches: &clap::ArgMatches,
    store: &mut UserStore,
    username: &str,
    _password: &str,
    cache: &SecurePasswordCache,
) {
    // First, check if the user's session is still valid
    // This prevents unauthorized access to profile information
    if let Ok(None) = cache.get_cached_password() {
        println!("Session expired due to inactivity. Please log in again.");
        return;
    }

    // If no arguments provided (i.e., just 'profile' command), show profile by default
    // This makes the command more user-friendly by having a sensible default behavior
    if !sub_matches.contains_id("email") && !sub_matches.get_flag("show") {
        if let Some(user) = store.users.get(username) {
            // Display basic profile information in a formatted manner
            println!("\nUser Profile");
            println!("------------");
            println!("Username: {}", user.username);
            println!("Email: {}", user.email);
            println!(
                "Account created: {}",
                format_timestamp(user.created_at) // Convert Unix timestamp to readable format
            );
            println!(
                "Last login: {}",
                format_timestamp(user.last_login) // Show when user last logged in
            );
            println!(
                "Last active: {}",
                format_timestamp(user.last_activity) // Show last activity timestamp
            );
        }
        return; // Return after displaying information
    }

    // Handle the --show flag if present
    // This explicitly shows profile information even if other arguments are present
    if sub_matches.get_flag("show") {
        if let Some(user) = store.users.get(username) {
            // Display the same profile information as above
            println!("\nUser Profile");
            println!("------------");
            println!("Username: {}", user.username);
            println!("Email: {}", user.email);
            println!("Account created: {}", format_timestamp(user.created_at));
            println!("Last login: {}", format_timestamp(user.last_login));
            println!("Last active: {}", format_timestamp(user.last_activity));
        }
    }

    // Handle email update if --email argument is provided
    if let Some(new_email) = sub_matches.get_one::<String>("email") {
        // Validate the new email format using the is_valid_email function
        if !crate::modules::utils::io::is_valid_email(new_email) {
            println!("Invalid email format. Please provide a valid email address.");
            return;
        }

        // Check if the new email is already in use by another user
        // This prevents email address conflicts between users
        if store
            .users
            .values()
            .any(|u| u.email == *new_email && u.username != username)
        {
            println!("This email address is already registered to another account.");
            return;
        }

        // Get mutable reference to the current user to update their email
        if let Some(user) = store.users.get_mut(username) {
            // Require password confirmation for security
            println!("Please enter your password to confirm changes:");
            let confirm_password = read_password().unwrap();

            // Verify the provided password by comparing hashes
            let password_hash = hex::encode(
                crate::modules::encryption::keys::derive_key_from_passphrase(
                    &confirm_password,
                    &store.salt,
                ),
            );
            if user.password_hash != password_hash {
                println!("Incorrect password. Email update cancelled.");
                return;
            }

            // Update the email address
            user.email = new_email.to_string();

            // Save the updated user store to persist the change
            match save_user_store(store) {
                Ok(_) => println!("Email updated successfully."),
                Err(e) => println!("Failed to update email: {}", e),
            }
        }
    }
}

/// Show help information for various commands
pub fn show_help_information() {
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

    // Profile Command Details
    println!("\nProfile Command Usage:");
    println!("  profile                    - Show your profile information");
    println!("  profile --show             - Explicitly display profile information");
    println!("  profile --email NEW_EMAIL  - Update your email address");
    println!("\nProfile command notes:");
    println!("  - Email updates require password confirmation");
    println!("  - Profile information includes:");
    println!("    * Username");
    println!("    * Email address");
    println!("    * Account creation date");
    println!("    * Last login time");
    println!("    * Last activity time");

    // Account Management Section
    println!("\nAccount Management:");
    println!("  change-password            - Change your account password");
    println!("  delete-account             - Delete your account permanently");
    println!("  \u{2022} Requires multiple confirmations");
    println!("  \u{2022} Deletes all tasks and user data");
    println!("  \u{2022} Action cannot be undone");

    // Security Notes
    println!("\nSecurity Notes:");
    println!("  - Sessions timeout after 15 minutes of inactivity");
    println!("  - Profile changes require password confirmation");
    println!("  - Password must contain uppercase, lowercase, numbers, and special characters");

    println!("\nType any command with --help for more specific information");
}

/// Show command-specific help
pub fn show_command_help(command: &str) {
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
        // Add other command-specific help sections as needed
        _ => {
            println!("\nNo detailed help available for '{}' command.", command);
            println!("Use 'help' to see general usage information.");
        }
    }
}
