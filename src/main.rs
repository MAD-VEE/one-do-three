use std::process;

use one_do_three::{
    admin::{
        enhanced_initialize_admin_credentials, generate_admin_setup_token,
        handle_admin_password_change,
    },
    auth::{load_user_store, main_auth_flow},
    email::{setup_email_credentials, test_email_configuration},
    utils::logging::initialize_logging,
};

/// Main entry point - clean and minimal
fn main() {
    // Initialize logging system
    if let Err(e) = initialize_logging() {
        eprintln!("Failed to initialize logging: {}", e);
        process::exit(1);
    }

    // Parse command line arguments for admin commands
    if handle_command_line_args() {
        return; // Exit if we handled an admin command
    }

    // Regular application flow
    run_application();
}

/// Handle command line arguments for admin and email setup
fn handle_command_line_args() -> bool {
    let args: Vec<String> = std::env::args().collect();

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
            "--test-email" => {
                match test_email_configuration() {
                    Ok(_) => println!("Email configuration test successful!"),
                    Err(e) => println!("Email configuration test failed: {}", e),
                }
                return true;
            }
            _ => {}
        }
    }
    false
}

/// Main application loop - now extremely minimal
fn run_application() {
    // Load the user store
    let mut store = match load_user_store() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("Failed to load user store: {}", e);
            process::exit(1);
        }
    };

    loop {
        // Show options and authenticate user
        match main_auth_flow(&mut store) {
            Some((username, password)) => {
                // Handle authenticated session in separate function from auth module
                one_do_three::auth::handle_authenticated_session(&mut store, &username, &password);
            }
            None => {
                // Authentication failed
                println!("Exiting program");
                break;
            }
        }
    }
}
