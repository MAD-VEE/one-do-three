// src/modules/email/setup.rs
use std::io;

use super::SecureEmailManager;
use crate::admin::SecureAdminManager;
use crate::auth::password::read_password;
use crate::email::send_email;
use crate::utils::io::{is_valid_email, read_line};

/// Function to set up email credentials securely
pub fn setup_email_credentials() -> Result<(), String> {
    let admin_manager = SecureAdminManager::new();

    // Check if admin credentials are initialized
    if !admin_manager.is_initialized() {
        return Err(
            "Admin credentials not initialized. Please set up admin password first.".to_string(),
        );
    }

    println!("\n=== Admin Authentication Required ===");
    println!("Please enter admin password to modify email settings:");

    // Limited number of admin password attempts
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

        // Basic domain validation
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
            break 587; // Default port
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

        if !is_valid_email(input) {
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

        // For Gmail app passwords, verify the format (16 characters)
        if host.contains("gmail.com") && pass.len() != 16 {
            println!("Warning: Gmail app passwords are typically 16 characters long.");
            println!("Are you sure you want to use this password? (y/n)");
            let mut confirm = String::new();
            io::stdin()
                .read_line(&mut confirm)
                .map_err(|e| format!("Failed to read input: {}", e))?;
            if confirm.trim().to_lowercase() != "y" {
                continue;
            }
        }

        break pass;
    };

    // Store credentials securely
    let email_manager = SecureEmailManager::new();
    email_manager.store_credentials(&username, &password, &host, port)?;

    println!("\nEmail configuration saved securely.");
    println!("Important: Please run 'test-email' to verify your configuration.");

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

/// Function to test email configuration
pub fn test_email_configuration() -> Result<(), String> {
    let email_manager = SecureEmailManager::new();
    let creds = email_manager.get_credentials()?;

    println!("Testing email configuration with the following settings:");
    println!("SMTP Server: {}", creds.host);
    println!("SMTP Port: {}", creds.port);
    println!("Username: {}", creds.username);
    println!("Attempting to send test email...");

    // Send a test email to the configured address
    let test_body = "This is a test email to verify your SMTP configuration.";

    send_email(
        &creds.username,
        "Task Manager - Email Configuration Test",
        test_body,
    )?;

    println!("Test email sent successfully to: {}", creds.username);
    Ok(())
}
