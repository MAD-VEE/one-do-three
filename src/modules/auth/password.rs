use super::store::{save_user_store, UserStore};
use super::tokens::SecurePasswordCache;
use crate::modules::encryption::keys::derive_key_from_passphrase;
use crate::modules::utils::logging::log_data_operation;
use std::io;

/// Password management struct
#[derive(Debug)]
pub enum PasswordError {
    TooShort,
    NoUppercase,
    NoLowercase,
    NoNumber,
    NoSpecialChar,
}

/// Function to validate password strength
pub fn validate_password(password: &str) -> Result<(), PasswordError> {
    if password.len() < 8 {
        return Err(PasswordError::TooShort);
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(PasswordError::NoUppercase);
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err(PasswordError::NoLowercase);
    }
    if !password.chars().any(|c| c.is_numeric()) {
        return Err(PasswordError::NoNumber);
    }
    if !password
        .chars()
        .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
    {
        return Err(PasswordError::NoSpecialChar);
    }
    Ok(())
}

/// Helper function to read a password securely
pub fn read_password() -> io::Result<String> {
    rpassword::read_password()
}

/// Function to handle the interactive password change process
/// Takes mutable references to both UserStore and the current User
/// Returns Result indicating success or failure with error message
/// Includes proper cache management after password change
pub fn handle_password_change(
    store: &mut UserStore,
    username: &str,
    cache: &SecurePasswordCache,
) -> Result<(), String> {
    // First, get a reference to the user
    let user = store.users.get(username).ok_or("User not found")?;

    println!("\n=== Password Change ===");

    // Get current password for verification
    println!("Enter your current password:");
    let current_password =
        read_password().map_err(|e| format!("Failed to read current password: {}", e))?;

    // Verify current password by comparing hashes
    let current_hash = hex::encode(derive_key_from_passphrase(&current_password, &store.salt));
    if current_hash != user.password_hash {
        return Err("Current password is incorrect".to_string());
    }

    // Get and validate new password
    println!("\nEnter new password");
    println!("Requirements:");
    println!("- Minimum 8 characters");
    println!("- At least one uppercase letter");
    println!("- At least one lowercase letter");
    println!("- At least one number");
    println!("- At least one special character");

    let new_password = loop {
        let password =
            read_password().map_err(|e| format!("Failed to read new password: {}", e))?;

        // Validate password strength
        match validate_password(&password) {
            Ok(_) => {
                // Check if new password is different from current
                if password == current_password {
                    println!("New password must be different from current password");
                    continue;
                }
                break password;
            }
            Err(e) => {
                println!("Password validation failed: {:?}", e);
                println!("Please try again.");
                continue;
            }
        }
    };

    // Confirm new password
    println!("\nConfirm new password:");
    let confirm_password =
        read_password().map_err(|e| format!("Failed to read password confirmation: {}", e))?;

    if new_password != confirm_password {
        return Err("Passwords don't match".to_string());
    }

    // Get mutable reference to user and update password
    if let Some(user) = store.users.get_mut(username) {
        // Update the password hash
        user.password_hash = hex::encode(derive_key_from_passphrase(&new_password, &store.salt));

        // Then, clear the existing password cache
        cache
            .clear_cache()
            .map_err(|e| format!("Failed to clear password cache: {}", e))?;

        // Finally, cache the new password
        cache
            .cache_password(username, &new_password)
            .map_err(|e| format!("Failed to update password cache: {}", e))?;

        // Log the password change event
        log_data_operation(
            "change_password",
            username,
            "user_store",
            true,
            Some("Password changed successfully"),
        );

        // Update the cached password
        cache
            .cache_password(username, &new_password)
            .map_err(|e| format!("Failed to update password cache: {}", e))?;

        // Save the updated user store
        save_user_store(store).map_err(|e| format!("Failed to save user store: {}", e))?;

        Ok(())
    } else {
        Err("Failed to update password: User not found".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_validation() {
        // Test valid password
        let valid_password = "Password123!";
        assert!(validate_password(valid_password).is_ok());

        // Test too short
        let short_password = "Pass1!";
        assert!(matches!(
            validate_password(short_password),
            Err(PasswordError::TooShort)
        ));

        // Test missing uppercase
        let no_upper_password = "password123!";
        assert!(matches!(
            validate_password(no_upper_password),
            Err(PasswordError::NoUppercase)
        ));

        // Test missing lowercase
        let no_lower_password = "PASSWORD123!";
        assert!(matches!(
            validate_password(no_lower_password),
            Err(PasswordError::NoLowercase)
        ));

        // Test missing number
        let no_number_password = "Password!";
        assert!(matches!(
            validate_password(no_number_password),
            Err(PasswordError::NoNumber)
        ));

        // Test missing special character
        let no_special_password = "Password123";
        assert!(matches!(
            validate_password(no_special_password),
            Err(PasswordError::NoSpecialChar)
        ));
    }
}
