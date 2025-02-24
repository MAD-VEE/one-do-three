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