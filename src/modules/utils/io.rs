use std::io::{self, Write};

/// Helper function to read a line from stdin
pub fn read_line() -> io::Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

/// Helper function to prompt for input with confirmation
pub fn prompt_with_confirmation(prompt: &str, confirmation: &str) -> io::Result<bool> {
    println!("{}", prompt);
    print!("{} (y/n): ", confirmation);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let response = input.trim().to_lowercase();

    Ok(response.is_empty() || response == "y")
}

/// Helper function to validate email format
pub fn is_valid_email(email: &str) -> bool {
    // Basic email validation
    email.contains('@')
        && email.contains('.')
        && !email.contains(' ')
        && email.chars().filter(|&c| c == '@').count() == 1
        && email.len() >= 5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_validation() {
        // Valid emails
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("user.name@example.co.uk"));
        assert!(is_valid_email("user+tag@example.com"));

        // Invalid emails
        assert!(!is_valid_email("user@example")); // Missing TLD
        assert!(!is_valid_email("user example.com")); // Contains space
        assert!(!is_valid_email("user")); // No @ symbol
        assert!(!is_valid_email("")); // Empty string
        assert!(!is_valid_email("user@@example.com")); // Multiple @ symbols
    }
}
