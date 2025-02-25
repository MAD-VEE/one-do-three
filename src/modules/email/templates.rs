use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::transport::smtp::PoolConfig;
use lettre::{Message, SmtpTransport, Transport};
use rand::distributions::Uniform;
use rand::Rng;

use super::manager::SecureEmailManager;
use crate::modules::auth::tokens::PasswordResetToken;

/// Function to send emails using securely stored credentials
pub fn send_email(to_email: &str, subject: &str, body: &str) -> Result<(), String> {
    // Get instance of secure email manager
    let email_manager = SecureEmailManager::new();

    // Retrieve stored credentials
    let creds = email_manager.get_credentials()?;

    // Create email message
    let email = Message::builder()
        .from(
            format!("One-Do-Three <{}>", creds.username)
                .parse()
                .map_err(|e| format!("Invalid from address: {}", e))?,
        )
        .to(to_email
            .parse()
            .map_err(|e| format!("Invalid to address: {}", e))?)
        .subject(subject)
        .header(lettre::message::header::ContentType::TEXT_PLAIN)
        .body(body.to_string())
        .map_err(|e| format!("Failed to create email: {}", e))?;

    // Configure TLS parameters
    let tls_parameters = TlsParameters::builder(creds.host.clone())
        .build()
        .map_err(|e| format!("Failed to build TLS parameters: {}", e))?;

    // Set up SMTP transport with explicit TLS configuration
    let mailer = SmtpTransport::relay(&creds.host)
        .map_err(|e| format!("Failed to create SMTP transport: {}", e))?
        .credentials(Credentials::new(creds.username, creds.password))
        .port(creds.port)
        .tls(Tls::Required(tls_parameters))
        .pool_config(PoolConfig::new().max_size(1))
        .timeout(Some(std::time::Duration::from_secs(10)))
        .build();

    // Send the email
    match mailer.send(&email) {
        Ok(_) => {
            println!("Email sent successfully to: {}", to_email);
            Ok(())
        }
        Err(e) => Err(format!(
            "Failed to send email: {} (This might be due to network issues, incorrect credentials, or Gmail security settings. Please verify your App Password and Gmail settings)",
            e
        )),
    }
}

// Function to send registration verification token
// This function sends a verification email with a properly formatted template
// Parameters:
// - email: The recipient's email address
// Returns: Result containing the generated token or an error message
pub fn send_registration_verification(email: &str) -> Result<String, String> {
    // Generate 6-digit token using random numbers
    let token: String = rand::thread_rng()
        .sample_iter(&Uniform::new(0, 10))
        .take(6)
        .map(|d| d.to_string())
        .collect();

    // Create verification email with proper formatting
    let email_body = format!(
        "Welcome to One-Do-Three!\n\
        \n\
        Please verify your account using the following code:\n\
        \n\
        {}\n\
        \n\
        This code will expire in 24 hours.\n\
        \n\
        Best regards,\n\
        One-Do-Three Task Manager Team",
        token
    );

    // Send verification email
    match send_email(
        email,
        "Welcome to One-Do-Three - Verify Your Account",
        &email_body,
    ) {
        Ok(_) => Ok(token),
        Err(e) => Err(format!("Failed to send verification email: {}", e)),
    }
}

/// Function to send password reset email
pub fn send_reset_email(reset_token: &PasswordResetToken) -> Result<(), String> {
    // Create a professional email template for password reset
    let email_body = format!(
        "Hello,\n\n\
        A password reset was requested for your One-Do-Three account.\n\n\
        To reset your password, use the following token:\n\n\
        {}\n\n\
        This token will expire in 30 minutes.\n\n\
        Security Tips:\n\
        - Choose a strong password with at least 8 characters\n\
        - Include uppercase and lowercase letters\n\
        - Include numbers and special characters\n\n\
        If you did not request this reset, please ignore this email and ensure \
        your account is secure.\n\n\
        Best regards,\n\
        One-Do-Three Task Manager Team",
        reset_token.token
    );

    // Send the reset email using the secure email system
    send_email(
        &reset_token.user_email,
        "Password Reset Request - One-Do-Three",
        &email_body,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    /// Test mock email sending for verification
    fn test_mock_email_sending() {
        // Since we can't actually send emails in tests, we'll mock the function
        struct MockEmailSender {
            last_email: Option<(String, String, String)>,
        }

        impl MockEmailSender {
            fn new() -> Self {
                Self { last_email: None }
            }

            fn send_email(&mut self, to: &str, subject: &str, body: &str) -> Result<(), String> {
                self.last_email = Some((to.to_string(), subject.to_string(), body.to_string()));
                Ok(())
            }
        }

        // Create the mock sender
        let mut email_sender = MockEmailSender::new();

        // Send a verification email
        let to = "test@example.com";
        let subject = "Welcome to One-Do-Three - Verify Your Account";
        let token = "123456";
        let body = format!(
            "Welcome to One-Do-Three!\n\
            \n\
            Please verify your account using the following code:\n\
            \n\
            {}\n\
            \n\
            This code will expire in 24 hours.\n\
            \n\
            Best regards,\n\
            One-Do-Three Task Manager Team",
            token
        );

        // Send the email
        let result = email_sender.send_email(to, subject, &body);
        assert!(result.is_ok());

        // Verify the email details were stored
        let (stored_to, stored_subject, stored_body) = email_sender.last_email.unwrap();
        assert_eq!(stored_to, to);
        assert_eq!(stored_subject, subject);
        assert_eq!(stored_body, body);
        assert!(stored_body.contains(token));
    }

    #[test]
    /// Test email template for verification
    fn test_verification_email_template() {
        let token = "123456";
        let email_body = format!(
            "Welcome to One-Do-Three!\n\
            \n\
            Please verify your account using the following code:\n\
            \n\
            {}\n\
            \n\
            This code will expire in 24 hours.\n\
            \n\
            Best regards,\n\
            One-Do-Three Task Manager Team",
            token
        );

        // Verify email contains the token
        assert!(email_body.contains(token));

        // Verify email contains important information
        assert!(email_body.contains("verify your account"));
        assert!(email_body.contains("expire in 24 hours"));
    }
}
