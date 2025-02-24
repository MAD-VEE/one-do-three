pub mod manager;
mod setup;
mod smtp;
mod templates;

pub use manager::SecureEmailManager;
pub use setup::{setup_email_credentials, test_email_configuration};
pub use smtp::SmtpCredentials;
pub use templates::{send_email, send_registration_verification, send_reset_email};
