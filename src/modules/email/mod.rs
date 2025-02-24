pub mod manager;
mod smtp;
mod templates;

pub use manager::SecureEmailManager;
pub use smtp::SmtpCredentials;
pub use templates::{send_registration_verification, send_reset_email};