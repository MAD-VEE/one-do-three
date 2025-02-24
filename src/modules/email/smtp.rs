use serde::{Deserialize, Serialize};

/// Structure to hold SMTP credentials with metadata
#[derive(Serialize, Deserialize)]
pub struct SmtpCredentials {
    // The email address/username for SMTP authentication
    pub username: String,
    // The password or app-specific password for SMTP
    pub password: String,
    // SMTP server hostname (e.g., smtp.gmail.com)
    pub host: String,
    // SMTP server port (typically 587 for TLS)
    pub port: u16,
    // When these credentials were last updated
    pub last_updated: u64,
}
