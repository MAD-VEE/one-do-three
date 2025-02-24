pub mod store;
pub mod password;
pub mod tokens;
pub mod verification;

// Re-export the main types and functions
pub use store::{User, UserStore, VerificationStatus};
pub use password::{PasswordError, validate_password};
pub use tokens::{PasswordResetToken, ResetAttemptTracker, SecureTokenManager};
pub use verification::{RegistrationVerification, verify_registration_token};