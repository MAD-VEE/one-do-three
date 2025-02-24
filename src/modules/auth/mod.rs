// src/modules/auth/mod.rs
pub mod password;
pub mod store;
pub mod tokens;
mod user_interface;
mod verification;

pub use password::{handle_password_change, read_password, validate_password, PasswordError};
pub use store::{load_user_store, save_user_store, User, UserStore, VerificationStatus};
pub use tokens::{
    CachedPassword, PasswordResetToken, ResetAttemptTracker, SecurePasswordCache,
    SecureTokenManager,
};
pub use user_interface::{
    authenticate_user, handle_account_deletion, handle_authenticated_session,
    handle_interactive_registration, handle_user_creation, main_auth_flow, show_command_help,
    show_help_information, show_initial_options, DeletionStatus,
};
pub use verification::{verify_registration_token, RegistrationVerification};
