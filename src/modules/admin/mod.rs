pub mod config;
mod credentials;
mod setup;

pub use config::{AdminAuthTracker, AdminConfig};
pub use credentials::SecureAdminManager;
pub use setup::{
    enhanced_initialize_admin_credentials, enhanced_verify_admin, generate_admin_setup_token,
    handle_admin_password_change,
};
