// First, declare the modules folder itself
mod modules;

// Re-export everything from modules for easier access
pub use modules::{
    admin,
    auth,
    email,
    encryption,
    tasks,
    security,
    utils,
};

// Re-export commonly used types
pub use modules::auth::store::UserStore;
pub use modules::tasks::model::Task;
pub use modules::admin::config::AdminConfig;
pub use modules::email::manager::SecureEmailManager;

// Constants
pub const USERS_FILE: &str = "users.json";
pub const MAX_ADMIN_ATTEMPTS: u32 = 3;
pub const ADMIN_LOCKOUT_DURATION: u64 = 1800;
pub const SETUP_TOKEN_DURATION: u64 = 3600;

// Type aliases
pub type HmacSha256 = hmac::Hmac<sha2::Sha256>;
pub type Aes256Cbc = block_modes::Cbc<aes::Aes256, block_modes::block_padding::Pkcs7>;