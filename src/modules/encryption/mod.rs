mod crypto;
pub mod keys;

pub use crypto::{decrypt_data, encrypt_data};
pub use keys::{derive_key_from_passphrase, generate_random_iv, generate_random_salt};