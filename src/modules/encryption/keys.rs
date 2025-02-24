use crate::HmacSha256;
use pbkdf2::pbkdf2;
use rand::Rng;
use std::num::NonZeroU32;

/// Function to generate a random salt for PBKDF2
pub fn generate_random_salt() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..16).map(|_| rng.gen()).collect()
}

/// Function to generate a random IV for AES encryption
pub fn generate_random_iv() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..16).map(|_| rng.gen()).collect()
}

/// Function to derive a 32-byte key from the passphrase using PBKDF2
pub fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> Vec<u8> {
    let mut key = vec![0u8; 32];
    let iterations = NonZeroU32::new(100_000).unwrap();

    pbkdf2::<HmacSha256>(
        passphrase.as_bytes(),
        salt,
        iterations.get().into(),
        &mut key,
    );

    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let passphrase = "MySecurePassword123!";
        let salt = generate_random_salt();

        let key = derive_key_from_passphrase(passphrase, &salt);
        assert_eq!(key.len(), 32);

        let key2 = derive_key_from_passphrase(passphrase, &salt);
        assert_eq!(key, key2);

        let different_passphrase = "DifferentPassword456!";
        let key3 = derive_key_from_passphrase(different_passphrase, &salt);
        assert_ne!(key, key3);

        let different_salt = generate_random_salt();
        let key4 = derive_key_from_passphrase(passphrase, &different_salt);
        assert_ne!(key, key4);
    }

    #[test]
    fn test_random_generation() {
        let salt1 = generate_random_salt();
        let salt2 = generate_random_salt();
        assert_eq!(salt1.len(), 16);
        assert_ne!(salt1, salt2);

        let iv1 = generate_random_iv();
        let iv2 = generate_random_iv();
        assert_eq!(iv1.len(), 16);
        assert_ne!(iv1, iv2);
    }
}
