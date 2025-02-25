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
    use std::collections::HashSet;

    #[test]
    /// Test key derivation from passphrase
    fn test_key_derivation() {
        // Test data
        let passphrase = "MySecurePassword123!";
        let salt = generate_random_salt();

        // Derive key
        let key = derive_key_from_passphrase(passphrase, &salt);

        // Key should be 32 bytes
        assert_eq!(key.len(), 32);

        // Deriving again with the same passphrase and salt should yield the same key
        let key2 = derive_key_from_passphrase(passphrase, &salt);
        assert_eq!(key, key2);

        // Using a different passphrase should yield a different key
        let different_passphrase = "DifferentPassword456!";
        let key3 = derive_key_from_passphrase(different_passphrase, &salt);
        assert_ne!(key, key3);

        // Using a different salt should yield a different key
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

    #[test]
    /// Test that random salt and IV generation produces truly random values
    /// This ensures our cryptographic primitives have sufficient entropy
    fn test_random_generation_uniqueness() {
        // Generate multiple salts and IVs to test uniqueness
        const SAMPLE_SIZE: usize = 100;

        // Generate salts
        let mut salts = HashSet::new();
        for _ in 0..SAMPLE_SIZE {
            let salt = generate_random_salt();

            // Verify correct length
            assert_eq!(salt.len(), 16, "Salt should be 16 bytes");

            // Convert to a format that can be stored in a HashSet
            let salt_tuple: Vec<u8> = salt.into_iter().collect();

            // Check that this salt is unique
            assert!(salts.insert(salt_tuple), "Generated salt should be unique");
        }

        // Generate IVs
        let mut ivs = HashSet::new();
        for _ in 0..SAMPLE_SIZE {
            let iv = generate_random_iv();

            // Verify correct length
            assert_eq!(iv.len(), 16, "IV should be 16 bytes");

            // Convert to a format that can be stored in a HashSet
            let iv_tuple: Vec<u8> = iv.into_iter().collect();

            // Check that this IV is unique
            assert!(ivs.insert(iv_tuple), "Generated IV should be unique");
        }

        // With 16 bytes of random data, the chance of collision in 100 samples
        // is astronomically small, so this test should always pass unless
        // there's a serious problem with the RNG
    }

    #[test]
    /// Test that key derivation is consistent and sensitive to inputs
    /// This verifies that our key derivation works as expected for authentication
    fn test_key_derivation_properties() {
        // Test case: same passphrase and salt should yield same key
        let passphrase = "TestPassphrase123!";
        let salt = generate_random_salt();

        let key1 = derive_key_from_passphrase(passphrase, &salt);
        let key2 = derive_key_from_passphrase(passphrase, &salt);

        assert_eq!(key1, key2, "Same passphrase and salt should yield same key");

        // Test case: different passphrases should yield different keys
        let alt_passphrase = "DifferentPassword456!";
        let key3 = derive_key_from_passphrase(alt_passphrase, &salt);

        assert_ne!(
            key1, key3,
            "Different passphrases should yield different keys"
        );

        // Test case: same passphrase with different salts should yield different keys
        let alt_salt = generate_random_salt();
        let key4 = derive_key_from_passphrase(passphrase, &alt_salt);

        assert_ne!(
            key1, key4,
            "Same passphrase with different salts should yield different keys"
        );

        // Test case: key should be exactly 32 bytes (256 bits) for AES-256
        assert_eq!(key1.len(), 32, "Derived key should be 32 bytes");

        // Test case: small changes in passphrase should result in completely different keys
        let similar_passphrase = "TestPassphrase123@"; // Just one character different
        let key5 = derive_key_from_passphrase(similar_passphrase, &salt);

        assert_ne!(
            key1, key5,
            "Similar passphrases should yield completely different keys"
        );

        // Test how many bits differ - there should be many
        let different_bits = key1
            .iter()
            .zip(key5.iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum::<u32>();

        // With good key derivation, about half the bits should differ
        assert!(
            different_bits > 64,
            "Similar passphrases should result in keys that differ in many bits"
        );
    }
}
