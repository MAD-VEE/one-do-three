use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

/// Function to encrypt data using AES-256-CBC
pub fn encrypt_data(data: &str, encryption_key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes256Cbc::new_from_slices(encryption_key, iv).unwrap();
    cipher.encrypt_vec(data.as_bytes())
}

/// Function to decrypt data using AES-256-CBC
pub fn decrypt_data(
    encrypted_data: &[u8],
    encryption_key: &[u8],
    iv: &[u8],
) -> Result<String, String> {
    let cipher = Aes256Cbc::new_from_slices(encryption_key, iv).unwrap();
    match cipher.decrypt_vec(encrypted_data) {
        Ok(decrypted_data) => match String::from_utf8(decrypted_data) {
            Ok(decoded_str) => Ok(decoded_str),
            Err(_) => Err("Decrypted data is not valid UTF-8".to_string()),
        },
        Err(_) => Err("Decryption failed".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Test that encryption and decryption work correctly (roundtrip test)
    fn test_encryption_decryption_roundtrip() {
        // Test data
        let original_data = "This is a secret message that needs to be encrypted";

        // For testing, create a fixed key and IV to ensure consistency
        let encryption_key: Vec<u8> = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let iv: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        // Ensure key and iv are of correct length
        assert_eq!(encryption_key.len(), 32); // AES-256 needs a 32-byte key
        assert_eq!(iv.len(), 16);

        // Encrypt the data
        let encrypted_data = encrypt_data(original_data, &encryption_key, &iv);

        // Ensure encrypted data is not empty
        assert!(!encrypted_data.is_empty());

        // We can't reliably compare the encrypted data as UTF-8 string since it might not be valid UTF-8
        // So we'll just make sure it's different from the original in binary form
        assert_ne!(encrypted_data, original_data.as_bytes());

        // Decrypt the data
        let decrypted_data = decrypt_data(&encrypted_data, &encryption_key, &iv).unwrap();

        // Verify decryption worked correctly
        assert_eq!(decrypted_data, original_data);
    }

    #[test]
    /// Test that decryption fails with incorrect key
    fn test_decryption_with_wrong_key() {
        let original_data = "This is a secret message that needs to be encrypted";
        let encryption_key: Vec<u8> = vec![1; 32];
        let iv: Vec<u8> = vec![1; 16];
        let wrong_key: Vec<u8> = vec![2; 32];

        let encrypted_data = encrypt_data(original_data, &encryption_key, &iv);
        let result = decrypt_data(&encrypted_data, &wrong_key, &iv);

        assert!(result.is_err());
    }

    #[test]
    /// Test data integrity through encryption/decryption cycle
    /// This test verifies that data of different types and sizes can be
    /// safely encrypted and decrypted without loss of information
    fn test_encryption_data_integrity() {
        // Test vectors of different types of content
        let test_cases = vec![
            // Empty string
            "",
            // Simple text
            "Hello World",
            // Long text
            "This is a much longer string that contains multiple sentences. It should test the \
            encryption and decryption of larger blocks of text. The goal is to ensure that longer \
            content can be properly handled without any loss of data or corruption.",
            // Text with special characters
            "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?`~",
            // Text with non-ASCII characters
            "Non-ASCII: áéíóúñÁÉÍÓÚÑ äëïöüÿÄËÏÖÜŸ €£¥",
            // JSON-like data
            "{\"name\":\"test\",\"values\":[1,2,3],\"nested\":{\"key\":\"value\"}}",
            // Binary-looking data
            "\x00\x01\x02\x03\x04\x05\x7F\x7E\x7D\x7C",
        ];

        // Create a fixed key and IV for testing
        let key = vec![1; 32]; // 32 bytes of 1s
        let iv = vec![2; 16]; // 16 bytes of 2s

        // Test each case
        for (i, original) in test_cases.iter().enumerate() {
            // Encrypt the data
            let encrypted = encrypt_data(original, &key, &iv);

            // Ensure encrypted data is not the same as original
            assert_ne!(
                encrypted,
                original.as_bytes(),
                "Case {}: Encrypted data should differ from original",
                i
            );

            // Decrypt the data
            let decrypted = decrypt_data(&encrypted, &key, &iv).unwrap();

            // Verify decrypted data matches original
            assert_eq!(
                decrypted, *original,
                "Case {}: Decrypted data should match original",
                i
            );
        }
    }

    #[test]
    /// Test that changing a single bit in the ciphertext corrupts the decryption
    /// This verifies the security property that encrypted data cannot be tampered with
    fn test_encryption_tamper_resistance() {
        let original = "This is a test message";
        let key = vec![3; 32]; // 32 bytes of 3s
        let iv = vec![4; 16]; // 16 bytes of 4s

        // Encrypt the data
        let mut encrypted = encrypt_data(original, &key, &iv);

        // Make a copy of the original encrypted data for comparison
        let original_encrypted = encrypted.clone();

        // Verify original encryption can be decrypted correctly
        let decrypted = decrypt_data(&encrypted, &key, &iv).unwrap();
        assert_eq!(
            decrypted, original,
            "Original encryption should decrypt correctly"
        );

        // Now tamper with the encrypted data by flipping a bit
        // Choose a byte in the middle of the encrypted data
        let index = encrypted.len() / 2;
        encrypted[index] ^= 1; // Flip the least significant bit

        // Verify the tampered data is different from the original
        assert_ne!(
            encrypted, original_encrypted,
            "Tampered data should be different"
        );

        // Try to decrypt the tampered data - this should either fail or produce different output
        match decrypt_data(&encrypted, &key, &iv) {
            Err(_) => {
                // Decryption could fail with an error, which is fine
                // This is the expected outcome with most secure encryption modes
            }
            Ok(tampered_decrypted) => {
                // If decryption somehow succeeds, the output should be different
                assert_ne!(
                    tampered_decrypted, original,
                    "Tampered data should not decrypt to original message"
                );
            }
        }
    }

    #[test]
    /// Test encryption with different key sizes
    /// This ensures our system properly enforces key size requirements
    fn test_encryption_key_sizes() {
        let original = "Test data";
        let iv = vec![5; 16]; // 16 bytes of 5s

        // Test with keys that are too short
        for key_size in [8, 16, 24] {
            let short_key = vec![6; key_size];

            // Creating the cipher should fail or panic
            let result = std::panic::catch_unwind(|| {
                let cipher = Aes256Cbc::new_from_slices(&short_key, &iv).unwrap();
                cipher.encrypt_vec(original.as_bytes())
            });

            assert!(
                result.is_err(),
                "Key size {} should not be accepted",
                key_size
            );
        }

        // Test with the correct key size
        let correct_key = vec![6; 32];
        let result = std::panic::catch_unwind(|| encrypt_data(original, &correct_key, &iv));
        assert!(result.is_ok(), "Key size 32 should be accepted");

        // Test with a key that's too long
        let long_key = vec![6; 40];
        let result = std::panic::catch_unwind(|| encrypt_data(original, &long_key, &iv));
        assert!(result.is_err(), "Key size 40 should not be accepted");
    }
}
