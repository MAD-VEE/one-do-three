use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

/// Function to encrypt data using AES-256-CBC
pub fn encrypt_data(data: &str, encryption_key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes256Cbc::new_from_slices(encryption_key, iv).unwrap();
    cipher.encrypt_vec(data.as_bytes())
}

/// Function to decrypt data using AES-256-CBC
pub fn decrypt_data(encrypted_data: &[u8], encryption_key: &[u8], iv: &[u8]) -> Result<String, String> {
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
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let iv: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        // Ensure key and iv are of correct length
        assert_eq!(encryption_key.len(), 32); // AES-256 needs a 32-byte key
        assert_eq!(iv.len(), 16);

        // Encrypt the data
        let encrypted_data = encrypt_data(original_data, &encryption_key, &iv);

        // Ensure encrypted data is not empty
        assert!(!encrypted_data.is_empty());
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
}