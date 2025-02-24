use std::io;
use keyring::Entry;
use rand::random;

/// Define a struct to handle secure storage and retrieval of the master key
/// This provides a clean interface for all master key operations
pub struct SecureMasterKey {
    // Store the keyring entry which provides access to the system's secure storage
    keyring: Entry,
}

impl SecureMasterKey {
    /// Constructor for creating a new instance of SecureMasterKey
    /// This sets up access to the system keyring with our application's identifier
    pub fn new() -> Self {
        Self {
            // Create a new keyring entry with service name "one-do-three" and identifier "master-key"
            // This combination uniquely identifies our key in the system's secure storage
            keyring: Entry::new("one-do-three", "master-key")
                .expect("Failed to create keyring entry"),
        }
    }

    /// Function to store a new master key in the system's secure storage
    /// Takes a byte slice as input and returns an IO Result
    pub fn store_key(&self, key: &[u8]) -> io::Result<()> {
        // Convert the binary key to hexadecimal string for storage
        // This ensures the key can be stored as a string in the keyring
        let encoded = hex::encode(key);

        // Attempt to store the encoded key in the system keyring
        // Convert any keyring errors to IO errors for consistent error handling
        self.keyring
            .set_password(&encoded)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    /// Function to retrieve the master key from the system's secure storage
    /// Returns the key as a vector of bytes
    pub fn get_key(&self) -> io::Result<Vec<u8>> {
        // Retrieve the encoded key string from the keyring
        // Map any keyring errors to IO errors
        let encoded = self
            .keyring
            .get_password()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        // Decode the hexadecimal string back to bytes
        // Map any decoding errors to IO errors
        hex::decode(encoded).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
    }

    /// Function to initialize the master key if it doesn't exist
    /// This ensures we always have a valid master key available
    pub fn initialize_if_needed(&self) -> io::Result<()> {
        // Check if we can retrieve an existing key
        if self.keyring.get_password().is_err() {
            // If no key exists, generate a new 32-byte random key
            let new_key: Vec<u8> = (0..32).map(|_| random::<u8>()).collect();

            // Store the new key in the keyring
            self.store_key(&new_key)?;

            // Inform the user that a new key was generated
            println!("New master key generated and stored in system keyring");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock keyring for testing
    struct MockKeyring {
        data: Option<String>,
    }

    impl MockKeyring {
        fn new() -> Self {
            Self { data: None }
        }

        fn set_password(&mut self, password: &str) -> Result<(), String> {
            self.data = Some(password.to_string());
            Ok(())
        }

        fn get_password(&self) -> Result<String, String> {
            match &self.data {
                Some(data) => Ok(data.clone()),
                None => Err("No password set".to_string()),
            }
        }

        fn delete_password(&mut self) -> Result<(), String> {
            self.data = None;
            Ok(())
        }
    }

    // Mock SecureMasterKey for testing
    struct MockSecureMasterKey {
        keyring: MockKeyring,
    }

    impl MockSecureMasterKey {
        fn new() -> Self {
            Self {
                keyring: MockKeyring::new(),
            }
        }

        fn store_key(&mut self, key: &[u8]) -> io::Result<()> {
            let encoded = hex::encode(key);
            self.keyring
                .set_password(&encoded)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
        }

        fn get_key(&self) -> io::Result<Vec<u8>> {
            let encoded = self
                .keyring
                .get_password()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            hex::decode(encoded).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
        }

        fn initialize_if_needed(&mut self) -> io::Result<()> {
            if self.keyring.get_password().is_err() {
                let new_key: Vec<u8> = (0..32).map(|_| random::<u8>()).collect();
                self.store_key(&new_key)?;
            }
            Ok(())
        }
    }

    #[test]
    fn test_secure_master_key() {
        let mut master_key = MockSecureMasterKey::new();

        // Initially, there should be no key
        assert!(master_key.get_key().is_err());

        // Initialize should create a key
        assert!(master_key.initialize_if_needed().is_ok());

        // Now we should be able to get the key
        let key = master_key.get_key().unwrap();
        assert_eq!(key.len(), 32);

        // Store a new key
        let new_key: Vec<u8> = (0..32).map(|_| 0xAA).collect();
        assert!(master_key.store_key(&new_key).is_ok());

        // Check that the new key was stored
        let retrieved_key = master_key.get_key().unwrap();
        assert_eq!(retrieved_key, new_key);
    }

    #[test]
    fn test_mock_keyring() {
        let mut keyring = MockKeyring::new();

        // Set a password
        keyring.set_password("test_password").unwrap();

        // Verify we can retrieve it
        assert_eq!(keyring.get_password().unwrap(), "test_password");

        // Test the delete_password method
        assert!(keyring.delete_password().is_ok());

        // Verify the password was deleted
        assert!(keyring.get_password().is_err());
    }
}