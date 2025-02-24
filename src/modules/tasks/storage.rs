use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use super::model::Task;
use crate::modules::auth::User;
use crate::modules::encryption::keys::derive_key_from_passphrase;
use crate::modules::encryption::{decrypt_data, encrypt_data};

/// Custom error type for task operations
#[derive(Debug)]
pub enum TaskError {
    FilePermissionDenied(String),
    FileNotFound(String),
    InvalidData(String),
    EncryptionError(String),
    IoError(io::Error),
}

// Implement conversion from io::Error to TaskError
impl From<io::Error> for TaskError {
    fn from(error: io::Error) -> Self {
        TaskError::IoError(error)
    }
}

// Implementation of Display trait for TaskError
impl std::fmt::Display for TaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskError::FilePermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            TaskError::FileNotFound(msg) => write!(f, "File not found: {}", msg),
            TaskError::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            TaskError::EncryptionError(msg) => write!(f, "Encryption error: {}", msg),
            TaskError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

/// Function to check file permissions for a user
fn check_file_permissions(_user: &User, file_path: &str) -> Result<(), TaskError> {
    let _metadata = match std::fs::metadata(file_path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // If file doesn't exist, we'll create it later
            return Ok(());
        }
        Err(e) => {
            return Err(TaskError::IoError(e));
        }
    };

    // Check if file is owned by current process
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let current_uid = nix::unistd::getuid().as_raw();

        if _metadata.uid() != current_uid {
            return Err(TaskError::FilePermissionDenied(format!(
                "File {} is not owned by current user",
                file_path
            )));
        }
    }

    // Check if file is writable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if _metadata.permissions().mode() & 0o200 == 0 {
            return Err(TaskError::FilePermissionDenied(format!(
                "File {} is not writable",
                file_path
            )));
        }
    }

    Ok(())
}

/// Function to check if the passphrase is correct
pub fn is_passphrase_correct(user: &User, passphrase: &str) -> bool {
    match File::open(&user.tasks_file) {
        Ok(mut file) => {
            let mut file_data = Vec::new();
            if let Err(_) = file.read_to_end(&mut file_data) {
                return false;
            }

            if file_data.len() >= 32 {
                let salt = file_data[..16].to_vec();
                let iv = file_data[16..32].to_vec();
                let encrypted_data = &file_data[32..];

                let encryption_key = derive_key_from_passphrase(passphrase, &salt);
                decrypt_data(encrypted_data, &encryption_key, &iv).is_ok()
            } else {
                false
            }
        }
        Err(_) => true, // Return true if file doesn't exist (new user)
    }
}

/// Function to load tasks from the user-specific encrypted file
pub fn load_tasks_from_file(
    user: &User,
    passphrase: &str,
) -> Result<HashMap<String, Task>, TaskError> {
    // Check file permissions first
    check_file_permissions(user, &user.tasks_file)?;

    let mut tasks = HashMap::new();

    // Attempt to open the user's specific task file
    let file_data = match File::open(&user.tasks_file) {
        Ok(mut file) => {
            let mut data = Vec::new();
            file.read_to_end(&mut data)?;
            data
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(tasks); // Return empty HashMap for new users
        }
        Err(e) => {
            return Err(TaskError::IoError(e));
        }
    };

    // Check if file has minimum required data (salt + iv)
    if file_data.len() < 32 {
        return Err(TaskError::InvalidData("File data is too short".to_string()));
    }

    let salt = file_data[..16].to_vec();
    let iv = file_data[16..32].to_vec();
    let encrypted_data = &file_data[32..];

    // Derive encryption key from user's passphrase
    let encryption_key = derive_key_from_passphrase(passphrase, &salt);
    let decrypted_data = decrypt_data(encrypted_data, &encryption_key, &iv)
        .map_err(|e| TaskError::EncryptionError(e))?;

    tasks =
        serde_json::from_str(&decrypted_data).map_err(|e| TaskError::InvalidData(e.to_string()))?;

    Ok(tasks)
}

/// Function to save tasks to the user-specific encrypted file
pub fn save_tasks_to_file(
    tasks: &HashMap<String, Task>,
    user: &User,
    passphrase: &str,
) -> Result<(), TaskError> {
    // Check file permissions first
    check_file_permissions(user, &user.tasks_file)?;

    // Convert tasks to JSON string
    let data =
        serde_json::to_string_pretty(tasks).map_err(|e| TaskError::InvalidData(e.to_string()))?;

    // Generate new IV and salt for each save
    let iv = crate::modules::encryption::keys::generate_random_iv();
    let salt = crate::modules::encryption::keys::generate_random_salt();

    // Derive encryption key from user's passphrase
    let encryption_key = derive_key_from_passphrase(passphrase, &salt);

    // Encrypt the task data
    let encrypted_data = encrypt_data(&data, &encryption_key, &iv);

    // Combine salt, IV, and encrypted data
    let mut file_data = Vec::new();
    file_data.extend_from_slice(&salt);
    file_data.extend_from_slice(&iv);
    file_data.extend_from_slice(&encrypted_data);

    // Write to user's specific task file
    File::create(&user.tasks_file)
        .and_then(|mut file| file.write_all(&file_data))
        .map_err(TaskError::IoError)?;

    println!("Changes successfully saved to file {}.", user.tasks_file);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tempfile::NamedTempFile;

    fn create_test_user_with_task_file() -> (User, NamedTempFile, String) {
        let task_file = NamedTempFile::new().unwrap();
        let task_file_path = task_file.path().to_str().unwrap().to_string();

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let user = User {
            username: "TestUser".to_string(),
            username_normalized: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "dummy_hash".to_string(),
            created_at: current_time,
            last_login: current_time,
            failed_attempts: 0,
            last_failed_attempt: 0,
            tasks_file: task_file_path.clone(),
            last_activity: current_time,
            verification_status: crate::modules::auth::store::VerificationStatus::Verified,
        };

        (user, task_file, task_file_path)
    }

    #[test]
    fn test_task_file_operations() {
        let (user, _temp_file, _) = create_test_user_with_task_file();
        let password = "TestPassword123!";

        let mut tasks = HashMap::new();
        tasks.insert(
            "Test Task".to_string(),
            Task {
                name: "Test Task".to_string(),
                description: "Test Description".to_string(),
                priority: "High".to_string(),
                completed: false,
                progress_percent: 50,
                progress_bar_style: "simple".to_string(),
            },
        );

        // Test saving tasks
        let save_result = save_tasks_to_file(&tasks, &user, password);
        assert!(save_result.is_ok());

        // Test loading tasks
        let loaded_tasks = load_tasks_from_file(&user, password).unwrap();
        assert_eq!(loaded_tasks.len(), 1);
        assert!(loaded_tasks.contains_key("Test Task"));

        let loaded_task = loaded_tasks.get("Test Task").unwrap();
        assert_eq!(loaded_task.name, "Test Task");
        assert_eq!(loaded_task.progress_percent, 50);
    }

    #[test]
    fn test_wrong_password_load() {
        let (user, _temp_file, _) = create_test_user_with_task_file();
        let correct_password = "TestPassword123!";
        let wrong_password = "WrongPassword123!";

        // Create and save task with correct password
        let mut tasks = HashMap::new();
        tasks.insert(
            "Task1".to_string(),
            Task {
                name: "Task1".to_string(),
                description: "Description".to_string(),
                priority: "High".to_string(),
                completed: false,
                progress_percent: 0,
                progress_bar_style: "simple".to_string(),
            },
        );

        let save_result = save_tasks_to_file(&tasks, &user, correct_password);
        assert!(save_result.is_ok());

        // Try to load with wrong password
        let load_result = load_tasks_from_file(&user, wrong_password);
        assert!(load_result.is_err());

        // Should still be able to load with correct password
        let load_result = load_tasks_from_file(&user, correct_password);
        assert!(load_result.is_ok());
    }

    #[test]
    fn test_passphrase_verification() {
        let (user, _temp_file, _) = create_test_user_with_task_file();
        let password = "TestPassword123!";

        // Create and save a task
        let mut tasks = HashMap::new();
        tasks.insert(
            "Task1".to_string(),
            Task {
                name: "Task1".to_string(),
                description: "Description".to_string(),
                priority: "High".to_string(),
                completed: false,
                progress_percent: 0,
                progress_bar_style: "simple".to_string(),
            },
        );

        let save_result = save_tasks_to_file(&tasks, &user, password);
        assert!(save_result.is_ok());

        // Verify correct passphrase returns true
        assert!(is_passphrase_correct(&user, password));

        // Verify incorrect passphrase returns false
        assert!(!is_passphrase_correct(&user, "WrongPassword123!"));
    }
}
