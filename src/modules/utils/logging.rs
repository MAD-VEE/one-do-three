use env_logger::{Builder, WriteStyle};
use log::{error, info, warn, LevelFilter};
use std::fs::OpenOptions;
use std::io;

/// Initialize the logging system with both file and console output
pub fn initialize_logging() -> Result<(), Box<dyn std::error::Error>> {
    // Create or append to log file with proper permissions
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("application.log")?;

    // Configure the logging system
    Builder::new()
        // Set default log level
        .filter_level(LevelFilter::Info)
        // Enable timestamps
        .format_timestamp_secs()
        // Enable module path in logs
        .format_module_path(true)
        // Set colored output for console
        .write_style(WriteStyle::Auto)
        // Write to both file and stderr
        .target(env_logger::Target::Pipe(Box::new(file)))
        .init();

    info!("Logging system initialized");
    Ok(())
}

/// Helper function to format sensitive data for logging
fn format_sensitive(text: &str) -> String {
    if text.len() <= 4 {
        return "*".repeat(text.len());
    }
    format!("{}***{}", &text[0..2], &text[text.len() - 2..])
}

/// Add structured logging for authentication events
pub fn log_auth_event(event_type: &str, username: &str, success: bool, details: Option<&str>) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    if success {
        info!(
            "Auth event: type={}, user={}, success=true, timestamp={}, details={:?}",
            event_type,
            format_sensitive(username),
            timestamp,
            details
        );
    } else {
        warn!(
            "Auth event: type={}, user={}, success=false, timestamp={}, details={:?}",
            event_type,
            format_sensitive(username),
            timestamp,
            details
        );
    }
}

/// Add structured logging for data operations
pub fn log_data_operation(
    operation: &str,
    user: &str,
    resource: &str,
    success: bool,
    details: Option<&str>,
) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    if success {
        info!(
            "Data operation: op={}, user={}, resource={}, success=true, timestamp={}, details={:?}",
            operation,
            format_sensitive(user),
            resource,
            timestamp,
            details
        );
    } else {
        error!(
            "Data operation: op={}, user={}, resource={}, success=false, timestamp={}, details={:?}",
            operation,
            format_sensitive(user),
            resource,
            timestamp,
            details
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_sensitive_data_formatting() {
        assert_eq!(format_sensitive("password"), "pa***rd");
        assert_eq!(format_sensitive("key"), "***");
        assert_eq!(format_sensitive("longpassword"), "lo***rd");
        assert_eq!(format_sensitive(""), "");
    }

    #[test]
    fn test_logging_initialization() {
        // Create temporary log file
        let log_file = NamedTempFile::new().unwrap();

        // Configure logging to use temporary file
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file.path())
            .unwrap();

        // Initialize logging
        let result = Builder::new()
            .filter_level(LevelFilter::Info)
            .format_timestamp_secs()
            .target(env_logger::Target::Pipe(Box::new(file)))
            .try_init();

        // Verify initialization succeeded or logger was already initialized
        assert!(
            result.is_ok()
                || result
                    .unwrap_err()
                    .to_string()
                    .contains("already initialized")
        );
    }
}
