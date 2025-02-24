use chrono::{DateTime, Local, TimeZone, Utc};
use std::time::{SystemTime, UNIX_EPOCH};

/// Function to format timestamp as readable date
pub fn format_timestamp(timestamp: u64) -> String {
    DateTime::from_timestamp(timestamp as i64, 0)
        .unwrap_or_default()
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

/// Get current Unix timestamp
pub fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Format duration in seconds to human readable string
pub fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{} seconds", seconds)
    } else if seconds < 3600 {
        format!("{} minutes", seconds / 60)
    } else if seconds < 86400 {
        format!("{} hours", seconds / 3600)
    } else {
        format!("{} days", seconds / 86400)
    }
}

/// Convert UTC timestamp to local time string
pub fn utc_to_local(timestamp: u64) -> String {
    let utc_time = Utc.timestamp_opt(timestamp as i64, 0).unwrap();
    let local_time: DateTime<Local> = DateTime::from(utc_time);
    local_time.format("%Y-%m-%d %H:%M:%S %Z").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_formatting() {
        let timestamp = 1609459200; // 2021-01-01 00:00:00
        let formatted = format_timestamp(timestamp);
        assert_eq!(formatted, "2021-01-01 00:00:00");
    }

    #[test]
    fn test_current_timestamp() {
        let timestamp = get_current_timestamp();
        assert!(timestamp > 0);
        // Verify timestamp is recent (within last minute)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(now - timestamp < 60);
    }

    #[test]
    fn test_duration_formatting() {
        assert_eq!(format_duration(30), "30 seconds");
        assert_eq!(format_duration(90), "1 minutes");
        assert_eq!(format_duration(3600), "1 hours");
        assert_eq!(format_duration(86400), "1 days");
    }

    #[test]
    fn test_utc_to_local() {
        let timestamp = get_current_timestamp();
        let local_time = utc_to_local(timestamp);
        assert!(!local_time.is_empty());
        assert!(local_time.contains(":"));
        assert!(local_time.len() > 15);
    }
}
