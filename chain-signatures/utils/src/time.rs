use std::time::{SystemTime, UNIX_EPOCH};

/// Current time in seconds since the UNIX epoch.
pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
