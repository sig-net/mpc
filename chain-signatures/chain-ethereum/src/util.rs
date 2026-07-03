use std::time::{SystemTime, UNIX_EPOCH};

// TODO: this is a duplicate of the same function in `mpc-node`, consider moving to shared crate like `mpc-utils` or something.
pub fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
