//! Rate-limits repeated log emission: one entry per key per interval, carrying
//! the occurrence count for the elapsed window.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const MAX_KEYS: usize = 1024;
const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);

struct KeyState {
    window_start: Instant,
    count: u64,
}

pub struct Throttle {
    interval: Duration,
    state: Mutex<HashMap<String, KeyState>>,
}

impl Throttle {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Records an occurrence for `key`. Returns the total occurrence count for
    /// the elapsed window when the entry should be logged, `None` while
    /// suppressed. The first occurrence of a key logs immediately.
    pub fn check(&self, key: &str) -> Option<u64> {
        self.check_at(key, Instant::now())
    }

    pub fn check_at(&self, key: &str, now: Instant) -> Option<u64> {
        let mut state = self.state.lock().unwrap();
        let Some(entry) = state.get_mut(key) else {
            if state.len() >= MAX_KEYS {
                return Some(1);
            }
            state.insert(
                key.to_owned(),
                KeyState {
                    window_start: now,
                    count: 1,
                },
            );
            return Some(1);
        };
        entry.count += 1;
        if now.saturating_duration_since(entry.window_start) >= self.interval {
            let count = entry.count;
            entry.count = 0;
            entry.window_start = now;
            Some(count)
        } else {
            None
        }
    }
}

static GLOBAL: OnceLock<Throttle> = OnceLock::new();

/// Checks the process-wide throttle (60s windows). Intended for log call sites:
///
/// ```ignore
/// if let Some(count) = mpc_utils::throttle::check("my-key") {
///     tracing::warn!(count, "repeated failure");
/// }
/// ```
pub fn check(key: &str) -> Option<u64> {
    GLOBAL
        .get_or_init(|| Throttle::new(DEFAULT_INTERVAL))
        .check(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_occurrence_logs_immediately() {
        let t = Throttle::new(Duration::from_secs(60));
        let now = Instant::now();
        assert_eq!(t.check_at("k", now), Some(1));
    }

    #[test]
    fn suppresses_within_window_and_reports_count_on_next() {
        let t = Throttle::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert_eq!(t.check_at("k", t0), Some(1));
        assert_eq!(t.check_at("k", t0 + Duration::from_secs(10)), None);
        assert_eq!(t.check_at("k", t0 + Duration::from_secs(59)), None);
        assert_eq!(t.check_at("k", t0 + Duration::from_secs(60)), Some(4));
        assert_eq!(t.check_at("k", t0 + Duration::from_secs(61)), None);
    }

    #[test]
    fn keys_are_independent() {
        let t = Throttle::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert_eq!(t.check_at("a", t0), Some(1));
        assert_eq!(t.check_at("b", t0), Some(1));
        assert_eq!(t.check_at("a", t0 + Duration::from_secs(1)), None);
    }

    #[test]
    fn key_cap_degrades_to_pass_through() {
        let t = Throttle::new(Duration::from_secs(60));
        let t0 = Instant::now();
        for i in 0..MAX_KEYS {
            assert_eq!(t.check_at(&i.to_string(), t0), Some(1));
        }
        assert_eq!(t.check_at("overflow", t0 + Duration::from_secs(1)), Some(1));
    }
}
