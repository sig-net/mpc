use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub static TIMINGS: std::sync::LazyLock<Mutex<HashMap<String, Vec<Duration>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

pub struct Timer {
    start: Instant,
    label: String,
}

impl Timer {
    pub fn new(label: &str) -> Self {
        Self {
            start: Instant::now(),
            label: label.to_string(),
        }
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        let mut timings = TIMINGS.lock().unwrap();
        timings.entry(self.label.clone()).or_insert_with(Vec::new).push(duration);
    }
}

pub fn print_timing_report() {
    let timings = TIMINGS.lock().unwrap();
    if timings.is_empty() {
        println!("No timings recorded.");
        return;
    }

    println!("\n=== MPC Node Timing Report ===");
    for (label, durations) in timings.iter() {
        let count = durations.len();
        let total: Duration = durations.iter().sum();
        let avg = total / count as u32;
        let min = durations.iter().min().unwrap();
        let max = durations.iter().max().unwrap();

        println!("{}:", label);
        println!("  Count: {}", count);
        println!("  Total: {:.3}s", total.as_secs_f64());
        println!("  Average: {:.3}s", avg.as_secs_f64());
        println!("  Min: {:.3}s", min.as_secs_f64());
        println!("  Max: {:.3}s", max.as_secs_f64());
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_timing_collection() {
        // Clear any existing timings
        TIMINGS.lock().unwrap().clear();

        // Create some timers
        {
            let _t1 = Timer::new("test_timer");
            thread::sleep(Duration::from_millis(10));
        }

        {
            let _t2 = Timer::new("test_timer");
            thread::sleep(Duration::from_millis(20));
        }

        {
            let _t3 = Timer::new("another_timer");
            thread::sleep(Duration::from_millis(5));
        }

        let timings = TIMINGS.lock().unwrap();
        assert!(timings.contains_key("test_timer"));
        assert!(timings.contains_key("another_timer"));
        assert_eq!(timings["test_timer"].len(), 2);
        assert_eq!(timings["another_timer"].len(), 1);

        // Check that durations are reasonable
        for duration in &timings["test_timer"] {
            assert!(*duration >= Duration::from_millis(10));
            assert!(*duration < Duration::from_millis(50)); // Allow some tolerance
        }
    }
}