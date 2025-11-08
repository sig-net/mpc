use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::info;

pub static TIMINGS: std::sync::LazyLock<Mutex<HashMap<String, Vec<Duration>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

pub static ACCOUNT_ID: std::sync::LazyLock<Mutex<Option<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(None));

pub fn set_account_id(account_id: String) {
    *ACCOUNT_ID.lock().unwrap() = Some(account_id);
}

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
        timings
            .entry(self.label.clone())
            .or_insert_with(Vec::new)
            .push(duration);

        // Print timing data to stderr immediately for test capture
        eprintln!("TIMING: {} completed in {:.3}s", self.label, duration.as_secs_f64());

        // Write timing data to file immediately
        if let Some(account_id) = ACCOUNT_ID.lock().unwrap().as_ref() {
            let filename = format!("{}.timings.txt", account_id);
            if let Ok(mut file) = File::create(&filename) {
                let mut output = String::new();
                for (label, durations) in timings.iter() {
                    let count = durations.len();
                    let total: Duration = durations.iter().sum();
                    let avg = total / count as u32;
                    let min = durations.iter().min().unwrap();
                    let max = durations.iter().max().unwrap();

                    output.push_str(&format!("{}:\n  Count: {}\n  Total: {:.3}s\n  Average: {:.3}s\n  Min: {:.3}s\n  Max: {:.3}s\n\n",
                                           label, count, total.as_secs_f64(), avg.as_secs_f64(), min.as_secs_f64(), max.as_secs_f64()));
                }
                let _ = file.write_all(output.as_bytes());
            }
        }
    }
}

pub fn print_timing_report() {
    print_timing_report_with_account_id(None);
}

pub fn print_timing_report_with_account_id(account_id: Option<&str>) {
    let timings = TIMINGS.lock().unwrap();
    if timings.is_empty() {
        let msg = "No timings recorded.";
        info!("{}", msg);
        if let Some(account_id) = account_id {
            write_to_file(account_id, msg);
        }
        return;
    }

    let mut output = String::new();
    output.push_str("\n=== MPC Node Timing Report ===\n");
    for (label, durations) in timings.iter() {
        let count = durations.len();
        let total: Duration = durations.iter().sum();
        let avg = total / count as u32;
        let min = durations.iter().min().unwrap();
        let max = durations.iter().max().unwrap();

        output.push_str(&format!("{}:\n", label));
        output.push_str(&format!("  Count: {}\n", count));
        output.push_str(&format!("  Total: {:.3}s\n", total.as_secs_f64()));
        output.push_str(&format!("  Average: {:.3}s\n", avg.as_secs_f64()));
        output.push_str(&format!("  Min: {:.3}s\n", min.as_secs_f64()));
        output.push_str(&format!("  Max: {:.3}s\n", max.as_secs_f64()));
        output.push_str("\n");
    }

    info!("{}", output);

    if let Some(account_id) = account_id {
        write_to_file(account_id, &output);
    }
}

/// Print timing report immediately, useful for debugging or when process might be killed
pub fn print_timing_report_now() {
    print_timing_report_now_with_account_id(None);
}

pub fn print_timing_report_now_with_account_id(account_id: Option<&str>) {
    eprintln!("\n=== MPC Node Timing Report (Immediate) ===");
    let timings = TIMINGS.lock().unwrap();
    if timings.is_empty() {
        let msg = "No timings recorded.";
        eprintln!("{}", msg);
        if let Some(account_id) = account_id {
            write_to_file(account_id, msg);
        }
        return;
    }

    let mut output = String::new();
    for (label, durations) in timings.iter() {
        let count = durations.len();
        let total: Duration = durations.iter().sum();
        let avg = total / count as u32;
        let min = durations.iter().min().unwrap();
        let max = durations.iter().max().unwrap();

        let entry = format!("{}:\n  Count: {}\n  Total: {:.3}s\n  Average: {:.3}s\n  Min: {:.3}s\n  Max: {:.3}s\n\n",
                          label, count, total.as_secs_f64(), avg.as_secs_f64(), min.as_secs_f64(), max.as_secs_f64());
        eprintln!("{}", entry.trim_end());
        output.push_str(&entry);
    }

    if let Some(account_id) = account_id {
        write_to_file(account_id, &output);
    }
}

fn write_to_file(account_id: &str, content: &str) {
    let filename = format!("{}.timings.txt", account_id);
    if let Ok(mut file) = File::create(&filename) {
        if file.write_all(content.as_bytes()).is_ok() {
            eprintln!("Timing report written to {}", filename);
        } else {
            eprintln!("Failed to write timing report to {}", filename);
        }
    } else {
        eprintln!("Failed to create timing report file {}", filename);
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

    #[test]
    fn test_file_writing() {
        // Clear any existing timings
        TIMINGS.lock().unwrap().clear();

        // Create a timer
        {
            let _t = Timer::new("file_test_timer");
            thread::sleep(Duration::from_millis(5));
        }

        // Test file writing
        print_timing_report_now_with_account_id(Some("test.account.near"));

        // Check if file was created
        let filename = "test.account.near.timings.txt";
        assert!(std::path::Path::new(filename).exists(), "Timing file should be created");

        // Clean up
        let _ = std::fs::remove_file(filename);
    }
}
