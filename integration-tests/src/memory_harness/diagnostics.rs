use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
use tokio_util::task::AbortOnDropHandle;

/// Human-friendly byte formatter (e.g. "12.34 MB", "1.20 GB").
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Instantaneous snapshot of process memory usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySnapshot {
    pub rss_bytes: u64,
    pub virtual_bytes: u64,
    #[serde(skip, default = "Instant::now")]
    pub timestamp: Instant,
}

impl MemorySnapshot {
    pub fn current() -> Self {
        let (rss, virt) = sample_current_process_memory();
        Self {
            rss_bytes: rss,
            virtual_bytes: virt,
            timestamp: Instant::now(),
        }
    }

    pub fn rss_human(&self) -> String {
        format_bytes(self.rss_bytes)
    }

    pub fn virtual_human(&self) -> String {
        format_bytes(self.virtual_bytes)
    }
}

/// Result summary for a memory benchmark scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySummary {
    pub scenario_name: String,
    pub iteration: usize,
    pub initial_rss: u64,
    pub baseline_rss: u64,
    pub peak_rss: u64,
    pub final_rss: u64,
    pub retained_rss: i64,
    pub drift_from_baseline: i64,
    pub peak_delta: u64,
    pub duration: Duration,
    pub operations: usize,
    pub ops_per_sec: f64,
    pub passed_leak_check: bool,
}

impl MemorySummary {
    #[allow(clippy::too_many_arguments)]
    pub fn calculate(
        scenario_name: impl Into<String>,
        iteration: usize,
        baseline_rss: u64,
        initial: MemorySnapshot,
        peak_rss: u64,
        final_snapshot: MemorySnapshot,
        duration: Duration,
        operations: usize,
        max_allowed_leak_bytes: u64,
    ) -> Self {
        let retained_rss = final_snapshot.rss_bytes as i64 - initial.rss_bytes as i64;
        let drift_from_baseline = final_snapshot.rss_bytes as i64 - baseline_rss as i64;
        let peak_delta = peak_rss.saturating_sub(initial.rss_bytes);
        let ops_per_sec = if duration.as_secs_f64() > 0.0 {
            operations as f64 / duration.as_secs_f64()
        } else {
            0.0
        };
        let passed_leak_check = retained_rss <= max_allowed_leak_bytes as i64;

        Self {
            scenario_name: scenario_name.into(),
            iteration,
            initial_rss: initial.rss_bytes,
            baseline_rss,
            peak_rss,
            final_rss: final_snapshot.rss_bytes,
            retained_rss,
            drift_from_baseline,
            peak_delta,
            duration,
            operations,
            ops_per_sec,
            passed_leak_check,
        }
    }

    pub fn to_csv_header() -> String {
        "scenario_name,iteration,initial_rss_bytes,baseline_rss_bytes,peak_rss_bytes,final_rss_bytes,retained_rss_bytes,drift_from_baseline_bytes,peak_delta_bytes,duration_ms,operations,ops_per_sec,passed_leak_check\n"
            .to_string()
    }

    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{},{},{},{},{},{:.2},{}\n",
            self.scenario_name,
            self.iteration,
            self.initial_rss,
            self.baseline_rss,
            self.peak_rss,
            self.final_rss,
            self.retained_rss,
            self.drift_from_baseline,
            self.peak_delta,
            self.duration.as_millis(),
            self.operations,
            self.ops_per_sec,
            self.passed_leak_check
        )
    }
}

/// High-frequency background memory tracker that monitors RSS spikes
/// during scenario execution.
pub struct HighWaterMarkTracker {
    peak_rss: Arc<AtomicU64>,
    stop_signal: Arc<AtomicBool>,
    handle: AbortOnDropHandle<()>,
}

impl HighWaterMarkTracker {
    /// Starts sampling current process memory at the specified interval.
    pub fn start(sample_interval: Duration) -> Self {
        let (current_rss, _) = sample_current_process_memory();
        let peak_rss = Arc::new(AtomicU64::new(current_rss));
        let stop_signal = Arc::new(AtomicBool::new(false));

        let peak_clone = Arc::clone(&peak_rss);
        let stop_clone = Arc::clone(&stop_signal);

        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(sample_interval);
            while !stop_clone.load(Ordering::Relaxed) {
                interval.tick().await;
                let (rss, _) = sample_current_process_memory();
                peak_clone.fetch_max(rss, Ordering::Relaxed);
            }
        });

        Self {
            peak_rss,
            stop_signal,
            handle: AbortOnDropHandle::new(task),
        }
    }

    /// Read the current peak RSS observed so far.
    pub fn current_peak(&self) -> u64 {
        self.peak_rss.load(Ordering::Relaxed)
    }

    /// Stop tracking and return the recorded peak RSS.
    pub fn stop(self) -> u64 {
        self.stop_signal.store(true, Ordering::Relaxed);
        let (final_sample, _) = sample_current_process_memory();
        self.peak_rss.fetch_max(final_sample, Ordering::Relaxed);
        let peak = self.peak_rss.load(Ordering::Relaxed);
        drop(self.handle);
        peak
    }
}

/// Samples the current process's RSS and virtual memory in bytes.
pub fn sample_current_process_memory() -> (u64, u64) {
    // 1. Try fast OS-native /proc read on Linux
    #[cfg(target_os = "linux")]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            let mut parts = statm.split_whitespace();
            if let (Some(virt_pages), Some(rss_pages)) = (parts.next(), parts.next()) {
                if let (Ok(v), Ok(r)) = (virt_pages.parse::<u64>(), rss_pages.parse::<u64>()) {
                    let page_size = unsafe {
                        let sz = libc::sysconf(libc::_SC_PAGESIZE);
                        if sz > 0 {
                            sz as u64
                        } else {
                            4096u64
                        }
                    };
                    return (r * page_size, v * page_size);
                }
            }
        }
    }

    // 2. Fall back to sysinfo (cross-platform, works on macOS, Linux, Windows)
    let pid = match sysinfo::get_current_pid() {
        Ok(p) => p,
        Err(_) => return (0, 0),
    };

    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::new().with_memory(),
    );

    if let Some(proc) = system.process(pid) {
        (proc.memory(), proc.virtual_memory())
    } else {
        (0, 0)
    }
}

/// Print formatted table header for benchmark results.
pub fn print_memory_summary_header() {
    println!(
        "{:<32} {:<5} {:<12} {:<12} {:<12} {:<14} {:<14} {:<10} {:<8}",
        "SCENARIO",
        "RUN",
        "INITIAL RSS",
        "PEAK RSS",
        "FINAL RSS",
        "RETAINED DELTA",
        "BASELINE DRIFT",
        "TIME",
        "STATUS"
    );
    println!("{}", "-".repeat(125));
}

/// Print formatted row for a single scenario summary.
pub fn print_memory_summary_row(summary: &MemorySummary) {
    let retained_str = if summary.retained_rss >= 0 {
        format!("+{}", format_bytes(summary.retained_rss as u64))
    } else {
        format!("-{}", format_bytes(summary.retained_rss.unsigned_abs()))
    };

    let drift_str = if summary.drift_from_baseline >= 0 {
        format!("+{}", format_bytes(summary.drift_from_baseline as u64))
    } else {
        format!(
            "-{}",
            format_bytes(summary.drift_from_baseline.unsigned_abs())
        )
    };

    let status = if summary.passed_leak_check {
        "PASS"
    } else {
        "WARN"
    };

    let time_str = format!("{:.2}s", summary.duration.as_secs_f64());

    println!(
        "{:<32} {:<5} {:<12} {:<12} {:<12} {:<14} {:<14} {:<10} {:<8}",
        summary.scenario_name,
        summary.iteration,
        format_bytes(summary.initial_rss),
        format_bytes(summary.peak_rss),
        format_bytes(summary.final_rss),
        retained_str,
        drift_str,
        time_str,
        status,
    );
}
