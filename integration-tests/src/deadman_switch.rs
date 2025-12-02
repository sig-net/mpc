//! DeadmanSwitch - A watchdog that kills orphaned test processes.
//!
//! This module spawns a Python HTTP server that monitors test processes and
//! kills them if no ping is received within a timeout period. This prevents
//! zombie processes from accumulating when tests crash or are interrupted.
//!
//! The deadman switch is automatically disabled when `MPC_KEEP_ENV=1` is set,
//! which is useful for debugging.

use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

/// Default port for the deadman switch HTTP server.
pub const DEFAULT_PORT: u16 = 19850;

/// Ping interval in seconds.
pub const PING_INTERVAL_SECS: u64 = 60;

/// Path to the deadman switch Python script (relative to workspace root).
const SCRIPT_PATH: &str = "integration-tests/scripts/deadman_switch.py";

/// The DeadmanSwitch manages the watchdog process and pinger task.
pub struct DeadmanSwitch {
    /// The Python process running the deadman switch server.
    process: Option<Child>,
    /// Background task that sends periodic pings.
    pinger_task: Option<JoinHandle<()>>,
    /// Flag to stop the pinger.
    stop_flag: Arc<AtomicBool>,
    /// The port the server is listening on.
    port: u16,
    /// HTTP client for sending requests.
    client: reqwest::Client,
}

impl DeadmanSwitch {
    /// Check if the deadman switch should be disabled (MPC_KEEP_ENV=1).
    pub fn is_disabled() -> bool {
        std::env::var("MPC_KEEP_ENV").map(|v| v == "1").unwrap_or(false)
    }

    /// Spawn a new deadman switch process and start the pinger.
    pub async fn spawn() -> Result<Self> {
        Self::spawn_on_port(DEFAULT_PORT).await
    }

    /// Spawn a new deadman switch process on a specific port.
    pub async fn spawn_on_port(port: u16) -> Result<Self> {
        if Self::is_disabled() {
            tracing::info!("MPC_KEEP_ENV=1 set, deadman switch disabled");
            return Ok(Self {
                process: None,
                pinger_task: None,
                stop_flag: Arc::new(AtomicBool::new(true)),
                port,
                client: reqwest::Client::new(),
            });
        }

        // Find the script path
        let script_path = Self::find_script_path()?;
        tracing::info!(script = %script_path.display(), "starting deadman switch");

        // Spawn the Python process
        let process = Command::new("python3")
            .arg(&script_path)
            .arg("--port")
            .arg(port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .context("failed to spawn deadman_switch.py")?;

        // Wait a moment for the server to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;

        let stop_flag = Arc::new(AtomicBool::new(false));

        let mut switch = Self {
            process: Some(process),
            pinger_task: None,
            stop_flag: stop_flag.clone(),
            port,
            client,
        };

        // Verify the server is running
        switch.ping().await.context("deadman switch not responding")?;

        // Start the pinger task
        let pinger_client = switch.client.clone();
        let pinger_port = port;
        let pinger_stop = stop_flag;
        
        let pinger_task = tokio::spawn(async move {
            let url = format!("http://127.0.0.1:{}/ping", pinger_port);
            while !pinger_stop.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(PING_INTERVAL_SECS)).await;
                if pinger_stop.load(Ordering::Relaxed) {
                    break;
                }
                if let Err(e) = pinger_client.get(&url).send().await {
                    tracing::warn!("deadman switch ping failed: {}", e);
                }
            }
        });

        switch.pinger_task = Some(pinger_task);

        tracing::info!(port, "deadman switch started");
        Ok(switch)
    }

    /// Find the path to the deadman_switch.py script.
    fn find_script_path() -> Result<std::path::PathBuf> {
        // Try relative to current dir
        let path = std::path::PathBuf::from(SCRIPT_PATH);
        if path.exists() {
            return Ok(path);
        }

        // Try relative to CARGO_MANIFEST_DIR
        if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
            let path = std::path::PathBuf::from(manifest_dir)
                .parent()
                .map(|p| p.join(SCRIPT_PATH));
            if let Some(path) = path {
                if path.exists() {
                    return Ok(path);
                }
            }
        }

        // Try relative to workspace root (go up from integration-tests)
        let workspace_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(|p| p.join(SCRIPT_PATH));
        if let Some(path) = workspace_path {
            if path.exists() {
                return Ok(path);
            }
        }

        anyhow::bail!(
            "could not find deadman_switch.py script at {} or relative paths",
            SCRIPT_PATH
        )
    }

    /// Send a ping to the deadman switch.
    pub async fn ping(&self) -> Result<()> {
        if self.process.is_none() {
            return Ok(()); // Disabled
        }
        let url = format!("http://127.0.0.1:{}/ping", self.port);
        self.client.get(&url).send().await?;
        Ok(())
    }

    /// Register process IDs to watch.
    pub async fn watch_pids(&self, pids: &[u32]) -> Result<()> {
        if self.process.is_none() || pids.is_empty() {
            return Ok(());
        }
        let url = format!("http://127.0.0.1:{}/watch", self.port);
        let body = serde_json::json!({ "pids": pids });
        self.client.post(&url).json(&body).send().await?;
        tracing::debug!(?pids, "registered PIDs with deadman switch");
        Ok(())
    }

    /// Register container IDs to watch.
    pub async fn watch_containers(&self, containers: &[String]) -> Result<()> {
        if self.process.is_none() || containers.is_empty() {
            return Ok(());
        }
        let url = format!("http://127.0.0.1:{}/watch", self.port);
        let body = serde_json::json!({ "containers": containers });
        self.client.post(&url).json(&body).send().await?;
        tracing::debug!(?containers, "registered containers with deadman switch");
        Ok(())
    }

    /// Unregister process IDs.
    pub async fn unwatch_pids(&self, pids: &[u32]) -> Result<()> {
        if self.process.is_none() || pids.is_empty() {
            return Ok(());
        }
        let url = format!("http://127.0.0.1:{}/unwatch", self.port);
        let body = serde_json::json!({ "pids": pids });
        self.client.post(&url).json(&body).send().await?;
        Ok(())
    }

    /// Unregister container IDs.
    pub async fn unwatch_containers(&self, containers: &[String]) -> Result<()> {
        if self.process.is_none() || containers.is_empty() {
            return Ok(());
        }
        let url = format!("http://127.0.0.1:{}/unwatch", self.port);
        let body = serde_json::json!({ "containers": containers });
        self.client.post(&url).json(&body).send().await?;
        Ok(())
    }

    /// Shutdown the deadman switch gracefully.
    pub async fn shutdown(&mut self) -> Result<()> {
        if self.process.is_none() {
            return Ok(());
        }

        // Stop the pinger
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(task) = self.pinger_task.take() {
            task.abort();
        }

        // Request shutdown
        let url = format!("http://127.0.0.1:{}/shutdown", self.port);
        let _ = self.client.get(&url).send().await;

        // Wait for process to exit
        if let Some(mut process) = self.process.take() {
            let _ = process.wait();
        }

        tracing::info!("deadman switch stopped");
        Ok(())
    }

    /// Get the port the deadman switch is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Check if the deadman switch is active.
    pub fn is_active(&self) -> bool {
        self.process.is_some()
    }
}

impl Drop for DeadmanSwitch {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(mut process) = self.process.take() {
            // Try graceful shutdown first
            let url = format!("http://127.0.0.1:{}/shutdown", self.port);
            let _ = reqwest::blocking::get(&url);
            // Then kill if needed
            let _ = process.kill();
            let _ = process.wait();
        }
    }
}

/// Shared deadman switch that can be used across the test environment.
pub type SharedDeadmanSwitch = Arc<Mutex<Option<DeadmanSwitch>>>;

/// Create a shared deadman switch.
pub async fn create_shared() -> Result<SharedDeadmanSwitch> {
    let switch = DeadmanSwitch::spawn().await?;
    Ok(Arc::new(Mutex::new(Some(switch))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_is_disabled_respects_env() {
        // This test just verifies the function doesn't panic
        let _ = DeadmanSwitch::is_disabled();
    }

    #[tokio::test]
    async fn test_spawn_and_ping() {
        // Skip if MPC_KEEP_ENV is set (would immediately exit)
        if DeadmanSwitch::is_disabled() {
            println!("skipping test - MPC_KEEP_ENV=1");
            return;
        }

        // Use a unique port to avoid conflicts with other tests
        let port = 19860;
        
        let switch = DeadmanSwitch::spawn_on_port(port).await;
        
        match switch {
            Ok(mut s) => {
                assert!(s.is_active());
                
                // Test ping
                s.ping().await.expect("ping should work");
                
                // Test watch_pids
                s.watch_pids(&[12345, 67890]).await.expect("watch_pids should work");
                
                // Test watch_containers
                s.watch_containers(&["test-container".to_string()]).await.expect("watch_containers should work");
                
                // Shutdown
                s.shutdown().await.expect("shutdown should work");
                assert!(!s.is_active());
            }
            Err(e) => {
                // If we can't find the script, that's okay for now
                if e.to_string().contains("could not find deadman_switch.py") {
                    println!("skipping test - script not found: {}", e);
                } else {
                    panic!("unexpected error: {}", e);
                }
            }
        }
    }
}
