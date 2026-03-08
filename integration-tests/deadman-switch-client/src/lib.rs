use anyhow::{Context, Result};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tokio::time::sleep;

#[derive(Clone)]
pub struct DeadmanSwitchClient {
    base_url: String,
    client: Client,
}

#[derive(Serialize)]
struct RegisterRequest {
    pids: Vec<u32>,
}

impl DeadmanSwitchClient {
    pub fn new(port: u16) -> Self {
        Self {
            base_url: format!("http://localhost:{}", port),
            client: Client::new(),
        }
    }

    pub async fn check_or_spawn_service(port: u16) -> Result<Self> {
        let client = Self::new(port);

        // Try to connect to existing service
        if client.is_healthy().await {
            return Ok(client);
        }

        // Spawn new service
        println!("Spawning deadman switch service on port {}", port);

        // Locate the python service directory
        // Assuming we are in the workspace root or the test binary is run from somewhere predictable?
        // Let's try to find it relative to CARGO_MANIFEST_DIR
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        // manifest_dir is .../integration-tests/deadman-switch-client
        // service is .../integration-tests/deadman-switch
        let service_dir = manifest_dir
            .parent()
            .context("Failed to get parent of CARGO_MANIFEST_DIR")?
            .join("deadman-switch");

        if !service_dir.exists() {
            anyhow::bail!("Deadman switch service directory not found at {:?}", service_dir);
        }

        let _child = Command::new("python3")
            .arg("-m")
            .arg("uvicorn")
            .arg("main:app")
            .arg("--host")
            .arg("0.0.0.0")
            .arg("--port")
            .arg(port.to_string())
            .current_dir(&service_dir)
            .stdout(Stdio::null()) // Or Piped/Inherit if we want logs
            .stderr(Stdio::inherit())
            .spawn()
            .context("Failed to spawn deadman switch service")?;

        // Wait for it to be healthy
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            if client.is_healthy().await {
                return Ok(client);
            }
            sleep(Duration::from_millis(200)).await;
        }

        anyhow::bail!("Timed out waiting for deadman switch service to start");
    }

    pub async fn is_healthy(&self) -> bool {
        match self.client.get(format!("{}/health", self.base_url)).send().await {
            Ok(resp) => resp.status() == StatusCode::OK,
            Err(_) => false,
        }
    }

    pub async fn register_processes(&self, pids: Vec<u32>) -> Result<()> {
        let req = RegisterRequest { pids };
        let resp = self.client.post(format!("{}/register", self.base_url))
            .json(&req)
            .send()
            .await
            .context("Failed to send register request")?;

        if !resp.status().is_success() {
            anyhow::bail!("Register request failed with status: {}", resp.status());
        }
        Ok(())
    }

    pub async fn ping(&self) -> Result<()> {
        let resp = self.client.post(format!("{}/ping", self.base_url))
            .send()
            .await
            .context("Failed to send ping request")?;

        if !resp.status().is_success() {
            anyhow::bail!("Ping request failed with status: {}", resp.status());
        }
        Ok(())
    }
}
