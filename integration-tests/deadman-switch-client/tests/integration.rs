use anyhow::Result;
use deadman_switch_client::DeadmanSwitchClient;
use std::process::Command;
use std::thread;
use std::time::Duration;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;

#[tokio::test]
async fn test_deadman_switch_lifecycle() -> Result<()> {
    // Set a short timeout for the deadman switch
    std::env::set_var("DEADMAN_TIMEOUT", "2");

    // Start on a random-ish port or fixed port? Fixed for simplicity, but avoid collision.
    // Let's use 8001.
    let port = 8001;

    // 1. Ensure any previous instance is killed?
    // Ideally we'd find it, but for now assuming clean env or just relying on fast restart.
    // The service might already be running from a previous test run with a different timeout.
    // To be safe, we might want to kill it if we could check `lsof` or such, but let's assume `check_or_spawn` handles it.
    // Wait, `check_or_spawn` reuses if healthy. If we reuse one with default 60s timeout, our test will fail waiting 2s.
    // So we should try to ensure a fresh spawn if we depend on the timeout.
    // But `check_or_spawn_service` doesn't provide a way to force restart.
    // We can try to ping it and if it exists, maybe kill it?
    // Or just kill anything on port 8001 before starting.
    let _ = Command::new("fuser")
        .arg("-k")
        .arg(format!("{}/tcp", port))
        .output();

    // Give it a moment to die
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 2. Spawn the service
    let client = DeadmanSwitchClient::check_or_spawn_service(port).await?;

    // 3. Spawn a victim process
    let mut victim = Command::new("sleep")
        .arg("100")
        .spawn()
        .expect("Failed to spawn sleep");

    let pid = victim.id();
    println!("Spawned victim process with PID {}", pid);

    // 4. Register the victim
    client.register_processes(vec![pid]).await?;
    println!("Registered PID {}", pid);

    // 5. Ping and wait a bit (less than timeout)
    client.ping().await?;
    println!("Pinged. Waiting 1s...");
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Verify victim still alive
    // try_wait returns Ok(None) if still running
    match victim.try_wait() {
        Ok(Some(status)) => anyhow::bail!("Victim process died too early: {}", status),
        Ok(None) => println!("Victim process still alive (good)."),
        Err(e) => anyhow::bail!("Error checking victim process: {}", e),
    }

    // 6. Wait for timeout (2s total, we waited 1s. Let's wait 2 more seconds to be sure > 2s elapsed since ping)
    println!("Waiting for timeout...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // 7. Verify victim is dead
    // We expect it to be gone.
    // try_wait might pick it up if it was terminated.
    match victim.try_wait() {
        Ok(Some(_)) => println!("Victim process is dead (success)."),
        Ok(None) => {
             // It might take a moment if the system is slow, but 3s wait for 2s timeout should be enough.
             // Double check with kill(0) via nix to be sure?
             // Or just bail.

             // Try sending signal 0
             let pid_res = Pid::from_raw(pid as i32);
             match signal::kill(pid_res, None) {
                 Ok(_) => anyhow::bail!("Victim process survived deadman switch!"),
                 Err(_) => println!("Victim process confirmed dead via kill(0) check."),
             }

             // Also we should ensure to clean up the child handle in rust
             let _ = victim.kill();
        }
        Err(e) => println!("Error checking victim status: {}", e),
    }

    // Cleanup: Kill the service so next tests can start fresh
    let _ = Command::new("fuser")
        .arg("-k")
        .arg(format!("{}/tcp", port))
        .output();

    Ok(())
}
