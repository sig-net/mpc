use anyhow::Context;
use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use near_workspaces::{
    network::Sandbox,
    types::{KeyType, SecretKey},
    Account, AccountId, Worker,
};
use rand::Rng;
use std::sync::{Mutex, Once};
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};
use tracing_subscriber::EnvFilter;

/// Tracks ports already handed out by `pick_unused_port` within this process
/// to prevent the OS from recycling the same ephemeral port for multiple nodes.
static ALLOCATED_PORTS: Mutex<Option<HashSet<u16>>> = Mutex::new(None);

static INIT: Once = Once::new();

/// Call at least once in every test to see tracing output
pub fn init_tracing_log() {
    INIT.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_thread_ids(true)
            .with_env_filter(EnvFilter::from_default_env());

        subscriber.init();
    });
}

pub async fn vote_join(
    accounts: &[&Account],
    mpc_contract: &AccountId,
    account_id: &AccountId,
) -> anyhow::Result<()> {
    let vote_futures = accounts.iter().map(|account| {
        tracing::info!("{} voting for new participant {}", account.id(), account_id);
        account
            .call(mpc_contract, "vote_join")
            .args_json(serde_json::json!({
                "candidate": account_id
            }))
            .transact()
    });

    let mut errs = Vec::new();
    for result in futures::future::join_all(vote_futures).await {
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(err) => {
                errs.push(anyhow::anyhow!("workspaces/rpc failed: {err:?}"));
                continue;
            }
        };

        if !outcome.failures().is_empty() {
            errs.push(anyhow::anyhow!(
                "contract(vote_join) failure: {:?}",
                outcome.failures()
            ))
        }
    }

    if !errs.is_empty() {
        let err = format!("failed to vote_join: {errs:#?}");
        tracing::warn!(err);
        anyhow::bail!(err);
    }

    Ok(())
}

pub async fn vote_leave(
    accounts: &[&Account],
    mpc_contract: &AccountId,
    account_id: &AccountId,
) -> anyhow::Result<()> {
    let vote_futures = accounts
        .iter()
        .filter(|account| account.id() != account_id)
        .map(|account| {
            account
                .call(mpc_contract, "vote_leave")
                .args_json(serde_json::json!({
                    "kick": account_id
                }))
                .transact()
        })
        .collect::<Vec<_>>();

    let mut kicked = false;
    let mut errs = Vec::new();
    for result in futures::future::join_all(vote_futures).await {
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(err) => {
                errs.push(anyhow::anyhow!("workspaces/rpc failed: {err:?}"));
                continue;
            }
        };

        if !outcome.failures().is_empty() {
            errs.push(anyhow::anyhow!(
                "contract(vote_leave) failure: {:?}",
                outcome.failures()
            ))
        } else {
            kicked = kicked || outcome.json::<bool>().unwrap();
        }
    }

    if !errs.is_empty() {
        let err = format!("failed to vote_leave: {errs:#?}");
        tracing::warn!(err);
        anyhow::bail!(err);
    }

    if !kicked {
        let err = "failed to vote_leave on number of votes";
        tracing::warn!(err);
        anyhow::bail!(err);
    }

    Ok(())
}

/// Send `vote_threshold` for every participant and verify the contract
/// transitions into resharing with the new threshold.
pub async fn vote_threshold(
    accounts: &[&Account],
    mpc_contract: &AccountId,
    new_threshold: u64,
) -> anyhow::Result<()> {
    let vote_futures = accounts.iter().map(|account| {
        tracing::info!(
            "{} voting for new threshold {}",
            account.id(),
            new_threshold
        );
        account
            .call(mpc_contract, "vote_threshold")
            .args_json(serde_json::json!({
                "new_threshold": new_threshold
            }))
            .transact()
    });

    let mut started_resharing = false;
    let mut errs = Vec::new();
    for result in futures::future::join_all(vote_futures).await {
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(err) => {
                errs.push(anyhow::anyhow!("workspaces/rpc failed: {err:?}"));
                continue;
            }
        };

        if !outcome.failures().is_empty() {
            errs.push(anyhow::anyhow!(
                "contract(vote_threshold) failure: {:?}",
                outcome.failures()
            ))
        } else {
            started_resharing = started_resharing || outcome.json::<bool>().unwrap_or(false);
        }
    }

    if !errs.is_empty() {
        let err = format!("failed to vote_threshold: {errs:#?}");
        tracing::warn!(err);
        anyhow::bail!(err);
    }

    if !started_resharing {
        let err = "failed to vote_threshold: network did not start resharing";
        tracing::warn!(err);
        anyhow::bail!(err);
    }

    Ok(())
}

pub async fn get<U>(uri: U) -> anyhow::Result<StatusCode>
where
    Uri: TryFrom<U>,
    <Uri as TryFrom<U>>::Error: Into<hyper::http::Error>,
{
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::empty())
        .context("failed to build the request")?;

    let client = Client::new();
    let response = client
        .request(req)
        .await
        .context("failed to send the request")?;
    Ok(response.status())
}

pub async fn is_port_available(port: u16) -> bool {
    is_port_available_sync(port)
}

fn is_port_available_sync(port: u16) -> bool {
    let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, port);
    std::net::TcpListener::bind(addr).is_ok()
}

fn reserve_port_block(start: u16, len: usize) -> bool {
    if len == 0 {
        return false;
    }

    let end = start as usize + len - 1;
    if end > u16::MAX as usize {
        return false;
    }

    let end = end as u16;

    let mut guard = ALLOCATED_PORTS.lock().unwrap();
    let set = guard.get_or_insert_with(HashSet::new);

    for port in start..=end {
        if set.contains(&port) || !is_port_available_sync(port) {
            return false;
        }
    }

    for port in start..=end {
        set.insert(port);
    }

    true
}

/// Returns the range of ports allocated to this process's slice of the port range.
/// This ensures that each process gets a unique subset of the port range, preventing conflicts between parallel test processes.
fn process_port_slice() -> std::ops::RangeInclusive<u16> {
    const SLICE_LEN: u16 = 160;
    const NUM_SLICES: u32 = 100;
    const BASE: u16 = 16_000;

    // Use the process ID and the NEXTEST_RUN_ID environment variable to determine a unique slice for this process.
    let pid = std::process::id();
    let execution_id = std::env::var("NEXTEST_RUN_ID")
        .ok()
        .and_then(|id| id.parse::<u32>().ok())
        .unwrap_or(0);

    let unique_id = (pid ^ execution_id) % NUM_SLICES;
    let start = BASE + (unique_id as u16) * SLICE_LEN;
    start..=start + SLICE_LEN - 1
}

/// Request an unused port, guaranteed unique within this process and
/// allocated from this process's slice of the port range.
pub async fn pick_unused_port() -> anyhow::Result<u16> {
    let slice = process_port_slice();
    let (lo, hi) = (*slice.start(), *slice.end());
    let span = (hi - lo) as u32;
    let offset = rand::thread_rng().gen_range(0..=span);

    for i in 0..=span {
        // reserve_port_block checks both the in-process dedup set and that the
        // port is actually bindable right now.
        let port = lo + ((offset + i) % (span + 1)) as u16;
        if reserve_port_block(port, 1) {
            return Ok(port);
        }
    }

    // Slice exhausted: fall back to an OS-assigned ephemeral port with the
    // original drop-and-dedup behavior.
    // Port 0 means the OS gives us an unused port.
    // Important to use localhost as using 0.0.0.0 leads to users getting brief firewall popups to
    // allow inbound connections on macOS.
    let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0);
    loop {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let port = listener.local_addr()?.port();
        drop(listener);

        if reserve_port_block(port, 1) {
            return Ok(port);
        }
        // Port was already handed out; drop this listener and retry.
    }
}

/// Request an unused contiguous port block from the OS, guaranteed unique within this process.
pub async fn pick_preferred_or_unused_port_block(preferred: u16, len: usize) -> u16 {
    assert!(len > 0, "port block length must be greater than zero");
    assert!(
        len <= u16::MAX as usize + 1,
        "port block length must be at most {}",
        u16::MAX as usize + 1
    );

    let max_start = u16::MAX as usize + 1 - len;
    let preferred_start = preferred.max(1) as usize;

    if preferred_start <= max_start && reserve_port_block(preferred_start as u16, len) {
        return preferred_start as u16;
    }

    if len == 1 {
        return pick_unused_port().await.unwrap_or(preferred.max(1));
    }

    if preferred_start < max_start {
        for start in (preferred_start + 1)..=max_start {
            if reserve_port_block(start as u16, len) {
                return start as u16;
            }
        }
    }

    for start in 1..preferred_start.min(max_start + 1) {
        if reserve_port_block(start as u16, len) {
            return start as u16;
        }
    }

    panic!("failed to allocate a contiguous block of {len} ports");
}

pub async fn pick_preferred_or_unused_port(preferred: u16) -> u16 {
    pick_preferred_or_unused_port_block(preferred, 1).await
}

/// Wait until the node's web server answers `GET /` with 200.
pub async fn ping_until_ok(
    process: &mut async_process::Child,
    addr: &str,
    timeout: u64,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(timeout);
    loop {
        match process.try_status() {
            Ok(Some(status)) => {
                anyhow::bail!(
                    "node process exited with {status} while waiting for its web server on {addr}"
                );
            }
            Ok(None) => {}
            Err(err) => {
                anyhow::bail!("failed to check node process status while pinging {addr}: {err}");
            }
        }

        if let Ok(status) = get(addr).await {
            if status == StatusCode::OK {
                return Ok(());
            }
        }

        if Instant::now() >= deadline {
            anyhow::bail!(
                "node web server on {addr} did not respond within {timeout}s \
                 (process still running; likely failed to bind its web port)"
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

// Account with short name for testing
pub async fn dev_gen_indexed(worker: &Worker<Sandbox>, index: usize) -> anyhow::Result<Account> {
    let random_chars: String = (0..5)
        .map(|_| {
            let c = rand::thread_rng().gen_range(b'a'..=b'z');
            c as char
        })
        .collect();
    let account_id = format!("{index}-{random_chars}");
    let account_id: AccountId = account_id.try_into().expect("Failed to create Acc ID");
    let sk = SecretKey::from_seed(KeyType::ED25519, "seed");
    let account = worker
        .create_tla(account_id.clone(), sk)
        .await?
        .into_result()?;
    Ok(account)
}

#[cfg(test)]
mod tests {
    use super::{pick_preferred_or_unused_port, pick_preferred_or_unused_port_block};

    #[tokio::test]
    async fn preferred_port_zero_is_not_returned() {
        let port = pick_preferred_or_unused_port(0).await;
        let next = pick_preferred_or_unused_port(port).await;

        assert_ne!(port, 0);
        assert_ne!(next, port);
    }

    #[tokio::test]
    async fn preferred_block_zero_is_not_returned() {
        let port = pick_preferred_or_unused_port_block(0, 2).await;
        let next = pick_preferred_or_unused_port_block(port, 2).await;

        assert_ne!(port, 0);
        assert_ne!(next, port);
    }
}
