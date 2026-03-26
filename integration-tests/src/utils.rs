use anyhow::Context;
use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use near_workspaces::{
    network::Sandbox,
    types::{KeyType, SecretKey},
    Account, AccountId, Worker,
};
use rand::Rng;
use std::sync::Once;
use tracing_subscriber::EnvFilter;

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
    let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, port);
    tokio::net::TcpListener::bind(addr).await.is_ok()
}

/// Request an unused port from the OS.
pub async fn pick_unused_port() -> anyhow::Result<u16> {
    // Port 0 means the OS gives us an unused port
    // Important to use localhost as using 0.0.0.0 leads to users getting brief firewall popups to
    // allow inbound connections on macOS
    let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let port = listener.local_addr()?.port();
    Ok(port)
}

pub fn pick_unused_port_block(start: u16, width: u16) -> anyhow::Result<u16> {
    for base in start..=u16::MAX.saturating_sub(width) {
        let mut tcp_listeners = Vec::with_capacity(width as usize);
        let mut udp_sockets = Vec::with_capacity(width as usize);
        let mut available = true;

        for offset in 0..width {
            let port = base + offset;

            match std::net::TcpListener::bind(("0.0.0.0", port)) {
                Ok(listener) => tcp_listeners.push(listener),
                Err(_) => {
                    available = false;
                    break;
                }
            }

            match std::net::UdpSocket::bind(("0.0.0.0", port)) {
                Ok(socket) => udp_sockets.push(socket),
                Err(_) => {
                    available = false;
                    break;
                }
            }
        }

        if available {
            return Ok(base);
        }
    }

    anyhow::bail!("no free port block of width {width} found starting from {start}")
}

pub async fn pick_preferred_or_unused_port(preferred: u16) -> u16 {
    // Try preferred port first
    if is_port_available(preferred).await {
        return preferred;
    }
    pick_unused_port().await.unwrap_or(preferred)
}

pub async fn ping_until_ok(addr: &str, timeout: u64) -> anyhow::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(timeout), async {
        loop {
            match get(addr).await {
                Ok(status) if status == StatusCode::OK => break,
                _ => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
            }
        }
    })
    .await?;
    Ok(())
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
