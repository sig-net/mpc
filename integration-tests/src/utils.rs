use anyhow::Context;
use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use near_workspaces::{Account, AccountId};

use std::path::Path;
use std::{fs, io};

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

pub fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    fs::create_dir_all(&dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}
