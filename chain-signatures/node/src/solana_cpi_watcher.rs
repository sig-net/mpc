use std::collections::HashMap;
use std::ops::ControlFlow;
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::Result;
use anchor_client::anchor_lang;
use futures_util::StreamExt;
use solana_client::nonblocking::{pubsub_client::PubsubClient, rpc_client::RpcClient};
use solana_client::rpc_config::{
    RpcTransactionConfig, RpcTransactionLogsConfig, RpcTransactionLogsFilter,
};
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use tracing::warn;

/// Subscribe to CPI-emitted Anchor events for the given `program_id`.
///
/// The caller supplies a list of `log_hints` that must be present in a log entry to trigger
/// transaction inspection, a `parse_fn` that converts raw event discriminators + data into a list
/// of typed events, and an `handle_fn` that consumes each parsed event. Returning
/// `ControlFlow::Break(())` from the handler stops the subscription loop early.
pub async fn subscribe_anchor_cpi_events<T, P, H>(
    program_id: Pubkey,
    rpc_http_url: &str,
    rpc_ws_url: &str,
    log_hints: &[&str],
    mut parse_fn: P,
    mut handle_fn: H,
) -> Result<()>
where
    T: Send + 'static,
    P: FnMut(&[u8], &[u8]) -> Result<Vec<T>> + Send,
    H: FnMut(T, Signature, u64) -> ControlFlow<(), ()> + Send,
{
    let rpc_client = RpcClient::new(rpc_http_url.to_string());
    let pubsub_client = PubsubClient::new(rpc_ws_url).await?;

    let filter = RpcTransactionLogsFilter::Mentions(vec![program_id.to_string()]);
    let config = RpcTransactionLogsConfig {
        commitment: Some(CommitmentConfig::confirmed()),
    };
    let (mut stream, _unsubscribe) = pubsub_client.logs_subscribe(filter, config).await?;

    let mut seen: HashMap<Signature, Instant> = HashMap::new();
    let ttl = Duration::from_secs(30);
    let program_invoke_prefix = format!("Program {} invoke [", program_id);

    while let Some(response) = stream.next().await {
        if response.value.err.is_some() {
            continue;
        }

        let logs = &response.value.logs;
        if !logs_contain_hints(logs, log_hints)
            || !has_log_start_with(logs, &program_invoke_prefix)
        {
            continue;
        }

        let signature = match Signature::from_str(&response.value.signature) {
            Ok(sig) => sig,
            Err(err) => {
                warn!(?err, "invalid signature string from log subscription");
                continue;
            }
        };

        let now = Instant::now();
        seen.retain(|_, ts| now.duration_since(*ts) < ttl);
        if seen.contains_key(&signature) {
            continue;
        }
        seen.insert(signature, now);

        let events = match parse_anchor_cpi_events(&rpc_client, &signature, &program_id, &mut parse_fn).await {
            Ok(events) => events,
            Err(err) => {
                warn!(?err, signature = %signature, "failed to parse CPI events");
                continue;
            }
        };

        for event in events {
            if matches!(handle_fn(event, signature, response.context.slot), ControlFlow::Break(()))
            {
                return Ok(());
            }
        }
    }

    Ok(())
}

/// Fetch and decode CPI-emitted Anchor events for a specific transaction/signature.
///
/// The supplied `parse_fn` receives the event discriminator and event bytes, and
/// returns zero or more typed events derived from that payload.
pub async fn parse_anchor_cpi_events<T, P>(
    rpc_client: &RpcClient,
    signature: &Signature,
    program_id: &Pubkey,
    parse_fn: &mut P,
) -> Result<Vec<T>>
where
    P: FnMut(&[u8], &[u8]) -> Result<Vec<T>>,
{
    use solana_transaction_status::{UiInstruction, UiParsedInstruction};

    let tx = rpc_client
        .get_transaction_with_config(
            signature,
            RpcTransactionConfig {
                encoding: Some(solana_transaction_status::UiTransactionEncoding::JsonParsed),
                commitment: Some(CommitmentConfig::confirmed()),
                max_supported_transaction_version: Some(0),
            },
        )
        .await?;

    let Some(meta) = tx.transaction.meta else {
        return Ok(Vec::new());
    };

    let inner_ixs = match meta.inner_instructions {
        solana_transaction_status::option_serializer::OptionSerializer::Some(inner) => inner,
        _ => return Ok(Vec::new()),
    };

    let program_id_str = program_id.to_string();
    let anchor_event_tag = anchor_lang::event::EVENT_IX_TAG_LE;

    let mut out = Vec::new();
    for inner_ix_set in inner_ixs.iter() {
        for instruction in inner_ix_set.instructions.iter() {
            let UiInstruction::Parsed(UiParsedInstruction::PartiallyDecoded(parsed)) = instruction else {
                continue;
            };

            if parsed.program_id != program_id_str {
                continue;
            }

            let ix_data = match solana_sdk::bs58::decode(&parsed.data).into_vec() {
                Ok(data) => data,
                Err(err) => {
                    warn!(?err, "failed to decode CPI instruction data");
                    continue;
                }
            };

            if ix_data.len() < anchor_event_tag.len() + 8
                || !ix_data.starts_with(anchor_event_tag)
            {
                continue;
            }

            let discriminator = &ix_data[8..16];
            let event_data = &ix_data[16..];

            match parse_fn(discriminator, event_data) {
                Ok(mut events) => out.append(&mut events),
                Err(err) => warn!(?err, "failed to parse CPI event payload"),
            }
        }
    }

    Ok(out)
}

fn logs_contain_hints(logs: &[String], hints: &[&str]) -> bool {
    if hints.is_empty() {
        return true;
    }

    hints
        .iter()
        .any(|hint| logs.iter().any(|log| log.contains(hint)))
}

fn has_log_start_with(logs: &[String], prefix: &str) -> bool {
    logs.iter().any(|log| log.starts_with(prefix))
}
