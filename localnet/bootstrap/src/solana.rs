//! The Solana leg of the localnet: installing the signet program, initialising its state,
//! and submitting signature requests against it.

use std::str::FromStr;
use std::time::{Duration, Instant};

use anchor_lang::{AnchorDeserialize, Discriminator};
use anyhow::{anyhow, Context};
use borsh::BorshSerialize;
use signet_program::{SignatureRequestedEvent, SignatureRespondedEvent};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_client::rpc_config::RpcTransactionConfig;
use solana_sdk::commitment_config::CommitmentConfig;
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{Keypair, SeedDerivable, Signature};
use solana_sdk::signer::Signer;
use solana_sdk::transaction::Transaction;
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_transaction_status::{UiInstruction, UiParsedInstruction, UiTransactionEncoding};

/// Address the bundled `chain_signatures.so` artifact must live at.
///
/// The artifact is prebuilt from sig-net/solana-signet-program 0.4.0 and its `declare_id!`
/// is enforced by anchor at instruction time, so it only works here. Note this is *not*
/// the id declared by `chain-signatures/contract-sol/src/lib.rs`, which is a different
/// build of the program.
pub const PROGRAM_ID: &str = "FR5pWwinRBn35GNhg7bsvw8Q13kRept2pm561DwZCQzT";

/// Seed for the deterministic requester used by the `sign` subcommand, matching the payer
/// the integration tests use.
pub const REQUESTER_SEED: [u8; 32] = [102u8; 32];

const PROGRAM_STATE_SEED: &[u8] = b"program-state";
const EVENT_AUTHORITY_SEED: &[u8] = b"__event_authority";

/// First eight bytes of sha256("global:sign").
const SIGN_DISCRIMINATOR: [u8; 8] = [5, 221, 155, 46, 237, 91, 28, 236];

/// `surfnet_writeProgram` accepts up to 5 MB per call. Chunking well below that keeps the
/// request bodies comfortable without needing many round trips.
const WRITE_PROGRAM_CHUNK: usize = 128 * 1024;

pub fn program_id() -> anyhow::Result<Pubkey> {
    Pubkey::from_str(PROGRAM_ID).context("PROGRAM_ID constant is not a valid pubkey")
}

pub fn requester_keypair() -> anyhow::Result<Keypair> {
    Keypair::from_seed(&REQUESTER_SEED).map_err(|err| anyhow!("building requester keypair: {err}"))
}

pub fn program_state_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[PROGRAM_STATE_SEED], program_id).0
}

pub fn event_authority_pda(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[EVENT_AUTHORITY_SEED], program_id).0
}

fn anchor_discriminator(name: &str) -> [u8; 8] {
    let hash = solana_sdk::hash::hash(format!("global:{name}").as_bytes()).to_bytes();
    hash[..8].try_into().expect("sha256 yields 32 bytes")
}

/// Arguments to the program's `sign` instruction, in declaration order.
#[derive(BorshSerialize)]
struct SignArgs {
    payload: [u8; 32],
    key_version: u32,
    path: String,
    algo: String,
    dest: String,
    params: String,
}

/// Minimal JSON-RPC caller for the `surfnet_*` cheat codes, which have no client binding.
async fn cheatcode(
    http: &reqwest::Client,
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let response: serde_json::Value = http
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("calling {method}"))?
        .json()
        .await
        .with_context(|| format!("decoding the {method} response"))?;

    if let Some(error) = response.get("error") {
        anyhow::bail!("{method} failed: {error}");
    }
    Ok(response)
}

/// Whether an executable program account already exists at `program_id`.
pub async fn is_program_installed(rpc: &RpcClient, program_id: &Pubkey) -> anyhow::Result<bool> {
    match rpc.get_account(program_id).await {
        Ok(account) => Ok(account.executable),
        Err(_) => Ok(false),
    }
}

/// Install a program binary at an arbitrary address using surfpool's `surfnet_writeProgram`
/// cheat code.
///
/// This replaces a real BPF loader deploy, so the localnet needs neither the Solana CLI nor
/// the program's own keypair. Surfpool creates both the program and programdata accounts.
pub async fn install_program(
    rpc: &RpcClient,
    rpc_url: &str,
    program_id: &Pubkey,
    binary: &[u8],
) -> anyhow::Result<()> {
    let http = reqwest::Client::new();
    let mut offset = 0usize;
    while offset < binary.len() {
        let end = (offset + WRITE_PROGRAM_CHUNK).min(binary.len());
        cheatcode(
            &http,
            rpc_url,
            "surfnet_writeProgram",
            serde_json::json!([program_id.to_string(), hex::encode(&binary[offset..end]), offset]),
        )
        .await?;
        tracing::debug!(offset, len = end - offset, "wrote program chunk");
        offset = end;
    }

    let account = rpc
        .get_account(program_id)
        .await
        .context("reading back the program account after writing it")?;
    if !account.executable {
        anyhow::bail!("program account at {program_id} is not executable after writing it");
    }
    tracing::info!(%program_id, bytes = binary.len(), "installed solana program");
    Ok(())
}

/// Fraction of the target balance below which an account is topped back up.
///
/// Topping up whenever the balance is merely under target would airdrop on every re-run,
/// since the requester has by then paid a signature deposit and the nodes have paid for
/// their `respond` transactions. Surfpool rate-limits airdrops, so those requests fail and
/// take the bootstrap down with them. A floor well under the target keeps re-runs quiet
/// while still refilling an account that has genuinely been drained.
const FUNDING_FLOOR_DIVISOR: u64 = 10;

/// Top an account up to `target_lamports` if its balance has fallen near empty.
///
/// The nodes pay for their own `respond` transactions and the requester pays the signature
/// deposit, so both need a balance. Doing this here rather than through surfpool's
/// `--airdrop` startup flags keeps the funding in one place and means the validator can be
/// restarted without the accounts silently losing their balance.
pub async fn ensure_funded(
    rpc: &RpcClient,
    pubkey: &Pubkey,
    target_lamports: u64,
) -> anyhow::Result<()> {
    let balance = rpc.get_balance(pubkey).await.unwrap_or(0);
    if balance >= target_lamports / FUNDING_FLOOR_DIVISOR {
        tracing::debug!(%pubkey, balance, "account is already funded");
        return Ok(());
    }
    let signature = rpc
        .request_airdrop(pubkey, target_lamports - balance)
        .await
        .with_context(|| format!("airdropping to {pubkey}"))?;
    rpc.confirm_transaction(&signature)
        .await
        .with_context(|| format!("confirming the airdrop to {pubkey}"))?;
    tracing::info!(%pubkey, lamports = target_lamports, "funded account");
    Ok(())
}

/// Whether the program's `program-state` PDA has already been initialised.
pub async fn is_program_initialized(rpc: &RpcClient, program_id: &Pubkey) -> anyhow::Result<bool> {
    let pda = program_state_pda(program_id);
    match rpc.get_account(&pda).await {
        Ok(account) => Ok(!account.data.is_empty()),
        Err(_) => Ok(false),
    }
}

/// Call the program's `initialize` instruction, which creates the `program-state` PDA.
pub async fn initialize(
    rpc: &RpcClient,
    payer: &Keypair,
    program_id: &Pubkey,
    signature_deposit: u64,
    chain_id: &str,
) -> anyhow::Result<Signature> {
    let mut data = anchor_discriminator("initialize").to_vec();
    signature_deposit.serialize(&mut data)?;
    chain_id.to_string().serialize(&mut data)?;

    let instruction = Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(program_state_pda(program_id), false),
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
        ],
        data,
    };

    let blockhash = rpc.get_latest_blockhash().await?;
    let transaction =
        Transaction::new_signed_with_payer(&[instruction], Some(&payer.pubkey()), &[payer], blockhash);
    let signature = rpc
        .send_and_confirm_transaction(&transaction)
        .await
        .context("sending the initialize transaction")?;
    tracing::info!(%signature, signature_deposit, chain_id, "initialised solana program state");
    Ok(signature)
}

/// Submit a signature request through the program's `sign` instruction.
///
/// The account list mirrors the program's `#[event_cpi]` requirement: the event authority
/// PDA and the program itself have to be passed for the CPI event to be emitted.
#[allow(clippy::too_many_arguments)]
pub async fn sign(
    rpc: &RpcClient,
    requester: &Keypair,
    program_id: &Pubkey,
    payload: [u8; 32],
    path: &str,
    key_version: u32,
    algo: &str,
    dest: &str,
    params: &str,
) -> anyhow::Result<Signature> {
    let mut data = SIGN_DISCRIMINATOR.to_vec();
    SignArgs {
        payload,
        key_version,
        path: path.to_string(),
        algo: algo.to_string(),
        dest: dest.to_string(),
        params: params.to_string(),
    }
    .serialize(&mut data)?;

    let instruction = Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new(program_state_pda(program_id), false),
            AccountMeta::new(requester.pubkey(), true),
            AccountMeta::new(requester.pubkey(), true),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(event_authority_pda(program_id), false),
            AccountMeta::new_readonly(*program_id, false),
        ],
        data,
    };

    let blockhash = rpc.get_latest_blockhash().await?;
    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&requester.pubkey()),
        &[requester],
        blockhash,
    );
    let signature = rpc
        .send_and_confirm_transaction(&transaction)
        .await
        .context("sending the sign transaction")?;
    tracing::info!(%signature, payload = hex::encode(payload), path, "submitted signature request");
    Ok(signature)
}

/// A CPI event decoded out of a transaction's inner instructions.
pub enum DecodedEvent {
    SignatureRequested(Box<SignatureRequestedEvent>),
    SignatureResponded(Box<SignatureRespondedEvent>),
}

/// Decode the anchor `emit_cpi!` events a transaction emitted.
///
/// This deliberately mirrors `parse_cpi_events` in the MPC node's Solana indexer: same
/// `JsonParsed` encoding, same walk over `meta.inner_instructions`, same `PartiallyDecoded`
/// shape, same `EVENT_IX_TAG_LE` prefix check. If this works against a given validator then
/// so does the node.
pub async fn decode_events(
    rpc: &RpcClient,
    signature: &Signature,
    program_id: &Pubkey,
) -> anyhow::Result<Vec<DecodedEvent>> {
    let tx = rpc
        .get_transaction_with_config(
            signature,
            RpcTransactionConfig {
                encoding: Some(UiTransactionEncoding::JsonParsed),
                commitment: Some(CommitmentConfig::confirmed()),
                max_supported_transaction_version: Some(0),
            },
        )
        .await
        .context("fetching the transaction to decode its events")?;

    let Some(meta) = tx.transaction.meta else {
        return Ok(Vec::new());
    };
    let OptionSerializer::Some(inner_sets) = meta.inner_instructions else {
        return Ok(Vec::new());
    };

    let program = program_id.to_string();
    let mut events = Vec::new();
    for set in &inner_sets {
        for instruction in &set.instructions {
            let UiInstruction::Parsed(UiParsedInstruction::PartiallyDecoded(ui)) = instruction
            else {
                continue;
            };
            if ui.program_id != program {
                continue;
            }
            let Ok(data) = solana_sdk::bs58::decode(&ui.data).into_vec() else {
                continue;
            };
            if !data.starts_with(anchor_lang::event::EVENT_IX_TAG_LE) || data.len() < 16 {
                continue;
            }
            let (discriminator, payload) = (&data[8..16], &data[16..]);
            if discriminator == SignatureRequestedEvent::DISCRIMINATOR {
                events.push(DecodedEvent::SignatureRequested(Box::new(
                    SignatureRequestedEvent::deserialize(&mut &payload[..])?,
                )));
            } else if discriminator == SignatureRespondedEvent::DISCRIMINATOR {
                events.push(DecodedEvent::SignatureResponded(Box::new(
                    SignatureRespondedEvent::deserialize(&mut &payload[..])?,
                )));
            }
        }
    }
    Ok(events)
}

/// Poll the program's recent transactions for a `SignatureRespondedEvent` matching
/// `request_id`, giving up after `timeout`.
pub async fn await_response(
    rpc: &RpcClient,
    program_id: &Pubkey,
    request_id: [u8; 32],
    timeout: Duration,
) -> anyhow::Result<SignatureRespondedEvent> {
    let deadline = Instant::now() + timeout;
    let mut seen = std::collections::HashSet::new();
    while Instant::now() < deadline {
        let signatures = rpc
            .get_signatures_for_address(program_id)
            .await
            .context("listing recent program transactions")?;
        for status in signatures {
            if !seen.insert(status.signature.clone()) {
                continue;
            }
            let Ok(signature) = Signature::from_str(&status.signature) else {
                continue;
            };
            for event in decode_events(rpc, &signature, program_id).await? {
                if let DecodedEvent::SignatureResponded(responded) = event {
                    if responded.request_id == request_id {
                        return Ok(*responded);
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!(
        "no SignatureRespondedEvent for request {} within {:?}",
        hex::encode(request_id),
        timeout
    )
}

/// Block until the validator answers `getHealth`, or give up after `timeout`.
pub async fn wait_until_healthy(rpc: &RpcClient, timeout: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    let mut last_error = None;
    while Instant::now() < deadline {
        match rpc.get_health().await {
            Ok(()) => return Ok(()),
            Err(err) => last_error = Some(err),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("solana rpc did not become healthy within {timeout:?}: {last_error:?}")
}
