//! Live-network gate for the wire layer: assemble, sign, broadcast, and
//! settle a `TriggerSmartContract` transaction against a configured
//! endpoint, plus duplicate-broadcast and codeless-address probes.
//!
//! The mock-backed sequence below runs in CI. The live legs need
//! `cargo test --test live_gate -- --ignored --nocapture` with
//! `TRON_ENDPOINT`, `TRON_PRIVATE_KEY` (32-byte hex, e.g.
//! `openssl rand -hex 32`), and optional `TRON_CONTRACT` (hex address;
//! default is Nile USDT, pinned on-chain by `name()` = "Tether USD"),
//! `TRON_API_KEY`, `TRON_POLL_SECS`, `TRON_DEADLINE_SECS`. A key with no
//! TRX stops the run after printing its address to fund at the faucet.

mod common;

use anyhow::{bail, Context};
use common::build_raw;
use k256::ecdsa::SigningKey;
use mpc_chain_tron::pb::{Message, RawTransaction};
use mpc_chain_tron::{
    parse_hex, BroadcastOutcome, NowBlock, TronAddress, TronConfig, TronHttp, TronReceipt,
};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use url::Url;

use alloy::primitives::{Address, B256, U256};
use alloy::sol_types::SolCall;

fn env_secs(name: &str, default: u64) -> anyhow::Result<Duration> {
    Ok(Duration::from_secs(match std::env::var(name) {
        Ok(value) => value
            .parse()
            .with_context(|| format!("{name}: not a number of seconds"))?,
        Err(_) => default,
    }))
}

/// Nile USDT; verified by `triggerconstantcontract name()` = "Tether USD".
const DEFAULT_CONTRACT: &str = "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf";

alloy::sol! {
    interface Trc20 {
        function transfer(address to, uint256 amount) external returns (bool);
    }
}

/// `transfer(address,uint256)` calldata: selector plus two padded words —
/// the exact shape of the recorded mainnet USDT transfers.
fn usdt_transfer_calldata(to: &TronAddress, amount: u64) -> Vec<u8> {
    Trc20::transferCall {
        to: Address::from_slice(&to.as_bytes()[1..]),
        amount: U256::from(amount),
    }
    .abi_encode()
}

fn transfer_topic() -> B256 {
    alloy::primitives::keccak256(b"Transfer(address,address,uint256)")
}

/// One gate run: connection, signer, and timing.
struct Gate {
    client: TronHttp,
    key: SigningKey,
    owner: TronAddress,
    contract: TronAddress,
    poll: Duration,
    deadline: Duration,
}

/// What the later probes reuse from the acceptance broadcast.
struct Broadcast {
    signed: Vec<u8>,
    reference: NowBlock,
    now_ms: i64,
}

/// keccak256 of the uncompressed public key, last 20 bytes — the EVM
/// form Tron prefixes with 0x41. Parity-checked against tronWeb.
fn derive_address(key: &SigningKey) -> Address {
    let public = key.verifying_key().to_encoded_point(false);
    let hash = alloy::primitives::keccak256(&public.as_bytes()[1..]);
    Address::from_slice(&hash[12..])
}

/// Signs the raw bytes: sha256 prehash, 65-byte `[r ‖ s ‖ v]` with the
/// recovery-id parity, returning the signed transaction and its txID.
fn sign(key: &SigningKey, raw_bytes: &[u8]) -> anyhow::Result<(Vec<u8>, [u8; 32])> {
    let digest = Sha256::digest(raw_bytes);
    let (signature, recovery) = key.sign_prehash_recoverable(&digest)?;
    let (r, s) = signature.split_bytes();
    let r: [u8; 32] = r.into();
    let s: [u8; 32] = s.into();
    let (signed, txid) =
        RawTransaction::parse(raw_bytes)?.sign_and_hash(&r, &s, u8::from(recovery.is_y_odd()))?;
    Ok((signed, txid))
}

impl Gate {
    /// Runs the sequence: acceptance, duplicate, then the codeless probe —
    /// which must come back `CONTRACT_VALIDATE_ERROR`, the classification
    /// recorded on Nile and mainnet.
    async fn run(&self) -> anyhow::Result<()> {
        println!("[gate] owner {} -> contract {}", self.owner, self.contract);
        let accepted = self.acceptance().await?;
        self.duplicate(&accepted.signed).await?;
        let probe = self.codeless(&accepted.reference, accepted.now_ms).await?;
        anyhow::ensure!(
            matches!(&probe, BroadcastOutcome::Rejected { code, .. }
                if code == "CONTRACT_VALIDATE_ERROR"),
            "codeless address: expected CONTRACT_VALIDATE_ERROR, got {probe:?}"
        );
        Ok(())
    }

    /// Acceptance probe: broadcast a USDT transfer, settle it, and check
    /// the txID and receipt classification. A zero-token balance reverts
    /// instead of settling successfully — both classify the receipt.
    async fn acceptance(&self) -> anyhow::Result<Broadcast> {
        let reference = self.client.get_now_block().await?;
        let now_ms = reference.timestamp as i64;
        let raw = build_raw(
            &self.owner,
            &self.contract,
            &usdt_transfer_calldata(&self.owner, 1),
            &reference,
            now_ms,
        );
        let raw_bytes = raw.encode_to_vec();
        let local_txid: [u8; 32] = Sha256::digest(&raw_bytes).into();
        let (signed, txid) = sign(&self.key, &raw_bytes)?;
        anyhow::ensure!(
            txid == local_txid,
            "txID must be sha256 of the raw bytes, signature aside"
        );
        println!(
            "[broadcast] reference block {}, txid {}",
            reference.number,
            hex::encode(txid)
        );
        match self.client.broadcast_transaction(&signed).await? {
            BroadcastOutcome::Accepted => println!("[broadcast] accepted"),
            other => bail!("[broadcast] {other:?}"),
        }
        let receipt = self.settle(&txid).await?;
        anyhow::ensure!(
            receipt.id == B256::from(txid),
            "receipt id must equal the txID"
        );
        let result = receipt
            .contract_ret
            .as_deref()
            .or(receipt.receipt_result.as_deref());
        anyhow::ensure!(
            matches!(result, Some("SUCCESS") | Some("REVERT")),
            "execution result {result:?}"
        );
        if result == Some("SUCCESS") {
            anyhow::ensure!(
                receipt
                    .logs
                    .first()
                    .is_some_and(|log| log.topics().first() == Some(&transfer_topic())),
                "expected the Transfer event"
            );
            println!(
                "[broadcast] settled, fee {} sun, {} log(s)",
                receipt.fee,
                receipt.logs.len()
            );
        } else {
            println!(
                "[broadcast] reverted, fee {} sun, resMessage {:?}",
                receipt.fee, receipt.res_message
            );
        }
        Ok(Broadcast {
            signed,
            reference,
            now_ms,
        })
    }

    /// Duplicate probe: the identical signed bytes again, rejected by
    /// txID — replay protection without a nonce, and an id the network
    /// never derives from the signature.
    async fn duplicate(&self, signed: &[u8]) -> anyhow::Result<()> {
        match self.client.broadcast_transaction(signed).await? {
            BroadcastOutcome::AlreadyKnown => {
                println!("[duplicate] rejected as DUP_TRANSACTION_ERROR")
            }
            other => bail!("[duplicate] expected the rejection, got {other:?}"),
        }
        Ok(())
    }

    /// Codeless-address probe: a call to an address with no code —
    /// recorded mainnet classification is CONTRACT_VALIDATE_ERROR.
    async fn codeless(
        &self,
        reference: &NowBlock,
        now_ms: i64,
    ) -> anyhow::Result<BroadcastOutcome> {
        let codeless = TronAddress::from_evm(Address::repeat_byte(0x33));
        let void = build_raw(&self.owner, &codeless, &[0u8; 4], reference, now_ms);
        let (void_signed, _) = sign(&self.key, &void.encode_to_vec())?;
        let probe = self.client.broadcast_transaction(&void_signed).await?;
        match &probe {
            BroadcastOutcome::Rejected { code, message } => {
                println!("[codeless] rejected {code}: {message}")
            }
            other => println!("[codeless] probe outcome: {other:?}"),
        }
        Ok(probe)
    }

    /// Polls the solidity router until the receipt appears (solidified);
    /// absence is pending, not an error.
    async fn settle(&self, txid: &[u8; 32]) -> anyhow::Result<TronReceipt> {
        let start = Instant::now();
        loop {
            if let Some(receipt) = self
                .client
                .get_transaction_info_solidity(&B256::from(*txid))
                .await?
            {
                println!(
                    "[settle] solidified in {:.1?} at block {}",
                    start.elapsed(),
                    receipt.block_number
                );
                return Ok(receipt);
            }
            anyhow::ensure!(
                start.elapsed() < self.deadline,
                "not solidified within {:?}",
                self.deadline
            );
            tokio::time::sleep(self.poll).await;
        }
    }
}

fn mock_config(endpoint: Url) -> TronConfig {
    TronConfig {
        endpoint,
        poll_interval: Duration::from_millis(10),
        request_timeout: Duration::from_secs(2),
        ..Default::default()
    }
}

/// A raw response body recorded from nile.trongrid.io; the mock below
/// serves these verbatim.
fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("tests/fixtures/nile/{name}.json"))
        .unwrap_or_else(|err| panic!("fixture {name}: {err}"))
}

#[tokio::test]
async fn relay_sequence_runs_against_recorded_nile_responses() {
    // Reference block from the recorded now block, so the signed bytes
    // answer to the recorded responses.
    let nowblock = fixture("nowblock");
    let now: serde_json::Value = serde_json::from_str(&nowblock).unwrap();
    let reference = NowBlock {
        block_id: now["blockID"].as_str().unwrap().parse().unwrap(),
        number: now["block_header"]["raw_data"]["number"].as_u64().unwrap(),
        timestamp: now["block_header"]["raw_data"]["timestamp"]
            .as_u64()
            .unwrap(),
    };

    let mut key_bytes = [0u8; 32];
    key_bytes[31] = 1;
    let key = SigningKey::from_bytes(&k256::FieldBytes::from(key_bytes)).unwrap();
    let owner = TronAddress::from_evm(derive_address(&key));
    let contract = DEFAULT_CONTRACT.parse().expect("pinned default contract");

    let calldata = usdt_transfer_calldata(&owner, 1);
    // A truncated amount word zero-pads on load to amount·2¹⁹² — always
    // reverting.
    assert_eq!(calldata.len(), 4 + 32 + 32);
    assert_eq!(
        calldata[..4],
        alloy::primitives::keccak256(b"transfer(address,uint256)")[..4]
    );

    let raw = build_raw(
        &owner,
        &contract,
        &calldata,
        &reference,
        reference.timestamp as i64,
    );
    let (signed, txid) = sign(&key, &raw.encode_to_vec()).unwrap();
    let codeless = TronAddress::from_evm(Address::repeat_byte(0x33));
    let void = build_raw(
        &owner,
        &codeless,
        &[0u8; 4],
        &reference,
        reference.timestamp as i64,
    );
    let (void_signed, _) = sign(&key, &void.encode_to_vec()).unwrap();

    // Patch the recorded receipt to match the txid of the signed transaction.
    let receipt = fixture("receipt-success");
    let recorded_id = serde_json::from_str::<serde_json::Value>(&receipt).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let receipt = receipt.replace(&recorded_id, &hex::encode(txid));

    let mut server = mockito::Server::new_async().await;
    let endpoint: Url = server.url().parse().unwrap();
    // Mockito answers the first stub whose expectation is still unmet:
    // accept's `expect(1)` hands the second identical broadcast to dup,
    // and the pending `{}` stub hands the first poll to the receipt.
    server
        .mock("POST", "/wallet/getnowblock")
        .with_body(nowblock)
        .create_async()
        .await;

    server
        .mock("POST", "/wallet/broadcasthex")
        .match_body(mockito::Matcher::Json(serde_json::json!({
            "transaction": hex::encode(&void_signed)
        })))
        .with_body(fixture("broadcast-codeless"))
        .create_async()
        .await;

    server
        .mock("POST", "/wallet/broadcasthex")
        .match_body(mockito::Matcher::Json(serde_json::json!({
            "transaction": hex::encode(&signed)
        })))
        .with_body(fixture("broadcast-accept"))
        .expect(1)
        .create_async()
        .await;

    server
        .mock("POST", "/wallet/broadcasthex")
        .match_body(mockito::Matcher::Json(serde_json::json!({
            "transaction": hex::encode(&signed)
        })))
        .with_body(fixture("broadcast-dup"))
        .create_async()
        .await;

    server
        .mock("POST", "/walletsolidity/gettransactioninfobyid")
        .match_body(mockito::Matcher::PartialJson(serde_json::json!({
            "value": hex::encode(txid)
        })))
        .with_body(fixture("receipt-pending"))
        .expect(1)
        .create_async()
        .await;

    server
        .mock("POST", "/walletsolidity/gettransactioninfobyid")
        .match_body(mockito::Matcher::PartialJson(serde_json::json!({
            "value": hex::encode(txid)
        })))
        .with_body(receipt)
        .create_async()
        .await;

    let gate = Gate {
        client: TronHttp::new(&mock_config(endpoint)).unwrap(),
        key,
        owner,
        contract,
        poll: Duration::from_millis(10),
        deadline: Duration::from_secs(2),
    };
    gate.run().await.unwrap();
}

#[tokio::test]
#[ignore = "live network: TRON_ENDPOINT, TRON_PRIVATE_KEY"]
async fn live_gate() -> anyhow::Result<()> {
    let endpoint: Url = std::env::var("TRON_ENDPOINT")?
        .parse()
        .context("TRON_ENDPOINT must be a url")?;
    let key_hex = std::env::var("TRON_PRIVATE_KEY").context("TRON_PRIVATE_KEY")?;
    let key_bytes: [u8; 32] = hex::decode(key_hex.trim_start_matches("0x"))?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            anyhow::anyhow!("TRON_PRIVATE_KEY: {} bytes, want 32", bytes.len())
        })?;
    let key = SigningKey::from_bytes(&k256::FieldBytes::from(key_bytes))?;
    let contract = match std::env::var("TRON_CONTRACT") {
        Ok(value) => TronAddress::from_evm(parse_hex(&value).context("TRON_CONTRACT")?),
        Err(_) => DEFAULT_CONTRACT
            .parse()
            .expect("pinned default contract parses"),
    };

    let poll = env_secs("TRON_POLL_SECS", 3)?;
    let deadline = env_secs("TRON_DEADLINE_SECS", 180)?;
    let config = TronConfig {
        endpoint,
        api_key: std::env::var("TRON_API_KEY").ok(),
        poll_interval: poll,
        ..Default::default()
    };
    let owner = TronAddress::from_evm(derive_address(&key));
    let client = TronHttp::new(&config)?;
    anyhow::ensure!(
        client.get_account_balance(&owner).await? > 0,
        "owner {owner} holds no TRX — fund it at the testnet faucet \
         (Nile: https://nileex.io), then re-run"
    );
    let gate = Gate {
        client,
        key,
        owner,
        contract,
        poll,
        deadline,
    };
    gate.run().await
}
