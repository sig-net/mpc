use std::fmt;
use std::future::IntoFuture;
use std::str::FromStr;
use std::time::Duration;

use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::Provider;
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use anyhow::Context as _;
use cait_sith::FullSignature;
use elliptic_curve::sec1::FromEncodedPoint;
use generic_array::GenericArray;
use k256::Secp256k1;
use mpc_contract::errors;
use mpc_contract::primitives::SignRequest;
use mpc_crypto::ScalarExt;
use mpc_primitives::{SignId, Signature, LATEST_MPC_KEY_VERSION};
use near_crypto::InMemorySigner;
use near_fetch::ops::AsyncTransactionStatus;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::{Account, AccountId};
use rand::Rng;

use crate::actions::{self, wait_for};
use crate::cluster::Cluster;

// ChainSignatures contract ABI
alloy::sol! {
    #[sol(rpc)]
    interface ChainSignatures {
        struct SignRequest {
            bytes32 payload;
            string path;
            uint32 keyVersion;
            string algo;
            string dest;
            string params;
        }

        struct AffinePoint {
            uint256 x;
            uint256 y;
        }

        struct Signature {
            AffinePoint bigR;
            uint256 s;
            uint8 recoveryId;
        }

        function sign(SignRequest memory _request) external payable;
        function getSignatureDeposit() external view returns (uint256);

        event SignatureRequested(
            address indexed sender,
            bytes32 payload,
            uint32 keyVersion,
            uint256 deposit,
            uint256 chainId,
            string path,
            string algo,
            string dest,
            string params
        );

        event SignatureResponded(
            bytes32 indexed requestId,
            address indexed responder,
            Signature signature
        );
    }

    // Event encoding for request_id calculation
    event SignatureRequestedEncoding(
        address sender,
        bytes payload,
        string path,
        uint32 keyVersion,
        uint256 chainId,
        string algo,
        string dest,
        string params
    );
}

pub const SIGN_GAS: Gas = Gas::from_tgas(50);
pub const SIGN_DEPOSIT: NearToken = NearToken::from_yoctonear(1);

pub struct SignOutcome {
    /// The account that signed the payload.
    pub account: Account,

    /// Underlying rogue account that responded to the signature request if we wanted
    /// to test the rogue behavior.
    pub rogue: Option<Account>,

    pub payload: [u8; 32],
    pub payload_hash: [u8; 32],
    pub signature: FullSignature<Secp256k1>,
}

impl fmt::Debug for SignOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignOutcome")
            .field("account", &self.account)
            .field("rogue", &self.rogue)
            .field("payload", &self.payload)
            .field("payload_hash", &self.payload_hash)
            .field("signature_big_r", &self.signature.big_r)
            .field("signature_s", &self.signature.s)
            .finish()
    }
}

pub struct SignAction<'a> {
    nodes: &'a Cluster,
    count: usize,
    account: Option<Account>,
    payload: Option<[u8; 32]>,
    path: String,
    key_version: u32,
    gas: Gas,
    deposit: NearToken,
    execute_rogue: bool,
}

impl<'a> SignAction<'a> {
    pub fn new(nodes: &'a Cluster) -> Self {
        Self {
            nodes,
            count: 1,
            account: None,
            payload: None,
            path: "test".into(),
            key_version: LATEST_MPC_KEY_VERSION,
            gas: SIGN_GAS,
            deposit: SIGN_DEPOSIT,
            execute_rogue: false,
        }
    }
}

impl<'a> SignAction<'a> {
    /// Specify how many sign calls to be performed sequentially. If not specified, only
    /// one sign call will be performed.
    pub fn many(mut self, count: usize) -> Self {
        self.count = count;
        self
    }

    /// Set the account to sign with. If not set, a new account will be created.
    pub fn account(mut self, account: Account) -> Self {
        self.account = Some(account);
        self
    }

    /// Set the payload of this sign call. The keccak hash of this payload will be signed.
    pub fn payload(mut self, payload: [u8; 32]) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Set the derivation path of this sign call.
    pub fn path(mut self, path: &str) -> Self {
        self.path = path.into();
        self
    }

    /// Set the key version of this sign call. If not set, the default key version will be used.
    pub fn key_version(mut self, key_version: u32) -> Self {
        self.key_version = key_version;
        self
    }

    /// Set the gas for this sign call. If not set, the default gas will be used.
    pub fn gas(mut self, gas: Gas) -> Self {
        self.gas = gas;
        self
    }

    /// Set the deposit for this sign call. If not set, the default deposit will be used.
    pub fn deposit(mut self, deposit: NearToken) -> Self {
        self.deposit = deposit;
        self
    }

    pub fn rogue_responder(mut self) -> Self {
        self.execute_rogue = true;
        self
    }

    /// Create an ETH contract sign request builder
    pub fn eth(self) -> EthSignAction<'a> {
        EthSignAction::new(self)
    }
}

impl<'a> IntoFuture for SignAction<'a> {
    type Output = anyhow::Result<SignOutcome>;
    type IntoFuture =
        std::pin::Pin<Box<dyn std::future::Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.execute())
    }
}

// Helper methods for the SignAction
impl SignAction<'_> {
    async fn execute(mut self) -> anyhow::Result<SignOutcome> {
        let state = self.nodes.expect_running().await?;
        let account = self.account_or_new().await;
        let payload = self.payload_or_random();
        let payload_hash = self.payload_hash();
        let status = self.transact_sign(&account, payload_hash).await?;

        // We have to use seperate transactions because one could fail.
        // This leads to a potential race condition where this transaction could get sent after the signature completes, but I think that's unlikely
        let rogue = if self.execute_rogue {
            let (rogue, rogue_status) = self
                .transact_rogue_respond(payload_hash, account.id())
                .await?;
            let err = wait_for::rogue_message_responded(rogue_status).await?;

            assert!(err.contains(&errors::RespondError::InvalidSignature.to_string()));
            Some(rogue)
        } else {
            None
        };

        let signature = wait_for::signature_responded(status).await?;
        let mut mpc_pk_bytes = vec![0x04];
        mpc_pk_bytes.extend_from_slice(&state.public_key.as_bytes()[1..]);

        // Useful for populating the "signatures_havent_changed" test's hardcoded values
        // tracing::warn!(
        //     "ref_string: big_r={}, s={}, mpc_pk_bytes={}, payload_hash={}, account_id={}",
        //     hex::encode(signature.big_r.to_encoded_point(true).to_bytes()),
        //     hex::encode(signature.s.to_bytes()),
        //     hex::encode(&mpc_pk_bytes),
        //     hex::encode(payload_hash),
        //     account.id(),
        // );
        actions::validate_signature(account.id(), &mpc_pk_bytes, payload_hash, &signature).await?;

        Ok(SignOutcome {
            account,
            rogue,
            signature,
            payload,
            payload_hash,
        })
    }

    async fn account_or_new(&self) -> Account {
        if let Some(account) = &self.account {
            account.clone()
        } else {
            self.nodes.worker().dev_create_account().await.unwrap()
        }
    }

    fn payload_or_random(&mut self) -> [u8; 32] {
        let payload = self.payload.unwrap_or_else(|| rand::thread_rng().gen());
        self.payload = Some(payload);
        payload
    }

    fn payload_hash(&mut self) -> [u8; 32] {
        *alloy::primitives::keccak256(self.payload_or_random())
    }

    async fn transact_sign(
        &self,
        account: &Account,
        payload_hashed: [u8; 32],
    ) -> anyhow::Result<AsyncTransactionStatus> {
        let signer = InMemorySigner {
            account_id: account.id().clone(),
            public_key: account.secret_key().public_key().to_string().parse()?,
            secret_key: account.secret_key().to_string().parse()?,
        };
        let request = SignRequest {
            payload: payload_hashed,
            path: self.path.clone(),
            key_version: self.key_version,
        };
        let status = self
            .nodes
            .rpc_client
            .call(&signer, self.nodes.contract().id(), "sign")
            .args_json(serde_json::json!({
                "request": request,
            }))
            .gas(self.gas)
            .deposit(self.deposit)
            .transact_async()
            .await?;
        Ok(status)
    }

    async fn transact_rogue_respond(
        &self,
        payload_hash: [u8; 32],
        predecessor: &AccountId,
    ) -> anyhow::Result<(Account, AsyncTransactionStatus)> {
        let rogue = self.nodes.worker().dev_create_account().await?;
        let signer = InMemorySigner {
            account_id: rogue.id().clone(),
            public_key: rogue.secret_key().public_key().to_string().parse()?,
            secret_key: rogue.secret_key().to_string().parse()?,
        };

        let big_r = serde_json::from_value(
            "02EC7FA686BB430A4B700BDA07F2E07D6333D9E33AEEF270334EB2D00D0A6FEC6C".into(),
        )?; // Fake BigR
        let s = serde_json::from_value(
            "20F90C540EE00133C911EA2A9ADE2ABBCC7AD820687F75E011DFEEC94DB10CD6".into(),
        )?; // Fake S

        let signature = Signature {
            big_r,
            s,
            recovery_id: 0,
        };

        let sign_id = SignId::from_parts(predecessor, &payload_hash, &self.path, self.key_version);
        let status = self
            .nodes
            .rpc_client
            .call(&signer, self.nodes.contract().id(), "respond")
            .args_json(serde_json::json!({
                "sign_id": sign_id,
                "signature": signature,
            }))
            .max_gas()
            .transact_async()
            .await?;

        Ok((rogue, status))
    }
}

/// Ethereum contract signature request outcome
pub struct EthSignOutcome {
    pub signer_address: Address,
    pub contract_address: String,
    pub eth_tx_hash: Option<String>,
    pub deposit_amount: u64,
    pub signature: FullSignature<Secp256k1>,
    pub payload: [u8; 32],
    pub payload_hash: [u8; 32],
    pub algo: String,
    pub dest: String,
    pub params: String,
}

impl fmt::Debug for EthSignOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EthSignOutcome")
            .field("contract_address", &self.contract_address)
            .field("eth_tx_hash", &self.eth_tx_hash)
            .field("deposit_amount", &self.deposit_amount)
            .field("signature_big_r", &self.signature.big_r)
            .field("signature_s", &self.signature.s)
            .field("payload", &self.payload)
            .field("payload_hash", &self.payload_hash)
            .field("algo", &self.algo)
            .field("dest", &self.dest)
            .field("params", &self.params)
            .finish()
    }
}

/// ETH contract signature request builder
pub struct EthSignAction<'a> {
    sign_action: SignAction<'a>,
    contract_addr: String,
    signer: PrivateKeySigner,
    deposit_amount: U256,
    algo: String,
    dest: String,
    params: String,
}

impl<'a> EthSignAction<'a> {
    pub fn new(sign_action: SignAction<'a>) -> Self {
        let eth = sign_action.nodes.cfg.eth.as_ref().unwrap().clone();
        let signer = PrivateKeySigner::from_str(eth.account_sk.as_ref())
            .with_context(|| "invalid private key")
            .unwrap();
        Self {
            sign_action,
            contract_addr: eth.contract_address.clone(),
            signer,
            deposit_amount: U256::from(1), // 1 wei
            algo: "ECDSA".to_string(),
            dest: "ethereum".to_string(),
            params: "{}".to_string(),
        }
    }

    /// Set the ETH contract address to interact with
    pub fn contract_address(mut self, address: &str) -> Self {
        self.contract_addr = address.to_string();
        self
    }

    /// Set the ETH deposit amount in wei
    pub fn deposit(mut self, amount: u64) -> Self {
        self.deposit_amount = U256::from(amount);
        self
    }

    /// Set the signing algorithm
    pub fn algorithm(mut self, algo: &str) -> Self {
        self.algo = algo.to_string();
        self
    }

    /// Set the destination
    pub fn destination(mut self, dest: &str) -> Self {
        self.dest = dest.to_string();
        self
    }

    /// Set additional parameters
    pub fn parameters(mut self, params: &str) -> Self {
        self.params = params.to_string();
        self
    }

    /// Set the account to sign with (delegates to underlying SignAction)
    pub fn account(mut self, account: Account) -> Self {
        self.sign_action = self.sign_action.account(account);
        self
    }

    /// Set the payload to sign (delegates to underlying SignAction)
    pub fn payload(mut self, payload: [u8; 32]) -> Self {
        self.sign_action = self.sign_action.payload(payload);
        self
    }

    /// Set the derivation path (delegates to underlying SignAction)
    pub fn path(mut self, path: &str) -> Self {
        self.sign_action = self.sign_action.path(path);
        self
    }

    /// Set the key version (delegates to underlying SignAction)
    pub fn key_version(mut self, key_version: u32) -> Self {
        self.sign_action = self.sign_action.key_version(key_version);
        self
    }
}

impl<'a> IntoFuture for EthSignAction<'a> {
    type Output = anyhow::Result<EthSignOutcome>;
    type IntoFuture =
        std::pin::Pin<Box<dyn std::future::Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.execute())
    }
}

impl EthSignAction<'_> {
    async fn execute(self) -> anyhow::Result<EthSignOutcome> {
        // Store values we need
        let path = self.sign_action.path.clone();
        let payload = self
            .sign_action
            .payload
            .unwrap_or_else(|| rand::thread_rng().gen());
        let payload_hash = *alloy::primitives::keccak256(payload);
        let rpc_url = "https://ethereum-sepolia-rpc.publicnode.com";
        let contract_addr: Address = self
            .contract_addr
            .parse()
            .with_context(|| format!("invalid contract address {}", self.contract_addr))?;

        tracing::info!(
            "calling ETH ChainSignatures contract: contract=0x{}, payload={:?}, path={}, algo={}, dest={}, params={}, deposit={}",
            self.contract_addr,
            payload,
            path,
            self.algo,
            self.dest,
            self.params,
            self.deposit_amount
        );

        // Prepare the signer and contract for signing and listening for events.
        let signer_address = self.signer.address();
        let provider = ProviderBuilder::new()
            .wallet(self.signer)
            .connect_http(rpc_url.parse()?);
        let contract = ChainSignatures::new(contract_addr, provider.clone());

        // Prepare the sign request
        let sign_request = ChainSignatures::SignRequest {
            payload: FixedBytes::<32>::from_slice(&payload_hash),
            path: path.clone(),
            keyVersion: self.sign_action.key_version,
            algo: self.algo.clone(),
            dest: self.dest.clone(),
            params: self.params.clone(),
        };

        tracing::info!(
            contract = format!("0x{}", self.contract_addr),
            from = format!("0x{:x}", signer_address),
            payload = format!("0x{}", hex::encode(payload_hash)),
            path,
            key_version = self.sign_action.key_version,
            algorithm = self.algo,
            destination = self.dest,
            parameters = self.params,
            deposit = ?self.deposit_amount,
            rpc = rpc_url,
            "calling ChainSignatures.sign() on Sepolia network"
        );

        // Call the contract
        let pending_tx = match contract
            .sign(sign_request)
            .value(U256::from(self.deposit_amount))
            .send()
            .await
        {
            Ok(pending_tx) => pending_tx,
            Err(err) => {
                tracing::error!("failed to send transaction: {}", err);
                anyhow::bail!("Failed to send transaction: {}", err);
            }
        };
        tracing::info!("eth transaction sent successfully!");

        // Wait for transaction to be mined
        let tx_hash = *pending_tx.tx_hash();
        if let Err(err) = pending_tx.watch().await {
            anyhow::bail!("Transaction failed to mine: {err}");
        }

        // Calculate the request ID using the same ABI encoding as the indexer
        let signature_requested_encoding = SignatureRequestedEncoding {
            sender: signer_address,
            payload: payload_hash.into(),
            path: path.clone(),
            keyVersion: self.sign_action.key_version,
            chainId: U256::from(11155111u64), // Sepolia chain ID
            algo: self.algo.clone(),
            dest: self.dest.clone(),
            params: self.params.clone(),
        };
        let request_id = alloy::primitives::keccak256(signature_requested_encoding.encode_data());
        tracing::info!(
            request_id = hex::encode(request_id),
            "transaction mined: 0x{tx_hash:x}; waiting for SignatureResponded event..."
        );

        // Poll for events
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 60; // 1 minute max wait
        let mut interval = tokio::time::interval(Duration::from_millis(1000));

        // Now wait for the SignatureResponded event
        loop {
            interval.tick().await;
            attempts += 1;
            if attempts > MAX_ATTEMPTS {
                anyhow::bail!(
                    "timeout waiting for SignatureResponded after {MAX_ATTEMPTS} attempts"
                );
            }

            let current_block = match provider.get_block_number().await {
                Ok(block) => block,
                Err(e) => {
                    tracing::debug!("error getting block number (attempt {}): {}", attempts, e);
                    continue;
                }
            };

            // filter for SignatureResponded events
            let filter = alloy::rpc::types::Filter::new()
                .address(contract_addr)
                .from_block(current_block.saturating_sub(10)) // Look back 10 blocks
                .to_block(current_block)
                .event_signature(alloy::primitives::keccak256(
                    "SignatureResponded(bytes32,address,((uint256,uint256),uint256,uint8))",
                ));

            // Query for logs
            let logs = match provider.get_logs(&filter).await {
                Ok(logs) => logs,
                Err(err) => {
                    tracing::debug!("Error querying logs (attempt {}): {}", attempts, err);
                    continue;
                }
            };
            for log in logs.iter().filter(|log| log.topics().len() >= 2) {
                // topics[0] is the event signature
                // topics[1] is the indexed requestId
                let event_request_id =
                    alloy::primitives::FixedBytes::<32>::from_slice(&log.topics()[1].0);
                if event_request_id != request_id {
                    continue;
                }
                tracing::info!(
                    request_id = hex::encode(event_request_id),
                    "SignatureResponded event found!"
                );

                // Parse the event data. Event data format: responder (address, 32 bytes) + signature struct
                if log.data().data.len() < 32 + 32 * 4 {
                    tracing::warn!("event data too short: {} bytes", log.data().data.len());
                    continue;
                }
                // responder + bigR.x + bigR.y + s + recoveryId
                // Skip responder address (32 bytes)
                let sig_data = &log.data().data[32..];
                let big_r_x = U256::from_be_slice(&sig_data[0..32]);
                let big_r_y = U256::from_be_slice(&sig_data[32..64]);
                let s = U256::from_be_slice(&sig_data[64..96]);
                tracing::info!(
                    big_r_x = hex::encode(big_r_x.to_be_bytes::<32>()),
                    big_r_y = hex::encode(big_r_y.to_be_bytes::<32>()),
                    s = hex::encode(s.to_be_bytes::<32>()),
                    "parsing signature from SignatureResponded event..."
                );

                // Convert to k256 types
                let x_bytes: GenericArray<u8, generic_array::typenum::U32> =
                    GenericArray::clone_from_slice(&big_r_x.to_be_bytes::<32>());
                let y_bytes: GenericArray<u8, generic_array::typenum::U32> =
                    GenericArray::clone_from_slice(&big_r_y.to_be_bytes::<32>());

                let encoded_point =
                    k256::EncodedPoint::from_affine_coordinates(&x_bytes, &y_bytes, false);
                let big_r = k256::AffinePoint::from_encoded_point(&encoded_point).unwrap();

                let s_bytes: GenericArray<u8, generic_array::typenum::U32> =
                    GenericArray::clone_from_slice(&s.to_be_bytes::<32>());
                let s = k256::Scalar::from_bytes(s_bytes.into())
                    .ok_or_else(|| anyhow::anyhow!("invalid scalar value in event {s_bytes:?}"))?;

                let signature = FullSignature::<Secp256k1> { big_r, s };

                tracing::info!("successfully parsed signature from SignatureResponded event");
                return Ok(EthSignOutcome {
                    signer_address,
                    contract_address: self.contract_addr,
                    eth_tx_hash: Some(format!("0x{:x}", tx_hash)),
                    deposit_amount: self.deposit_amount.try_into().unwrap(),
                    signature,
                    payload,
                    payload_hash,
                    algo: self.algo,
                    dest: self.dest,
                    params: self.params,
                });
            }
        }
    }
}
