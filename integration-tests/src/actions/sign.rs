use std::fmt;
use std::future::IntoFuture;

use cait_sith::FullSignature;
use k256::Secp256k1;
use mpc_contract::errors;
use mpc_contract::primitives::SignRequest;
use mpc_primitives::{SignId, Signature};
use near_crypto::InMemorySigner;
use near_fetch::ops::AsyncTransactionStatus;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::{Account, AccountId};
use rand::Rng;

use crate::actions::{self, wait_for};
use crate::cluster::Cluster;

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
            key_version: 0,
            gas: SIGN_GAS,
            deposit: SIGN_DEPOSIT,
            execute_rogue: false,
        }
    }
}

impl SignAction<'_> {
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
        let payload = self.payload.unwrap_or_else(|| rand::thread_rng().r#gen());
        self.payload = Some(payload);
        payload
    }

    fn payload_hash(&mut self) -> [u8; 32] {
        web3::signing::keccak256(&self.payload_or_random())
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
            public_key: rogue.secret_key().public_key().clone().into(),
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
