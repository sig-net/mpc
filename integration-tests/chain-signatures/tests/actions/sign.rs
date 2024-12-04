use std::future::IntoFuture;

use cait_sith::FullSignature;
use k256::Secp256k1;
use mpc_contract::errors;
use mpc_contract::primitives::SignRequest;
use near_crypto::InMemorySigner;
use near_fetch::ops::AsyncTransactionStatus;
use near_workspaces::types::{Gas, NearToken};
use near_workspaces::Account;
use rand::Rng;

use crate::actions::{self, wait_for};
use crate::cluster::Cluster;

pub const SIGN_GAS: Gas = Gas::from_tgas(50);
pub const SIGN_DEPOSIT: NearToken = NearToken::from_yoctonear(1);

pub struct SignAction<'a> {
    nodes: &'a Cluster,
    count: usize,
    account: Option<Account>,
    payload: Option<[u8; 32]>,
    path: String,
    key_version: u32,
    gas: Gas,
    deposit: NearToken,
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
}

impl<'a> IntoFuture for SignAction<'a> {
    type Output = anyhow::Result<SignResult>;
    type IntoFuture =
        std::pin::Pin<Box<dyn std::future::Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        let Self { nodes, .. } = self;

        Box::pin(async move {
            let state = nodes.expect_running().await?;
            let account = self.account_or_new().await;
            let (payload, payload_hash) = self.payload_or_random().await;
            let status = self.transact_async(&account, payload_hash).await?;

            // We have to use seperate transactions because one could fail.
            // This leads to a potential race condition where this transaction could get sent after the signature completes, but I think that's unlikely
            let rogue_status =
                actions::rogue_respond_(nodes, payload_hash, account.id(), "test").await?;
            let err = wait_for::rogue_message_responded(rogue_status).await?;

            assert!(err.contains(&errors::RespondError::InvalidSignature.to_string()));
            let signature = wait_for::signature_responded(status).await?;

            let mut mpc_pk_bytes = vec![0x04];
            mpc_pk_bytes.extend_from_slice(&state.public_key.as_bytes()[1..]);

            // Useful for populating the "signatures_havent_changed" test's hardcoded values
            // dbg!(
            //     hex::encode(signature.big_r.to_encoded_point(true).to_bytes()),
            //     hex::encode(signature.s.to_bytes()),
            //     hex::encode(&mpc_pk_bytes),
            //     hex::encode(&payload_hash),
            //     account.id(),
            // );
            actions::assert_signature(account.id(), &mpc_pk_bytes, payload_hash, &signature).await;

            Ok(SignResult {
                account,
                signature,
                payload,
                payload_hash,
            })
        })
    }
}

// Helper methods for the SignAction
impl SignAction<'_> {
    async fn account_or_new(&self) -> Account {
        if let Some(account) = &self.account {
            account.clone()
        } else {
            self.nodes.worker().dev_create_account().await.unwrap()
        }
    }

    async fn payload_or_random(&self) -> ([u8; 32], [u8; 32]) {
        let payload = if let Some(payload) = &self.payload {
            *payload
        } else {
            rand::thread_rng().gen()
        };
        (payload, web3::signing::keccak256(&payload))
    }

    async fn transact_async(
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
}

pub struct SignResult {
    pub account: Account,
    pub payload: [u8; 32],
    pub payload_hash: [u8; 32],
    pub signature: FullSignature<Secp256k1>,
}
