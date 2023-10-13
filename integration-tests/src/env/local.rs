#![allow(clippy::too_many_arguments)]

use aes_gcm::aead::consts::U32;
use aes_gcm::aead::generic_array::GenericArray;
use anyhow::Context;
use async_process::{Child, Command, Stdio};
use hyper::StatusCode;
use mpc_recovery::firewall::allowed::DelegateActionRelayer;
use mpc_recovery::relayer::NearRpcAndRelayerClient;
use multi_party_eddsa::protocols::ExpandedKeyPair;

use crate::env::{LeaderNodeApi, SignerNodeApi};
use crate::util;

pub struct SignerNode {
    pub address: String,
    node_id: usize,
    sk_share: ExpandedKeyPair,
    cipher_key: GenericArray<u8, U32>,
    gcp_project_id: String,
    gcp_datastore_url: String,

    // process held so it's not dropped. Once dropped, process will be killed.
    #[allow(unused)]
    process: Child,
}

impl SignerNode {
    pub async fn run(
        web_port: u16,
        node_id: u64,
        sk_share: &ExpandedKeyPair,
        cipher_key: &GenericArray<u8, U32>,
        ctx: &super::Context<'_>,
        release: bool,
    ) -> anyhow::Result<Self> {
        let executable = util::executable(release)
            .context("could not find target dir while running signing node")?;

        let args = mpc_recovery::Cli::StartSign {
            env: "dev".to_string(),
            node_id,
            web_port,
            sk_share: Some(serde_json::to_string(&sk_share)?),
            cipher_key: Some(hex::encode(cipher_key)),
            oidc_providers_filepath: None,
            oidc_providers: Some(
                serde_json::json!([
                    {
                        "issuer": format!("https://securetoken.google.com/{}", ctx.audience_id),
                        "audience": ctx.audience_id,
                    },
                ])
                .to_string(),
            ),
            gcp_project_id: ctx.gcp_project_id.clone(),
            gcp_datastore_url: Some(ctx.datastore.local_address.clone()),
            jwt_signature_pk_url: ctx.oidc_provider.jwt_local_url.clone(),
        }
        .into_str_args();

        let address = format!("http://localhost:{web_port}");
        let child = Command::new(&executable)
            .args(&args)
            .env("RUST_LOG", "mpc_recovery=DEBUG")
            .envs(std::env::vars())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| {
                format!(
                    "failed to run signing node: [node_id={node_id}, {}]",
                    executable.display()
                )
            })?;

        tracing::info!("Signer node is start on {}", address);
        loop {
            let x: anyhow::Result<StatusCode> = util::get(&address).await;
            match x {
                std::result::Result::Ok(status) if status == StatusCode::OK => break,
                _ => (),
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        tracing::info!("Signer node started [node_id={node_id}, {address}]");

        Ok(Self {
            address,
            node_id: node_id as usize,
            sk_share: sk_share.clone(),
            cipher_key: *cipher_key,
            gcp_project_id: ctx.gcp_project_id.clone(),
            gcp_datastore_url: ctx.datastore.local_address.clone(),
            process: child,
        })
    }

    pub fn api(&self) -> SignerNodeApi {
        SignerNodeApi {
            address: self.address.clone(),
            node_id: self.node_id,
            sk_share: self.sk_share.clone(),
            cipher_key: self.cipher_key,
            gcp_project_id: self.gcp_project_id.clone(),
            gcp_datastore_local_url: self.gcp_datastore_url.clone(),
        }
    }
}

pub struct LeaderNode {
    pub address: String,
    near_rpc: String,
    relayer_url: String,

    // process held so it's not dropped. Once dropped, process will be killed.
    #[allow(unused)]
    process: Child,
}

impl LeaderNode {
    pub async fn run(
        ctx: &super::Context<'_>,
        web_port: u16,
        sign_nodes: Vec<String>,
        near_root_account: &workspaces::AccountId,
        account_creator_id: &workspaces::AccountId,
        account_creator_sk: &workspaces::types::SecretKey,
        release: bool,
    ) -> anyhow::Result<Self> {
        tracing::info!("Running leader node...");
        let executable = util::executable(release)
            .context("could not find target dir while running leader node")?;

        let args = mpc_recovery::Cli::StartLeader {
            env: "dev".to_string(),
            web_port,
            sign_nodes,
            near_rpc: ctx.relayer_ctx.sandbox.local_address.clone(),
            near_root_account: near_root_account.to_string(),
            account_creator_id: account_creator_id.clone(),
            account_creator_sk: Some(account_creator_sk.to_string()),
            fast_auth_partners: Some(
                serde_json::json!([
                    {
                        "oidc_provider": {
                            "issuer": format!("https://securetoken.google.com/{}", ctx.audience_id),
                            "audience": ctx.audience_id,
                        },
                        "relayer": {
                            "url": &ctx.relayer_ctx.relayer.local_address,
                            "api_key": serde_json::Value::Null,
                        },
                    },
                ])
                .to_string(),
            ),
            fast_auth_partners_filepath: None,
            gcp_project_id: ctx.gcp_project_id.clone(),
            gcp_datastore_url: Some(ctx.datastore.local_address.clone()),
            jwt_signature_pk_url: ctx.oidc_provider.jwt_local_url.clone(),
        }
        .into_str_args();

        let child = Command::new(&executable)
            .args(&args)
            .envs(std::env::vars())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("failed to run leader node: {}", executable.display()))?;

        let address = format!("http://localhost:{web_port}");
        tracing::info!("Leader node container is starting at {}", address);
        loop {
            match util::get(&address).await {
                std::result::Result::Ok(status) if status == StatusCode::OK => break,
                _ => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
            }
        }

        tracing::info!("Leader node container is running at {address}");
        Ok(Self {
            address,
            near_rpc: ctx.relayer_ctx.sandbox.local_address.clone(),
            relayer_url: ctx.relayer_ctx.relayer.local_address.clone(),
            process: child,
        })
    }

    pub fn api(&self) -> LeaderNodeApi {
        LeaderNodeApi {
            address: self.address.clone(),
            client: NearRpcAndRelayerClient::connect(&self.near_rpc),
            relayer: DelegateActionRelayer {
                url: self.relayer_url.clone(),
                api_key: None,
            },
        }
    }
}
