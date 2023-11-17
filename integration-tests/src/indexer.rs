use k256::{AffinePoint, Scalar};
use near_lake_framework::{LakeBuilder, LakeContext};
use near_lake_primitives::actions::ActionMetaDataExt;
use near_lake_primitives::{receipts::ExecutionStatus, AccountId};
use near_primitives::hash::CryptoHash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Serialize, Deserialize)]
struct RespondPayload {
    receipt_id: [u8; 32],
    big_r: AffinePoint,
    s: Scalar,
}

pub struct FullSignature {
    pub big_r: AffinePoint,
    pub s: Scalar,
}

#[derive(LakeContext)]
struct Context {
    mpc_contract_id: AccountId,
    responses: Arc<RwLock<HashMap<CryptoHash, FullSignature>>>,
}

async fn handle_block(
    mut block: near_lake_primitives::block::Block,
    ctx: &Context,
) -> anyhow::Result<()> {
    for action in block.actions().cloned().collect::<Vec<_>>() {
        if action.receiver_id() == ctx.mpc_contract_id {
            let receipt = block.receipt_by_id(&action.receipt_id()).unwrap();
            if let Some(function_call) = action.as_function_call() {
                if function_call.method_name() == "respond" {
                    let ExecutionStatus::SuccessValue(_) = receipt.status() else {
                        tracing::error!("indexed a failed `respond` function call");
                        continue;
                    };
                    if let Ok(respond_payload) =
                        serde_json::from_slice::<'_, RespondPayload>(function_call.args())
                    {
                        let receipt_id = CryptoHash(respond_payload.receipt_id);
                        tracing::info!(
                            receipt_id = %receipt_id,
                            caller_id = receipt.predecessor_id().to_string(),
                            big_r = ?respond_payload.big_r,
                            s = ?respond_payload.s,
                            "indexed new `respond` function call"
                        );
                        let mut responses = ctx.responses.write().await;
                        responses.insert(
                            receipt_id,
                            FullSignature {
                                big_r: respond_payload.big_r,
                                s: respond_payload.s,
                            },
                        );
                        drop(responses);
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn run(
    s3_bucket: &str,
    s3_region: &str,
    start_block_height: u64,
    s3_url: &str,
    mpc_contract_id: AccountId,
    responses: Arc<RwLock<HashMap<CryptoHash, FullSignature>>>,
) -> anyhow::Result<()> {
    let mut lake_builder = LakeBuilder::default()
        .s3_bucket_name(s3_bucket)
        .s3_region_name(s3_region)
        .start_block_height(start_block_height);
    let lake = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let aws_config = aws_config::from_env().load().await;
            let s3_config = aws_sdk_s3::config::Builder::from(&aws_config)
                .endpoint_url(s3_url)
                .build();
            lake_builder = lake_builder.s3_config(s3_config);
            lake_builder.build()
        })?;
    let context = Context {
        mpc_contract_id,
        responses,
    };
    lake.run_with_context(handle_block, &context)?;
    Ok(())
}
