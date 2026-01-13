use alloy::network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use alloy::providers::ProviderBuilder;
use alloy::rpc::types::request::TransactionRequest;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::sol_types::{SolEvent, SolValue};
use anyhow::{Context, Result};
use serde_json::Value;

alloy::sol! {
    #[sol(rpc)]
    contract ChainSignatures {
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
            address sender,
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
            address responder,
            Signature signature
        );
    }

    // Event encoding used to derive the off-chain request id
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

    // Constructor args for deployment
    struct ChainSignaturesConstructor {
        address mpcNetwork;
        uint256 signatureDeposit;
    }
}

pub fn client(
    endpoint: &str,
    secret_key: &str,
    chain_id: u64,
) -> Result<(impl Provider + Clone + Send + Sync + 'static, Address)> {
    let signer: PrivateKeySigner = secret_key.parse()?;
    let signer = signer.with_chain_id(Some(chain_id));
    let address = signer.address();
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(endpoint.parse()?);
    Ok((provider, address))
}

pub async fn deploy_chain_signatures<P>(
    client: P,
    deployer_address: Address,
    mpc_address: Address,
    signature_deposit: U256,
) -> Result<Address>
where
    P: Provider + Clone + Send + Sync + 'static,
{
    let artifact: Value = serde_json::from_slice(include_bytes!(
        "../../chain-signatures/contract-eth/artifacts/contracts/ChainSignatures.sol/ChainSignatures.json"
    ))?;

    let bytecode = artifact
        .get("bytecode")
        .and_then(Value::as_str)
        .context("bytecode missing from artifact")?;
    let mut deployment = hex::decode(bytecode.trim_start_matches("0x"))?;

    let constructor_args = ChainSignaturesConstructor {
        mpcNetwork: mpc_address,
        signatureDeposit: signature_deposit,
    };
    deployment.extend_from_slice(&constructor_args.abi_encode());

    let tx = <TransactionRequest as TransactionBuilder<Ethereum>>::with_input(
        <TransactionRequest as TransactionBuilder<Ethereum>>::with_from(
            <TransactionRequest as TransactionBuilder<Ethereum>>::into_create(
                TransactionRequest::default(),
            ),
            deployer_address,
        ),
        deployment,
    );

    let pending = client.send_transaction(tx).await?;
    let receipt = pending.get_receipt().await?;
    let contract_address = receipt
        .contract_address
        .context("deployment receipt missing contract address")?;
    Ok(contract_address)
}

#[allow(clippy::too_many_arguments)]
pub fn compute_request_id(
    requester: Address,
    payload: [u8; 32],
    path: &str,
    key_version: u32,
    chain_id: U256,
    algo: &str,
    dest: &str,
    params: &str,
) -> B256 {
    let encoding = SignatureRequestedEncoding {
        sender: requester,
        payload: payload.to_vec().into(),
        path: path.to_string(),
        keyVersion: key_version,
        chainId: chain_id,
        algo: algo.to_string(),
        dest: dest.to_string(),
        params: params.to_string(),
    };

    alloy::primitives::keccak256(encoding.encode_data())
}

pub use ChainSignatures::SignRequest;
pub use ChainSignatures::SignatureResponded;
