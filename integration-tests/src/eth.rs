use anyhow::{Context, Result};
use alloy::dyn_abi::DynSolValue;
use alloy::network::{Ethereum, EthereumWallet, TransactionBuilder};
use alloy::primitives::{
    keccak256, Address as AlloyAddress, B256, Bytes, U256 as AlloyU256,
};
use alloy::providers::fillers::{FillProvider, JoinFill, WalletFiller};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::{Filter, Log, TransactionReceipt, TransactionRequest};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolEvent;
use std::sync::Arc;

type SandboxFillProvider = FillProvider<
    JoinFill<
        JoinFill<
            alloy::providers::Identity,
            JoinFill<
                alloy::providers::fillers::GasFiller,
                JoinFill<
                    alloy::providers::fillers::BlobGasFiller,
                    JoinFill<
                        alloy::providers::fillers::NonceFiller,
                        alloy::providers::fillers::ChainIdFiller,
                    >,
                >,
            >,
        >,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider,
>;

alloy::sol! {
    struct ContractSignRequest {
        bytes32 payload;
        string path;
        uint32 keyVersion;
        string algo;
        string dest;
        string params;
    }

    struct ContractAffinePoint {
        uint256 x;
        uint256 y;
    }

    struct ContractSignature {
        ContractAffinePoint bigR;
        uint256 s;
        uint8 recoveryId;
    }

    struct ContractResponse {
        bytes32 requestId;
        ContractSignature signature;
    }

    #[sol(rpc)]
    contract ChainSignaturesContract {
        constructor(address _mpc_network, uint256 _signatureDeposit);

        function sign(ContractSignRequest memory _request) external payable;
        function respond(ContractResponse[] calldata _responses) external;
        function getSignatureDeposit() external view returns (uint256);
    }

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

    event SignatureResponded(
        bytes32 indexed requestId,
        address responder,
        ContractSignature signature
    );
}

pub type Address = AlloyAddress;
pub type U256 = AlloyU256;
pub type SandboxMiddleware = SandboxFillProvider;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
    pub algo: String,
    pub dest: String,
    pub params: String,
}

pub mod chain_signatures_contract {
    use super::U256;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct AffinePoint {
        pub x: U256,
        pub y: U256,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Signature {
        pub big_r: AffinePoint,
        pub s: U256,
        pub recovery_id: u8,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Response {
        pub request_id: [u8; 32],
        pub signature: Signature,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureRespondedFilter {
    pub request_id: B256,
    pub responder: Address,
    pub signature: chain_signatures_contract::Signature,
}

fn to_contract_sign_request(request: SignRequest) -> ContractSignRequest {
    ContractSignRequest {
        payload: request.payload.into(),
        path: request.path,
        keyVersion: request.key_version,
        algo: request.algo,
        dest: request.dest,
        params: request.params,
    }
}

fn to_contract_signature(
    signature: chain_signatures_contract::Signature,
) -> ContractSignature {
    ContractSignature {
        bigR: ContractAffinePoint {
            x: signature.big_r.x,
            y: signature.big_r.y,
        },
        s: signature.s,
        recoveryId: signature.recovery_id,
    }
}

fn to_contract_response(response: chain_signatures_contract::Response) -> ContractResponse {
    ContractResponse {
        requestId: response.request_id.into(),
        signature: to_contract_signature(response.signature),
    }
}

fn provider_with_signer(endpoint: &str, signer: PrivateKeySigner) -> Result<Arc<SandboxMiddleware>> {
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(endpoint.parse()?);
    Ok(Arc::new(provider))
}

pub fn client(
    endpoint: &str,
    secret_key: &str,
    _chain_id: u64,
) -> Result<(Arc<SandboxMiddleware>, Address)> {
    let signer: PrivateKeySigner = secret_key.parse()?;
    let address = signer.address();
    let client = provider_with_signer(endpoint, signer)?;
    Ok((client, address))
}

pub fn random_client(endpoint: &str, _chain_id: u64) -> Result<(Arc<SandboxMiddleware>, Address)> {
    let signer = PrivateKeySigner::random();
    let address = signer.address();
    let client = provider_with_signer(endpoint, signer)?;
    Ok((client, address))
}

pub fn address_from_low_u64_be(value: u64) -> Address {
    let mut bytes = [0u8; 20];
    bytes[12..].copy_from_slice(&value.to_be_bytes());
    Address::from_slice(&bytes)
}

pub fn value_transfer(to: Address, value: U256) -> TransactionRequest {
    let tx = <TransactionRequest as TransactionBuilder<Ethereum>>::with_to(
        TransactionRequest::default(),
        to,
    );
    <TransactionRequest as TransactionBuilder<Ethereum>>::with_value(tx, value)
}

pub fn value_transfer_with_gas(to: Address, value: U256, gas_limit: u64) -> TransactionRequest {
    <TransactionRequest as TransactionBuilder<Ethereum>>::with_gas_limit(
        value_transfer(to, value),
        gas_limit,
    )
}

pub async fn send_transaction_and_wait(
    client: &Arc<SandboxMiddleware>,
    tx: TransactionRequest,
    dropped_message: &'static str,
) -> Result<TransactionReceipt> {
    client
        .send_transaction(tx)
        .await?
        .get_receipt()
        .await
        .context(dropped_message)
}

pub async fn send_sign_request(
    client: &Arc<SandboxMiddleware>,
    contract_address: Address,
    request: SignRequest,
    deposit: U256,
) -> Result<TransactionReceipt> {
    ChainSignaturesContract::new(contract_address, client.clone())
        .sign(to_contract_sign_request(request))
        .value(deposit)
        .send()
        .await?
        .get_receipt()
        .await
        .context("sign transaction failed")
}

pub async fn send_responses(
    client: &Arc<SandboxMiddleware>,
    contract_address: Address,
    responses: Vec<chain_signatures_contract::Response>,
) -> Result<TransactionReceipt> {
    ChainSignaturesContract::new(contract_address, client.clone())
        .respond(responses.into_iter().map(to_contract_response).collect())
        .send()
        .await?
        .get_receipt()
        .await
        .context("respond transaction execution failed")
}

pub async fn signature_responded_events(
    client: &Arc<SandboxMiddleware>,
    contract_address: Address,
    from_block: u64,
) -> Result<Vec<SignatureRespondedFilter>> {
    let filter = Filter::new()
        .address(contract_address)
        .from_block(from_block)
        .event_signature(signature_responded_topic());

    let logs = client.get_logs(&filter).await?;
    let mut events = Vec::new();
    for log in logs {
        if let Some(event) = parse_signature_responded_log(log)? {
            events.push(event);
        }
    }
    Ok(events)
}

fn parse_signature_responded_log(log: Log) -> Result<Option<SignatureRespondedFilter>> {
    if log
        .topics()
        .first()
        .is_none_or(|topic| *topic != signature_responded_topic())
    {
        return Ok(None);
    }

    let Some(request_id) = log.topics().get(1).copied() else {
        return Ok(None);
    };

    let data = &log.data().data;
    if data.len() < 160 {
        return Ok(None);
    }

    let responder = Address::from_slice(&data[12..32]);
    let signature = chain_signatures_contract::Signature {
        big_r: chain_signatures_contract::AffinePoint {
            x: U256::from_be_slice(&data[32..64]),
            y: U256::from_be_slice(&data[64..96]),
        },
        s: U256::from_be_slice(&data[96..128]),
        recovery_id: data[159],
    };

    Ok(Some(SignatureRespondedFilter {
        request_id,
        responder,
        signature,
    }))
}

pub fn signature_from_coordinates(
    x: &[u8],
    y: &[u8],
    s: &[u8],
    recovery_id: u8,
) -> chain_signatures_contract::Signature {
    let big_r = chain_signatures_contract::AffinePoint {
        x: U256::from_be_slice(x),
        y: U256::from_be_slice(y),
    };

    chain_signatures_contract::Signature {
        big_r,
        s: U256::from_be_slice(s),
        recovery_id,
    }
}

pub fn signature_responded_topic() -> B256 {
    SignatureResponded::SIGNATURE_HASH
}

fn contract_deploy_code(mpc_address: Address, signature_deposit: U256) -> Result<Bytes> {
    let artifact: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../chain-signatures/contract-eth/artifacts/contracts/ChainSignatures.sol/ChainSignatures.json"
    ))?;
    let bytecode = artifact
        .get("bytecode")
        .and_then(serde_json::Value::as_str)
        .context("missing ChainSignatures bytecode in artifact")?;

    let bytecode = bytecode.strip_prefix("0x").unwrap_or(bytecode);
    let mut deploy_code = hex::decode(bytecode)?;
    let constructor_args = DynSolValue::Tuple(vec![
        DynSolValue::Address(mpc_address),
        DynSolValue::Uint(signature_deposit, 256),
    ])
    .abi_encode();
    deploy_code.extend_from_slice(&constructor_args);

    Ok(Bytes::from(deploy_code))
}

pub async fn deploy_chain_signatures(
    client: Arc<SandboxMiddleware>,
    mpc_address: Address,
    signature_deposit: U256,
) -> Result<Address> {
    let deploy_code = contract_deploy_code(mpc_address, signature_deposit)?;
    let tx = <TransactionRequest as TransactionBuilder<Ethereum>>::with_deploy_code(
        TransactionRequest::default(),
        deploy_code,
    );
    let receipt = send_transaction_and_wait(&client, tx, "chain signatures deploy transaction failed")
        .await?;
    receipt
        .contract_address
        .context("missing contract address in deploy receipt")
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
    let chain_id_bytes = chain_id.to_be_bytes::<32>();

    let event = SignatureRequestedEncoding {
        sender: AlloyAddress::from_slice(requester.as_slice()),
        payload: payload.to_vec().into(),
        path: path.to_string(),
        keyVersion: key_version,
        chainId: AlloyU256::from_be_bytes(chain_id_bytes),
        algo: algo.to_string(),
        dest: dest.to_string(),
        params: params.to_string(),
    };

    B256::from_slice(keccak256(event.encode_data()).as_slice())
}
