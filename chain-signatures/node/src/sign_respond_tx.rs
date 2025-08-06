use crate::protocol::SignRequestType;
use alloy::primitives::{Bytes, B256};
use alloy_rlp::Decodable;
use anchor_lang::prelude::Pubkey;
use ethers_core::types::U256;
use hex;
use k256::elliptic_curve::point::AffineCoordinates;
use mpc_primitives::Signature;
use sha3::{Digest, Keccak256};
use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Copy)]
pub struct SignRespondTxId(pub B256);

impl From<B256> for SignRespondTxId {
    fn from(b256: B256) -> Self {
        SignRespondTxId(b256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct SignRespondTx {
    pub id: SignRespondTxId,
    pub sender: Pubkey,
    pub transaction_data: Vec<u8>,
    pub slip44_chain_id: u32,
    pub key_version: u32,
    pub deposit: u64,
    pub path: String,
    pub algo: String,
    pub dest: String,
    pub params: String,
    pub explorer_deserialization_format: u8,
    pub explorer_deserialization_schema: Vec<u8>,
    pub callback_serialization_format: u8,
    pub callback_serialization_schema: Vec<u8>,
    pub request_id: [u8; 32],
    pub from_address: String,
    pub nonce: u64,
}

impl SignRespondTx {
    pub fn new(
        sign_request: crate::protocol::IndexedSignRequest,
        signature: Signature,
    ) -> anyhow::Result<Self> {
        let SignRequestType::SignRespond(sign_respond_event) = sign_request.sign_request_type
        else {
            anyhow::bail!("sign request is not a sign respond");
        };

        let rlp_data = sign_respond_event.transaction_data.clone();
        let is_eip1559 = rlp_data[0] == 0x02;
        let tx_type = if is_eip1559 { 0x02 } else { 0x00 };
        let decoded = decode_rlp(rlp_data, false)?;
        let decoded_string: Vec<String> = decoded
            .iter()
            .map(|b| format!("0x{}", hex::encode(b)))
            .collect();
        let nonce = if is_eip1559 {
            decoded_string[1].parse::<u64>()?
        } else {
            decoded_string[0].parse::<u64>()?
        };

        let signed_transaction_hash = get_signed_transaction_hash(
            decoded,
            signature,
            is_eip1559,
            sign_respond_event.slip44_chain_id as u64,
            tx_type,
        );

        Ok(Self {
            id: SignRespondTxId(signed_transaction_hash),
            sender: sign_respond_event.sender,
            transaction_data: sign_respond_event.transaction_data,
            slip44_chain_id: sign_respond_event.slip44_chain_id,
            key_version: sign_respond_event.key_version,
            deposit: sign_respond_event.deposit,
            path: sign_respond_event.path,
            algo: sign_respond_event.algo,
            dest: sign_respond_event.dest,
            params: sign_respond_event.params,
            explorer_deserialization_format: sign_respond_event.explorer_deserialization_format,
            explorer_deserialization_schema: sign_respond_event.explorer_deserialization_schema,
            callback_serialization_format: sign_respond_event.callback_serialization_format,
            callback_serialization_schema: sign_respond_event.callback_serialization_schema,
            request_id: sign_request.id.request_id,
            from_address: sign_request.args.id.to_string(),
            nonce,
        })
    }
}

pub fn hash_rlp_data(rlp_data: Vec<u8>) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(&rlp_data);
    hasher.finalize().into()
}

pub fn decode_rlp(rlp_data: Vec<u8>, is_eip1559: bool) -> anyhow::Result<Vec<Bytes>> {
    let payload = if is_eip1559 {
        &rlp_data[1..]
    } else {
        &rlp_data
    };

    let mut stream = payload;
    let decoded: Vec<Bytes> = Vec::<Bytes>::decode(&mut stream)
        .map_err(|e| anyhow::anyhow!("Failed to decode RLP list: {e:?}"))?;

    // let strings = decoded
    //     .into_iter()
    //     .map(|b| format!("0x{}", hex::encode(b)))
    //     .collect();

    // Ok(strings)
    Ok(decoded)
}

pub fn to_eip155_v(recovery_id: u8, chain_id: u64) -> u64 {
    (recovery_id as u64) + 35 + chain_id * 2
}

fn to_be_bytes_fixed(value: U256, width: usize) -> Bytes {
    let mut buf = vec![0u8; width];
    value.to_big_endian(&mut buf[width.saturating_sub(value.bits() as usize / 8)..]);
    Bytes::from(buf)
}

fn get_signed_transaction_hash(
    mut decoded: Vec<Bytes>,
    signature: Signature,
    is_eip1559: bool,
    chain_id: u64,
    tx_type: u8,
) -> B256 {
    let ethers_r = ethers_core::types::U256::from_big_endian(&signature.big_r.x());
    let ethers_s = ethers_core::types::U256::from_big_endian(signature.s.to_bytes().as_slice());
    let ethers_v: U256 = to_eip155_v(signature.recovery_id, chain_id).into();

    // Convert U256 → Bytes
    let r_bytes = {
        let mut buf = [0u8; 32];
        ethers_r.to_big_endian(&mut buf);
        Bytes::copy_from_slice(&buf)
    };

    let s_bytes = {
        let mut buf = [0u8; 32];
        ethers_s.to_big_endian(&mut buf);
        Bytes::copy_from_slice(&buf)
    };
    // Append v, r, s
    decoded.push(to_be_bytes_fixed(ethers_v, 1));
    decoded.push(s_bytes);
    decoded.push(r_bytes);

    // Step 3: RLP encode all fields
    let rlp_encoded = alloy_rlp::encode(&decoded);

    // Step 4: Handle EIP-1559 typed transaction
    let signed_tx = if is_eip1559 {
        let mut tx = vec![tx_type];
        tx.extend_from_slice(&rlp_encoded);
        Bytes::from(tx)
    } else {
        rlp_encoded.into()
    };

    // Step 5: Hash the signed transaction
    let hash_bytes: [u8; 32] = Keccak256::digest(&signed_tx).into();
    B256::from(hash_bytes)
}

async fn run(
    mut sign_respond_responded_rx: mpsc::Receiver<(crate::protocol::IndexedSignRequest, Signature)>,
) {
    while let Some((sign_respond_event, signature)) = sign_respond_responded_rx.recv().await {}
}
