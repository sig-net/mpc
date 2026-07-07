//! Typed decoding of reassembled SGN1 part groups, per the offset tables in
//! `docs/signet-midnight-events.md` (all offsets within the 224-byte tail),
//! and param-based EIP-1559 transaction building for bidirectional requests.

use crate::wire::{ascii_field, le_uint, EventPart, RequestKind};
use k256::elliptic_curve::sec1::FromEncodedPoint;
use mpc_primitives::{ScalarExt, Signature};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignBody {
    pub nonce: u64,
    pub commitment: [u8; 32],
    pub payload: [u8; 32],
    pub key_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignBiBody {
    pub nonce: u64,
    pub commitment: [u8; 32],
    pub key_version: u32,
    pub caip2_id: String,
    pub dest: String,
    pub params: String,
    pub evm_to: [u8; 20],
    pub evm_chain_id: u64,
    pub evm_nonce: u64,
    pub evm_gas_limit: u64,
    pub evm_max_fee: u128,
    pub evm_priority_fee: u128,
    pub evm_value: u128,
    pub arg_count: u8,
    pub func_sig: String,
    pub args: [[u8; 32]; 4],
    pub output_schema: String,
    pub respond_schema: String,
}

fn fixed<const N: usize>(tail: &[u8], offset: usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&tail[offset..offset + N]);
    out
}

fn expect_parts(parts: &[EventPart], kind: RequestKind) -> anyhow::Result<()> {
    anyhow::ensure!(
        parts.len() == kind.part_count() && parts.iter().all(|p| p.kind == kind),
        "expected {} parts of kind {kind:?}, got {}",
        kind.part_count(),
        parts.len()
    );
    for (i, p) in parts.iter().enumerate() {
        anyhow::ensure!(p.part_index == i + 1, "parts out of order at index {i}");
    }
    Ok(())
}

pub fn decode_sign(parts: &[EventPart]) -> anyhow::Result<SignBody> {
    expect_parts(parts, RequestKind::Sign)?;
    let t = &parts[0].tail;
    Ok(SignBody {
        nonce: le_uint(&t[0..8]) as u64,
        commitment: fixed::<32>(t, 8),
        payload: fixed::<32>(t, 40),
        key_version: le_uint(&t[72..76]) as u32,
    })
}

pub fn decode_sign_bidirectional(parts: &[EventPart]) -> anyhow::Result<SignBiBody> {
    expect_parts(parts, RequestKind::SignBidirectional)?;
    let (t1, t2, t3, t4, t5) = (
        &parts[0].tail,
        &parts[1].tail,
        &parts[2].tail,
        &parts[3].tail,
        &parts[4].tail,
    );
    let mut args = [[0u8; 32]; 4];
    for (i, word) in args.iter_mut().enumerate() {
        *word = fixed::<32>(t3, i * 32);
    }
    let body = SignBiBody {
        nonce: le_uint(&t1[0..8]) as u64,
        commitment: fixed::<32>(t1, 8),
        key_version: le_uint(&t1[40..44]) as u32,
        caip2_id: ascii_field(&t1[44..76]),
        dest: ascii_field(&t1[76..108]),
        params: ascii_field(&t1[108..172]),
        evm_to: fixed::<20>(t2, 0),
        evm_chain_id: le_uint(&t2[20..28]) as u64,
        evm_nonce: le_uint(&t2[28..36]) as u64,
        evm_gas_limit: le_uint(&t2[36..44]) as u64,
        evm_max_fee: le_uint(&t2[44..60]),
        evm_priority_fee: le_uint(&t2[60..76]),
        evm_value: le_uint(&t2[76..92]),
        arg_count: t2[92],
        func_sig: ascii_field(&t2[93..157]),
        args,
        output_schema: ascii_field(&t4[0..128]),
        respond_schema: ascii_field(&t5[0..128]),
    };
    anyhow::ensure!(body.arg_count <= 4, "argCount {} exceeds 4", body.arg_count);
    Ok(body)
}

/// Parse the `RespondSig` layout at the start of a tail: R.x(32) || R.y(32) ||
/// s(32) || recoveryId(1), all big-endian scalars.
fn parse_signature_tail(tail: &[u8]) -> anyhow::Result<Signature> {
    let x = k256::FieldBytes::from(fixed::<32>(tail, 0));
    let y = k256::FieldBytes::from(fixed::<32>(tail, 32));
    let point = k256::EncodedPoint::from_affine_coordinates(&x, &y, false);
    let big_r = Option::<k256::AffinePoint>::from(k256::AffinePoint::from_encoded_point(&point))
        .ok_or_else(|| anyhow::anyhow!("signature R is not on the curve"))?;
    let s = <k256::Scalar as ScalarExt>::from_bytes(fixed::<32>(tail, 64))
        .ok_or_else(|| anyhow::anyhow!("invalid signature s scalar"))?;
    let recovery_id = tail[96];
    anyhow::ensure!(recovery_id <= 1, "invalid recovery_id {recovery_id}");
    Ok(Signature::new(big_r, s, recovery_id))
}

pub fn decode_respond(parts: &[EventPart]) -> anyhow::Result<Signature> {
    expect_parts(parts, RequestKind::Respond)?;
    parse_signature_tail(&parts[0].tail)
}

pub fn decode_respond_bidirectional(parts: &[EventPart]) -> anyhow::Result<(Vec<u8>, Signature)> {
    expect_parts(parts, RequestKind::RespondBidirectional)?;
    let t1 = &parts[0].tail;
    let output_len = t1[128] as usize;
    anyhow::ensure!(output_len <= 128, "outputLen {output_len} exceeds 128");
    let output = t1[..output_len].to_vec();
    let signature = parse_signature_tail(&parts[1].tail)?;
    Ok((output, signature))
}

/// `calldata = keccak256(funcSig)[0..4] || args[0..argCount]` — the arg words
/// are ABI-ready big-endian and used verbatim (SGN1 spec). An empty funcSig
/// means a plain value transfer: empty calldata, argCount must be 0.
pub fn build_calldata(
    func_sig: &str,
    args: &[[u8; 32]; 4],
    arg_count: u8,
) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(arg_count <= 4, "argCount {arg_count} exceeds 4");
    if func_sig.is_empty() {
        anyhow::ensure!(arg_count == 0, "argCount must be 0 without a funcSig");
        return Ok(Vec::new());
    }
    let selector = alloy_primitives::keccak256(func_sig.as_bytes());
    let mut out = Vec::with_capacity(4 + 32 * arg_count as usize);
    out.extend_from_slice(&selector[..4]);
    for word in &args[..arg_count as usize] {
        out.extend_from_slice(word);
    }
    Ok(out)
}

/// Unsigned EIP-1559 signing preimage: `0x02 || rlp([...])`, exactly what the
/// phase-1 signature covers (golden `unsignedSerializedTx`).
pub fn build_unsigned_eip1559(body: &SignBiBody) -> anyhow::Result<Vec<u8>> {
    use alloy_consensus::{SignableTransaction, TxEip1559};
    use alloy_primitives::{Address, Bytes, TxKind, U256};
    let tx = TxEip1559 {
        chain_id: body.evm_chain_id,
        nonce: body.evm_nonce,
        gas_limit: body.evm_gas_limit,
        max_fee_per_gas: body.evm_max_fee,
        max_priority_fee_per_gas: body.evm_priority_fee,
        to: TxKind::Call(Address::from(body.evm_to)),
        value: U256::from(body.evm_value),
        access_list: Default::default(),
        input: Bytes::from(build_calldata(&body.func_sig, &body.args, body.arg_count)?),
    };
    Ok(tx.encoded_for_signing())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_goldens::{golden, hex32, payload_bytes};
    use crate::wire::EventPart;

    fn parts_of(case: &serde_json::Value) -> Vec<EventPart> {
        case["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|ev| {
                let name = hex::decode(ev["name"].as_str().unwrap()).unwrap();
                EventPart::parse(&name, &payload_bytes(ev)).unwrap()
            })
            .collect()
    }

    #[test]
    fn decodes_sign_body_from_golden() {
        let g = golden("sign.json");
        let case = &g["cases"][0];
        let body = decode_sign(&parts_of(case)).unwrap();
        assert_eq!(body.nonce, 0);
        assert_eq!(body.key_version, 1);
        assert_eq!(body.commitment, hex32(case["commitment"].as_str().unwrap()));
        assert_eq!(
            body.payload,
            hex32(case["inputs"]["payload"].as_str().unwrap())
        );
    }

    #[test]
    fn decodes_sign_bidirectional_body_from_golden() {
        let g = golden("sign_bidirectional.json");
        let case = &g["cases"][0];
        let inputs = &case["inputs"];
        let body = decode_sign_bidirectional(&parts_of(case)).unwrap();
        assert_eq!(body.nonce, 0);
        assert_eq!(body.key_version, 1);
        assert_eq!(body.caip2_id, inputs["caip2Id"].as_str().unwrap());
        assert_eq!(body.dest, inputs["dest"].as_str().unwrap());
        assert_eq!(body.params, "");
        assert_eq!(hex::encode(body.evm_to), inputs["evmTo"].as_str().unwrap());
        assert_eq!(
            body.evm_chain_id.to_string(),
            inputs["evmChainId"].as_str().unwrap()
        );
        assert_eq!(
            body.evm_nonce.to_string(),
            inputs["evmNonce"].as_str().unwrap()
        );
        assert_eq!(
            body.evm_gas_limit.to_string(),
            inputs["evmGasLimit"].as_str().unwrap()
        );
        assert_eq!(
            body.evm_max_fee.to_string(),
            inputs["evmMaxFee"].as_str().unwrap()
        );
        assert_eq!(
            body.evm_priority_fee.to_string(),
            inputs["evmPriorityFee"].as_str().unwrap()
        );
        assert_eq!(
            body.evm_value.to_string(),
            inputs["evmValue"].as_str().unwrap()
        );
        assert_eq!(body.arg_count, 2);
        assert_eq!(body.func_sig, inputs["funcSig"].as_str().unwrap());
        assert_eq!(body.output_schema, inputs["outputSchema"].as_str().unwrap());
        assert_eq!(
            body.respond_schema,
            inputs["respondSchema"].as_str().unwrap()
        );
    }

    #[test]
    fn calldata_and_unsigned_tx_match_golden() {
        let g = golden("sign_bidirectional.json");
        let case = &g["cases"][0];
        let body = decode_sign_bidirectional(&parts_of(case)).unwrap();

        let calldata = build_calldata(&body.func_sig, &body.args, body.arg_count).unwrap();
        assert_eq!(
            hex::encode(&calldata),
            case["evm"]["calldata"].as_str().unwrap()
        );

        let unsigned = build_unsigned_eip1559(&body).unwrap();
        let expected = case["evm"]["unsignedSerializedTx"].as_str().unwrap();
        assert_eq!(format!("0x{}", hex::encode(&unsigned)), expected);

        let signing_hash = alloy_primitives::keccak256(&unsigned);
        assert_eq!(
            format!("0x{}", hex::encode(signing_hash)),
            case["evm"]["signingHash"].as_str().unwrap()
        );
    }

    #[test]
    fn empty_func_sig_means_value_transfer() {
        assert!(build_calldata("", &[[0u8; 32]; 4], 0).unwrap().is_empty());
        assert!(build_calldata("", &[[0u8; 32]; 4], 1).is_err());
    }

    #[test]
    fn decodes_respond_signature_from_golden() {
        let g = golden("respond.json");
        let case = &g["cases"][0];
        let sig = decode_respond(&parts_of(case)).unwrap();
        // The golden uses the secp256k1 generator point and s = 9.
        assert_eq!(sig.big_r, k256::AffinePoint::GENERATOR);
        assert_eq!(sig.s, k256::Scalar::from(9u64));
        assert_eq!(sig.recovery_id, 0);
    }

    #[test]
    fn decodes_respond_bidirectional_from_golden() {
        let g = golden("respond_bidirectional.json");
        let case = &g["cases"][0];
        let (output, sig) = decode_respond_bidirectional(&parts_of(case)).unwrap();
        assert_eq!(output.len(), 32);
        let mut abi_true = vec![0u8; 32];
        abi_true[31] = 1;
        assert_eq!(output, abi_true);
        assert_eq!(sig.big_r, k256::AffinePoint::GENERATOR);

        // Phase-2 message = keccak256(requestId || output[..outputLen]).
        let rid = hex32(case["inputs"]["requestId"].as_str().unwrap());
        let mut preimage = rid.to_vec();
        preimage.extend_from_slice(&output);
        assert_eq!(
            hex::encode(alloy_primitives::keccak256(&preimage)),
            case["phase2"]["messageHash"].as_str().unwrap()
        );
    }

    #[test]
    fn rejects_out_of_order_and_wrong_kind_parts() {
        let g = golden("sign_bidirectional.json");
        let mut parts = parts_of(&g["cases"][0]);
        parts.swap(1, 2);
        assert!(decode_sign_bidirectional(&parts).is_err());
        assert!(decode_sign(&parts[..1]).is_err());
    }
}
