//! Pins `derive_epsilon_midnight` + derived-EVM-address against the TS-generated
//! golden vectors (fixture contract address + golden caller commitment).

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint};
use serde_json::Value;

fn golden(name: &str) -> Value {
    let path = format!("{}/tests/goldens/{}", env!("CARGO_MANIFEST_DIR"), name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn scalar_hex(s: &k256::Scalar) -> String {
    hex::encode(s.to_bytes())
}

fn root_pk(g: &Value) -> AffinePoint {
    let bytes = hex::decode(g["fixtures"]["rootPublicKeyUncompressed"].as_str().unwrap()).unwrap();
    let point = EncodedPoint::from_bytes(&bytes).unwrap();
    AffinePoint::from_encoded_point(&point).unwrap()
}

fn eth_address(pk: &AffinePoint) -> String {
    let encoded = pk.to_encoded_point(false);
    let hash = alloy_primitives::keccak256(&encoded.as_bytes()[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

#[test]
fn epsilon_and_derived_address_match_sign_golden() {
    let g = golden("sign.json");
    let contract = g["fixtures"]["contractAddress"].as_str().unwrap();
    let case = &g["cases"][0];
    let path = case["indexed"]["path"].as_str().unwrap();

    let epsilon = mpc_crypto::kdf::derive_epsilon_midnight(1, contract, path);
    assert_eq!(
        scalar_hex(&epsilon),
        case["derivation"]["epsilon"].as_str().unwrap(),
        "epsilon v2 derivation must match the TS golden"
    );

    let derived = mpc_crypto::derive_key(root_pk(&g), epsilon);
    assert_eq!(
        eth_address(&derived),
        case["derivation"]["evmAddress"]
            .as_str()
            .unwrap()
            .to_lowercase()
    );
}

#[test]
fn respond_key_epsilon_matches_phase2_golden() {
    let g = golden("respond_bidirectional.json");
    let sign_g = golden("sign.json");
    let contract = sign_g["fixtures"]["contractAddress"].as_str().unwrap();
    let phase2 = &g["cases"][0]["phase2"];

    let epsilon =
        mpc_crypto::kdf::derive_epsilon_midnight(1, contract, phase2["path"].as_str().unwrap());
    assert_eq!(scalar_hex(&epsilon), phase2["epsilon"].as_str().unwrap());

    let derived = mpc_crypto::derive_key(root_pk(&sign_g), epsilon);
    assert_eq!(
        eth_address(&derived),
        phase2["evmAddress"].as_str().unwrap().to_lowercase()
    );
}
