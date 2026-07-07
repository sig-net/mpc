//! Test-only helpers for reading the SGN1 golden vectors in `tests/goldens/`.

use serde_json::Value;

pub(crate) fn golden(name: &str) -> Value {
    let path = format!("{}/tests/goldens/{}", env!("CARGO_MANIFEST_DIR"), name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read golden {path}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("invalid golden JSON {path}: {e}"))
}

pub(crate) fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).expect("golden hex32");
    out
}

pub(crate) fn payload_bytes(ev: &Value) -> Vec<u8> {
    hex::decode(ev["payload"].as_str().expect("event payload")).expect("payload hex")
}
