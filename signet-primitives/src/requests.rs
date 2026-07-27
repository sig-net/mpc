use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Arguments a client submits to the contract's `sign` entrypoint.
///
/// This is the exact type the NEAR contract deserializes, so a client
/// compiling against this crate is wire-correct by construction. `payload`
/// is the 32-byte hash to sign; `path` is the derivation path; `key_version`
/// must be `<=` the contract's latest key version (see
/// [`crate::LATEST_MPC_KEY_VERSION`]).
#[derive(Serialize, Deserialize, BorshDeserialize, BorshSerialize, Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

impl SignRequest {
    pub fn new(payload: [u8; 32], path: String, key_version: u32) -> Self {
        Self {
            payload,
            path,
            key_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_wire_form_is_stable() {
        // The contract deserializes this exact JSON shape: `payload` is a
        // sequence of byte values (not a hex string), `key_version` is snake
        // case. Locking it here guards the on-chain ABI.
        let req = SignRequest::new([1u8; 32], "m/44'/60'/0'/0/0".to_string(), 1);
        let json = serde_json::to_value(&req).unwrap();
        assert!(json["payload"].is_array());
        assert_eq!(json["payload"].as_array().unwrap().len(), 32);
        assert_eq!(json["payload"][0], 1);
        assert_eq!(json["path"], "m/44'/60'/0'/0/0");
        assert_eq!(json["key_version"], 1);

        let back: SignRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn borsh_roundtrip() {
        let req = SignRequest::new([7u8; 32], "path".to_string(), 0);
        let bytes = borsh::to_vec(&req).unwrap();
        let back: SignRequest = borsh::from_slice(&bytes).unwrap();
        assert_eq!(back, req);
    }
}
