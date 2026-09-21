use alloy::primitives::keccak256;
use mpc_primitives::RequestId;

use super::request_id::EvmRequestId;

/// Transitional wrapper over [`EvmRequestId::from_evm_sign_request`] for the
/// Solana and Hydration indexers; removed once they call the constructor directly.
#[allow(clippy::too_many_arguments)]
pub fn compute_request_id(
    sender: &str,
    payload: &[u8; 32],
    path: &str,
    key_version: u32,
    chain_id: &str,
    algo: &str,
    dest: &str,
    params: &str,
) -> [u8; 32] {
    RequestId::from_evm_sign_request(
        sender,
        payload,
        path,
        key_version,
        chain_id,
        algo,
        dest,
        params,
    )
    .bytes
}

/// Computes the Keccak256 hash of the given payload.
pub fn hash_payload(data: &[u8]) -> [u8; 32] {
    keccak256(data).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_payload_empty() {
        // keccak256("")
        let expected: [u8; 32] = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];
        assert_eq!(hash_payload(&[]), expected);
    }

    #[test]
    fn hash_payload_known_value() {
        let result = hash_payload(b"hello");
        // Must be 32 bytes and deterministic
        assert_eq!(result.len(), 32);
        // Same input must return the same hash
        assert_eq!(result, hash_payload(b"hello"));
    }

    #[test]
    fn hash_payload_single_byte() {
        let a = hash_payload(&[0x00]);
        let b = hash_payload(&[0x01]);
        assert_ne!(a, b);
        assert_eq!(a, hash_payload(&[0x00]));
    }
}
