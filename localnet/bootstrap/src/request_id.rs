//! Deriving the request id the MPC cluster will key its response on.
//!
//! This duplicates `SignatureRequestedEvent::generate_request_id` in
//! `chain-signatures/node/src/indexer_sol.rs`, which is a private trait impl inside
//! `mpc-node`. Importing it would mean compiling the whole node into the bootstrap image
//! for fifteen lines of ABI encoding. Delete this module and call the node's version if
//! that derivation ever moves into `mpc-primitives`, or if `mpc-node` becomes a dependency
//! here for another reason. If the two ever disagree, `sign` waits forever for a response
//! that is really there under a different id.

use ethabi::{encode, Token};
use sha3::{Digest, Keccak256};
use signet_program::SignatureRequestedEvent;

pub fn for_signature_request(event: &SignatureRequestedEvent) -> [u8; 32] {
    let encoded = encode(&[
        Token::String(event.sender.to_string()),
        Token::Bytes(event.payload.to_vec()),
        Token::String(event.path.clone()),
        Token::Uint(event.key_version.into()),
        Token::String(event.chain_id.clone()),
        Token::String(event.algo.clone()),
        Token::String(event.dest.clone()),
        Token::String(event.params.clone()),
    ]);
    let mut hasher = Keccak256::new();
    hasher.update(&encoded);
    hasher.finalize().into()
}
