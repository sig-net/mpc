use base58::FromBase58;
use hex;
use sha3::{Digest, Keccak256};

fn main() {
    // The Base58 encoded public key
    let base58_pub_key =
        "DG1Q7zuxgWu5MyQNZry1B4nqGTfxNEzrjsSVBCoKyarfQVk4eXEy2Mykgi8zBW32Ly6Y9LMSxAjnDZNydqSf6fi";

    // Step 1: Base58 decode the public key
    let decoded_pub_key = base58_pub_key
        .from_base58()
        .expect("Failed to decode Base58");

    println!("Decoded Pub Key: {}", hex::encode(decoded_pub_key.clone()));

    // Step 2: Perform Keccak-256 hash on the decoded public key (skip the 0x04 prefix for uncompressed keys)
    let mut hasher = Keccak256::new();
    hasher.update(&decoded_pub_key[1..]); // Skip the 0x04 prefix
    let hash_result = hasher.finalize();

    // Step 3: Get the last 20 bytes of the hash to get the Ethereum address
    let eth_address = &hash_result[12..]; // Ethereum address is the last 20 bytes of the hash

    // Format the Ethereum address as a hex string with 0x prefix
    let eth_address_hex = format!("0x{}", hex::encode(eth_address));

    println!("Ethereum Address: {}", eth_address_hex);
}
