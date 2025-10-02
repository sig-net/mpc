use base58::FromBase58;
use k256::{PublicKey as K256PublicKey, EncodedPoint};
use sha3::{Digest, Keccak256};
use anyhow::{bail, Result};
use k256::elliptic_curve::sec1::ToEncodedPoint;

fn to_uncompressed_payload(pubkey_bytes: &[u8]) -> Result<[u8; 64]> {
    match pubkey_bytes {
        // 65-byte uncompressed, 0x04 || X(32) || Y(32)
        bytes if bytes.len() == 65 && bytes[0] == 0x04 => {
            let mut xy = [0u8; 64];
            xy.copy_from_slice(&bytes[1..]);
            Ok(xy)
        }
        // 33-byte compressed, 0x02/0x03 || X(32): decompress first
        bytes if bytes.len() == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03) => {
            let pk = K256PublicKey::from_sec1_bytes(bytes)?;
            let uncompressed = pk.to_encoded_point(false);
            let un = uncompressed.as_bytes();
            debug_assert_eq!(un.len(), 65);
            let mut xy = [0u8; 64];
            xy.copy_from_slice(&un[1..]);
            Ok(xy)
        }
        // 64-byte raw X||Y (no prefix)
        bytes if bytes.len() == 64 => {
            // Validate it’s a real secp256k1 point by adding 0x04 and parsing
            let mut un = Vec::with_capacity(65);
            un.push(0x04);
            un.extend_from_slice(bytes);
            let _ = K256PublicKey::from_sec1_bytes(&un)?; // will error if not on-curve
            let mut xy = [0u8; 64];
            xy.copy_from_slice(bytes);
            Ok(xy)
        }
        // Anything else (e.g., 32 bytes) is not a usable secp256k1 pubkey format
        _ => bail!("unsupported pubkey format: len={}", pubkey_bytes.len()),
    }
}

fn evm_address_from_pubkey_any(pubkey_bytes: &[u8]) -> Result<[u8; 20]> {
    let xy = to_uncompressed_payload(pubkey_bytes)?;
    let mut hasher = Keccak256::new();
    hasher.update(&xy); // x||y, 64 bytes
    let hash = hasher.finalize();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Ok(addr)
}

fn main() -> Result<()> {
    let b58 = "5hvYxCbsj5pfSZEntnk5tZXvxgaz6qCg1ybVVpGSq9Pc8mYRerc9agn8br7Eq3rRkbwVTLgLUrBD8rReFiem8sAK";
    let decoded = b58.from_base58().unwrap(); // your 64-byte blob
    println!("decoded pub key:{}", hex::encode(&decoded));

    // Derive address
    let addr = evm_address_from_pubkey_any(&decoded)?;
    println!("EVM address: 0x{}", hex::encode(addr));

    // If you need [u8;20] for Anchor:
    println!("mpc_root_signer_address bytes: {:?}", addr);
    Ok(())
}
