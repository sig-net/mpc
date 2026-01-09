use k256::ecdsa::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand::RngCore;
use mpc_keys::hpke;
use sp_core::crypto::{Ss58AddressFormatRegistry, Ss58Codec};
use sp_core::{sr25519, Pair};
use std::env;

fn new_eth_wallet_from_entropy() -> (Vec<u8>, Vec<u8>) {
    // Generate a random 32-byte private key for test wallets
    let mut rng = rand::thread_rng();
    let mut private = [0u8; 32];
    rng.fill_bytes(&mut private);

    let signing_key = SigningKey::from_bytes(&private).unwrap();
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);

    (private.to_vec(), encoded.as_bytes().to_vec())
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let (hydration_pair, hydration_phrase, _seed) = sr25519::Pair::generate_with_phrase(None);

    let hydration_account_id = hydration_pair
        .public()
        .to_ss58check_with_version(Ss58AddressFormatRegistry::PolkadotAccount.into());

    println!("Hydrationsigner_uri (secret phrase): {hydration_phrase}");
    println!("Hydration ss58 address: {hydration_account_id}");

    let solana_sk = near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
    let solana_pk = solana_sk.public_key();
    println!(
        "Solana public key: {}",
        solana_pk.to_string().trim_start_matches("ed25519:")
    );
    println!(
        "Solana private key: {}",
        solana_sk.to_string().trim_start_matches("ed25519:")
    );

    if args.len() >= 3 && args[2] == "--only-solana" {
        return;
    }

    let (cipher_sk, cipher_pk) = hpke::generate();
    let cipher_pk = hex::encode(cipher_pk.to_bytes());
    let cipher_sk = hex::encode(cipher_sk.to_bytes());
    println!("cipher public key: {}", cipher_pk);
    println!("cipher private key: {}", cipher_sk);
    let sign_sk = near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
    let sign_pk = sign_sk.public_key();
    println!("sign public key sign_pk: {}", sign_pk);
    println!("sign secret key sign_sk: {}", sign_sk);
    let near_account_sk = near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);
    let near_account_pk = near_account_sk.public_key();
    println!("near account public key: {}", near_account_pk);
    println!("near account secret key: {}", near_account_sk);

    // generate ethereum account secret and public key
    let (private_key, public_key, phrase) = new_eth_wallet_from_entropy();
    println!("ethereum account private key: {}", hex::encode(private_key));
    println!(
        "ethereum account public key: {}",
        hex::encode(public_key)
    );
    println!("Ethereum mnemonic phrase: {}", phrase);
}
