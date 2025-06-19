use ethers::signers::LocalWallet;
use ethers::signers::Signer;
use mpc_keys::hpke;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

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
    let wallet = LocalWallet::new(&mut rand::thread_rng());
    let private_key = wallet.signer().to_bytes();
    let public_key = wallet.signer().verifying_key().to_encoded_point(false);
    println!("ethereum account private key: {}", hex::encode(private_key));
    println!(
        "ethereum account public key: {}",
        hex::encode(public_key.as_bytes())
    );
    println!("Ethereum Address: {:?}", wallet.address());
}
