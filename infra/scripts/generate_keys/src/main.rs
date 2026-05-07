use ethers::signers::LocalWallet;
use ethers::signers::Signer;
use hpke::kem::X25519HkdfSha256;
use hpke::{Kem as KemTrait, Serializable};
use sp_core::crypto::{Ss58AddressFormatRegistry, Ss58Codec};
use sp_core::{sr25519, Pair};
use std::env;

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

    let mut csprng = <rand::rngs::StdRng as rand::SeedableRng>::from_entropy();
    let (cipher_sk, cipher_pk) = X25519HkdfSha256::gen_keypair(&mut csprng);
    let cipher_pk = hex::encode(Serializable::to_bytes(&cipher_pk));
    let cipher_sk = hex::encode(Serializable::to_bytes(&cipher_sk));
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
