use anyhow::Context;
use borsh::BorshSerialize;
use ed25519_dalek::{Digest, Sha512, Signature};
use near_crypto::PublicKey;

use crate::{
    msg::{AddKey, ClaimOidcRequest, ClaimOidcResponse},
    sign_node::CommitError,
};

pub fn add_key_digest(
    AddKey {
        account_id_from_leader,
        near_account_id,
        oidc_token,
        user_local_pk,
        ..
    }: &AddKey,
) -> Result<Vec<u8>, CommitError> {
    // As per the readme
    // The signature field is a signature of:
    // sha256.hash(Borsh.serialize<u32>(SALT + 2) ++ Borsh.serialize(
    #[derive(BorshSerialize)]
    struct B {
        near_account_id: Option<String>,
        oidc_token: String,
        public_key: String,
    }
    // ))
    // signed by the key you used to claim the oidc token.
    // This does not have to be the same as the key in the public key field.
    let mut hasher = Sha512::default();
    BorshSerialize::serialize(&HashSalt::ClaimOidcRequest.get_salt(), &mut hasher)
        .map_err(|e| CommitError::Other(anyhow::anyhow!(e)))?;
    let near_account_id = if *account_id_from_leader {
        None
    } else {
        Some(near_account_id.clone())
    };
    BorshSerialize::serialize(
        &B {
            near_account_id: near_account_id.clone(),
            oidc_token: oidc_token.clone(),
            public_key: user_local_pk.clone(),
        },
        &mut hasher,
    );
    Ok(hasher.finalize().to_vec())
}

pub fn claim_id_token_request_digest(
    ClaimOidcRequest {
        id_token_hash,
        public_key,
        signature,
    }: &ClaimOidcRequest,
) -> Result<Vec<u8>, CommitError> {
    // As per the readme
    // To verify the signature of the message verify:
    // sha256.hash(Borsh.serialize<u32>(SALT + 0) ++ Borsh.serialize<[u8]>(id_token_hash))
    let mut hasher = Sha512::default();
    BorshSerialize::serialize(&HashSalt::ClaimOidcRequest.get_salt(), &mut hasher)
        .context("Serialization failed")?;
    BorshSerialize::serialize(&id_token_hash, &mut hasher).context("Serialization failed")?;
    Ok(hasher.finalize().to_vec())
}

pub fn claim_id_token_response_digest(users_signature: Signature) -> Result<Vec<u8>, CommitError> {
    // As per the readme
    // If you successfully claim the token you will receive a signature in return of:
    // sha256.hash(Borsh.serialize<u32>(SALT + 1) ++ Borsh.serialize<[u8]>(signature))
    let mut hasher = Sha512::default();
    BorshSerialize::serialize(&HashSalt::ClaimOidcResponse.get_salt(), &mut hasher)
        .context("Serialization failed")?;
    BorshSerialize::serialize(&users_signature.to_bytes(), &mut hasher)
        .context("Serialization failed")?;
    Ok(hasher.finalize().to_vec())
}

pub fn check_signature(
    public_key: &PublicKey,
    signature: &Signature,
    request_digest: &[u8],
) -> Result<(), CommitError> {
    {
        if !near_crypto::Signature::ED25519(signature.clone()).verify(&request_digest, &public_key)
        {
            return Err(CommitError::SignatureVerificationFailed(anyhow::anyhow!(
                "Public key {}, digest {} and signature {} don't match",
                &public_key,
                &hex::encode(request_digest),
                &signature
            )));
        } else {
            Ok(())
        }
    }
}

pub fn oidc_digest(oidc_token: &str) -> [u8; 32] {
    let hasher = Sha512::default().chain(oidc_token.as_bytes());

    <[u8; 32]>::try_from(hasher.finalize().as_slice()).expect("Hash is the wrong size")
}

#[derive(Copy, Clone)]
pub enum HashSalt {
    ClaimOidcRequest = 0,
    ClaimOidcResponse = 1,
    CreateAccountRequest = 2,
    SignRequest = 3,
}

/// Mentioned in the readme, here to avoid collisions with legitimate transactions
// chosen by a fair dice roll.
// guaranteed to be random.
const SALT_BASE: u32 = 3177899144;
impl HashSalt {
    pub fn get_salt(&self) -> u32 {
        SALT_BASE + (*self as u32)
    }
}
