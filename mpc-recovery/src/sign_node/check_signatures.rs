use borsh::BorshSerialize;
use ed25519_dalek::{Digest, Sha512, Signature};
use near_crypto::PublicKey;

use crate::{msg::AddKey, sign_node::CommitError};

pub fn check_add_key_signature(
    AddKey {
        account_id_from_leader,
        user_recovery_pk,
        near_account_id,
        oidc_token,
        user_local_pk: public_key,
        ..
    }: &AddKey,
    oidc_owner_public_key: PublicKey,
    signature: Signature,
) -> Result<(), CommitError> {
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
    {
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
                public_key: public_key.clone(),
            },
            &mut hasher,
        );
        let request_digest = hasher.finalize();

        if !near_crypto::Signature::ED25519(signature)
            .verify(&request_digest, &oidc_owner_public_key)
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
    AddKeyRequest = 2,
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
