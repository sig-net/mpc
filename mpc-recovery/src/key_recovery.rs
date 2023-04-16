use crate::primitives::InternalAccountId;
use near_crypto::{PublicKey, SecretKey};

pub fn get_user_recovery_pk(_id: InternalAccountId) -> PublicKey {
    // TODO: use key derivation or other techniques to generate a key
    return "ed25519:3BUQYE4ZfQ6A94CqCtAbdLURxo4eHv2L8JjC2KiXXdFn"
        .parse()
        .unwrap();
}

pub fn get_user_recovery_sk(_id: InternalAccountId) -> SecretKey {
    // TODO: use key derivation or other techniques to generate a key
    return "ed25519:5pFJN3czPAHFWHZYjD4oTtnJE7PshLMeTkSU7CmWkvLaQWchCLgXGF1wwcJmh2AQChGH85EwcL5VW7tUavcAZDSG".parse().unwrap();
}
