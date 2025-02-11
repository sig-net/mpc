use mpc_keys::hpke;
use crypto_shared::{self, derive_epsilon_admin_addr_eth, derive_key, x_coordinate, ScalarExt};
use integration_tests::actions;

fn main() {
    let (sk, pk) = hpke::generate();
    let derivation_path = "sig-network-eth-contract-balance-gov";
    let epsilon = derive_epsilon_admin_addr_eth(derivation_path);
    let derived_pk = derive_key(pk, epsilon);
    let derived_pk_x = x_coordinate(&derived_pk);
    let derived_pk_y_parity = match derived_pk.y_is_odd().unwrap_u8() {
        1 => secp256k1::Parity::Odd,
        0 => secp256k1::Parity::Even,
        _ => unreachable!(),
    };
    let derived_pk_x = secp256k1::XOnlyPublicKey::from_slice(&derived_pk_x.to_bytes()).unwrap();
    let derived_secp_pk =
        secp256k1::PublicKey::from_x_only_public_key(derived_pk_x, derived_pk_y_parity);
    let derived_addr = actions::public_key_to_address(&derived_secp_pk);
    println!("Derived address: {}", derived_addr);
}