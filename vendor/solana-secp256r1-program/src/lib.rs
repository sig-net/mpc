//! Instructions for the [secp256r1 native program][np].
//! [np]: https://docs.solana.com/developing/runtime-facilities/programs#secp256r1-program
//!
//! Note on Signature Malleability:
//! This precompile requires low-S values in signatures (s <= half_curve_order) to prevent signature
//! malleability. Signature malleability means that for a valid signature (r,s), (r, order-s) is also
//! valid for the same message and public key.
use bytemuck::{Pod, Zeroable};
pub use solana_sdk_ids::secp256r1_program::{check_id, id, ID};

#[cfg(not(any(feature = "rustls", feature = "openssl")))]
compile_error!("either the `rustls` or `openssl` feature must be enabled");

pub const FIELD_SIZE: usize = 32;
pub const COMPRESSED_PUBKEY_SERIALIZED_SIZE: usize = 33;
pub const SIGNATURE_SERIALIZED_SIZE: usize = FIELD_SIZE * 2;
pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 14;
pub const SIGNATURE_OFFSETS_START: usize = 2;
pub const DATA_START: usize = SIGNATURE_OFFSETS_SERIALIZED_SIZE + SIGNATURE_OFFSETS_START;

// Order as defined in SEC2: 2.7.2 Recommended Parameters secp256r1
pub const SECP256R1_ORDER: [u8; FIELD_SIZE] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

// Computed SECP256R1_ORDER - 1
pub const SECP256R1_ORDER_MINUS_ONE: [u8; FIELD_SIZE] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x50,
];

// Computed half order
pub const SECP256R1_HALF_ORDER: [u8; FIELD_SIZE] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

#[derive(Default, Debug, Copy, Clone, Zeroable, Pod, Eq, PartialEq)]
#[repr(C)]
pub struct Secp256r1SignatureOffsets {
    pub signature_offset: u16,
    pub signature_instruction_index: u16,
    pub public_key_offset: u16,
    pub public_key_instruction_index: u16,
    pub message_data_offset: u16,
    pub message_data_size: u16,
    pub message_instruction_index: u16,
}

#[cfg(all(
    not(target_arch = "wasm32"),
    not(target_os = "solana"),
    any(feature = "rustls", feature = "openssl"),
))]
mod native_host {
    use {
        super::{
            get_data_slice, COMPRESSED_PUBKEY_SERIALIZED_SIZE, FIELD_SIZE,
            Secp256r1SignatureOffsets, SECP256R1_HALF_ORDER, SECP256R1_ORDER,
            SECP256R1_ORDER_MINUS_ONE, SIGNATURE_OFFSETS_SERIALIZED_SIZE,
            SIGNATURE_OFFSETS_START, SIGNATURE_SERIALIZED_SIZE,
        },
        p256::{
            ecdsa::{signature::Verifier as _, Signature, VerifyingKey},
            elliptic_curve::bigint::U256,
        },
        solana_feature_set::FeatureSet,
        solana_precompile_error::PrecompileError,
    };

    pub fn verify(
        data: &[u8],
        instruction_datas: &[&[u8]],
        _feature_set: &FeatureSet,
    ) -> Result<(), PrecompileError> {
        if data.len() < SIGNATURE_OFFSETS_START {
            return Err(PrecompileError::InvalidInstructionDataSize);
        }
        let num_signatures = data[0] as usize;
        if num_signatures == 0 {
            return Err(PrecompileError::InvalidInstructionDataSize);
        }
        if num_signatures > 8 {
            return Err(PrecompileError::InvalidInstructionDataSize);
        }

        let expected_data_size = num_signatures
            .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
            .saturating_add(SIGNATURE_OFFSETS_START);

        if data.len() < expected_data_size {
            return Err(PrecompileError::InvalidInstructionDataSize);
        }

        let half_order = U256::from_be_slice(&SECP256R1_HALF_ORDER);
        let order_minus_one = U256::from_be_slice(&SECP256R1_ORDER_MINUS_ONE);
        let order = U256::from_be_slice(&SECP256R1_ORDER);
        let one = U256::from_u64(1);

        for i in 0..num_signatures {
            let start = i
                .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
                .saturating_add(SIGNATURE_OFFSETS_START);
            let end = start.saturating_add(SIGNATURE_OFFSETS_SERIALIZED_SIZE);

            let offsets: &Secp256r1SignatureOffsets =
                bytemuck::try_from_bytes(&data[start..end])
                    .map_err(|_| PrecompileError::InvalidDataOffsets)?;

            let signature = get_data_slice(
                data,
                instruction_datas,
                offsets.signature_instruction_index,
                offsets.signature_offset,
                SIGNATURE_SERIALIZED_SIZE,
            )?;

            let pubkey = get_data_slice(
                data,
                instruction_datas,
                offsets.public_key_instruction_index,
                offsets.public_key_offset,
                COMPRESSED_PUBKEY_SERIALIZED_SIZE,
            )?;

            let message = get_data_slice(
                data,
                instruction_datas,
                offsets.message_instruction_index,
                offsets.message_data_offset,
                offsets.message_data_size as usize,
            )?;

            let r = U256::from_be_slice(&signature[..FIELD_SIZE]);
            let s = U256::from_be_slice(&signature[FIELD_SIZE..]);

            if r < one || r > order_minus_one || s < one || s > half_order {
                return Err(PrecompileError::InvalidSignature);
            }

            let ecdsa_signature = Signature::try_from(signature)
                .map_err(|_| PrecompileError::InvalidSignature)?;

            let verifying_key = VerifyingKey::from_sec1_bytes(pubkey)
                .map_err(|_| PrecompileError::InvalidPublicKey)?;
            verifying_key
                .verify(message, &ecdsa_signature)
                .map_err(|_| PrecompileError::InvalidSignature)?;
        }

        debug_assert_eq!(order, half_order.wrapping_mul(&U256::from_u64(2)));
        debug_assert_eq!(order, order_minus_one.wrapping_add(&one));

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use {
            super::*,
            bytemuck,
            p256::ecdsa::{signature::Signer as _, SigningKey},
            rand_core::OsRng,
            solana_feature_set::FeatureSet,
            solana_precompile_error::PrecompileError,
        };

        fn build_instruction(
            signing_key: &SigningKey,
            message: &[u8],
        ) -> (Vec<u8>, Vec<Vec<u8>>) {
            let verifying_key = signing_key.verifying_key();
            let mut signature_bytes = signing_key.sign(message).to_bytes().to_vec();

            let mut s = U256::from_be_slice(&signature_bytes[FIELD_SIZE..]);
            let half_order = U256::from_be_slice(&SECP256R1_HALF_ORDER);
            if s > half_order {
                let order = U256::from_be_slice(&SECP256R1_ORDER);
                s = order.wrapping_sub(&s);
                let mut s_bytes = [0u8; FIELD_SIZE];
                s.to_be_bytes(&mut s_bytes);
                signature_bytes[FIELD_SIZE..].copy_from_slice(&s_bytes);
            }

            let mut data = Vec::with_capacity(
                DATA_START
                    + COMPRESSED_PUBKEY_SERIALIZED_SIZE
                    + SIGNATURE_SERIALIZED_SIZE
                    + message.len(),
            );

            let public_key_offset = DATA_START;
            let signature_offset = public_key_offset + COMPRESSED_PUBKEY_SERIALIZED_SIZE;
            let message_offset = signature_offset + SIGNATURE_SERIALIZED_SIZE;

            data.extend_from_slice(&[1, 0]);
            let offsets = Secp256r1SignatureOffsets {
                signature_offset: signature_offset as u16,
                signature_instruction_index: u16::MAX,
                public_key_offset: public_key_offset as u16,
                public_key_instruction_index: u16::MAX,
                message_data_offset: message_offset as u16,
                message_data_size: message.len() as u16,
                message_instruction_index: u16::MAX,
            };
            data.extend_from_slice(bytemuck::bytes_of(&offsets));

            let compressed = verifying_key.to_encoded_point(true);
            data.extend_from_slice(compressed.as_bytes());
            data.extend_from_slice(&signature_bytes);
            data.extend_from_slice(message);

            (data, vec![])
        }

        #[test]
        fn verify_valid_signature() {
            let signing_key = SigningKey::random(&mut OsRng);
            let message = b"hello";
            let (instruction_data, instruction_datas) = build_instruction(&signing_key, message);
            let instruction_refs: Vec<&[u8]> =
                instruction_datas.iter().map(|v| v.as_slice()).collect();

            assert!(super::verify(
                &instruction_data,
                &instruction_refs,
                &FeatureSet::all_enabled()
            )
            .is_ok());
        }

        #[test]
        fn reject_modified_message() {
            let signing_key = SigningKey::random(&mut OsRng);
            let message = b"hello";
            let (mut instruction_data, instruction_datas) = build_instruction(&signing_key, message);
            *instruction_data.last_mut().unwrap() ^= 0xFF;
            let instruction_refs: Vec<&[u8]> =
                instruction_datas.iter().map(|v| v.as_slice()).collect();

            assert_eq!(
                super::verify(
                    &instruction_data,
                    &instruction_refs,
                    &FeatureSet::all_enabled()
                ),
                Err(PrecompileError::InvalidSignature)
            );
        }

        #[test]
        fn reject_high_s_signature() {
            let signing_key = SigningKey::random(&mut OsRng);
            let message = b"hello";
            let (mut instruction_data, instruction_datas) = build_instruction(&signing_key, message);

            let signature_offset = DATA_START + COMPRESSED_PUBKEY_SERIALIZED_SIZE;
            let s_slice = &mut instruction_data
                [signature_offset + FIELD_SIZE..signature_offset + SIGNATURE_SERIALIZED_SIZE];
            let order = U256::from_be_slice(&SECP256R1_ORDER);
            let current_s = U256::from_be_slice(s_slice);
            let mut high_s = order.wrapping_sub(&current_s);
            let mut high_s_bytes = [0u8; FIELD_SIZE];
            high_s.to_be_bytes(&mut high_s_bytes);
            s_slice.copy_from_slice(&high_s_bytes);
            let instruction_refs: Vec<&[u8]> =
                instruction_datas.iter().map(|v| v.as_slice()).collect();

            assert_eq!(
                super::verify(
                    &instruction_data,
                    &instruction_refs,
                    &FeatureSet::all_enabled()
                ),
                Err(PrecompileError::InvalidSignature)
            );
        }
    }
}

#[cfg(any(target_arch = "wasm32", target_os = "solana"))]
mod native_stub {
    use {solana_feature_set::FeatureSet, solana_precompile_error::PrecompileError};

    pub fn verify(
        _data: &[u8],
        _instruction_datas: &[&[u8]],
        _feature_set: &FeatureSet,
    ) -> Result<(), PrecompileError> {
        Err(PrecompileError::InvalidSignature)
    }
}

fn get_data_slice<'a>(
    data: &'a [u8],
    instruction_datas: &'a [&[u8]],
    instruction_index: u16,
    offset_start: u16,
    size: usize,
) -> Result<&'a [u8], solana_precompile_error::PrecompileError> {
    let instruction = if instruction_index == u16::MAX {
        data
    } else {
        let signature_index = instruction_index as usize;
        if signature_index >= instruction_datas.len() {
            return Err(solana_precompile_error::PrecompileError::InvalidDataOffsets);
        }
        instruction_datas[signature_index]
    };

    let start = offset_start as usize;
    let end = start.saturating_add(size);
    if end > instruction.len() {
        return Err(solana_precompile_error::PrecompileError::InvalidDataOffsets);
    }

    Ok(&instruction[start..end])
}

#[cfg(all(
    not(target_arch = "wasm32"),
    not(target_os = "solana"),
    any(feature = "rustls", feature = "openssl"),
))]
pub use native_host::*;

#[cfg(any(target_arch = "wasm32", target_os = "solana"))]
pub use native_stub::*;
