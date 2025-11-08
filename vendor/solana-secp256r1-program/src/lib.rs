//! Instructions for the [secp256r1 native program][np].
//! [np]: https://docs.solana.com/developing/runtime-facilities/programs#secp256r1-program
//!
//! Note on Signature Malleability:
//! This precompile requires low-S values in signatures (s <= half_curve_order) to prevent signature malleability.
//! Signature malleability means that for a valid signature (r,s), (r, order-s) is also valid for the
//! same message and public key.
//!
//! This property can be problematic for developers who assume each signature is unique. Without enforcing
//! low-S values, the same message and key can produce two different valid signatures, potentially breaking
//! replay protection schemes that rely on signature uniqueness.
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
    /// Offset to compact secp256r1 signature of 64 bytes
    pub signature_offset: u16,

    /// Instruction index where the signature can be found
    pub signature_instruction_index: u16,

    /// Offset to compressed public key of 33 bytes
    pub public_key_offset: u16,

    /// Instruction index where the public key can be found
    pub public_key_instruction_index: u16,

    /// Offset to the start of message data
    pub message_data_offset: u16,

    /// Size of message data in bytes
    pub message_data_size: u16,

    /// Instruction index where the message data can be found
    pub message_instruction_index: u16,
}

#[cfg(all(
    not(target_arch = "wasm32"),
    not(target_os = "solana"),
    feature = "openssl",
))]
mod native_openssl {
    #![allow(dead_code)]
    use {
        super::{
            get_data_slice, COMPRESSED_PUBKEY_SERIALIZED_SIZE, DATA_START, FIELD_SIZE,
            Secp256r1SignatureOffsets, SECP256R1_HALF_ORDER, SECP256R1_ORDER,
            SECP256R1_ORDER_MINUS_ONE, SIGNATURE_OFFSETS_SERIALIZED_SIZE,
            SIGNATURE_OFFSETS_START, SIGNATURE_SERIALIZED_SIZE,
        },
        bytemuck::bytes_of,
        openssl::{
            bn::{BigNum, BigNumContext},
            ec::{EcGroup, EcKey, EcPoint},
            ecdsa::EcdsaSig,
            nid::Nid,
            pkey::{PKey, Private},
            sign::{Signer, Verifier},
        },
        solana_feature_set::FeatureSet,
        solana_instruction::Instruction,
        solana_precompile_error::PrecompileError,
    };

    pub fn new_secp256r1_instruction(
        message: &[u8],
        signing_key: EcKey<Private>,
    ) -> Result<Instruction, Box<dyn std::error::Error>> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        if signing_key.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
            return Err(("Signing key must be on the secp256r1 curve".to_string()).into());
        }

        let mut ctx = BigNumContext::new()?;
        let pubkey = signing_key.public_key().to_bytes(
            &group,
            openssl::ec::PointConversionForm::COMPRESSED,
            &mut ctx,
        )?;

        let signing_key_pkey = PKey::from_ec_key(signing_key)?;

        let mut signer = Signer::new(openssl::hash::MessageDigest::sha256(), &signing_key_pkey)?;
        signer.update(message)?;
        let signature = signer.sign_to_vec()?;

        let ecdsa_sig = EcdsaSig::from_der(&signature)?;
        let r = ecdsa_sig.r().to_vec();
        let s = ecdsa_sig.s().to_vec();
        let mut signature = vec![0u8; SIGNATURE_SERIALIZED_SIZE];

        // Incase of an r or s value of 31 bytes we need to pad it to 32 bytes
        let mut padded_r = vec![0u8; FIELD_SIZE];
        let mut padded_s = vec![0u8; FIELD_SIZE];
        padded_r[FIELD_SIZE.saturating_sub(r.len())..].copy_from_slice(&r);
        padded_s[FIELD_SIZE.saturating_sub(s.len())..].copy_from_slice(&s);

        signature[..FIELD_SIZE].copy_from_slice(&padded_r);
        signature[FIELD_SIZE..].copy_from_slice(&padded_s);

        // Check if s > half_order, if so, compute s = order - s
        let s_bignum = BigNum::from_slice(&s)?;
        let half_order = BigNum::from_slice(&SECP256R1_HALF_ORDER)?;
        let order = BigNum::from_slice(&SECP256R1_ORDER)?;
        if s_bignum > half_order {
            let mut new_s = BigNum::new()?;
            new_s.checked_sub(&order, &s_bignum)?;
            let new_s_bytes = new_s.to_vec();

            // Incase the new s value is 31 bytes we need to pad it to 32 bytes
            let mut new_padded_s = vec![0u8; FIELD_SIZE];
            new_padded_s[FIELD_SIZE.saturating_sub(new_s_bytes.len())..]
                .copy_from_slice(&new_s_bytes);

            signature[FIELD_SIZE..].copy_from_slice(&new_padded_s);
        }

        assert_eq!(pubkey.len(), COMPRESSED_PUBKEY_SERIALIZED_SIZE);
        assert_eq!(signature.len(), SIGNATURE_SERIALIZED_SIZE);

        let mut instruction_data = Vec::with_capacity(
            DATA_START
                .saturating_add(SIGNATURE_SERIALIZED_SIZE)
                .saturating_add(COMPRESSED_PUBKEY_SERIALIZED_SIZE)
                .saturating_add(message.len()),
        );

        let num_signatures: u8 = 1;
        let public_key_offset = DATA_START;
        let signature_offset = public_key_offset.saturating_add(COMPRESSED_PUBKEY_SERIALIZED_SIZE);
        let message_data_offset = signature_offset.saturating_add(SIGNATURE_SERIALIZED_SIZE);

        instruction_data.extend_from_slice(bytes_of(&[num_signatures, 0]));

        let offsets = Secp256r1SignatureOffsets {
            signature_offset: signature_offset as u16,
            signature_instruction_index: u16::MAX,
            public_key_offset: public_key_offset as u16,
            public_key_instruction_index: u16::MAX,
            message_data_offset: message_data_offset as u16,
            message_data_size: message.len() as u16,
            message_instruction_index: u16::MAX,
        };

        instruction_data.extend_from_slice(bytes_of(&offsets));
        instruction_data.extend_from_slice(&pubkey);
        instruction_data.extend_from_slice(&signature);
        instruction_data.extend_from_slice(message);

        Ok(Instruction {
            program_id: crate::id(),
            accounts: vec![],
            data: instruction_data,
        })
    }

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

        let half_order: BigNum = BigNum::from_slice(&SECP256R1_HALF_ORDER)
            .map_err(|_| PrecompileError::InvalidSignature)?;
        let order_minus_one: BigNum = BigNum::from_slice(&SECP256R1_ORDER_MINUS_ONE)
            .map_err(|_| PrecompileError::InvalidSignature)?;
        let one = BigNum::from_u32(1).map_err(|_| PrecompileError::InvalidSignature)?;

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .map_err(|_| PrecompileError::InvalidSignature)?;
        let mut ctx = BigNumContext::new().map_err(|_| PrecompileError::InvalidSignature)?;

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

            let r_bignum = BigNum::from_slice(&signature[..FIELD_SIZE])
                .map_err(|_| PrecompileError::InvalidSignature)?;
            let s_bignum = BigNum::from_slice(&signature[FIELD_SIZE..])
                .map_err(|_| PrecompileError::InvalidSignature)?;

            let within_range = r_bignum >= one
                && r_bignum <= order_minus_one
                && s_bignum >= one
                && s_bignum <= half_order;

            if !within_range {
                return Err(PrecompileError::InvalidSignature);
            }

            let ecdsa_sig = openssl::ecdsa::EcdsaSig::from_private_components(r_bignum, s_bignum)
                .and_then(|sig| sig.to_der())
                .map_err(|_| PrecompileError::InvalidSignature)?;

            let public_key_point = EcPoint::from_bytes(&group, pubkey, &mut ctx)
                .map_err(|_| PrecompileError::InvalidPublicKey)?;
            let public_key = EcKey::from_public_key(&group, &public_key_point)
                .map_err(|_| PrecompileError::InvalidPublicKey)?;
            let public_key_as_pkey =
                PKey::from_ec_key(public_key).map_err(|_| PrecompileError::InvalidPublicKey)?;

            let mut verifier =
                Verifier::new(openssl::hash::MessageDigest::sha256(), &public_key_as_pkey)
                    .map_err(|_| PrecompileError::InvalidSignature)?;
            verifier
                .update(message)
                .map_err(|_| PrecompileError::InvalidSignature)?;

            if !verifier
                .verify(&ecdsa_sig)
                .map_err(|_| PrecompileError::InvalidSignature)?
            {
                return Err(PrecompileError::InvalidSignature);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod test {
        use {
            super::*,
            solana_feature_set::FeatureSet,
            solana_sdk::{
                hash::Hash,
                signature::{Keypair, Signer},
                transaction::Transaction,
            },
        };

        fn test_case(
            num_signatures: u16,
            offsets: &Secp256r1SignatureOffsets,
        ) -> Result<(), PrecompileError> {
            assert_eq!(
                bytemuck::bytes_of(offsets).len(),
                SIGNATURE_OFFSETS_SERIALIZED_SIZE
            );

            let mut instruction_data = vec![0u8; DATA_START];
            instruction_data[0..SIGNATURE_OFFSETS_START].copy_from_slice(bytes_of(&num_signatures));
            instruction_data[SIGNATURE_OFFSETS_START..DATA_START]
                .copy_from_slice(bytes_of(offsets));
            verify(
                &instruction_data,
                &[&[0u8; 100]],
                &FeatureSet::all_enabled(),
            )
        }

        #[test]
        fn test_invalid_offsets() {
            solana_logger::setup();

            let mut instruction_data = vec![0u8; DATA_START];
            let offsets = Secp256r1SignatureOffsets::default();
            instruction_data[0..SIGNATURE_OFFSETS_START].copy_from_slice(bytes_of(&1u16));
            instruction_data[SIGNATURE_OFFSETS_START..DATA_START]
                .copy_from_slice(bytes_of(&offsets));
            instruction_data.truncate(instruction_data.len() - 1);

            assert_eq!(
                verify(
                    &instruction_data,
                    &[&[0u8; 100]],
                    &FeatureSet::all_enabled()
                ),
                Err(PrecompileError::InvalidInstructionDataSize)
            );

            let offsets = Secp256r1SignatureOffsets {
                signature_instruction_index: 1,
                ..Secp256r1SignatureOffsets::default()
            };
            assert_eq!(
                test_case(1, &offsets),
                Err(PrecompileError::InvalidDataOffsets)
            );

            let offsets = Secp256r1SignatureOffsets {
                message_instruction_index: 1,
                ..Secp256r1SignatureOffsets::default()
            };
            assert_eq!(
                test_case(1, &offsets),
                Err(PrecompileError::InvalidDataOffsets)
            );

            let offsets = Secp256r1SignatureOffsets {
                public_key_instruction_index: 1,
                ..Secp256r1SignatureOffsets::default()
            };
            assert_eq!(
                test_case(1, &offsets),
                Err(PrecompileError::InvalidDataOffsets)
            );
        }

        #[test]
        fn test_invalid_signature_data_size() {
            solana_logger::setup();

            let small_data = vec![0u8; SIGNATURE_OFFSETS_START - 1];
            assert_eq!(
                verify(&small_data, &[&[]], &FeatureSet::all_enabled()),
                Err(PrecompileError::InvalidInstructionDataSize)
            );

            let mut zero_sigs_data = vec![0u8; DATA_START];
            zero_sigs_data[0] = 0;
            assert_eq!(
                verify(&zero_sigs_data, &[&[]], &FeatureSet::all_enabled()),
                Err(PrecompileError::InvalidInstructionDataSize)
            );

            let mut too_many_sigs = vec![0u8; DATA_START];
            too_many_sigs[0] = 9;
            assert_eq!(
                verify(&too_many_sigs, &[&[]], &FeatureSet::all_enabled()),
                Err(PrecompileError::InvalidInstructionDataSize)
            );
        }
    }
}

#[cfg(all(
    not(target_arch = "wasm32"),
    not(target_os = "solana"),
    feature = "rustls",
))]
mod native_rustls {
    use {
        core::convert::TryFrom,
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

        // Additional sanity checks to ensure constants align with expectations.
        debug_assert_eq!(order, half_order.wrapping_mul(&U256::from_u64(2)));
        debug_assert_eq!(order, order_minus_one.wrapping_add(&one));

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use {
            super::*,
            bytemuck,
            p256::ecdsa::{signature::Signer, SigningKey},
            rand_core::OsRng,
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
                crate::DATA_START
                    + COMPRESSED_PUBKEY_SERIALIZED_SIZE
                    + SIGNATURE_SERIALIZED_SIZE
                    + message.len(),
            );

            let public_key_offset = crate::DATA_START;
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
                &solana_feature_set::FeatureSet::all_enabled()
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
                    &solana_feature_set::FeatureSet::all_enabled()
                ),
                Err(PrecompileError::InvalidSignature)
            );
        }

        #[test]
        fn reject_high_s_signature() {
            let signing_key = SigningKey::random(&mut OsRng);
            let message = b"hello";
            let (mut instruction_data, instruction_datas) = build_instruction(&signing_key, message);

            let signature_offset = crate::DATA_START + COMPRESSED_PUBKEY_SERIALIZED_SIZE;
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
                    &solana_feature_set::FeatureSet::all_enabled()
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
    feature = "rustls",
))]
pub use native_rustls::*;

#[cfg(all(
    not(target_arch = "wasm32"),
    not(target_os = "solana"),
    feature = "openssl",
    not(feature = "rustls"),
))]
pub use native_openssl::*;

#[cfg(any(target_arch = "wasm32", target_os = "solana"))]
pub use native_stub::*;
