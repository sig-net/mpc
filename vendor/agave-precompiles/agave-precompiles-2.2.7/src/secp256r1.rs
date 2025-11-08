use {
    agave_feature_set::FeatureSet as AgaveFeatureSet,
    solana_precompile_error::PrecompileError,
};

pub fn verify(
    data: &[u8],
    instruction_datas: &[&[u8]],
    feature_set: &AgaveFeatureSet,
) -> Result<(), PrecompileError> {
    // agave exposes the interface FeatureSet wrapper, so rebuild the SDK struct before delegating
    let solana_feature_set = solana_feature_set::FeatureSet {
        active: feature_set.active().clone(),
        inactive: feature_set.inactive().clone(),
    };

    solana_secp256r1_program::verify(data, instruction_datas, &solana_feature_set)
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        agave_feature_set::FeatureSet as AgaveFeatureSet,
        bytemuck::bytes_of,
        p256::ecdsa::{signature::Signer as _, SigningKey},
        p256::elliptic_curve::bigint::U256,
        rand_core::OsRng,
        solana_precompile_error::PrecompileError,
        solana_secp256r1_program::{
            DATA_START, SECP256R1_HALF_ORDER, SECP256R1_ORDER, Secp256r1SignatureOffsets,
            COMPRESSED_PUBKEY_SERIALIZED_SIZE, FIELD_SIZE, SIGNATURE_OFFSETS_SERIALIZED_SIZE,
            SIGNATURE_OFFSETS_START, SIGNATURE_SERIALIZED_SIZE,
        },
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
        data.extend_from_slice(bytes_of(&offsets));

        let compressed = verifying_key.to_encoded_point(true);
        data.extend_from_slice(compressed.as_bytes());
        data.extend_from_slice(&signature_bytes);
        data.extend_from_slice(message);

        (data, vec![])
    }

    #[test]
    fn test_invalid_offsets() {
        solana_logger::setup();

        let mut instruction_data = vec![0u8; DATA_START];
        let offsets = Secp256r1SignatureOffsets::default();
        instruction_data[0..SIGNATURE_OFFSETS_START].copy_from_slice(bytes_of(&1u16));
        instruction_data[SIGNATURE_OFFSETS_START..DATA_START].copy_from_slice(bytes_of(&offsets));
        instruction_data.truncate(instruction_data.len() - 1);

        assert_eq!(
            super::verify(
                &instruction_data,
                &[&[0u8; 100]],
                &AgaveFeatureSet::all_enabled()
            ),
            Err(PrecompileError::InvalidInstructionDataSize)
        );

        let offsets = Secp256r1SignatureOffsets {
            signature_instruction_index: 1,
            ..Secp256r1SignatureOffsets::default()
        };
        assert_eq!(
            super::verify(
                &instruction_data,
                &[&[0u8; 100]],
                &AgaveFeatureSet::all_enabled()
            ),
            Err(PrecompileError::InvalidInstructionDataSize)
        );

        let offsets = Secp256r1SignatureOffsets {
            message_instruction_index: 1,
            ..Secp256r1SignatureOffsets::default()
        };
        assert_eq!(
            super::verify(
                &instruction_data,
                &[&[0u8; 100]],
                &AgaveFeatureSet::all_enabled()
            ),
            Err(PrecompileError::InvalidInstructionDataSize)
        );

        let offsets = Secp256r1SignatureOffsets {
            public_key_instruction_index: 1,
            ..Secp256r1SignatureOffsets::default()
        };
        assert_eq!(
            super::verify(
                &instruction_data,
                &[&[0u8; 100]],
                &AgaveFeatureSet::all_enabled()
            ),
            Err(PrecompileError::InvalidInstructionDataSize)
        );
    }

    #[test]
    fn test_invalid_signature_data_size() {
        solana_logger::setup();

        let small_data = vec![0u8; SIGNATURE_OFFSETS_START - 1];
        assert_eq!(
            super::verify(&small_data, &[&[]], &AgaveFeatureSet::all_enabled()),
            Err(PrecompileError::InvalidInstructionDataSize)
        );

        let mut zero_sigs_data = vec![0u8; DATA_START];
        zero_sigs_data[0] = 0;
        assert_eq!(
            super::verify(&zero_sigs_data, &[&[]], &AgaveFeatureSet::all_enabled()),
            Err(PrecompileError::InvalidInstructionDataSize)
        );

        let mut too_many_sigs = vec![0u8; DATA_START];
        too_many_sigs[0] = 9;
        assert_eq!(
            super::verify(&too_many_sigs, &[&[]], &AgaveFeatureSet::all_enabled()),
            Err(PrecompileError::InvalidInstructionDataSize)
        );
    }

    #[test]
    fn verify_valid_signature() {
        let signing_key = SigningKey::random(&mut OsRng);
        let message = b"hello";
        let (instruction_data, instruction_datas) = build_instruction(&signing_key, message);
        let instruction_refs: Vec<&[u8]> = instruction_datas.iter().map(|v| v.as_slice()).collect();

        assert!(super::verify(
            &instruction_data,
            &instruction_refs,
            &AgaveFeatureSet::all_enabled()
        )
        .is_ok());
    }

    #[test]
    fn reject_modified_message() {
        let signing_key = SigningKey::random(&mut OsRng);
        let message = b"hello";
        let (mut instruction_data, instruction_datas) = build_instruction(&signing_key, message);
        *instruction_data.last_mut().unwrap() ^= 0xFF;
        let instruction_refs: Vec<&[u8]> = instruction_datas.iter().map(|v| v.as_slice()).collect();

        assert_eq!(
            super::verify(
                &instruction_data,
                &instruction_refs,
                &AgaveFeatureSet::all_enabled()
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
        let instruction_refs: Vec<&[u8]> = instruction_datas.iter().map(|v| v.as_slice()).collect();

        assert_eq!(
            super::verify(
                &instruction_data,
                &instruction_refs,
                &AgaveFeatureSet::all_enabled()
            ),
            Err(PrecompileError::InvalidSignature)
        );
    }
}
