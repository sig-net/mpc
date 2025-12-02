use parity_scale_codec::{Decode, Encode};

/// SCALE-encodable affine point used by the Hydration pallet.
///
/// This type mirrors the on-chain representation of an affine point with
/// 32-byte `x` and `y` coordinates and is encoded/decoded using
/// `parity_scale_codec` to match the pallet's storage and extrinsic types.
#[derive(Clone, Debug, Encode, Decode)]
pub struct HydrationAffinePoint {
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// Signature type used by the Hydration pallet.
///
/// This structure matches the on-chain signature format, consisting of:
/// * `big_r` - the public point component of the signature as an
///   [`HydrationAffinePoint`],
/// * `s` - the 32-byte scalar part of the signature,
/// * `recovery_id` - a one-byte recovery identifier.
/// It is encoded with `parity_scale_codec` to remain compatible with the
/// pallet's on-chain signature type.
#[derive(Clone, Debug, Encode, Decode)]
pub struct HydrationSignature {
    pub big_r: HydrationAffinePoint,
    pub s: [u8; 32],
    pub recovery_id: u8,
}

/// Wrapper around `Vec<T>` corresponding to the pallet's bounded vector type.
///
/// This type exists to mirror the on-chain bounded vector used by the
/// Hydration pallet while preserving the same SCALE encoding as `Vec<T>`.
/// Any length constraints are enforced at the pallet level, while this
/// wrapper provides a strongly-typed representation for off-chain code.
#[derive(Clone, Debug, Encode, Decode)]
pub struct BoundedVec<T>(pub Vec<T>);
