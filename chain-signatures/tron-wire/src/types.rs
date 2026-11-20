//! The head block as needed for ref-block fields at assembly time.

use alloy::primitives::B256;

#[derive(Debug, Clone, Copy)]
pub struct NowBlock {
    pub block_id: B256,
    pub number: u64,
    pub timestamp: u64,
}

impl NowBlock {
    /// Reference fields per java-tron: `ref_block_bytes` is the height's low
    /// two bytes (big-endian), `ref_block_hash` is the block ID's bytes 8..16.
    /// Pinned against recorded mainnet fixtures.
    pub fn reference_fields(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.number.to_be_bytes()[6..8].to_vec(),
            self.block_id.as_slice()[8..16].to_vec(),
        )
    }
}
