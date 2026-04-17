// TODO(test): golden-test build_calldata against viem's encodeFunctionData for:
// - ERC20 transfer/approve (static types)
// - Uniswap exactInputSingle with tuple arg
// - Functions with dynamic types (string, bytes, address[])
// - Empty-args view functions (totalSupply)
// - Invalid signature rejection, invalid hex rejection

use alloy::primitives::keccak256;
use alloy_json_abi::Function;

/// Build EVM calldata from a Solidity function signature and a pre-encoded hex
/// parameter body.
///
/// Parses the function signature (for validation) and constructs
/// `selector || encoded_args`. The `encoded_args_hex` blob is the full
/// ABI-encoded parameter tuple (may include dynamic-type head+tail words);
/// no arg-count or per-arg size checks are performed here.
pub fn build_calldata(function_signature: &str, encoded_args_hex: &str) -> anyhow::Result<Vec<u8>> {
    let full_sig = format!("function {function_signature}");
    Function::parse(&full_sig).map_err(|e| {
        anyhow::anyhow!("failed to parse function signature '{function_signature}': {e}")
    })?;

    let selector: [u8; 4] = keccak256(function_signature.as_bytes()).0[..4]
        .try_into()
        .expect("keccak256 always produces 32 bytes");

    let mut calldata = selector.to_vec();
    if !encoded_args_hex.is_empty() {
        let bytes = hex::decode(encoded_args_hex)
            .map_err(|e| anyhow::anyhow!("invalid hex in calldata encodedArgs: {e}"))?;
        calldata.extend_from_slice(&bytes);
    }

    Ok(calldata)
}
