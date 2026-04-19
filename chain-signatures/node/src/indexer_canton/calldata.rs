// TODO(test): golden-test build_calldata against viem's encodeFunctionData for:
// - ERC20 transfer/approve (static types)
// - Uniswap exactInputSingle with tuple arg
// - Functions with dynamic types (string, bytes, address[])
// - Empty-args view functions (totalSupply)
// - Invalid signature rejection, invalid hex rejection

use alloy_json_abi::Function;

pub fn build_calldata(function_signature: &str, encoded_args_hex: &str) -> anyhow::Result<Vec<u8>> {
    let func = Function::parse(function_signature).map_err(|e| {
        anyhow::anyhow!("failed to parse function signature '{function_signature}': {e}")
    })?;

    let canonical = func.signature();
    if function_signature != canonical {
        anyhow::bail!(
            "function_signature must be canonical ABI form: got '{function_signature}', expected '{canonical}'"
        );
    }

    let selector: [u8; 4] = func.selector().0;

    let mut calldata = selector.to_vec();
    if !encoded_args_hex.is_empty() {
        let bytes = hex::decode(encoded_args_hex)
            .map_err(|e| anyhow::anyhow!("invalid hex in calldata encodedArgs: {e}"))?;
        calldata.extend_from_slice(&bytes);
    }

    Ok(calldata)
}
