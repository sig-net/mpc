# Ethereum Contract Fixtures

This fixture is the prebuilt Hardhat artifact of the SigNet EVM chain signatures contract (`ChainSignatures.sol`): the ABI + bytecode bundle the integration tests deploy to the local Anvil sandbox.

- **Source repository:** `signet-evm-program` (the source of truth for the EVM contract)
- **Source contract:** `contracts/ChainSignatures.sol` (checked in as `ChainSignatures.json`)
- **Built with:** Hardhat via `pnpm install && npx hardhat compile` in that repo

## Regenerate

```bash
# in the signet-evm-program repo
pnpm install
npx hardhat compile
# in this repo
cp <signet-evm-program-repo>/artifacts/contracts/ChainSignatures.sol/ChainSignatures.json \
   <this-directory>/ChainSignatures.json
```

Integration tests embed the artifact at compile time via `include_bytes!` in `integration-tests/src/eth.rs` (`deploy_chain_signatures`) and deploy it with `(address admin, uint256 signatureDeposit)` constructor args.
