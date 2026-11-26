# EVM Fixtures

Solidity mocks the Midnight tests run against, with their compiled Hardhat artifacts:

- `MidnightConformance.sol`: targets whose return values `tests/cases/midnight_stream.rs` encodes and compares with the SDK vectors.
- `MidnightVaultTargets.sol`: local USDC, stataUSDC and swap router the vault test deploys (`midnight-devtools/devtools/real-stack/vault-evm.ts`).
- `MidnightVaultTronTargets.sol`: the USDT-like TRC-20 and the ERC-4626 share token over it that the Tron vault test deploys on TRE as its lend pair (`midnight-devtools/devtools/real-stack/vault-tron.ts`).

## Regenerate

After editing a `.sol` file, recompile it with solc 0.8.27 and OpenZeppelin Contracts 5.2.0, for example in a checkout of [sig-net/ethereum-signet-contract](https://github.com/sig-net/ethereum-signet-contract):

```bash
npm ci
cp <this-directory>/*.sol contracts/
npx hardhat compile
find artifacts/contracts/Midnight*.sol -name '*.json' ! -name '*.dbg.json' -exec cp {} <this-directory>/ \;
rm contracts/Midnight*.sol
```
