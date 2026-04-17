# Canton DAR Fixture

**Source:** `canton-mpc-poc/daml-packages/daml-vault`
**Built with:** Daml SDK 3.4.x via `dpm build`

## Regenerate

```bash
cd canton-mpc-poc/daml-packages/daml-vault
dpm build
cp .daml/dist/daml-vault-0.0.1.dar <this-directory>/daml-vault-0.0.1.dar
```

The `daml-vault` DAR bundles `daml-signer` and all transitive dependencies
(`daml-eip712`, `daml-uint256`, `daml-abi`). Integration tests use it to
bootstrap a Canton sandbox with the Signer and Vault contracts.
