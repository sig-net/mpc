# Canton DAR Fixture

This fixture is a Daml Archive (`.dar`): the compiled Daml package bundle that
the Canton sandbox loads before the integration tests run.

- **Source repository:** [`sig-net/canton-poc`](https://github.com/sig-net/canton-poc)
- **Source package:** `daml-packages/daml-vault`
- **Built with:** Daml SDK 3.4.11 via `dpm build`

## Regenerate

```bash
cd canton-poc/daml-packages/daml-vault
dpm build
cp .daml/dist/daml-vault-0.0.1.dar <this-directory>/daml-vault-0.0.1.dar
```

The `daml-vault` DAR bundles the package itself plus its data dependencies from
the same repository: `daml-packages/daml-signer`, `daml-packages/daml-eip712`,
and `daml-packages/daml-abi`.
Integration tests use it to bootstrap a Canton sandbox with the Signer and Vault
contracts.
