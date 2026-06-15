# Canton DAR Fixtures

These fixtures are Daml Archives (`.dar`): the compiled Daml package bundles
that the Canton sandbox loads before the integration tests run.

- **Source repository:** [`sig-net/canton`](https://github.com/sig-net/canton)
- **Source packages:** `daml-packages/signet-vault-v1` (checked in as
  `signet-vault-v1-0.0.1.dar`; the package itself is named `signet-vault-v1`) and
  `daml-packages/signet-fee-amulet` (`signet-fee-amulet-0.0.1.dar`)
- **Built with:** Daml SDK 3.5.1 via `dpm build --all`

## Regenerate

```bash
# in the canton repo
dpm build --all
# in this repo
cp <canton-repo>/daml-packages/signet-vault-v1/.daml/dist/signet-vault-v1-0.0.1.dar \
   <this-directory>/signet-vault-v1-0.0.1.dar
cp <canton-repo>/daml-packages/signet-fee-amulet/.daml/dist/signet-fee-amulet-0.0.1.dar \
   <this-directory>/signet-fee-amulet-0.0.1.dar
```

The vault DAR bundles the package itself plus its data dependencies from the
same repository: `signet-signer-v1`, `signet-eip712`, `signet-abi`, the frozen
`signet-api-fee-v1` fee API, and the two vendored Splice token-standard API DARs
it uses (`splice-api-token-metadata-v1`, `splice-api-token-holding-v1`). The
`signet-fee-amulet` DAR carries the `CcFeeCollector` / `FeePriceConfig` fee
implementation that `Signer.RequestSignature` charges through — the sandbox
registers it with a zero-fee price config so tests stay off the Splice Amulet
machinery.

Integration tests use them to bootstrap a Canton sandbox with the Signer and
fee contracts (`CANTON_DAR_PATH` / `CANTON_FEE_DAR_PATH` override the paths).
