# Canton DAR Fixtures

These fixtures are Daml Archives (`.dar`): the compiled Daml package bundles
that the Canton sandbox loads before the integration tests run.

- **Source repository:** [`sig-net/canton`](https://github.com/sig-net/canton)
- **Source packages:** `daml-packages/signet-signer-v1` (checked in as
  `signet-signer-v1-0.0.1.dar`; the package itself is named `signet-signer-v1`) and
  `daml-packages/signet-fee-amulet` (`signet-fee-amulet-0.0.1.dar`)
- **Built with:** Daml SDK 3.5.1 via `dpm build --all`

## Regenerate

```bash
# in the canton repo
dpm build --all
# in this repo
cp <canton-repo>/daml-packages/signet-signer-v1/.daml/dist/signet-signer-v1-0.0.1.dar \
   <this-directory>/signet-signer-v1-0.0.1.dar
cp <canton-repo>/daml-packages/signet-fee-amulet/.daml/dist/signet-fee-amulet-0.0.1.dar \
   <this-directory>/signet-fee-amulet-0.0.1.dar
```

Integration tests use them to bootstrap a Canton sandbox with the Signer and
fee contracts (`CANTON_DAR_PATH` / `CANTON_FEE_DAR_PATH` override the paths).
