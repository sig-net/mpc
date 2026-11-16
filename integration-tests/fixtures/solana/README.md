# Solana Program Fixture

`chain_signatures.so` is the compiled Signet program that the integration
tests deploy to a local `solana-test-validator`.

- **Source repository:** [`sig-net/solana-signet-program`](https://github.com/sig-net/solana-signet-program)
- **Source package:** `signet-program/programs/signet`
- **Built with:** `anchor build`, with `declare_id!` set to the public key of
  `Solana::program_keypair()` (see `integration-tests/src/containers.rs`).
  Anchor rejects calls to a program deployed at any other address.

The exact source commit of the current binary was not recorded. It includes
the `emit_cpi!` change to `respond_bidirectional` and predates the
`update_chain_id` instruction, which no test calls.

## Regenerate

```bash
# in the solana-signet-program repo, under signet-program/
# set declare_id! in programs/signet/src/lib.rs to the test program id, then
anchor build
# in this repo
cp <program-repo>/signet-program/target/deploy/chain_signatures.so \
   <this-directory>/chain_signatures.so
```

Record the source commit here when you do.
