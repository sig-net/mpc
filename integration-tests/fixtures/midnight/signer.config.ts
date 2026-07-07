/**
 * toolkit-js contract config for the signet-signer.
 *
 * Loaded by `midnight-node-toolkit generate-intent …` inside the
 * signet/midnight-node-toolkit:2.0.0-rc.3-compact033 container with
 * COMPACTC_VERSION=0.33 — module resolution of @midnight-ntwrk/* is redirected
 * to the image's compact-0.33 workspace (compact-js 2.5.5-rc.5, runtime 0.18).
 *
 * Paths are absolute container paths: the Rust sandbox
 * (integration-tests/src/midnight.rs) and the midnight-publisher service mount
 * this fixtures directory at /work; the compiled artifacts live at
 * /work/signet-signer (contract source + compile pipeline: midnight-erc20-vault).
 *
 * The caller identity witness comes from SIGNER_SECRET_KEY (64-char hex);
 * the default is the golden fixture key, so a fresh deploy + `sign` with
 * golden inputs reproduces the pinned golden vectors on-chain.
 */
import { CompiledContract, ContractExecutable, type Contract } from '@midnight-ntwrk/compact-js/effect';
import { Contract as C_ } from '/work/signet-signer/contract/index.js';

type PrivateState = Record<string, never>;
type SignerContract = C_<PrivateState>;
const SignerContract = C_;

const skHex = process.env.SIGNER_SECRET_KEY ?? '11'.repeat(32);
if (!/^[0-9a-f]{64}$/.test(skHex)) {
  throw new Error('SIGNER_SECRET_KEY must be 64 lowercase hex chars');
}
const callerSecretKey = Uint8Array.from(skHex.match(/../g)!.map((b) => parseInt(b, 16)));

const witnesses: Contract.Contract.Witnesses<SignerContract> = {
  callerSecretKey: ({ privateState }) => [privateState, callerSecretKey]
};

const createInitialPrivateState: () => PrivateState = () => ({});

export default {
  contractExecutable: CompiledContract.make<SignerContract>('SignerContract', SignerContract).pipe(
    CompiledContract.withWitnesses(witnesses),
    CompiledContract.withCompiledFileAssets('/work/signet-signer'),
    ContractExecutable.make
  ),
  createInitialPrivateState,
  config: {
    keys: {
      // Coin public key of the dev genesis funding wallet
      // (seed 0000000000000000000000000000000000000000000000000000000000000001).
      coinPublic: 'aa0d72bb77ea46f986a800c66d75c4e428a95bd7e1244f1ed059374e6266eb98'
    },
    network: 'undeployed'
  }
};
