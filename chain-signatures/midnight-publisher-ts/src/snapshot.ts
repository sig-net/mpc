// A synced funding wallet's sub-wallet states, so a restarted process resumes indexing from
// where the last one stopped instead of replaying the chain. Opaque to Rust, which only
// stores and returns it. The SDK snapshots hold public keys and local state, never a secret
// key: the secrets are supplied again when the restored wallet starts.

import { z } from "zod";

const SNAPSHOT_VERSION = 1;

export interface WalletSnapshot {
  readonly shielded: string;
  readonly unshielded: string;
  readonly dust: string;
}

const EnvelopeSchema = z.object({
  version: z.literal(SNAPSHOT_VERSION),
  networkId: z.string(),
  owner: z.string(),
  takenAt: z.number(),
  shielded: z.string(),
  unshielded: z.string(),
  dust: z.string(),
});

export interface DecodedSnapshot {
  readonly states: WalletSnapshot;
  readonly takenAt: Date;
}

/** `owner` names the wallet the states belong to, so a rotated seed never restores another's. */
export function encodeSnapshot(
  networkId: string,
  owner: string,
  states: WalletSnapshot,
  takenAt: Date,
): string {
  return JSON.stringify({
    version: SNAPSHOT_VERSION,
    networkId,
    owner,
    takenAt: takenAt.getTime(),
    ...states,
  });
}

/** The states in `encoded` if it is this wallet's, on this network; otherwise why not. */
export function decodeSnapshot(
  encoded: string,
  networkId: string,
  owner: string,
): DecodedSnapshot | { readonly rejected: string } {
  let body: unknown;
  try {
    body = JSON.parse(encoded);
  } catch {
    return { rejected: "not JSON" };
  }
  const parsed = EnvelopeSchema.safeParse(body);
  if (!parsed.success) return { rejected: "not a version 1 wallet snapshot" };
  if (parsed.data.networkId !== networkId) {
    return { rejected: `taken on network ${parsed.data.networkId}` };
  }
  if (parsed.data.owner !== owner) return { rejected: "taken for another funding wallet" };
  const { shielded, unshielded, dust, takenAt } = parsed.data;
  return { states: { shielded, unshielded, dust }, takenAt: new Date(takenAt) };
}
