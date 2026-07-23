/**
 * Startup assertion: this node must retain historical state.
 *
 * Discovery reads what a block wrote by diffing a contract's state at that
 * block against its state at the parent, so it is sound only while both are
 * retrievable. Substrate's `--state-pruning` defaults to 256 blocks, roughly 25
 * minutes at 6s blocks, and of midnight-node's shipped presets ONLY `dev` sets
 * `archive` (`res/cfg/dev.toml`). Every other preset, stagenet and mainnet
 * included, takes the default. The preset injects its flags inside the binary,
 * so `docker inspect` shows an empty command line either way and the difference
 * is invisible from outside.
 *
 * Left unchecked this is a works-in-dev, silently-breaks-in-production failure:
 * the MPC would lose the ability to discover which request was notified after
 * any downtime longer than the window, and it would surface as a fetch error at
 * an arbitrary height rather than as a misconfiguration.
 *
 * The check exploits an asymmetry in the node's error taxonomy. Both failure
 * modes return `-32602` with no `data` field, so the CODE cannot discriminate:
 *
 *   pruned / unreachable state : "Unable to get requested contract state"
 *   contract did not exist yet : "Contract not present at the requested address"
 *
 * But `ContractNotPresent` is produced by the runtime API only AFTER it ran
 * successfully at that block, so receiving it is positive evidence that state at
 * that height was reachable. That makes the probe work with no deployed
 * contract and no configuration: any well-formed address will do, because
 * "contract not present" is the success case for this question.
 */

import { resolveAnchor, rpc, type NodeClient } from "./node.js";

/**
 * How far back state must be readable. Well outside the 256-block default, and
 * meant to match the deepest reachback catch-up could need.
 */
export const ARCHIVE_PROBE_WINDOW = 5000;

/** Substring of the node's catch-all "I could not answer" error. Not a pruning-specific signal. */
const UNABLE = "unable to get requested contract state";

/** Substring of the node's "the runtime API ran, the contract was not there" error. */
const NOT_PRESENT = "contract not present";

/** An address that is well-formed and certain to hold no contract. */
const PROBE_ADDRESS = "00".repeat(32);

/**
 * Refuse to start against a node that cannot serve historical state.
 *
 * @param client - Connected node client.
 * @param window - How many blocks back state must be readable.
 * @throws If state at `head - window` cannot be read, naming the height.
 */
export async function assertArchiveNode(
  client: NodeClient,
  window: number = ARCHIVE_PROBE_WINDOW,
): Promise<void> {
  const { anchor } = await resolveAnchor(client, undefined);
  const target = Math.max(1, anchor.height - window);
  const targetHash = (await client.api.rpc.chain.getBlockHash(target)).toHex();

  try {
    // A hex result proves state at `target` was reachable.
    await rpc(client, "midnight_contractState", [PROBE_ADDRESS, targetHash]);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    // `ContractNotPresent` is produced only AFTER the runtime API ran at that
    // block, so it is equally positive evidence. See the module comment: this
    // asymmetry is what the whole probe rests on.
    if (message.toLowerCase().includes(NOT_PRESENT)) return;

    throw new Error(
      `this node cannot serve contract state at height ${target} (head ${anchor.height}). ` +
        (looksLikePruning(message)
          ? `State-diff discovery requires an archive node: start it with ` +
            `'--state-pruning archive --blocks-pruning archive'. Note the mode can only be set ` +
            `when the database is first created, so an already-pruned database must be resynced. `
          : ``) +
        `Node said: ${message}`,
    );
  }
}

/**
 * True when a failed anchored state read looks like pruning rather than a
 * missing contract. Callers should raise this loudly rather than folding it into
 * a generic fetch failure: one means "this contract did not exist yet", the
 * other means "this node has lost the ability to answer".
 *
 * @param message - The error text the node returned.
 * @returns Whether the message is the catch-all that pruning produces.
 */
export function looksLikePruning(message: string): boolean {
  return message.toLowerCase().includes(UNABLE);
}
