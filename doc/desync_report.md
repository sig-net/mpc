# Desync reporting on MissingArtifact

When a proposer aborts a posit round on `MissingArtifact` rejects, it reports
each rejecting peer to the mesh as desynced. The mesh moves that peer from
`Active` to `Syncing`, which takes it out of `MeshState::active()` and puts it
into `need_sync()`. `SyncTask` then re-syncs against it and, on success,
reports it back as synced, restoring `Active`.

This document records what the mechanism assumes and why it is built the way
it is, so the next person to touch it knows which parts are load bearing.

## Assumptions

**A `MissingArtifact` reject is truthful evidence about the peer's storage.**
This is the assumption the whole mechanism rests on, and it does not currently
hold in one case. The deliberator decides with `ProtocolStorage::contains`,
which returns `false` both when the artifact is absent and when redis is
unavailable or errors. A node with slow or unreachable storage therefore
answers `MissingArtifact` for artifacts it does hold, while `/status` keeps
reporting it healthy because that endpoint does not touch redis. Under
correlated storage stress this turns a truthful-evidence mechanism into a
false-accusation one. Fixing it means making `contains` distinguish
unavailable from absent and answering something other than `MissingArtifact`
when its own storage failed.

**The repair direction is that our holder list is wrong about the peer, not
that the peer is wrong about us.** Sync is one-directional: node A sends a
`SyncUpdate` for the ids A owns, and B answers with what it actually holds, so
the round corrects A's record of B. The reject tells us our holder list names
a peer that does not have the artifact, and sync is the existing machinery
that repairs holder lists. Comments that describe this the other way round
are wrong; that error was in the first version of this change.

**Recovery is guaranteed as long as the node is alive.** `Syncing` is not a
dead end. A peer in `need_sync()` is retried by `SyncTask` roughly every
200ms, and a failed sync leaves it in the set for the next attempt rather than
dropping it. The only terminal path is `synced_peer_tx` returning an error,
which means the mesh receiver is gone and the node is finished anyway. Earlier
review of this change claimed peers could be stranded; that was wrong.

**Taking a peer out of `active()` is an acceptable price.** This holds only
while `active()` stays above threshold. Nothing enforces that. A report
removes the peer for every protocol this node initiates, and
`wait_for_active_participants` has no fallback if the set falls below
threshold.

## Design decisions

**Reuse the mesh sync path rather than repairing the single holder entry.**
The narrower fix would be to drop that peer from that one presignature's
holder list. Going through sync instead repairs everything that peer is
missing, triples included, and reuses machinery that already exists rather
than adding a second repair path. The price is blast radius: one stale record
about one artifact costs the peer its place in every protocol until a sync
round completes. If reports ever become more frequent, revisit this, because
the proportionate response to "peer X lacks presignature 42" is to fix that
row.

**The report is gated on the round aborting, not on the reject arriving.** It
sits inside `enough_rejects`, which is `rejects > participants - threshold`.
The participant set is the full `holders ∩ active` intersection and is never
trimmed to threshold, so wherever the holder set has slack a lone stale holder
does not clear the bar, and a round that dies on its deadline never reaches
the reporting block at all. The consequence is that the single stale holder
case is not repaired. Moving the report to where the reject is recorded would
cover it, and `report_node_desynced` is already idempotent so the extra
reports are cheap at the mesh. The catch is that the abort gate is currently
acting as an unintentional rate limiter: combined with the `contains` problem
above, per-reject reporting would let a node with failing storage be reported
by every proposer on every round. Per-reject reporting wants a per-peer
cooldown to go with it.

**`try_send` rather than a blocking send.** The reporting site sits in the
posit loop, which must not stall on a slow mesh consumer, so a full channel
drops the report and logs instead of applying backpressure to signing. This
differs from `SyncTask`, which uses a blocking send for synced-peer reports
because it is not on the signing path. A dropped report costs one more failed
round, so the failure mode is acceptable, but it does mean delivery is not
guaranteed.

**The transition is `Active` to `Syncing` only.** Reports are idempotent, so
concurrent sign tasks all noticing the same lagging peer collapse into one
transition rather than waking the mesh repeatedly. The guard also stops a
report from moving a peer out of `Offline` or `Inactive`, though in practice
the ping loop would correct that within one interval.

**A separate channel rather than extending the synced-peer channel.** Mirrors
the existing shape at the cost of a near-duplicate `select!` arm. Folding both
into one `Receiver<PeerReport>` carrying an enum would remove the duplication
and the second field on `Mesh`.

## Known gaps

Beyond the two above, pre-existing issues that this mechanism now leans on
more heavily:

- `remove_outdated` ignores the responder's own `generating` and `using` sets,
  so a sync arriving mid-generation can report an artifact as not held and get
  it pruned. The sender side is careful about this; the responder side is not.
- `SyncTask` keeps one broadcast in flight globally under a 120s timeout, so
  one slow peer delays every other peer's return to `active()`.
- Nothing floors `active()` at threshold.
- `/sync` is unauthenticated, unlike `/msg`.

## Testing notes

The mechanism is covered at two levels. `protocol/request/posit.rs` tests the
decision: which rejects report, that mixed reasons filter correctly, that
every rejector is reported, and that a lone rejector with slack in the set is
not. `mesh/mod.rs` tests the wiring and the status transition. The mesh tests
poll the state watch rather than sleeping, because a fixed sleep races the
connection tasks, which must complete a real `/status` round trip before any
report can take effect.

`advance_does_not_report_when_the_set_has_slack` asserts current behaviour,
not desired behaviour. It will fail if the trigger moves to per-reject
reporting, which is the intended signal to update it rather than a regression.
