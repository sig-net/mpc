# Posit state machine

Represents current implementation from 
`chain-signatures/node/src/protocol/request/` (`task.rs`, `organize.rs`,
`posit.rs`, `state.rs`) plus the generation tail in `protocol/signature.rs`. The
cait-sith signing math and the presignature/triple pipelines are not depicted here.

The top level state machine matches the `SignPhase` enum. Each
phase then gets its own diagram showing what happens inside it and where it can
leave. States drawn grey and dashed in a detail diagram belong to another phase;
they are there to show where the edges land.

## 1. Top level

```mermaid
stateDiagram-v2
    [*] --> Organizing
    Organizing --> Posit: proposer elected
    Posit --> Generating: participant set fixed
    Generating --> Done: signature produced

    Organizing --> Organizing: new round
    Posit --> Organizing: new round
    Generating --> Organizing: new round

    Done --> [*]
```

A task enters `Organizing` when `SignatureSpawner` spawns it for a newly indexed sign request at round 0. 

If governance is
not `Running` at that moment the request is retained but no task is spawned. 
`spawn_tasks` starts it once governance is running, and respawns every retained request on a governance change. 
A respawn re-enters `Organizing` too, but at the
round carried in `SignEntry.round` rather than at 0.

Every recoverable failure leads to the same transition back to phase
"Organizing", via `state.reorganize()`. It bumps the round, resets the round
timeout, releases the proposer's concurrency permit if one is held, and
re-enters `Organizing`. There is no other back edge, and no failure path leaves
the machine. The three detail diagrams below say what triggers each one.

## 2. Inside Organizing

```mermaid
stateDiagram-v2
    state "<b>Waiting for participants</b><br/>1. round timeout starts ticking<br/>2. wait for t active peers<br/>3. determine role" as WaitingForParticipants
    state "<b>Reserving</b><br/>1. take one of 4 permits<br/>2. reserve a presignature with at least t active holders<br/>3. send PROPOSE to holders" as Reserving
    state "Posit" as PositOut

    [*] --> WaitingForParticipants
    WaitingForParticipants --> Reserving: I am the proposer
    WaitingForParticipants --> PositOut: I am a deliberator
    Reserving --> PositOut: PROPOSE broadcast

    WaitingForParticipants --> WaitingForParticipants: mesh channel closed
    Reserving --> WaitingForParticipants: no permit or presignature

    classDef outside fill:#eef1f4,stroke:#9aa4b0,color:#48525e,stroke-dasharray:5 3
    class PositOut outside
```

`Waiting for participants` has no timeout of its own. It blocks on
`mesh_state.changed()` until `t` peers are active, and returns early only if the
mesh channel closes.

The round timeout `round_timeout(r)` is already running while it waits, because
it started when the round began. If the wait outlasts the round timeout, the
states after it get no time at all: the proposer's presignature fetch and the
deliberator's wait for `PROPOSE` are each given the time left in the round, which
is now zero, so they fail on the first poll and round `r` ends without a
`PROPOSE` going out. The next round restarts the clock, so the cost is one wasted
round, with a different proposer.

## 3. Inside Posit

```mermaid
stateDiagram-v2
    state "<b>Waiting for Propose</b><br/>1. wait for PROPOSE from the elected proposer<br/>2. reject any other proposer as InvalidRequest" as WaitingForPropose
    state "<b>Propose received</b><br/>1. check I hold the proposed presignature<br/>2. send ACCEPT to the proposer" as ProposeReceived
    state "<b>Waiting for Start</b><br/>1. ACCEPT already sent, stays binding for at least 2x ACCEPT_POSIT_TIMEOUT<br/>2. wait for START from the proposer" as WaitingForStart
    state "<b>Propose sent</b><br/>1. tally ACCEPT and REJECT<br/>2. send START to the accepters once enough ACCEPTs" as ProposeSent
    state "Organizing" as OrgIn
    state "Generating" as GenOut

    OrgIn --> ProposeSent: I am the proposer
    OrgIn --> WaitingForPropose: I am a deliberator

    WaitingForPropose --> ProposeReceived: PROPOSE from the elected proposer
    ProposeReceived --> WaitingForStart: ACCEPT sent
    ProposeReceived --> WaitingForPropose: presignature missing, REJECT MissingArtifact sent

    ProposeSent --> GenOut: enough ACCEPTs, START broadcast
    WaitingForStart --> GenOut: START with at least t participants

    ProposeSent --> OrgIn: too many REJECTs, or timeout
    WaitingForPropose --> OrgIn: no PROPOSE in time
    WaitingForStart --> OrgIn: no START, or START too small

    classDef outside fill:#eef1f4,stroke:#9aa4b0,color:#48525e,stroke-dasharray:5 3
    class OrgIn,GenOut outside
```

The two lanes never meet. A node takes one or the other per round, decided by
`is_proposer`, which is a pure function of `r`. `Propose received` is the only
instantaneous state; the other three can hold for the full round timeout.

The edge back from `Propose received` to `Waiting for Propose` is not an abort:
the round is not bumped. A deliberator that lacks the presignature sends
`MissingArtifact` and resumes waiting for a `Propose` that a correct proposer
will not resend, so it sits out the rest of the round and leaves via the timeout.

### Who each message goes to

None of the four messages is a cluster-wide broadcast.

| Message | Recipients |
|---|---|
| `PROPOSE` | the holders of the reserved presignature intersected with the active set, not all members |
| `ACCEPT` | the proposer only |
| `START` | the accepters only, a subset of the `PROPOSE` set |
| `REJECT` | whoever sent the message being rejected |

A member outside the `PROPOSE` set is never told that round `r` is running. It
sits in `Waiting for Propose` until its timeout expires and bumps to `r+1`,
where it may be elected proposer and reserve a *second* presignature for a
request that is already being signed. That is the waste the `pause_proposing_until`
flag exists to limit after the fact.

So yes, sending `PROPOSE` to every member would be an improvement, and a cheaper
one than it looks: the tally is keyed on `SinglePositCounter::participants`, and
`process_action` already drops anything from a sender outside that set, so extra
replies could not move `enough_rejects` or `meets_totality`. The message would
be a notification for the excluded, not a vote.

Two caveats before doing it. A member that happens to hold the presignature but
was not in the active set at reservation time would reply `ACCEPT`, not be
counted, and then wait for a `START` it will never receive, so it gains nothing
over silence. And the excluded member still has no way to tell "round `r`
succeeded without me" from "round `r` is still running", which is the actual
question it needs answered; a `PROPOSE` it cannot act on does not answer it. The
narrow addressing is a symptom, the missing round-outcome signal is the cause.

## 4. Inside Generating

```mermaid
stateDiagram-v2
    state "<b>Acquiring</b><br/>1. proposer commits its reservation, deliberator fetches the presignature from storage<br/>2. build the generator" as Acquiring
    state "<b>Signing</b><br/>1. poke cait-sith, relay SendMany and SendPrivate<br/>2. answer late PROPOSE with REJECT AlreadyGenerating<br/>3. Action Return carries big_r and s" as Signing
    state "<b>Recording</b><br/>1. reconstruct against the derived key<br/>2. mark the request publishing in the backlog<br/>3. proposer submits it" as Recording
    state "Posit" as PositIn
    state "Done" as DoneOut
    state "Organizing" as OrgOut

    PositIn --> Acquiring: START agreed

    Acquiring --> Signing: presignature in hand
    Signing --> Recording: Action Return
    Recording --> DoneOut: Complete Ok

    Acquiring --> OrgOut: commit failed, or generator build failed
    Signing --> OrgOut: poke error, receive timeout, or inbox closed

    classDef outside fill:#eef1f4,stroke:#9aa4b0,color:#48525e,stroke-dasharray:5 3
    class PositIn,DoneOut,OrgOut outside
```

`Recording` has no exit to a new round. Reconstruction failure returns `None`
from `build_publish_state`, which skips the backlog marking, but the proposer's
`rpc.publish` call sits outside that branch and runs anyway, and the task
returns `Ok` either way. Only the proposer submits; every node marks the
backlog.

## 5. The round filter

Every incoming posit message passes the same three-way test before any state
above sees it:

```mermaid
stateDiagram-v2
    state peer_round <<choice>>
    [*] --> peer_round
    peer_round --> Reject: peer_round below r<br/>reply REJECT StaleRound carrying r
    peer_round --> Buffer: peer_round above r<br/>keep one message per sender
    peer_round --> Process: peer_round equals r
    Reject --> [*]
    Buffer --> [*]
    Process --> [*]
```

Three rules make this work:

1. A node never jumps forward to a peer's round on sight. If it did, any peer
   could name a round that makes itself proposer and do so every time. It
   finishes its own round first and only catches up at the next bump.
2. A `StaleRound` reject carries the rejector's round, so the lagging node
   catches up in one bump instead of one round at a time.
3. Rejects are never answered with a reject, otherwise two nodes ping-pong.

Buffered messages are replayed only in `Waiting for Propose`, and only once
`highest_seen_round == r`.

## 6. State variables

Two variables survive a round; everything else is rebuilt.

| Variable | Lives in | Changes when |
|---|---|---|
| `r` — round | `SignState.round`, mirrored into `SignEntry.round` (`Arc<AtomicUsize>`) | a new round: `r := max(r+1, highest_seen_round)`. Never decreases, and survives a task respawn. |
| `highest_seen_round` | `SignState` | a peer message or a `StaleRound` reject reports a round above it. Raising it also clears the buffer. |

Derived from `r` alone, with no messaging:

- proposer of the round: `participants[(entropy[0] + r) % n]` (`organize.rs`)
- round timeout: `round_timeout(r)` (`mod.rs`). Round 0 gets 20s; round 1 starts
  at a 2s floor and each later round grows 1.15x up to a 600s ceiling. Short
  early rounds rotate quickly past dead proposers, long later rounds outlast
  the skew between nodes that indexed the request at different times.

So all nodes agree on who proposes and how long the round lasts as soon as they
agree on `r`. Rounds are the only synchronisation the protocol has.

## 7. The round timeout

`round_timeout(r)` starts when the round begins: at the round bump
(`bump_round`), or at task spawn for round 0. It starts before `t` participants
are known, and every state shares whatever is left of it.

| State | Time limit |
|---|---|
| Waiting for participants | none |
| Reserving | round timeout |
| Waiting for Propose | round timeout |
| Propose sent | round timeout |
| Waiting for Start | round timeout, but at least `2 * ACCEPT_POSIT_TIMEOUT` |
| Acquiring, Signing | the generation protocol's own timeouts |

`Waiting for Start` is the only state with a floor under its wait. That floor
keeps an `ACCEPT` binding: a node that promised to participate cannot leave just
because the round timeout ran out.

## 8. Invariants worth checking

- **Rounds are monotone per request**, including across a respawn
  (`carried_round`). Peers read a round reset as time travel; `set_round` is the
  only write path.
- **Exactly one proposer per round**, because election reads only `r`,
  membership and entropy — never the local active set. Filtering by local state
  is what caused the permanent divergence in #907.
- **A node walks one lane of `Posit` per round**, never both.
- **`Accept` is sent exactly once per round**, on the edge out of
  `Propose received`.
- **The proposer's `Start` set is a subset of the accepters**, so every node in
  `Generating` has agreed to the same presignature for the same round.
- **`Generating` is not preempted by a new round**; a node only leaves it by
  finishing or failing.

## 9. Observations the model surfaces

Stated as consequences of the machine, not as bug reports.

1. **The new-round edge has no exit but another round.** No round cap, no
   deadline spanning rounds, and `round_timeout` saturates at 600s rather than
   growing without bound. The one failure terminal, `Complete(Err(Aborted))`,
   needs a closed proposer semaphore, and `Semaphore::close` is never called, so
   no request ever fails from inside the machine. A wedged request rotates until
   something outside removes it; the delayed watcher only increments a metric.
2. **A late accepter burns a full round.** A node that catches up mid-round
   sends `Accept` after the proposer already broadcast `Start`. The proposer is
   in `Generating` and drops `Accept` there, so the late node waits out its
   timeout in `Waiting for Start` and only rejoins at `r+1`.
3. **`MissingArtifact` costs a whole round**, for the reason given under §3.
4. **The buffer holds one message per sender.** If a sender's later message for
   the same future round overwrites its `Propose`, the deliberator reaches that
   round with nothing to act on. Today only the proposer sends both, and it
   sends `Start` only to nodes that accepted (which a lagging node cannot have
   done), so this is currently unreachable rather than guarded against.
5. **`Done` overstates completion.** `Complete(Ok)` fires after `rpc.publish`,
   before any on-chain confirmation, and also fires when reconstruction failed
   and the backlog was never marked. The publish/confirm lifecycle lives in the
   spawner and indexer, not in this machine.
6. **`pause_proposing_until` is a hidden mode.** For up to `generation_timeout`
   a node declines proposership and takes the deliberator edge out of
   `Waiting for participants`. Since election is by round, nobody else proposes
   that round either, so the round is spent waiting for a `Propose` that will
   not come.
7. **`Waiting for participants` is unbounded**, and whatever time it spends is
   subtracted from the round that follows.

## 10. Files

- `request/task.rs` — `SignPhase`, the driver loop
- `request/organize.rs` — election, permit, presignature reservation, `Propose`
- `request/posit.rs` — `Propose`/`Accept`/`Start`, the round filter
- `request/state.rs` — round, timeout, buffering
- `protocol/signature.rs` — the generation tail and publish
- `protocol/posit.rs` — shared vote types; the `Posits` map there is used by the
  triple and presignature protocols, signing uses `SinglePositCounter`
