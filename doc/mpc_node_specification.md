# MPC Node Specification

This document describes how an MPC node is supposed to interact with other
nodes, in a way that the network can execute signature requests in a stable and
reliable manner.

It's a high level specification, describing the distributed algorithms and
messages.

## Definitions

### Protocols

The MPC network has three protocols that it serves.

- Triple Generation
- Pre-signature Seneration
- Signature

These are distributed algorithms. The execution of such an algorithm across the
network will be called `protocol invocation` in this document.

When using the pre-signature generation protocol, this specification ensures no
triple is used more than once as an input. Likewise, the signature protocol must
only use each pre-signature once. This is a security assumption of the
cryptographic protocol.


### Participant Roles

Each protocol invocation (triple generation, pre-signature generation,
signature) has a list of `Participants`. One of the participants is the `Owner`
who initiates the protocol.

The `Owner` of a protocol will usually follow different steps than the rest.

The `Owner` has full control over protocol invocations and inputs that it
owns. All other participants follow blindly and must not make any decisions
about the non-owned protocol invocation on their own. This makes it easier to
avoid many common distributed faults, such as two nodes deciding differently on
the same invocation. It is not byzantine fault-tolerant, however, which this
specification explicitly not is trying to achieve.

## Protocol State Machine

The following graph shows the lifetime of a protocol invocation. Each
participant has its own instance of this state machine. It is a form of
two-phase commit, with a pre-selected leader (called `Owner`), executed over a
peer-to-peer network.

The arrows in blue show how the `Owner` transitions between states, while the
red arrows are for all other `Participants`. Red arrows generally only wait on
messages by the owner, while the owner (blue) sends these messages whenever
itself transitions forward.

For the signature protocol, all participants must check that requests were
indexed and finalized, as noted in the graph.

![graph](./graphs/protocol_states.svg)


### States

`init` and `done` are implicit states. All other states must be explicitly
stored and ideally persisted.

#### init

In the `init` state, nodes should only accept incoming messages from the owner
of a protocol ID and discard all other messages they might receive about that
ID.

#### Prepare

The primary purpose of the `Prepare` phase is to avoid multiple instances of the
same (protocol ID, retry count) running simultaneously. It is crucial to have
this phase to satisfy the non-reuse security assumption of the cryptographic
protocol.

A secondary purpose is to support state sync, which we need for a fault-tolerant
participant selection.

In the `Prepare` state, the owner establishes the participants list. It sends an
INIT message to all valid participants, where a participant is valid if it is
currently active and holds necessary P or T according to the owner's directory.
All nodes that answer OK can be included in the participants list.

Participants enter the `Prepare` state after they answered an INIT with OK.
After that, they may accept messages from non-owner peers and put them in a
queue. However, crucially, participants are still not allowed to send messages
about the protocol, yet.

*Why can we not apply incoming messages in the Prepare phase?*

For simple fault-tolerance, applying messages can be okay but sending messages
is forbidden in all security models. Applying messages is only dangerous in
byzantine-fault tolerance security models, since malicious peers could perform a
DoS attack and overwhelm other nodes with CPU-intensive messages.

*Why can we not send messages, yet?*

This is due to the black box assumption on the underlying cryptography. Signing
messages and sending them out might reveal information. This could lead to
security vulnerabilities if we later invoke the same protocol again but with a
different set of participants, for example. Sending messages with one
participant set would mean we have to use a fresh P or T if we later change the
participant set. In the prepare phase, we specifically don't know the
participant set, yet, thus we should not send messages unless we are okay with
wasting Ps and Ts.

Even without the black box assumption, we know that cait-sith requires strict
non-reuse of Ps and Ts. 

*Why should we still care about incoming messages?*

Nodes in the `Prepare` state may receive messages from other nodes that are
already in the `Running` state. In that case, nodes should either reject
messages or keep them in a buffer. If rejected, the sender (in `Running` state)
must retry sending the rejected message. If buffered, the receiver should
process the buffered messages right after it transitions to the `Running` state.

*Why not skip the Prepare phase and go directly to Running?*

A phase between `init` and `Running` guarantees that as soon as one node is in
the `Running` phase, no other participant of that protocol is still in `init`.

We need this property for two reasons.

1. To avoid input reuse, we can only enter `Running` when the participant list
   is immutably decided. But as long as some participants could be in `init`,
   the list is just a guess. Making it immutable at this point would mean we
   have to use a fresh P or T on every change of participants set, leading to
   poor performance and reduced throughput.
   With the additional phase, we can select a minimal subset of fast responding
   nodes, which gives better latency and does not waste P and T inputs.
2. For state sync, this property solves corner cases. Example: When the owner is
   already done with a pre-signature generation but the peer has not even
   started the protocol, yet. The owner then sends a sync request, without the
   triple for that protocol in the list. The peer would than have to delete it
   and would no longer have it when the delayed `INIT` message arrives. But
   thanks to the `Prepare` state, we know all participants are at least in the
   `Prepare` phase and thus have marked the input Triples as `Using` before the
   owner can even start running the protocol. Hence, once it reaches `done`,
   every participant has it as `Using`. In that state, peers never delete
   triples since it knows the protocol is running and it should be expected that
   the owner may finish faster than the peer.


#### Running

In the `Running` state, nodes continuously poke the local message generators and
exchange messages to progress the protocol.

Messages sent to participants that are offline or reject the message must be
retried until either the receiver accepts the message or the protocol invocation
globally times out.

For recovery, we use the
[Event-Sourcing](https://dev.to/alisamir/understanding-event-sourcing-a-detailed-guide-4cjp)
pattern, while the protocol is running. The actual latest state is only held in
memory but the stored events allow to recover it from persisted data.

Specifically, this means tha all received messages during the `Running` state
must be persisted before they are applied. These can be replayed on boot for
recovery after a crash. After a protocol finishes, events can be discarded.

Note: Unlike fully event-driven architectures, the MPC network does not need to
have a separate even store component. The Event-Sourcing pattern is only applied
locally within one node.

### Owner Transitions

The owner of the protocol invocation progresses the protocol:

- When a new valid request is registered (indexed for the signature protocol,
  initiated by background task for triple/pre-signature generation)
    - Select a list of potential participants, based on the own view of which
      nodes are active and hold the relevant data in their storage.
    - Asynchronously send an INIT message to all the participants and wait until
      enough messages have been received. (HTTP success response or explicit
      OK message back)
    - Transition to `Prepare` state
- Once enough INIT messages have been answered with a success response
    - Wait for finality of the request (for signatures only)
    - Select participants that responded OK
    - Send out a START message to all participants, with the list of participants
    - Transition to `Running` state
    - Start poking own generator and sending out the corresponding messages

Owners must also handle the following error case:
- Not enough participants answered the INIT message with an HTTP success response
    - Retry, maybe some more participants are online now
    - After a threshold of retries, switch to a different P or T input that has
      more active participants.

Other error cases can be handled with a global timeout to abort and retry for
signatures.

## Triple and Pre-Signature State Machine

Triples and Pre-Signatures are persistently stored on each node. They go through
the following lifecycle. Nodes must keep track of them in order for state sync
to work.

![graph](./graphs/p_and_t_states.svg)

### States

`init` and `done` are implicit states. Both are represented by not having any
information about the P or T in storage. All other states must be explicitly
stored and ideally persisted.

#### Generating

A P or T in the `Generating` state has an active protocol invocation that will
generate it on success. It is treated the same way as `Available` for state
sync. But the storage does not actually hold the P or T, yet.

#### Available

In the `Available` phase, a P or T share is currently ready to be used in a
protocol. This state always implies that the P or T is available in state. As
soon as it is removed from persistent storage, we must persist the state change
to `Using`.

#### Using

A P or T in the `Using` state is currently being used in a protocol invocation.
We need to track this in order for state sync to not delete any data that's
still in use.

Only transition from `Using` to `done` when either the protocol finishes
successfully, or we hit the global protocol timeout. Once that transition
happens, the node can delete all info about the P or T and its ID from
persistent storage.


## Participant Selection

When a proposer selects a list of participants for a new protocol invocation, it should check these conditions:

- Participants must be online
- Participants must hold the relevant P and T shares

To enable the first, nodes keep a connection status for every peer. For the
second part, they keep a directory of each owned P and T with a list of share
holders. Both data structures are further specified below.

### Node Connection Status

![graph](./graphs/node_connection.svg)

Nodes keep pinging each other, checking their peers status.

Peers that don't respond are marked as `Offline`.

Peers that respond but indicate in their status response that they are not actively participating in the MPC network, are marked as `Inactive`.

Peers that respond and are participating in the MPC network are first listed as
`Syncing` and receive a sync request. Only after the response for that has been
answered, can the connection status transition to `Active`. Only peers with a
connection status `Active` are valid for inclusion in the participant list of
any protocol invocations.

### Share holder directory

An owner of a P and a T must always know which peers are holding a share of it.
It should keep this information up-to-date in a directory that's fully persisted.


```
# Example directory of node A

Triple 0: [Node B, Node C, Node D]
Triple 1: [Node B, Node C, Node D]
Triple 2: [Node B, Node D]
```

Note that this directory only contains entries for inputs owned by the node.

To keep this list up-to-date, nodes implement state sync.

### State Sync

Nodes may sometimes lose their persisted database. The network has to recover
from that without causing instability. That's why we have state sync, which
updates the directory used for participant selection.

State sync runs everytime a node connects to another, either after a fresh boot,
or when re-connecting after the connection was lost for another reason.

![graph](./graphs/state_sync.svg)

During state sync, the owner sends a list of Pre-signatures and Triples that it expects the other node to hold a share of. Specifically, it sends all owned IDs which satisfy:

- Is in the current directory of the owner
- The non-owning peer node (Node B) is in the list of valid participants in the owner's directory
- The owner currently holds the input data as `Available`, `Generating`, or `Using`.

The peer and afterwards the owner will then update their view on who holds which
data. This has to be done with care, to avoid race conditions. The following
describes all cases.

#### Non-owner action on state sync

Peer state of P or T | P or T is included in sync request | P or T is NOT included in sync request
-- | -- | --
Init / done / lost | <= respond missing | nop
Generating | nop | can delete
Available | nop | can delete
Using | nop | nop (let protocol finish)

Node B must always respond with a list of IDs that were in the request but node
B no longer holds the corresponding input in storage, in any state.

Node B can optionally use the sync request to delete all inputs
owned by node A that are not in the list, if B holds them as `Available` or
`Generating`.

Do not delete anything in `Using`, as it suggests the protocol has
not finished globally yet, even if on the owner's view it already has finished.


#### Owner action on state sync

Node A (owner) uses the response of node B to update its directory, as shown in
the table below.

Owner state of P or T | Owner action if peer responds with missing P or T
-- | --
Init / done / lost | nop (nothing to delete)
Generating | nop
Available | delete participant
Using | nop

Deleting from the directory should only happen if the current state as seen by the owner is `Available`.

The owner should not delete in `Generating`, as it could mean the peer simply hasn't processed the INIT(generate) message, yet.

The owner should not delete in `Using`, as it could mean the peer is already in `done` for this P or T.


#### Proof of all combinations

To prove that state-sync never messes up the directory or deletes too much data,
we have to consider all combinations of states on both ends.

The table below describes what happens in each of these cases, according to the
actions defined in this specification.


Owner / Peer | init | Generating | Available | Using | done | lost in crash
-- | -- | -- | -- | -- | -- | --
init | nop | Impossible: owner goes to Generating when it sends INIT(generate) | Impossible: owner goes to Generating when it sends INIT(generate) | Impossible: owner goes to Generating when it sends INIT(generate) | nop | nop
Generating | <= respond missingOwner ignores it | nop | nop | nop | Impossible, owner would never send INIT(output) while still generating the input | <= respond missingOwner should delete participant(but ignores it because it could also be init)
Available | Impossible: owner can’t reach Available before all participants are at least at Generating, since protocol won’t start before everybody is in Generating already | nop | nop | nop | Impossible, owner goes to Using when sending INIT | <= respond missingOwner deletes participant
Using | Impossible, Using comes after Available, see Available/init | nop | nop | nop | <= respond missingOwner ignores it | <= respond missingOwner ignores it
done | Impossible, done comes after Available, see Available/init | Impossible: peer must be in Prepare(consume) and Using(generate) when owner sends INIT(consume) | Impossible: peer must be in Prepare(consume) and Using(generate) when owner sends INIT(consume) | nop(partially finished protocol) | nop | nop
lost in crash | nop | optional: peer deletes obsolete input | optional: peer deletes obsolete input | nop | nop | nop


Note that each side only sees their own state, not that of the other side.
Therefore, we have to do the same peer actions in all columns and the same owner
action in all rows. Further, neither side can differentiate between the `init` /
`done` / `lost` states. So they must also have the same actions for all those
states.

Provably impossible states are key for correctness. The `Prepare` phase
specifically allows to mark all cases impossible where one node would still be
in `init` while others are already `Running`.
