# Architecture

There are several components that make up Sig.Network MPC. This includes but is not limited to the following:

- MPC nodes with root key-shares and indexers
- Orchestrating Smart Contract
- Signing contracts

Note that this list only includes components vital to creating signatures and not the components required to do foreign chain interactions like sending the signature from chain A to chain B. Each of these will be explained further in the following sections.

But first, here is a visual high-level overview.

![diagram](./doc/System%20Architecture%20Overview%20-%20High%20Level.svg)

### Orchestrating and Signing Smart Contract

The contract is simple in terms of functionality. It provides two main functions for users or developers to call into.

- The most common function is `sign`, which when called will yield a signature for the user to consume however they wish. For example, this signature can be used to sign into arbitrary chains given the derivation path of the account of that chain. For more info on how the MPC node picks these `sign` requests, refer to the Indexer section.
- The second method (and should realistically only be used by the MPC nodes themselves) is the `vote_*` methods. These allow the MPC nodes to each individually act as voters into the MPC network, facilitating the way new nodes join or current nodes get kicked out.

Besides the two methods for users, there are also methods only used by the MPC nodes.

- `respond` is the sibling of `sign`. It takes the completed signature from the MPC network, wakes up a waiting `sign` call, and returns it back to the calling user.
- `state` and `config` are view calls used by the MPC nodes to read the shared network state.
- `system_load` and `version` are for debugging.

The diagram below shows everything the Near smart contract does, combining the network management with the signing functionality, all in one contract.

![diagram](./doc/System%20Architecture%20Overview%20-%20Smart%20Contract.svg)

#### MPC State

Note that each MPC node does not maintain its own state, but rather queries the contract for the contract's state and then directly switches to the corresponding MPC node state. This is how state transitions also happen -- whenever the contract determines it is time to reshare or refresh the shares of the keys, the nodes themselves will properly transition to these corresponding states.

The contract also circumvents many possibilities such as going below the threshold amount of nodes in the network. This keeps it simple such that the MPC nodes only need to keep track of very few things like the beaver triples it stockpiles.

### Indexers

How does the MPC network pick up sign requests even though users are mainly interacting with the multichain sign smart contracts?

The answer is the indexer. Each node would ideally run an indexer to listen to a specific contract's address with a method `"sign"` being called. Note that currently each node does not run its own indexer, but rather uses indexing providers; which is a bit different but saves us the resource cost of having to run our own nodes where the indexer's blocks can be streamed from. To circumvent this, we can include ZK light client proofs to verify that the blocks are indeed correct.

### MPC Node

The MPC node is the central piece to the operation of the network itself. These nodes will listen to requests from the sign smart contracts, utilizing an `Indexer`, eventually forwarding the request over to the signature pipeline to be signed by each node. Most of the computation for this is pre-calculated ahead of time (i.e., beaver triple stockpiling) to save time on the signature being returned. If the network is congested, the bottleneck here would be a new set of triples being generated. One signature would require two owned triples per node. To generate a singular triple takes about 30 seconds in the best case with our default hardware configurations. Since we can run many of such protocols in parallel, the actual time is ~2 seconds. Signature protocols are much faster and take a couple of seconds each depending on the load.

#### Networking

Each of the MPC nodes needs to keep track of who is alive in the connective mesh. This is to ensure that messages for things like signature generation and triple generation are routed correctly and done in a reasonable amount of time.
