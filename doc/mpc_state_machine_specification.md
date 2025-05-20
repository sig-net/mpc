# State Machine

The state machine of the MPC network is one that models off of a base chain for its consensus of state. Each node will react to the contract on this base chain whenever it transitions to another state.

So we have two states, Contract state and Node state. Contract state is simpler meanwhile node state can be more complex due to all the various operations it needs to perform.


## Contract State

The contract defines the following states:
- Generating
- Running
- Resharing

Since we support more than one key/curve type, we can have partial states where we have Running for ECDSA and Generating for EdDSA. This partial state is currently not supported for resharing. So this would mean that only when a new keytype is introduced to the network can we have different states per keytype.


## Node State

The node defines the following states:
- Starting
- Started
- Generating
- Syncing
- Running
- Resharing

Starting/Started is used for facilitating loading from storage for items such as key shares.
