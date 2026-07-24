# mpc-primitives

Internal, node-side primitives for the MPC network. **Not published.**

If you are building a client against the network, you almost certainly want
[`signet-primitives`](../signet-primitives) instead — that is the small,
published crate of public interface types (chains, signatures, sign requests,
key versions) that the on-chain contracts deserialize.
