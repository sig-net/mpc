//! Output recovery for EVM-family target chains (§7.5.2.2 of
//! `doc/bidirectional-calls.md`): ABI-decode a call's return data against
//! the request's output schema and re-serialize it for the source chain.
//! The decision table is shared by every EVM-family integration —
//! Ethereum's `callTracer` top frame and Tron's receipt `contractResult`
//! feed it the same bytes. Pure: no async, no HTTP.

mod output_recovery;

pub use output_recovery::{
    build_serialized_output, is_contract_call, validate_schemas, TraceOutput,
};
