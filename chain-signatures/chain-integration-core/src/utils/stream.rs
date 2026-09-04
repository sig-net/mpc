use mpc_primitives::ChainEvent;
use tokio::sync::mpsc;

const CHAIN_EVENT_STREAM_SIZE: usize = 16384;

/// Creates a channel for chain events with a specified buffer size.
pub fn chain_event_channel() -> (mpsc::Sender<ChainEvent>, mpsc::Receiver<ChainEvent>) {
    mpsc::channel(CHAIN_EVENT_STREAM_SIZE)
}
