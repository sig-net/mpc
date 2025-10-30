# MPC Sign Request Lifecycle Visualizer

A real-time visualization tool for tracking MPC sign request lifecycle across all nodes in a cluster.

## Features

- **Real-time tracking** of sign requests across all nodes
- **Active requests view** showing:
  - Sign request ID
  - Request type (`sign`, `sign_bidirectional`, or `respond_bidirectional`)
  - Current status per node (`in_posits`, `generating`, or `completed`)
  - Time spent in current status
  - Time since last action
  - Message counts (sent and received) per node
- **Completed requests view** showing:
  - Total time to complete
  - Message counts
  - Request type

## Usage

### In Integration Tests

To enable the visualizer in your integration tests, use the `.visualize()` builder option:

```rust
use mpc1::cluster;

#[tokio::test]
async fn test_with_visualizer() {
    let cluster = cluster::spawn()
        .nodes(3)
        .visualize()  // Enable visualizer
        .await
        .unwrap();

    // Your test code here...
    // The visualizer UI will be available at http://localhost:8080/ui
}
```

The visualizer will automatically:
1. Start a web server on port 8080
2. Poll all cluster nodes for sign request data
3. Serve a real-time UI at `http://localhost:8080/ui`

### Running Standalone

You can also run the visualizer standalone:

```bash
cargo run -p visualizer -- 8080 http://node1:3000 http://node2:3000 http://node3:3000
```

Then open `http://localhost:8080/ui` in your browser.

## Architecture

The visualizer consists of:

1. **Node endpoints** (`/visualizer/active` and `/visualizer/completed`) - Added to each MPC node to expose sign request lifecycle data
2. **Visualizer backend** (`visualizer/src/main.rs`) - Aggregates data from all nodes and serves the UI
3. **Frontend UI** (`visualizer/frontend/dist/index.html`) - Real-time dashboard with tabs for active and completed requests

## Node Integration

The visualizer polls the following endpoints on each node:

- `GET /visualizer/active` - Returns currently active sign requests
- `GET /visualizer/completed` - Returns completed sign requests

These endpoints return JSON arrays of sign request data. Currently, they return empty arrays as placeholders. To implement full tracking, the node code needs to be enhanced to track sign request lifecycle events.

## Future Enhancements

To fully implement sign request tracking:

1. Add `VisualizerState` to the MPC node protocol
2. Track lifecycle events:
   - When a request enters `in_posits` status
   - When a request transitions to `generating`
   - When a request completes
   - Message send/receive events
3. Update status timestamps on each state transition
4. Move completed requests to the completed list

See `chain-signatures/node/src/visualizer.rs` for the tracking infrastructure (already created but not yet integrated into the protocol).
