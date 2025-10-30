# Visualizer Architecture

## Automatic Node Discovery & Aggregation

```
┌─────────────────────────────────────────────────────────────────┐
│                     Integration Test                            │
│                                                                  │
│  cluster::spawn()                                               │
│      .nodes(3)           ← Spawns 3 MPC nodes                   │
│      .visualize()        ← Enables visualizer                   │
│      .await?                                                     │
│                                                                  │
└──────────────────┬──────────────────────────────────────────────┘
                   │
                   │ 1. Spawns nodes
                   ▼
    ┌──────────────────────────────────────┐
    │         MPC Cluster Nodes             │
    │                                       │
    │  Node 0: http://127.0.0.1:3001       │
    │  Node 1: http://127.0.0.1:3002       │
    │  Node 2: http://127.0.0.1:3003       │
    │                                       │
    │  Each exposes:                        │
    │  - GET /visualizer/active             │
    │  - GET /visualizer/completed          │
    └──────────────────┬────────────────────┘
                       │
                       │ 2. Extracts URLs
                       │ 3. Spawns visualizer with node URLs
                       ▼
    ┌─────────────────────────────────────────────────────┐
    │           Visualizer Backend                        │
    │           (cargo run -p visualizer)              │
    │                                                      │
    │  Args: 8080 http://...3001 http://...3002 http://...3003│
    │                                                      │
    │  ┌────────────────────────────────────┐            │
    │  │  Polling Loop (500ms interval)     │            │
    │  │                                     │            │
    │  │  for each node_url:                │            │
    │  │    GET {node_url}/visualizer/active│            │
    │  │    GET {node_url}/visualizer/completed│         │
    │  │                                     │            │
    │  │  Aggregates into ClusterView       │            │
    │  └────────────────────────────────────┘            │
    │                                                      │
    │  HTTP Server:                                       │
    │  - GET /api/cluster  → ClusterView JSON            │
    │  - GET /ui           → Frontend HTML               │
    │                                                      │
    └────────────────────┬────────────────────────────────┘
                         │
                         │ 4. Serves UI
                         ▼
              ┌─────────────────────┐
              │      Browser        │
              │  localhost:8080/ui  │
              │                     │
              │  Polls /api/cluster │
              │  every 500ms        │
              │                     │
              │  Displays:          │
              │  - Active requests  │
              │  - Completed reqs   │
              │  - Per-node metrics │
              └─────────────────────┘
```

## Data Flow

### 1. Sign Request Starts (Future)
```
MPC Node Protocol
    ↓
VisualizerState.start_request(sign_id, type, status)
    ↓
Stored in active_requests HashMap
```

### 2. Visualizer Polls Node
```
Visualizer Backend
    ↓
GET /visualizer/active → Node HTTP endpoint
    ↓
Returns Vec<SignRequestView>
    ↓
Aggregated into ClusterView
```

### 3. Frontend Updates
```
Browser
    ↓
GET /api/cluster every 500ms
    ↓
Receives ClusterView JSON
    ↓
Renders active and completed requests per node
```

## Key Features

### ✅ Zero Configuration
- Nodes automatically discovered from cluster spawner
- No manual URL configuration needed
- Works with any number of nodes

### ✅ Real-Time Updates
- Backend polls nodes every 500ms
- Frontend polls backend every 500ms
- ~1 second end-to-end latency

### ✅ Per-Node Visibility
- Each node reports its own view of sign requests
- Visualizer aggregates and displays per-node data
- Easy to spot discrepancies across nodes

### ✅ Lifecycle Management
- Visualizer spawned with cluster
- Automatically stopped when cluster drops
- Process cleanup handled by VisualizerHandle Drop impl
