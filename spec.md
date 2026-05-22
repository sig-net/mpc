# Chain Indexer Redesign Specification

## Problem Statement

Current `ChainStream` and `ChainIndexer` abstractions stretched across Ethereum, Solana, and Canton implementations. Core issues:

1. **Block Type Mismatch**: Canton uses ledger offsets (u64), Ethereum uses full Block objects, Solana uses (slot, block) tuples - forced into single abstraction
2. **Catchup Iterator Inconsistency**: Only Ethereum truly async, others use sync iterators wrapped in trait
3. **Duplication**: Each chain reimplements catchup coordination, event channel setup, retry logic, backlog processing
4. **Architectural Mismatch**: Canton's continuous ledger stream fundamentally different from Ethereum/Solana's discrete block model
5. **Custom Processing**: Each chain has unique block fetching/streaming but shares identical event processing logic

## Design Goals

1. **Clear Separation**: Distinguish chain-specific block fetching from unified event processing
2. **Minimal Duplication**: Extract common patterns (catchup coordination, event handling, retry)
3. **Flexible Block Sources**: Support polling (Ethereum), WebSocket (Canton), hybrid (Solana)
4. **Type Safety**: Don't force incompatible models into same abstraction
5. **Maintainability**: New chain implementations should be straightforward

## Proposed Architecture

### Core Abstraction: BlockSource

Replace `ChainIndexer` with simpler `BlockSource` trait focused solely on fetching/streaming blocks:

```rust
#[async_trait]
pub trait BlockSource: Send + 'static {
    /// Chain-specific block representation
    type Block: Send;
    
    /// Chain this source serves
    const CHAIN: Chain;
    
    /// Initialize and return the current chain height (anchor point)
    async fn initialize(&mut self) -> anyhow::Result<u64>;
    
    /// Fetch a single block by height
    async fn fetch_block(&self, height: u64) -> anyhow::Result<Option<Self::Block>>;
    
    /// Stream next live block (returns None if not ready)
    async fn next_live_block(&mut self) -> Option<Self::Block>;
    
    /// Get height of a block
    fn block_height(&self, block: &Self::Block) -> u64;
}
```

**Key Changes:**
- No more `Iter` associated type - catchup handled generically
- No more `process()` vs `process_catchup()` split
- Focus: "give me blocks" not "process blocks"
- Chain-specific: how to fetch/stream
- Generic: catchup range iteration

### Event Extraction: BlockParser

Separate trait for transforming blocks into events:

```rust
#[async_trait]
pub trait BlockParser: Send + 'static {
    type Block: Send;
    
    /// Parse block into zero or more ChainEvents
    async fn parse_block(
        &self,
        block: &Self::Block,
        height: u64,
    ) -> anyhow::Result<Vec<ChainEvent>>;
}
```

**Key Changes:**
- Pure transformation: Block → Vec<ChainEvent>
- No side effects (backlog, channels)
- Testable in isolation
- Reusable across catchup/live

### Unified Coordinator: ChainIndexer

New `ChainIndexer` orchestrates catchup, live streaming, event processing:

```rust
pub struct ChainIndexer<S, P>
where
    S: BlockSource,
    P: BlockParser<Block = S::Block>,
{
    source: S,
    parser: P,
    backlog: Backlog,
    events_tx: mpsc::Sender<ChainEvent>,
    caught_up: bool,
}

impl<S, P> ChainIndexer<S, P>
where
    S: BlockSource,
    P: BlockParser<Block = S::Block>,
{
    pub fn new(
        source: S,
        parser: P,
        backlog: Backlog,
        events_tx: mpsc::Sender<ChainEvent>,
    ) -> Self {
        Self {
            source,
            parser,
            backlog,
            events_tx,
            caught_up: false,
        }
    }
    
    /// Run full indexer lifecycle: catchup then livestream
    pub async fn run(mut self) {
        let chain = S::CHAIN;
        
        // Initialize and get anchor height
        let anchor_height = match self.source.initialize().await {
            Ok(height) => height,
            Err(err) => {
                tracing::error!(?err, %chain, "failed to initialize block source");
                return;
            }
        };
        
        // Determine catchup range
        let start_height = self
            .backlog
            .processed_block(chain)
            .await
            .map(|h| h.saturating_add(1))
            .unwrap_or(anchor_height);
        
        // Catchup phase
        if start_height < anchor_height {
            tracing::info!(%chain, start_height, anchor_height, "starting catchup");
            if let Err(err) = self.catchup(start_height, anchor_height).await {
                tracing::error!(?err, %chain, "catchup failed");
                return;
            }
        }
        
        // Signal catchup complete
        if let Err(err) = self.events_tx.send(ChainEvent::CatchupCompleted).await {
            tracing::error!(?err, %chain, "failed to send catchup completed");
            return;
        }
        self.caught_up = true;
        
        // Livestream phase
        tracing::info!(%chain, "starting livestream");
        self.livestream().await;
    }
    
    async fn catchup(&mut self, start: u64, end: u64) -> anyhow::Result<()> {
        for height in start..end {
            self.process_height(height).await?;
        }
        Ok(())
    }
    
    async fn livestream(&mut self) {
        loop {
            let Some(block) = self.source.next_live_block().await else {
                tracing::warn!(chain = %S::CHAIN, "livestream ended");
                break;
            };
            
            let height = self.source.block_height(&block);
            if let Err(err) = self.process_block(&block, height).await {
                tracing::error!(?err, height, "failed to process live block");
            }
        }
    }
    
    async fn process_height(&mut self, height: u64) -> anyhow::Result<()> {
        const MAX_RETRIES: usize = 3;
        const RETRY_DELAY: Duration = Duration::from_millis(500);
        
        for attempt in 0..MAX_RETRIES {
            match self.source.fetch_block(height).await {
                Ok(Some(block)) => {
                    return self.process_block(&block, height).await;
                }
                Ok(None) => {
                    tracing::warn!(height, attempt, "block not found; retrying");
                }
                Err(err) => {
                    tracing::warn!(?err, height, attempt, "fetch failed; retrying");
                }
            }
            tokio::time::sleep(RETRY_DELAY).await;
        }
        
        anyhow::bail!("failed to fetch block {height} after {MAX_RETRIES} attempts")
    }
    
    async fn process_block(&mut self, block: &S::Block, height: u64) -> anyhow::Result<()> {
        // Parse block into events
        let events = self.parser.parse_block(block, height).await?;
        
        // Emit all events
        for event in events {
            self.events_tx.send(event).await?;
        }
        
        // Emit block height event for checkpoint tracking
        self.events_tx.send(ChainEvent::Block(height)).await?;
        
        Ok(())
    }
}
```

**Key Changes:**
- Generic over `BlockSource` and `BlockParser`
- Handles catchup coordination internally
- Unified retry logic
- No per-chain catchup implementations
- Single code path for block processing

### ChainStream Simplification

`ChainStream` becomes pure event channel:

```rust
pub struct ChainStream {
    events_rx: mpsc::Receiver<ChainEvent>,
}

impl ChainStream {
    pub fn new() -> (Self, mpsc::Sender<ChainEvent>) {
        let (tx, rx) = mpsc::channel(CHAIN_EVENT_STREAM_SIZE);
        (Self { events_rx: rx }, tx)
    }
    
    pub async fn next_event(&mut self) -> Option<ChainEvent> {
        self.events_rx.recv().await
    }
}
```

**Key Changes:**
- No trait needed
- Just a channel wrapper
- No per-chain implementations

## Implementation Examples

### Ethereum BlockSource

```rust
pub struct EthereumBlockSource {
    client: Arc<EthereumClient>,
    live_blocks_rx: Option<mpsc::Receiver<MaybeBlock>>,
    catchup_complete: Arc<Notify>,
}

#[async_trait]
impl BlockSource for EthereumBlockSource {
    type Block = MaybeBlock;
    const CHAIN: Chain = Chain::Ethereum;
    
    async fn initialize(&mut self) -> anyhow::Result<u64> {
        let start_block_number = loop {
            if let Some(block_number) = self.client.get_latest_block_number().await {
                break block_number.saturating_add(1);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        };
        
        let (live_blocks_tx, live_blocks_rx) = live_blocks_channel();
        tokio::spawn(Self::index_live_blocks(
            self.client.clone(),
            self.catchup_complete.clone(),
            start_block_number,
            live_blocks_tx,
        ));
        
        self.live_blocks_rx = Some(live_blocks_rx);
        Ok(start_block_number)
    }
    
    async fn fetch_block(&self, height: u64) -> anyhow::Result<Option<Self::Block>> {
        let block_id = BlockId::Number(BlockNumberOrTag::Number(height));
        match self.client.get_block(&block_id).await {
            Some(block) => Ok(Some(MaybeBlock::Block(block))),
            None => Ok(Some(MaybeBlock::Missing(block_id))),
        }
    }
    
    async fn next_live_block(&mut self) -> Option<Self::Block> {
        self.live_blocks_rx.as_mut()?.recv().await
    }
    
    fn block_height(&self, block: &Self::Block) -> u64 {
        match block {
            MaybeBlock::Block(b) => b.header.number,
            MaybeBlock::Missing(BlockId::Number(n)) => match n {
                BlockNumberOrTag::Number(num) => *num,
                _ => 0,
            },
            _ => 0,
        }
    }
}
```

### Ethereum BlockParser

```rust
pub struct EthereumBlockParser {
    client: Arc<EthereumClient>,
    backlog: Backlog,
}

#[async_trait]
impl BlockParser for EthereumBlockParser {
    type Block = MaybeBlock;
    
    async fn parse_block(
        &self,
        maybe_block: &Self::Block,
        height: u64,
    ) -> anyhow::Result<Vec<ChainEvent>> {
        let block = match maybe_block {
            MaybeBlock::Block(block) => block,
            MaybeBlock::Missing(block_id) => {
                // Refetch missing block
                let Some(block) = self.client.get_block(*block_id).await else {
                    anyhow::bail!("block {block_id:?} still unavailable");
                };
                // Can't return reference, need to handle differently
                // Option 1: Store in parser state
                // Option 2: Return empty and retry at higher level
                return Ok(vec![]);
            }
        };
        
        let block_and_requests = self.client.parse_block(block).await?;
        let mut events = Vec::new();
        
        // Add sign request events
        for request in block_and_requests.indexed_requests {
            events.push(ChainEvent::SignRequest(request));
        }
        
        // Add respond events
        for log in block_and_requests.respond_logs {
            if let Some(respond_event) = self.parse_respond_log(&log) {
                events.push(ChainEvent::Respond(respond_event));
            }
        }
        
        // Add execution events
        events.extend(block_and_requests.execution_events);
        
        Ok(events)
    }
}
```

### Canton BlockSource

```rust
pub struct CantonBlockSource {
    client: CantonClient,
    ws_conn: CantonConnection,
    last_seen_offset: u64,
}

#[async_trait]
impl BlockSource for CantonBlockSource {
    type Block = ledger_api::Update;
    const CHAIN: Chain = Chain::Canton;
    
    async fn initialize(&mut self) -> anyhow::Result<u64> {
        let anchor_height = self.client.fetch_ledger_end().await?;
        self.reconnect(0).await;
        Ok(anchor_height)
    }
    
    async fn fetch_block(&self, height: u64) -> anyhow::Result<Option<Self::Block>> {
        // Canton doesn't support random access - must stream sequentially
        // This is a limitation of the ledger API
        // For catchup, we'll stream from last_seen to target
        Ok(None)
    }
    
    async fn next_live_block(&mut self) -> Option<Self::Block> {
        self.next_update().await
    }
    
    fn block_height(&self, block: &Self::Block) -> u64 {
        match block {
            ledger_api::Update::Transaction { value } => value.offset,
            ledger_api::Update::OffsetCheckpoint { value } => value.offset,
        }
    }
}
```

**Canton Special Case**: Canton can't fetch arbitrary offsets, must stream sequentially. Two options:

1. **Option A**: Override catchup in `ChainIndexer` for Canton
2. **Option B**: Make `fetch_block` return iterator/stream for range

Recommend **Option B** - extend `BlockSource`:

```rust
#[async_trait]
pub trait BlockSource: Send + 'static {
    type Block: Send;
    const CHAIN: Chain;
    
    async fn initialize(&mut self) -> anyhow::Result<u64>;
    
    /// Fetch single block (optional - for random access chains)
    async fn fetch_block(&self, height: u64) -> anyhow::Result<Option<Self::Block>> {
        Ok(None)
    }
    
    /// Fetch range of blocks (for sequential-only chains like Canton)
    async fn fetch_range(
        &mut self,
        start: u64,
        end: u64,
    ) -> anyhow::Result<Vec<Self::Block>> {
        let mut blocks = Vec::new();
        for height in start..end {
            if let Some(block) = self.fetch_block(height).await? {
                blocks.push(block);
            }
        }
        Ok(blocks)
    }
    
    async fn next_live_block(&mut self) -> Option<Self::Block>;
    fn block_height(&self, block: &Self::Block) -> u64;
}
```

Canton overrides `fetch_range` to stream sequentially.

### Solana BlockSource

```rust
pub struct SolanaBlockSource {
    program_id: Pubkey,
    rpc_client: RpcClient,
    rpc_http_url: String,
    rpc_ws_url: String,
    live_rx: Option<mpsc::Receiver<(u64, EncodedConfirmedBlock)>>,
}

#[async_trait]
impl BlockSource for SolanaBlockSource {
    type Block = (u64, EncodedConfirmedBlock);
    const CHAIN: Chain = Chain::Solana;
    
    async fn initialize(&mut self) -> anyhow::Result<u64> {
        let (live_tx, live_rx) = mpsc::channel(1024);
        self.live_rx = Some(live_rx);
        
        let (anchor_tx, anchor_rx) = oneshot::channel::<u64>();
        
        tokio::spawn(subscribe_and_buffer_live_events(
            self.program_id,
            self.rpc_http_url.clone(),
            self.rpc_ws_url.clone(),
            live_tx,
            anchor_tx,
        ));
        
        Ok(anchor_rx.await?)
    }
    
    async fn fetch_block(&self, height: u64) -> anyhow::Result<Option<Self::Block>> {
        match self.rpc_client.get_block(height).await {
            Ok(block) => Ok(Some((height, block))),
            Err(_) => Ok(None),
        }
    }
    
    async fn fetch_range(
        &mut self,
        start: u64,
        end: u64,
    ) -> anyhow::Result<Vec<Self::Block>> {
        // Use optimized signature-based fetching
        let signatures = self.rpc_client
            .get_signatures_for_address_with_config(
                &self.program_id,
                GetConfirmedSignaturesForAddress2Config {
                    before: None,
                    until: None,
                    limit: Some(1000),
                    commitment: Some(CommitmentConfig::confirmed()),
                },
            )
            .await?;
        
        let slots: BTreeSet<u64> = signatures
            .iter()
            .filter(|sig| sig.slot >= start && sig.slot < end)
            .map(|sig| sig.slot)
            .collect();
        
        self.fetch_blocks_for_slots(slots).await
    }
    
    async fn next_live_block(&mut self) -> Option<Self::Block> {
        self.live_rx.as_mut()?.recv().await
    }
    
    fn block_height(&self, block: &Self::Block) -> u64 {
        block.0
    }
}
```

## Migration Strategy

### Phase 1: Introduce New Abstractions (No Breaking Changes)

1. Add `BlockSource` and `BlockParser` traits alongside existing code
2. Implement new `ChainIndexer<S, P>` coordinator
3. Keep existing `ChainIndexer` trait (rename to `LegacyChainIndexer`)

### Phase 2: Implement One Chain (Ethereum)

1. Create `EthereumBlockSource` and `EthereumBlockParser`
2. Wire up new `ChainIndexer<EthereumBlockSource, EthereumBlockParser>`
3. Run in parallel with existing implementation
4. Validate identical behavior via integration tests

### Phase 3: Migrate Remaining Chains

1. Implement Solana: `SolanaBlockSource` + `SolanaBlockParser`
2. Implement Canton: `CantonBlockSource` + `CantonBlockParser`
3. Switch all chains to new implementation
4. Remove `LegacyChainIndexer` trait and old implementations

### Phase 4: Cleanup

1. Remove duplicated catchup logic from old implementations
2. Consolidate retry/reconnect patterns
3. Update tests to use new abstractions

## Benefits

### Code Reduction

- **Eliminate**: Per-chain catchup coordination (~100 lines × 3 chains)
- **Eliminate**: Duplicate event processing (~50 lines × 3 chains)
- **Eliminate**: Retry logic duplication (~30 lines × 3 chains)
- **Consolidate**: Event channel setup (single implementation)

**Estimated**: ~500 lines removed, ~300 lines added = **200 line reduction**

### Maintainability

- **New Chain**: Implement 2 small traits vs 1 large trait + custom catchup
- **Testing**: Test `BlockSource` and `BlockParser` independently
- **Debugging**: Clear separation of concerns (fetch vs parse vs coordinate)

### Type Safety

- No more forcing Canton offsets into block abstraction
- No more `MaybeBlock` workarounds
- Each chain uses natural representation

### Flexibility

- Easy to add batched fetching (Ethereum already does this)
- Easy to add caching layer (wrap `BlockSource`)
- Easy to add metrics (wrap `BlockParser`)
- Easy to test (mock `BlockSource` or `BlockParser`)

## Open Questions

1. **Canton Sequential Access**: Should we special-case Canton's sequential-only access or make `fetch_range` the primary interface?
   - **Recommendation**: Add `fetch_range` as optional optimization, Canton overrides it

2. **Retry Policy**: Should retry be configurable per chain or unified?
   - **Recommendation**: Unified with sensible defaults, override via `BlockSource` if needed

3. **Backlog Access**: Should `BlockParser` have access to backlog for stateful parsing?
   - **Recommendation**: Yes, pass in constructor. Needed for execution event correlation.

4. **Event Batching**: Should `parse_block` return `Vec<ChainEvent>` or emit via channel?
   - **Recommendation**: Return `Vec` for testability, coordinator handles emission

5. **Error Handling**: Should parse errors skip block or fail entire indexer?
   - **Recommendation**: Fail and retry. Parse errors indicate serious issues.

## Testing Strategy

### Unit Tests

- `BlockSource::fetch_block` with mocked RPC
- `BlockParser::parse_block` with fixture blocks
- `ChainIndexer` catchup logic with mock source/parser

### Integration Tests

- Full indexer with real chain data (recorded)
- Catchup from various checkpoints
- Live streaming with simulated blocks
- Error recovery (network failures, missing blocks)

### Property Tests

- Catchup always processes blocks in order
- No blocks skipped between start and end
- All events from block emitted before next block

## Success Criteria

1. ✅ All three chains migrated to new abstractions
2. ✅ No behavioral changes (same events emitted)
3. ✅ Net reduction in code (>150 lines)
4. ✅ Improved test coverage (>80% for new code)
5. ✅ No performance regression (<5% overhead)
6. ✅ Documentation updated (architecture docs, examples)

## Timeline Estimate

- **Phase 1** (New abstractions): 2 days
- **Phase 2** (Ethereum migration): 3 days
- **Phase 3** (Solana + Canton): 4 days
- **Phase 4** (Cleanup + docs): 2 days

**Total**: ~2 weeks (10 working days)

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Behavioral differences in new implementation | High | Run both implementations in parallel, compare events |
| Canton sequential access doesn't fit model | Medium | Add `fetch_range` method, special-case if needed |
| Performance regression from abstraction overhead | Low | Benchmark before/after, optimize hot paths |
| Integration test failures during migration | Medium | Migrate one chain at a time, validate thoroughly |

## Conclusion

Redesign separates concerns:
- **BlockSource**: Chain-specific fetching/streaming
- **BlockParser**: Chain-specific event extraction  
- **ChainIndexer**: Generic coordination (catchup, retry, emit)

Result: Less duplication, clearer interfaces, easier maintenance, better testability.
