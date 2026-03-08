use std::time::Duration;

use cait_sith::protocol::Participant;
use mpc_node::protocol::sync::SyncUpdate;
use test_log::test;

/// Test to measure the actual payload sizes we're dealing with
#[test(tokio::test)]
async fn test_measure_payload_sizes() -> anyhow::Result<()> {
    println!("Measuring payload sizes for different dataset sizes...");
    
    for size in [100, 1_000, 5_000, 10_000, 25_000, 50_000] {
        let triples: Vec<u64> = (0..size).collect();
        let presignatures: Vec<u64> = (0..size).collect();
        
        let update = SyncUpdate {
            from: Participant::from(1),
            triples,
            presignatures,
        };
        
        // Measure JSON serialization (used for debugging)
        let json_size = serde_json::to_vec(&update)?.len();
        
        // Measure CBOR serialization (used in actual sync)
        let mut cbor_data = Vec::new();
        ciborium::into_writer(&update, &mut cbor_data)?;
        let cbor_size = cbor_data.len();
        
        println!("Size {}: JSON {} bytes ({:.2} MB), CBOR {} bytes ({:.2} MB)", 
                 size, 
                 json_size, json_size as f64 / (1024.0 * 1024.0),
                 cbor_size, cbor_size as f64 / (1024.0 * 1024.0));
                 
        // Check if we exceed common limits
        if cbor_size > 1024 * 1024 {
            println!("  ⚠️  Exceeds 1MB limit!");
        }
        if cbor_size > 20 * 1024 * 1024 {
            println!("  ❌ Exceeds current 20MB limit!");
        }
    }
    
    Ok(())
}

/// Test that demonstrates the potential for large payloads to cause issues
#[test(tokio::test)]
async fn test_sync_large_payload_size_demo() -> anyhow::Result<()> {
    // Demonstrate the issue with a large dataset
    const LARGE_DATASET_SIZE: usize = 100_000; // 100K IDs
    
    let triples: Vec<u64> = (0..LARGE_DATASET_SIZE).map(|i| i as u64).collect();
    let presignatures: Vec<u64> = (0..LARGE_DATASET_SIZE).map(|i| i as u64).collect();
    
    let large_update = SyncUpdate {
        from: Participant::from(1),
        triples,
        presignatures,
    };
    
    println!("Testing serialization of {} triple and presignature IDs each", LARGE_DATASET_SIZE);
    
    // Try to serialize the update to see the payload size
    let start = std::time::Instant::now();
    let json_result = serde_json::to_vec(&large_update);
    let json_elapsed = start.elapsed();
    
    match json_result {
        Ok(data) => {
            println!("JSON serialization successful:");
            println!("  Size: {} bytes ({:.2} MB)", data.len(), data.len() as f64 / (1024.0 * 1024.0));
            println!("  Time: {:?}", json_elapsed);
        }
        Err(e) => {
            println!("JSON serialization failed: {}", e);
        }
    }
    
    // Try CBOR serialization
    let start = std::time::Instant::now();
    let mut cbor_data = Vec::new();
    let cbor_result = ciborium::into_writer(&large_update, &mut cbor_data);
    let cbor_elapsed = start.elapsed();
    
    match cbor_result {
        Ok(()) => {
            println!("CBOR serialization successful:");
            println!("  Size: {} bytes ({:.2} MB)", cbor_data.len(), cbor_data.len() as f64 / (1024.0 * 1024.0));
            println!("  Time: {:?}", cbor_elapsed);
            
            if cbor_data.len() > 20 * 1024 * 1024 {
                println!("  ❌ Exceeds 20MB HTTP limit!");
                return Err(anyhow::anyhow!("Payload exceeds 20MB limit"));
            }
        }
        Err(e) => {
            println!("CBOR serialization failed: {}", e);
            return Err(e.into());
        }
    }
    
    println!("This demonstrates that very large sync payloads can be problematic");
    
    Ok(())
}