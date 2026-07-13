use mpc_primitives::Checkpoint;
use borsh::BorshDeserialize;
use std::fs;

fn main() {
    for i in 0..12 {
        let path = format!("../../tmp/node-{}.checkpoint", i);
        if let Ok(data) = fs::read(&path) {
            match Checkpoint::try_from_slice(&data) {
                Ok(cp) => println!("Node {}: Chain {:?}, Height {}", i, cp.chain, cp.block_height),
                Err(_) => {
                    // try rmp_serde
                    if let Ok(cp) = rmp_serde::from_slice::<Checkpoint>(&data) {
                        println!("Node {} (msgpack): Chain {:?}, Height {}", i, cp.chain, cp.block_height);
                    } else {
                        println!("Node {}: Failed to parse", i);
                    }
                }
            }
        }
    }
}
