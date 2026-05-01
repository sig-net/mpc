use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let redis_toml_path = Path::new(manifest_dir)
        .parent()
        .unwrap()
        .join("store")
        .join("redis.toml");

    // Read the redis.toml file
    let content = fs::read_to_string(&redis_toml_path).expect("Failed to read redis.toml");

    // Parse the TOML content
    let toml: toml::Value = content.parse().expect("Failed to parse redis.toml as TOML");

    // Extract storage_version
    let storage_version = toml
        .get("storage_version")
        .and_then(|v| v.as_str())
        .expect("redis.toml is missing 'storage_version' field");

    // Extract checkpoint_version
    let checkpoint_version = toml
        .get("checkpoint_version")
        .and_then(|v| v.as_str())
        .expect("redis.toml is missing 'checkpoint_version' field");

    // Emit environment variables
    println!("cargo:rustc-env=MPC_STORAGE_VERSION={}", storage_version);
    println!(
        "cargo:rustc-env=MPC_CHECKPOINT_VERSION={}",
        checkpoint_version
    );

    // Rerun build script if redis.toml changes
    println!("cargo:rerun-if-changed={}", redis_toml_path.display());
}
