use std::path::{Path, PathBuf};

pub use mpc_primitives::SANDBOX_VERSION;

pub fn contract_file_path() -> PathBuf {
    let workspace_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let target_dir = if let Some(target_dir) = std::env::var_os("CARGO_TARGET_DIR") {
        let target_dir = PathBuf::from(target_dir);
        if Path::new(&target_dir).is_absolute() {
            target_dir
        } else {
            workspace_dir.join(target_dir)
        }
    } else {
        workspace_dir.join("target")
    };
    target_dir.join("wasm32-unknown-unknown/release/mpc_contract.wasm")
}
