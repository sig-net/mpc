use std::fs;
use std::path::Path;

fn rerun_directory<T: AsRef<Path> + ?Sized>(dir: &T) {
    println!("cargo:rerun-if-changed={}", dir.as_ref().to_str().unwrap());

    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.expect("cannot access file in src directory");
        let path = entry.path();
        if path.is_dir() {
            // only look at directories for timestamps
            rerun_directory(&path);
        }
    }
}

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    rerun_directory("../../chain-signatures/");

    let release = true;
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let contract_task = tokio::task::spawn(forge::build_contract(release));
        let node_task = tokio::task::spawn(forge::build_node(release));
        let (contract, node) = tokio::try_join!(contract_task, node_task)?;
        match (contract, node) {
            (Ok(contract), Ok(node)) => {
                let mut msg = String::new();
                if !contract.success() {
                    msg.push_str(&format!("failed to build contract {contract:?}"));
                }
                if !node.success() {
                    msg.push_str(&format!("failed to build node {node:?}"));
                }
                if !msg.is_empty() {
                    anyhow::bail!(msg);
                }
            }
            (Err(e), _) => anyhow::bail!("failed to build contract: {e}"),
            (_, Err(e)) => anyhow::bail!("failed to build node: {e}"),
        }

        Ok(())
    })
}
