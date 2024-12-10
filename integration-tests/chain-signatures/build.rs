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
        mpc_forge::build_node(release).await?;
        mpc_forge::build_contract(release).await?;

        Ok(())
    })
}
