//! Build script for compiling Tron protobuf definitions.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto");
    let fds = protox::compile(
        [
            "proto/core/Tron.proto",
            "proto/core/contract/smart_contract.proto",
        ],
        ["proto"],
    )?;
    prost_build::Config::new().compile_fds(fds)?;
    Ok(())
}
