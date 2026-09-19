// HACK: required for env!(OUT_DIR) to work
fn main() {
    // This script has no inputs; avoid scanning the runtime fixtures and their dependencies.
    println!("cargo:rerun-if-changed=build.rs");
}
