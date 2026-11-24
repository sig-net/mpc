//! Build identity, fixed at compile time. `GIT_COMMIT_HASH` and
//! `BUILD_TIMESTAMP` are set by the image build; local builds get `unknown`.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const GIT_COMMIT_HASH: &str = match option_env!("GIT_COMMIT_HASH") {
    Some(hash) => hash,
    None => "unknown",
};

pub const BUILD_TIMESTAMP: &str = match option_env!("BUILD_TIMESTAMP") {
    Some(timestamp) => timestamp,
    None => "unknown",
};

/// `<version> (<commit>)`, as printed by `--version`.
pub fn version_with_commit() -> &'static str {
    static VERSION_WITH_COMMIT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION_WITH_COMMIT.get_or_init(|| format!("{VERSION} ({GIT_COMMIT_HASH})"))
}
