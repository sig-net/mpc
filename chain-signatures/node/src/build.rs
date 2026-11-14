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

/// Whether this binary was built with `test-feature`. Such a build has
/// test-only parameters and runs test cadences, and must not be deployed.
pub const TEST_BUILD: bool = cfg!(feature = "test-feature");

/// `<version> (<commit>)`, as printed by `--version`. A test build appends
/// ` test-feature`.
pub fn version_with_commit() -> &'static str {
    static VERSION_WITH_COMMIT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION_WITH_COMMIT.get_or_init(|| {
        let marker = if TEST_BUILD { " test-feature" } else { "" };
        format!("{VERSION} ({GIT_COMMIT_HASH}){marker}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a build with `test-feature` is marked.
    #[test]
    fn only_a_test_build_is_marked() {
        assert_eq!(
            version_with_commit().ends_with(" test-feature"),
            cfg!(feature = "test-feature")
        );
    }
}
