// Re-export the lightweight testing harness from `integration-tests` so we don't
// duplicate code during migration. Over time component-tests can grow its own
// fixtures if needed, but for now it depends on integration-tests for the core
// helpers.

pub use integration_tests::mpc_env;
pub use integration_tests::mpc_fixture;

// Place to add component-focused tests that do NOT require building contracts
// or the mpc-node binary. These tests will run with the cargo package name
// `component-tests` which allows setup.sh to skip heavy prebuild steps.

#[cfg(test)]
mod smoke {
    use super::mpc_env::MpcEnvBuilder;

    /// Quick sanity check that the builder compiles and the crate is wired
    /// correctly. This does NOT spin up the full MPC network (that would take
    /// ~40s). For actual protocol tests, see the tests migrated from
    /// integration-tests.
    #[test]
    fn builder_compiles() {
        let builder = MpcEnvBuilder::new(3, 2);
        assert_eq!(builder.config.nodes, 3);
        assert_eq!(builder.config.threshold, 2);
    }
}
