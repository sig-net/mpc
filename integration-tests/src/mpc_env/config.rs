/// Configuration flags for MpcEnv
#[derive(Debug, Clone)]
pub struct MpcEnvConfig {
    /// whether to spawn real external nodes (processes / docker)
    pub enable_real_nodes: bool,

    /// whether to use a real NEAR sandbox (if false, tests may use mocked governance)
    pub enable_near_sandbox: bool,

    /// number of nodes in the environment
    pub nodes: usize,
    /// signing threshold
    pub threshold: usize,
    // fixture-related options
    pub use_preshared_triples: bool,
    pub use_preshared_key: bool,
    pub presignature_stockpile: bool,

    pub min_triples: u32,
    pub max_triples: u32,
    pub min_presignatures: u32,
    pub max_presignatures: u32,

    pub signature_timeout_ms: u64,
    pub presignature_timeout_ms: u64,
    pub triple_timeout_ms: u64,
    // message_filters are intentionally kept out of the serializable/clonable
    // config structure because filters contain boxed closures which are not
    // Clone or Debug.
}

impl Default for MpcEnvConfig {
    fn default() -> Self {
        Self {
            enable_real_nodes: false,
            enable_near_sandbox: false,
            nodes: 3,
            threshold: 2,
            use_preshared_triples: false,
            use_preshared_key: false,
            presignature_stockpile: false,

            min_triples: 10,
            max_triples: 30,
            min_presignatures: 10,
            max_presignatures: 30,

            signature_timeout_ms: 10_000,
            presignature_timeout_ms: 10_000,
            triple_timeout_ms: mpc_contract::config::min_to_ms(10),
        }
    }
}
