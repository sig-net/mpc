/// Abstraction for nodes inside MpcEnv.
pub trait MpcEnvNode: Send + Sync {
    /// Participant index or id representation
    fn id(&self) -> usize;

    /// URL for the node web interface if applicable
    fn url(&self) -> Option<&str> {
        None
    }
}

/// In-process node (used by the fixture). Wrapper / placeholder for now.
pub struct InProcessNode {
    pub id: usize,
}

impl MpcEnvNode for InProcessNode {
    fn id(&self) -> usize {
        self.id
    }
}

/// External node (container or local process) placeholder.
pub struct ExternalNode {
    pub id: usize,
    pub address: String,
}

impl MpcEnvNode for ExternalNode {
    fn id(&self) -> usize {
        self.id
    }

    fn url(&self) -> Option<&str> {
        Some(&self.address)
    }
}
