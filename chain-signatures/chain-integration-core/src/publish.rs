use std::sync::Arc;
use std::time::Instant;

use crate::utils::retry::{run_gated, SharedBackoff};

use cait_sith::protocol::Participant;
use mpc_primitives::{IndexedSignRequest, Signature};

/// Trait for publishing signatures to different blockchains (single attempt, caller handles retries).
#[async_trait::async_trait]
pub trait ChainPublisher: Send + Sync + 'static {
    /// Publishes a signature, resolving only once the response is on chain or
    /// the attempt fails. The caller's retry loop owns liveness retries and
    /// duplicate suppression.
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()>;
}

/// [`ChainPublisher`] adapter that owns a chain's shared cooldown gate for
/// publishers without internal gating: each attempt waits out the gate, a
/// throttled error (429/402) extends the window for everyone sharing it, and a
/// successful publish resets the penalty. `operation` labels the throttle
/// warn (e.g. "hydration publish") so shared-gate events stay attributable
/// per chain. Single-attempt like the inner publisher — the caller's retry
/// loop still owns retries.
///
/// TODO: transitional - deleted once every client gates its publishes
/// internally.
pub struct GatedPublisher<P> {
    inner: P,
    gate: SharedBackoff,
    operation: &'static str,
}

impl<P: ChainPublisher> GatedPublisher<P> {
    pub fn new(inner: P, gate: SharedBackoff, operation: &'static str) -> Self {
        Self {
            inner,
            gate,
            operation,
        }
    }
}

#[async_trait::async_trait]
impl<P: ChainPublisher> ChainPublisher for GatedPublisher<P> {
    async fn publish_signature(&self, action: &PublishAction) -> anyhow::Result<()> {
        run_gated(
            &self.gate,
            self.operation,
            self.inner.publish_signature(action),
        )
        .await
    }
}

/// Represents a signature that is ready to be published to a blockchain.
#[derive(Clone)]
pub struct PublishAction {
    /// The indexed sign request that this signature corresponds to.
    pub request: Arc<IndexedSignRequest>,
    /// The actual signature to be published.
    pub signature: Signature,
    /// The participants involved in the signing process.
    pub participants: Vec<Participant>,
    /// The timestamp when the publish action was created.
    pub timestamp: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test::make_publish_action;
    use mpc_primitives::{Chain, SignId, SignKind};
    use std::time::Duration;

    struct OkPublisher;

    #[async_trait::async_trait]
    impl ChainPublisher for OkPublisher {
        async fn publish_signature(&self, _action: &PublishAction) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct ThrottledPublisher;

    #[async_trait::async_trait]
    impl ChainPublisher for ThrottledPublisher {
        async fn publish_signature(&self, _action: &PublishAction) -> anyhow::Result<()> {
            anyhow::bail!("HTTP 429 Too Many Requests")
        }
    }

    struct ServerErrorPublisher;

    #[async_trait::async_trait]
    impl ChainPublisher for ServerErrorPublisher {
        async fn publish_signature(&self, _action: &PublishAction) -> anyhow::Result<()> {
            anyhow::bail!("HTTP 500 Internal Server Error")
        }
    }

    fn gate_with(base_ms: u64) -> SharedBackoff {
        SharedBackoff::with_cooldowns(
            Duration::from_millis(base_ms),
            Duration::from_millis(base_ms * 2),
        )
    }

    fn action() -> PublishAction {
        make_publish_action(Chain::Hydration, SignKind::Sign, SignId::new([0u8; 32]))
    }

    #[tokio::test]
    async fn gated_publisher_waits_out_an_engaged_gate() {
        let gate = gate_with(300);
        gate.extend_cooldown();
        let gated = GatedPublisher::new(OkPublisher, gate, "publish");

        let start = std::time::Instant::now();
        gated.publish_signature(&action()).await.unwrap();

        // the attempt must not fire before the pre-engaged window closes
        assert!(
            start.elapsed() >= Duration::from_millis(250),
            "gated publish must wait out the engaged cooldown, took {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn gated_publisher_extends_the_gate_on_throttled_errors() {
        let gate = gate_with(300);
        let gated = GatedPublisher::new(ThrottledPublisher, gate.clone(), "publish");

        assert!(gated.publish_signature(&action()).await.is_err());

        // the 429-flavored error must have opened the window: a shared
        // holder (e.g. the indexer) now waits before its next call
        let start = std::time::Instant::now();
        gate.wait().await;
        assert!(
            start.elapsed() >= Duration::from_millis(250),
            "the throttled error must engage the shared cooldown, took {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn gated_publisher_does_not_engage_the_gate_on_other_errors() {
        let gate = gate_with(300);
        let gated = GatedPublisher::new(ServerErrorPublisher, gate.clone(), "publish");

        assert!(gated.publish_signature(&action()).await.is_err());

        assert_eq!(
            gate.remaining(),
            Duration::ZERO,
            "a non-throttle error must not engage the cooldown"
        );
    }

    #[tokio::test]
    async fn gated_publisher_resets_escalation_on_success() {
        let gate = gate_with(300);
        let base = gate.extend_cooldown();
        let escalated = gate.extend_cooldown();
        assert!(escalated > base, "second engage must escalate");

        let gated = GatedPublisher::new(OkPublisher, gate.clone(), "publish");
        gated.publish_signature(&action()).await.unwrap();

        // a successful publish drops the penalty back to the base cooldown
        assert_eq!(
            gate.extend_cooldown(),
            base,
            "success must reset the escalation level"
        );
    }
}
