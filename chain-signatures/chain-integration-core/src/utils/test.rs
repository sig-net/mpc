use std::collections::VecDeque;
use std::time::Duration;

use anyhow::Context as _;
use cait_sith::FullSignature;
use k256::{AffinePoint, Secp256k1};
use mpc_crypto::kdf::derive_secret_key;
use mpc_primitives::{Chain, ChainEvent, IndexedSignRequest, SignArgs, SignId, SignKind};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use super::stream::chain_event_channel;
use crate::{ChainIndexer, PublishAction};

pub fn scalar(bytes: &[u8; 32]) -> k256::Scalar {
    use k256::elliptic_curve::ops::Reduce;
    <k256::Scalar as Reduce<<Secp256k1 as k256::elliptic_curve::Curve>::Uint>>::reduce_bytes(
        bytes.into(),
    )
}

pub fn make_signature(
    sk: &k256::SecretKey,
    epsilon: k256::Scalar,
    payload: k256::Scalar,
) -> FullSignature<Secp256k1> {
    use k256::elliptic_curve::point::DecompressPoint;
    let signing_key = k256::ecdsa::SigningKey::from(&derive_secret_key(sk, epsilon));
    let (ecdsa_sig, _): (k256::ecdsa::Signature, _) =
        <k256::ecdsa::SigningKey as k256::ecdsa::signature::hazmat::PrehashSigner<_>>::sign_prehash(
            &signing_key,
            &payload.to_bytes(),
        )
        .expect("signing should succeed");
    let (r_bytes, _) = ecdsa_sig.split_bytes();
    let big_r =
        AffinePoint::decompress(&r_bytes, k256::elliptic_curve::subtle::Choice::from(0)).unwrap();
    FullSignature {
        big_r,
        s: *ecdsa_sig.s().as_ref(),
    }
}

pub fn make_indexed(
    chain: Chain,
    epsilon: k256::Scalar,
    payload: k256::Scalar,
    kind: SignKind,
    sign_id: SignId,
) -> IndexedSignRequest {
    IndexedSignRequest {
        id: sign_id,
        args: SignArgs {
            entropy: [0u8; 32],
            epsilon,
            payload,
            path: "test".into(),
            key_version: 0,
        },
        chain,
        unix_timestamp_indexed: 0,
        kind,
    }
}

/// Build a `PublishAction` with fixed epsilon/payload; see [`make_publish_action_for`].
pub fn make_publish_action(chain: Chain, kind: SignKind, sign_id: SignId) -> PublishAction {
    make_publish_action_for(
        chain,
        kind,
        sign_id,
        scalar(&[1u8; 32]),
        scalar(&[42u8; 32]),
    )
}

/// Build a `PublishAction` targeting an arbitrary `sign_id`
/// with provided epsilon/payload and a generated signing key.
pub fn make_publish_action_for(
    chain: Chain,
    kind: SignKind,
    sign_id: SignId,
    epsilon: k256::Scalar,
    payload: k256::Scalar,
) -> PublishAction {
    let sk = k256::SecretKey::random(&mut rand::thread_rng());
    let pk: AffinePoint = sk.public_key().into();
    let output = make_signature(&sk, epsilon, payload);
    let request = make_indexed(chain, epsilon, payload, kind, sign_id);
    PublishAction::new(pk, request, output, vec![])
        .expect("valid signature should produce a publish action")
}

pub struct ChainIndexerStream {
    events_rx: mpsc::Receiver<ChainEvent>,
    pending: VecDeque<ChainEvent>,
    cancel: CancellationToken,
    run_task: JoinHandle<anyhow::Result<()>>,
}

impl ChainIndexerStream {
    pub async fn start(
        indexer: impl ChainIndexer,
        catchup_timeout: Duration,
    ) -> anyhow::Result<Self> {
        let (events_tx, mut events_rx) = chain_event_channel();
        let cancel = CancellationToken::new();
        let run_task = tokio::spawn({
            let cancel = cancel.clone();
            async move { indexer.run(events_tx, cancel).await }
        });

        let mut pending = VecDeque::new();
        timeout(catchup_timeout, async {
            loop {
                match events_rx.recv().await {
                    Some(ChainEvent::CatchupCompleted) => return Ok(()),
                    Some(event) => pending.push_back(event),
                    None => anyhow::bail!("indexer run() exited before completing catchup"),
                }
            }
        })
        .await
        .context("timed out waiting for indexer to complete catchup")??;

        Ok(Self {
            events_rx,
            pending,
            cancel,
            run_task,
        })
    }

    /// Next event, replaying buffered pre-catchup events first.
    pub async fn next_event(&mut self) -> Option<ChainEvent> {
        if let Some(event) = self.pending.pop_front() {
            return Some(event);
        }
        self.events_rx.recv().await
    }

    /// Next event within `duration`, failing on timeout.
    pub async fn next_event_within(&mut self, duration: Duration) -> anyhow::Result<ChainEvent> {
        timeout(duration, async {
            loop {
                if let Some(event) = self.next_event().await {
                    return event;
                }
            }
        })
        .await
        .context("timed out waiting for chain event")
    }

    /// First event matching `predicate` within `duration`.
    pub async fn wait_for(
        &mut self,
        predicate: impl Fn(&ChainEvent) -> bool,
        duration: Duration,
    ) -> anyhow::Result<ChainEvent> {
        timeout(duration, async {
            loop {
                match self.next_event().await {
                    Some(event) if predicate(&event) => return Ok(event),
                    Some(_) => continue,
                    None => anyhow::bail!("chain event stream closed while waiting for a match"),
                }
            }
        })
        .await
        .context("timed out waiting for a matching chain event")?
    }

    /// Assert no event arrives within `duration`.
    pub async fn expect_none_within(&mut self, duration: Duration) -> anyhow::Result<()> {
        match timeout(duration, self.next_event()).await {
            Ok(Some(event)) => {
                anyhow::bail!("expected no event within {duration:?}, but received {event:?}")
            }
            Ok(None) | Err(_) => Ok(()),
        }
    }
}

impl Drop for ChainIndexerStream {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.run_task.abort();
    }
}
