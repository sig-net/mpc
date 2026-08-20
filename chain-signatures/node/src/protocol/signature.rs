//! Signature generation: runs the cait-sith signing protocol once a posit round agrees on a presignature and participant set.

use crate::backlog::Backlog;
use crate::protocol::message::{MessageChannel, SignatureMessage};
use crate::protocol::presignature::PresignatureId;
use crate::rpc::{GovernanceInfo, RpcChannel};
use crate::sign_bidirectional::PublishState;
use crate::storage::presignature_storage::{PresignatureTaken, PresignatureTakenDropper};
use crate::storage::PresignatureStorage;
use crate::types::SignatureProtocol;
use mpc_chain_near::AffinePointExt as _;

use cait_sith::protocol::{Action, InitializationError, Participant};
use cait_sith::PresignOutput;
use chrono::Utc;
use k256::Secp256k1;
use mpc_contract::config::ProtocolConfig;
use mpc_crypto::derive_key;
use mpc_primitives::IndexedSignRequest;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Outcome of a signature task. Produced here on a protocol/abort error, and by
/// the `request` layer when organizing cannot proceed.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SignError {
    Aborted,
}

pub(crate) struct GenerateCtx {
    pub governance: GovernanceInfo,
    pub msg: MessageChannel,
    /// Publishes the finished signature (proposer only).
    pub rpc: RpcChannel,
    /// Marks the request as publishing once a signature is produced.
    pub backlog: Backlog,
    pub cfg: ProtocolConfig,
    /// Only used to label the debug page.
    #[cfg_attr(not(feature = "debug-page"), allow(dead_code))]
    pub node_account_id: near_account_id::AccountId,
}

/// An ongoing signature generator.
pub(crate) struct SignGenerator {
    protocol: SignatureProtocol,
    /// On drop, clears this (already consumed) presignature's in-memory `using`
    /// reservation. Does not return it to the pool — commit already removed it.
    dropper: PresignatureTakenDropper,
    participants: Vec<Participant>,
    /// Node that proposed this round (determines who publishes).
    proposer: Participant,
    request: Arc<IndexedSignRequest>,
    /// Start time, for the generation timeout and latency metrics.
    created: Instant,
    timeout: Duration,
    inbox: mpsc::Receiver<SignatureMessage>,
    /// Kept so `Drop` can unsubscribe and clear buffered messages.
    msg: MessageChannel,

    #[cfg(feature = "debug-page")]
    debug_view: crate::web::debug::DebugPageTaskHandle,
}

impl SignGenerator {
    /// Fetch the committed presignature, apply the delta, and build the cait-sith signing protocol.
    pub(crate) async fn new(
        ctx: &GenerateCtx,
        proposer: Participant,
        request: Arc<IndexedSignRequest>,
        presignature: PendingPresignature,
        participants: Vec<Participant>,
    ) -> Result<Self, InitializationError> {
        let presignature_id = presignature.id();
        let taken = presignature
            .fetch(Duration::from_millis(ctx.cfg.signature.generation_timeout))
            .await
            .ok_or_else(|| {
                InitializationError::BadParameters(format!(
                    "presignature {presignature_id} not found or timeout",
                ))
            })?;

        let sign_id = request.id;
        tracing::info!(
            me = ?ctx.governance.me,
            ?sign_id,
            ?presignature_id,
            "starting protocol to generate a new signature",
        );

        let (presignature, dropper) = taken.take();
        let PresignOutput { big_r, k, sigma } = presignature.output;
        let delta =
            mpc_crypto::kdf::derive_delta(request.id.request_id, request.args.entropy, big_r);
        // TODO: Check whether it is okay to use invert_vartime instead
        let output: PresignOutput<Secp256k1> = PresignOutput {
            big_r: (big_r * delta).to_affine(),
            k: k * delta.invert().unwrap(),
            sigma: (sigma + request.args.epsilon * k) * delta.invert().unwrap(),
        };
        let protocol = Box::new(cait_sith::sign(
            &participants,
            ctx.governance.me,
            derive_key(ctx.governance.public_key, request.args.epsilon),
            output,
            request.args.payload,
        )?);
        let inbox = ctx.msg.subscribe_signature(sign_id, presignature_id).await;
        Ok(Self {
            protocol,
            dropper,
            participants,
            proposer,
            request,
            created: Instant::now(),
            timeout: Duration::from_millis(ctx.cfg.signature.generation_timeout),
            inbox,
            msg: ctx.msg.clone(),
            #[cfg(feature = "debug-page")]
            debug_view: crate::web::debug::register_task(
                ctx.node_account_id.to_string(),
                format!("SignatureGenerator {sign_id:#?}"),
            ),
        })
    }

    /// Participants (excluding those in `seen`) we are still waiting on: the peers
    /// an abort is blocked behind. `seen` holds everyone we have already heard from.
    fn awaited(&self, seen: &[Participant]) -> Vec<Participant> {
        awaited_peers(&self.participants, seen)
    }

    /// Receive the next protocol message, erroring out on timeout. `seen` lists the
    /// participants already heard from, so an abort log can name who it waits on.
    async fn recv(&mut self, seen: &[Participant]) -> Result<SignatureMessage, SignError> {
        let sign_id = self.request.id;
        let presignature_id = self.dropper.id;
        match tokio::time::timeout(
            self.timeout.saturating_sub(self.created.elapsed()),
            self.inbox.recv(),
        )
        .await
        {
            Ok(Some(msg)) => Ok(msg),
            Ok(None) => {
                tracing::warn!(
                    ?sign_id,
                    ?presignature_id,
                    awaited = ?self.awaited(seen),
                    "signature generation aborted",
                );
                Err(SignError::Aborted)
            }
            Err(_err) => {
                tracing::warn!(
                    ?sign_id,
                    ?presignature_id,
                    awaited = ?self.awaited(seen),
                    "signature generation timeout",
                );
                Err(SignError::Aborted)
            }
        }
    }

    /// Poke-drive the protocol to completion: relay messages, and on `Return`
    /// publish the signature (proposer) and mark the request publishing.
    pub(crate) async fn run(mut self, ctx: &GenerateCtx) -> Result<(), SignError> {
        let me = ctx.governance.me;
        let epoch = ctx.governance.epoch;

        let sign_id = self.request.id;
        let presignature_id = self.dropper.id;

        let mut total_wait = Duration::from_millis(0);
        let mut total_pokes = 0;
        let mut poke_last_time = self.created;
        // Participants we have received a message from this instance, seeded with
        // `me` since we never wait on ourselves. Drives the awaited-peer abort logs.
        let mut seen: Vec<Participant> = vec![me];
        crate::metrics::protocols::SIGNATURE_BEFORE_POKE_DELAY
            .observe(self.created.elapsed().as_millis() as f64);

        loop {
            let poke_start_time = Instant::now();
            let action = match self.protocol.poke() {
                Ok(action) => action,
                Err(err) => {
                    crate::metrics::protocols::SIGNATURE_GENERATOR_FAILURES.inc();
                    if self.proposer == me {
                        crate::metrics::protocols::SIGNATURE_GENERATOR_MINE_FAILURES.inc();
                    }
                    tracing::error!(
                        ?sign_id,
                        ?err,
                        awaited = ?self.awaited(&seen),
                        "signature generation failed on protocol advancement",
                    );
                    break Err(SignError::Aborted);
                }
            };

            total_wait += poke_start_time - poke_last_time;
            total_pokes += 1;
            poke_last_time = Instant::now();
            crate::metrics::protocols::SIGNATURE_POKE_CPU_TIME
                .observe(poke_start_time.elapsed().as_millis() as f64);
            #[cfg(feature = "debug-page")]
            self.render_debug(total_pokes);

            match action {
                Action::Wait => {
                    let msg = self.recv(&seen).await.inspect_err(|_| {
                        crate::metrics::protocols::SIGNATURE_GENERATOR_FAILURES.inc();
                        if self.proposer == me {
                            crate::metrics::protocols::SIGNATURE_GENERATOR_MINE_FAILURES.inc();
                        }
                    })?;
                    if !seen.contains(&msg.from) {
                        seen.push(msg.from);
                    }
                    self.protocol.message(msg.from, msg.data);
                }
                Action::SendMany(data) => {
                    for &to in self.participants.iter() {
                        if to == me {
                            continue;
                        }
                        ctx.msg
                            .send(
                                me,
                                to,
                                SignatureMessage {
                                    id: sign_id,
                                    proposer: self.proposer,
                                    presignature_id: self.dropper.id,
                                    epoch,
                                    from: me,
                                    data: data.clone(),
                                    timestamp: Utc::now().timestamp() as u64,
                                },
                            )
                            .await;
                    }
                }
                Action::SendPrivate(to, data) => {
                    ctx.msg
                        .send(
                            me,
                            to,
                            SignatureMessage {
                                id: sign_id,
                                proposer: self.proposer,
                                presignature_id,
                                epoch,
                                from: me,
                                data,
                                timestamp: Utc::now().timestamp() as u64,
                            },
                        )
                        .await;
                }
                Action::Return(output) => {
                    let big_r = output.big_r;
                    let s = output.s;
                    tracing::info!(
                        ?sign_id,
                        ?me,
                        ?presignature_id,
                        big_r = ?big_r.to_base58(),
                        ?s,
                        elapsed = ?self.created.elapsed(),
                        "completed signature generation"
                    );

                    crate::metrics::protocols::SIGNATURE_ACCRUED_WAIT_DELAY
                        .observe(total_wait.as_millis() as f64);
                    crate::metrics::protocols::SIGNATURE_POKES_CNT.observe(total_pokes as f64);
                    crate::metrics::protocols::SIGN_GENERATION_LATENCY
                        .observe(self.created.elapsed().as_secs_f64());
                    crate::metrics::protocols::SIGNATURE_GENERATOR_SUCCESS.inc();

                    let is_proposer = self.proposer == me;
                    if let Some(publish) = build_publish_state(
                        ctx.governance.public_key,
                        &self.request,
                        &output,
                        &self.participants,
                        is_proposer,
                    ) {
                        if let Err(err) = ctx
                            .backlog
                            .mark_publishing(self.request.chain, &sign_id, Arc::clone(&publish))
                            .await
                        {
                            tracing::warn!(
                                ?sign_id,
                                ?err,
                                "failed to mark publishing for sign request"
                            );
                        }
                    }

                    if is_proposer {
                        crate::metrics::protocols::SIGNATURE_GENERATOR_MINE_SUCCESS.inc();
                        ctx.rpc.publish(
                            ctx.governance.public_key,
                            Arc::clone(&self.request),
                            output,
                            self.participants.clone(),
                        );
                    }

                    break Ok(());
                }
            }
        }
    }

    #[cfg(feature = "debug-page")]
    fn render_debug(&self, total_pokes: i32) {
        let markup = maud::html! {
            p { (format!("{total_pokes} pokes")) }
        };
        self.debug_view.send(markup);
    }
}

/// Participants in `participants` not present in `seen`: the peers a stalled
/// instance is still waiting on. Preserves participant order; small n, linear scan.
fn awaited_peers(participants: &[Participant], seen: &[Participant]) -> Vec<Participant> {
    participants
        .iter()
        .copied()
        .filter(|p| !seen.contains(p))
        .collect()
}

/// Reconstruct the full signature into a [`PublishState`], or `None` if reconstruction fails.
fn build_publish_state(
    public_key: mpc_crypto::PublicKey,
    request: &IndexedSignRequest,
    output: &cait_sith::FullSignature<Secp256k1>,
    participants: &[Participant],
    is_proposer: bool,
) -> Option<Arc<PublishState>> {
    let expected_public_key = mpc_crypto::derive_key(public_key, request.args.epsilon);
    let signature = mpc_crypto::reconstruct_signature(
        &expected_public_key,
        &output.big_r,
        &output.s,
        request.args.payload,
    )
    .ok()?;
    let publish = PublishState {
        signature,
        participants: participants.to_vec(),
        is_proposer,
    };

    Some(Arc::new(publish))
}

impl Drop for SignGenerator {
    /// Unsubscribe and drop any buffered messages for this signature.
    fn drop(&mut self) {
        let msg = self.msg.clone();
        let sign_id = self.request.id;
        let presignature_id = self.dropper.id;
        tokio::spawn(async move {
            msg.unsubscribe_signature(sign_id, presignature_id).await;
            msg.filter_sign(sign_id, presignature_id).await;
        });
    }
}

/// A presignature the generator will consume: already taken in memory, or still in storage (fetched with a timeout once generation starts).
pub(crate) enum PendingPresignature {
    Available(Box<PresignatureTaken>),
    InStorage(PresignatureId, Participant, PresignatureStorage),
}

impl PendingPresignature {
    pub fn id(&self) -> PresignatureId {
        match self {
            PendingPresignature::Available(taken) => taken.artifact.id,
            PendingPresignature::InStorage(id, _, _) => *id,
        }
    }

    /// Resolve to the taken presignature, polling storage up to `timeout` if not already in memory.
    pub async fn fetch(self, timeout: Duration) -> Option<PresignatureTaken> {
        let (id, storage, owner) = match self {
            PendingPresignature::Available(taken) => return Some(*taken),
            PendingPresignature::InStorage(id, owner, storage) => (id, storage, owner),
        };

        let presignature = tokio::time::timeout(timeout, async {
            // TODO: we can make storage wait for presignature to be available instead of here
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            loop {
                interval.tick().await;
                if let Some(presignature) = storage.take(id, owner).await {
                    break presignature;
                };
            }
        })
        .await;

        match presignature {
            Ok(presignature) => Some(presignature),
            Err(_) => {
                tracing::warn!(
                    id,
                    ?timeout,
                    "timeout waiting for presignature to be available"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(i: u32) -> Participant {
        Participant::from(i)
    }

    #[test]
    fn awaited_peers_returns_participants_not_yet_seen() {
        let participants = vec![p(1), p(2), p(3), p(4)];
        let seen = vec![p(1), p(3)];
        assert_eq!(awaited_peers(&participants, &seen), vec![p(2), p(4)]);
    }

    #[test]
    fn awaited_peers_empty_when_all_seen() {
        let participants = vec![p(1), p(2)];
        let seen = vec![p(2), p(1), p(9)];
        assert!(awaited_peers(&participants, &seen).is_empty());
    }

    #[test]
    fn awaited_peers_is_all_when_nothing_seen() {
        let participants = vec![p(1), p(2)];
        assert_eq!(awaited_peers(&participants, &[]), participants);
    }
}
