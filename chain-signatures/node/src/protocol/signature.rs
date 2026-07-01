//! Signature generation protocol: the sibling of `triple` and `presignature`.
//! Runs the cait-sith signing protocol once a posit round has agreed on a
//! presignature and participant set.

use crate::backlog::Backlog;
use crate::kdf;
use crate::protocol::message::{MessageChannel, PositMessage, PositProtocolId, SignatureMessage};
use crate::protocol::posit::{PositAction, PositRejectReason};
use crate::protocol::presignature::PresignatureId;
use crate::rpc::{GovernanceInfo, RpcChannel};
use crate::sign_bidirectional::{PublishState, SignBidirectionalEventExt};
use crate::storage::presignature_storage::{PresignatureTaken, PresignatureTakenDropper};
use crate::storage::PresignatureStorage;
use crate::types::SignatureProtocol;
use crate::util::AffinePointExt;

use cait_sith::protocol::{Action, InitializationError, Participant};
use cait_sith::PresignOutput;
use chrono::Utc;
use k256::Secp256k1;
use mpc_contract::config::ProtocolConfig;
use mpc_crypto::derive_key;
use mpc_primitives::{IndexedSignRequest, SignKind};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Outcome of a signature task. Produced here on a protocol/abort error, and by
/// the `request` layer when organizing cannot proceed.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SignError {
    Aborted,
}

/// Posit messages routed to a running signature task. Driven by the `request`
/// layer; the generator also consumes them to reject late `Propose`s while
/// generating.
pub(crate) enum SignTaskMessage {
    PositMessage {
        presignature_id: PresignatureId,
        round: usize,
        from: Participant,
        action: PositAction,
    },
}

/// The subset of `SignTask` the generator needs, so it never sees the
/// request-fulfillment machinery (limiter, organizer, posit state).
pub(crate) struct GenerateCtx {
    pub governance: GovernanceInfo,
    pub msg: MessageChannel,
    pub rpc: RpcChannel,
    pub backlog: Backlog,
    pub cfg: ProtocolConfig,
    #[cfg_attr(not(feature = "debug-page"), allow(dead_code))]
    pub node_account_id: near_account_id::AccountId,
}

/// An ongoing signature generator.
pub(crate) struct SignGenerator {
    protocol: SignatureProtocol,
    dropper: PresignatureTakenDropper,
    participants: Vec<Participant>,
    proposer: Participant,
    indexed: IndexedSignRequest,
    created: Instant,
    timeout: Duration,
    inbox: mpsc::Receiver<SignatureMessage>,
    msg: MessageChannel, // Needed for Drop

    #[cfg(feature = "debug-page")]
    debug_view: crate::web::debug::DebugPageTaskHandle,
}

impl SignGenerator {
    pub(crate) async fn new(
        ctx: &GenerateCtx,
        proposer: Participant,
        indexed: IndexedSignRequest,
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

        let sign_id = indexed.id;
        tracing::info!(
            me = ?ctx.governance.me,
            ?sign_id,
            ?presignature_id,
            "starting protocol to generate a new signature",
        );

        let (presignature, dropper) = taken.take();
        let PresignOutput { big_r, k, sigma } = presignature.output;
        let delta = kdf::derive_delta(indexed.id.request_id, indexed.args.entropy, big_r);
        // TODO: Check whether it is okay to use invert_vartime instead
        let output: PresignOutput<Secp256k1> = PresignOutput {
            big_r: (big_r * delta).to_affine(),
            k: k * delta.invert().unwrap(),
            sigma: (sigma + indexed.args.epsilon * k) * delta.invert().unwrap(),
        };
        let protocol = Box::new(cait_sith::sign(
            &participants,
            ctx.governance.me,
            derive_key(ctx.governance.public_key, indexed.args.epsilon),
            output,
            indexed.args.payload,
        )?);
        let inbox = ctx.msg.subscribe_signature(sign_id, presignature_id).await;
        Ok(Self {
            protocol,
            dropper,
            participants,
            proposer,
            indexed,
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

    /// Receive the next message for the signature protocol; error out on the timeout being reached
    async fn recv(&mut self) -> Result<SignatureMessage, SignError> {
        let sign_id = self.indexed.id;
        let presignature_id = self.dropper.id;
        match tokio::time::timeout(
            self.timeout.saturating_sub(self.created.elapsed()),
            self.inbox.recv(),
        )
        .await
        {
            Ok(Some(msg)) => Ok(msg),
            Ok(None) => {
                tracing::warn!(?sign_id, ?presignature_id, "signature generation aborted");
                Err(SignError::Aborted)
            }
            Err(_err) => {
                tracing::warn!(?sign_id, ?presignature_id, "signature generation timeout");
                Err(SignError::Aborted)
            }
        }
    }

    pub(crate) async fn run(
        mut self,
        ctx: &GenerateCtx,
        task_rx: &mut mpsc::Receiver<SignTaskMessage>,
    ) -> Result<(), SignError> {
        let me = ctx.governance.me;
        let epoch = ctx.governance.epoch;

        let sign_id = self.indexed.id;
        let presignature_id = self.dropper.id;

        let mut total_wait = Duration::from_millis(0);
        let mut total_pokes = 0;
        let mut poke_last_time = self.created;
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
                    // Wait for the next set of messages to arrive.
                    tokio::select! {
                        result = self.recv() => {
                            let msg = result.inspect_err(|_| {
                                crate::metrics::protocols::SIGNATURE_GENERATOR_FAILURES.inc();
                                if self.proposer == me {
                                    crate::metrics::protocols::SIGNATURE_GENERATOR_MINE_FAILURES.inc();
                                }
                            })?;
                            self.protocol.message(msg.from, msg.data);
                        }
                        Some(task_msg) = task_rx.recv() => {
                            let SignTaskMessage::PositMessage {
                                presignature_id: posit_presig_id,
                                round: posit_round,
                                from,
                                action,
                            } = task_msg;
                            if matches!(action, PositAction::Propose) {
                                tracing::info!(
                                    ?sign_id,
                                    ?from,
                                    posit_round,
                                    "received Propose while already generating, rejecting"
                                );
                                ctx.msg
                                    .send(
                                        me,
                                        from,
                                        PositMessage {
                                            id: PositProtocolId::Signature(
                                                sign_id,
                                                posit_presig_id,
                                                posit_round,
                                            ),
                                            from: me,
                                            action: PositAction::RejectWithReason(
                                                PositRejectReason::AlreadyGenerating
                                            ),
                                        },
                                    )
                                    .await;
                            }
                            // Other variants (stale Accept/Reject/Start) are silently dropped.
                        }
                    }
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
                    if let Some(publish) = publish_status(
                        ctx.governance.public_key,
                        &self.indexed,
                        &output,
                        self.participants.clone(),
                        is_proposer,
                    ) {
                        if !matches!(self.indexed.kind, SignKind::Checkpoint(_)) {
                            if let Err(err) = ctx
                                .backlog
                                .mark_publishing(self.indexed.chain, &sign_id, publish)
                                .await
                            {
                                tracing::warn!(
                                    ?sign_id,
                                    ?err,
                                    "failed to mark publishing for sign request"
                                );
                            }
                        }
                    }

                    if is_proposer {
                        crate::metrics::protocols::SIGNATURE_GENERATOR_MINE_SUCCESS.inc();
                        ctx.rpc.publish(
                            ctx.governance.public_key,
                            self.indexed.clone(),
                            output,
                            self.participants.clone(),
                        );
                    }

                    if let SignKind::SignBidirectional(event) = &self.indexed.kind {
                        // Note: The promotion to Bidirectional will happen when we receive the
                        // SignatureRespondedEvent in the Solana indexer, which has the signature data.
                        // For now, we just complete the signature generation. The indexer will handle the promotion.
                        tracing::info!(
                            ?sign_id,
                            source_chain = ?self.indexed.chain,
                            target_chain = ?event.target_chain().ok(),
                            "generated signature for bidirectional request, awaiting indexer to process"
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

fn publish_status(
    public_key: mpc_crypto::PublicKey,
    indexed: &IndexedSignRequest,
    output: &cait_sith::FullSignature<Secp256k1>,
    participants: Vec<Participant>,
    is_proposer: bool,
) -> Option<PublishState> {
    let expected_public_key = mpc_crypto::derive_key(public_key, indexed.args.epsilon);
    let signature = mpc_crypto::reconstruct_signature(
        &expected_public_key,
        &output.big_r,
        &output.s,
        indexed.args.payload,
    )
    .ok()?;
    let publish = PublishState {
        signature,
        participants,
        is_proposer,
    };

    Some(publish)
}

impl Drop for SignGenerator {
    fn drop(&mut self) {
        let msg = self.msg.clone();
        let sign_id = self.indexed.id;
        let presignature_id = self.dropper.id;
        tokio::spawn(async move {
            msg.unsubscribe_signature(sign_id, presignature_id).await;
            msg.filter_sign(sign_id, presignature_id).await;
        });
    }
}
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
