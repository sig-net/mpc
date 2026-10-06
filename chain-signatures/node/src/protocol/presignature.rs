use super::message::{ArtifactMessage, MessageChannel, PresignatureMessage};
use super::triple::{Triple, TripleId};
use crate::storage::presignature_storage::PresignatureSlot;
use crate::types::PresignatureProtocol;
use mpc_chain_near::AffinePointExt as _;

use cait_sith::protocol::{Action, InitializationError, Participant};
use cait_sith::{KeygenOutput, PresignArguments, PresignOutput};
use chrono::Utc;
use k256::{AffinePoint, Scalar, Secp256k1};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

/// Unique number used to identify a specific ongoing presignature generation protocol.
pub type PresignatureId = u64;

/// The full presignature id. Encapsulates presignature id and pair_id (which are unified).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct FullPresignatureId {
    pub id: PresignatureId,
    pub pair_id: TripleId,
}

impl FullPresignatureId {
    pub fn new(id: PresignatureId) -> Self {
        Self { id, pair_id: id }
    }

    pub fn from_pair(pair_id: TripleId) -> Self {
        Self::new(pair_id)
    }

    pub fn validate(&self) -> bool {
        self.id == self.pair_id
    }
}


/// A completed presignature.
pub struct Presignature {
    pub id: PresignatureId,
    pub output: PresignOutput<Secp256k1>,
    /// Original protocol participants
    pub participants: Vec<Participant>,
    /// Nodes still holding their share of the artifact
    pub holders: Option<Vec<Participant>>,
}

impl fmt::Debug for Presignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Presignature")
            .field("id", &self.id)
            .field("participants", &self.participants)
            .field("holders", &self.holders)
            .finish()
    }
}

impl Serialize for Presignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Presignature", 5)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("output_big_r", &self.output.big_r)?;
        state.serialize_field("output_k", &self.output.k)?;
        state.serialize_field("output_sigma", &self.output.sigma)?;
        state.serialize_field("participants", &self.participants)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Presignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct PresignatureFields {
            id: PresignatureId,
            output_big_r: AffinePoint,
            output_k: Scalar,
            output_sigma: Scalar,
            participants: Vec<Participant>,
        }

        let fields = PresignatureFields::deserialize(deserializer)?;

        Ok(Self {
            id: fields.id,
            output: PresignOutput {
                big_r: fields.output_big_r,
                k: fields.output_k,
                sigma: fields.output_sigma,
            },
            holders: None,
            participants: fields.participants,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PresignatureGenerationError {
    #[error("timeout or aborted")]
    TimeoutOrAborted,
    #[error("protocol initialization failed: {0}")]
    Init(#[from] InitializationError),
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// Standalone generator driving Stage 2 (Cait-Sith presignature generation in RAM).
pub struct PresignatureGenerator {
    pub id: FullPresignatureId,
    pub me: Participant,
    pub owner: Participant,
    pub participants: Vec<Participant>,
    threshold: usize,
    keygen_out: KeygenOutput<Secp256k1>,
    timeout: Duration,
    created: Instant,
    slot: PresignatureSlot,
    msg: MessageChannel,
    ongoing_tx: watch::Sender<usize>,
    #[cfg(feature = "debug-page")]
    #[allow(dead_code)]
    debug_view: crate::web::debug::DebugPageTaskHandle,
}

impl PresignatureGenerator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: FullPresignatureId,
        me: Participant,
        owner: Participant,
        threshold: usize,
        participants: &[Participant],
        keygen_out: KeygenOutput<Secp256k1>,
        timeout: Duration,
        slot: PresignatureSlot,
        msg: &MessageChannel,
        ongoing_tx: watch::Sender<usize>,
        _node_account_id: &str,
    ) -> Self {
        #[cfg(feature = "debug-page")]
        let node_account_id = _node_account_id;
        #[cfg(not(feature = "debug-page"))]
        let _ = _node_account_id;

        let mut participants = participants.to_vec();
        participants.sort();

        Self {
            id,
            me,
            owner,
            participants,
            threshold,
            keygen_out,
            timeout,
            created: Instant::now(),
            slot,
            msg: msg.clone(),
            ongoing_tx,
            #[cfg(feature = "debug-page")]
            debug_view: crate::web::debug::register_task(
                node_account_id.to_string(),
                format!("PresignatureGenerator {id:#?}"),
            ),
        }
    }

    fn poke(
        &self,
        protocol: &mut PresignatureProtocol,
    ) -> Result<Action<PresignOutput<Secp256k1>>, PresignatureGenerationError> {
        let poke_start = Instant::now();
        let action = protocol
            .poke()
            .map_err(|e| PresignatureGenerationError::Protocol(e.to_string()))?;
        crate::metrics::protocols::PRESIGNATURE_POKE_CPU_TIME
            .observe(poke_start.elapsed().as_millis() as f64);
        Ok(action)
    }

    async fn recv(
        &self,
        inbox: &mut mpsc::Receiver<ArtifactMessage>,
    ) -> Result<ArtifactMessage, PresignatureGenerationError> {
        let remaining = self.timeout.saturating_sub(self.created.elapsed());
        match tokio::time::timeout(remaining, inbox.recv()).await {
            Ok(Some(msg)) => Ok(msg),
            Ok(None) | Err(_) => Err(PresignatureGenerationError::TimeoutOrAborted),
        }
    }

    async fn send_many(&self, data: Vec<u8>, epoch: u64) {
        for to in &self.participants {
            if *to == self.me {
                continue;
            }
            self.msg
                .send(
                    self.me,
                    *to,
                    PresignatureMessage {
                        id: self.id.id,
                        pair_id: self.id.id,
                        epoch,
                        from: self.me,
                        data: data.clone(),
                        timestamp: Utc::now().timestamp() as u64,
                    },
                )
                .await;
        }
    }

    async fn send_private(&self, to: Participant, data: Vec<u8>, epoch: u64) {
        self.msg
            .send(
                self.me,
                to,
                PresignatureMessage {
                    id: self.id.id,
                    pair_id: self.id.id,
                    epoch,
                    from: self.me,
                    data,
                    timestamp: Utc::now().timestamp() as u64,
                },
            )
            .await;
    }

    /// Insert the completed presignature into storage.
    pub async fn insert(&mut self, presignature: Presignature) -> bool {
        self.slot.insert(presignature, self.owner).await
    }

    /// Drive Cait-Sith presignature generation using Beaver triples generated in RAM.
    pub async fn run(
        &mut self,
        triples: [Triple; 2],
        early_messages: Vec<PresignatureMessage>,
        inbox: &mut mpsc::Receiver<ArtifactMessage>,
        epoch: u64,
    ) -> Result<Presignature, PresignatureGenerationError> {
        struct OngoingGuard {
            tx: watch::Sender<usize>,
        }

        impl OngoingGuard {
            fn new(tx: watch::Sender<usize>) -> Self {
                tx.send_modify(|v| *v += 1);
                crate::metrics::protocols::NUM_PRESIGNATURE_GENERATORS_TOTAL.inc();
                Self { tx }
            }
        }

        impl Drop for OngoingGuard {
            fn drop(&mut self) {
                self.tx.send_modify(|v| *v = v.saturating_sub(1));
                crate::metrics::protocols::NUM_PRESIGNATURE_GENERATORS_TOTAL.dec();
            }
        }

        crate::metrics::protocols::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS.inc();
        if self.owner == self.me {
            crate::metrics::protocols::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE.inc();
        }
        let _guard = OngoingGuard::new(self.ongoing_tx.clone());

        let start_time = Instant::now();
        let mut protocol: PresignatureProtocol = Box::new(cait_sith::presign(
            &self.participants,
            self.me,
            &self.participants,
            self.me,
            PresignArguments {
                triple0: (triples[0].share.clone(), triples[0].public.clone()),
                triple1: (triples[1].share.clone(), triples[1].public.clone()),
                keygen_out: self.keygen_out.clone(),
                threshold: self.threshold,
            },
        )?);

        for msg in early_messages {
            protocol.message(msg.from, msg.data);
        }

        let res = async {
            loop {
                let action = self.poke(&mut protocol)?;
                match action {
                    Action::Wait => {
                        let msg = self.recv(inbox).await?;
                        match msg {
                            ArtifactMessage::Presignature(m) => {
                                protocol.message(m.from, m.data);
                            }
                            ArtifactMessage::Triple(_) => {
                                // Lagging triple message from peer; ignore
                            }
                        }
                    }
                    Action::SendMany(data) => {
                        self.send_many(data, epoch).await;
                    }
                    Action::SendPrivate(to, data) => {
                        self.send_private(to, data, epoch).await;
                    }
                    Action::Return(output) => {
                        tracing::info!(
                            id = ?self.id,
                            me = ?self.me,
                            owner = ?self.owner,
                            big_r = ?output.big_r.to_base58(),
                            elapsed = ?self.created.elapsed(),
                            "completed presignature generation"
                        );
                        let presignature = Presignature {
                            id: self.id.id,
                            output,
                            participants: self.participants.clone(),
                            holders: Some(self.participants.clone()),
                        };
                        return Ok(presignature);
                    }
                }
            }
        }
        .await;

        match res {
            Ok(presignature) => {
                crate::metrics::protocols::PRESIGNATURE_LATENCY
                    .observe(start_time.elapsed().as_secs_f64());
                crate::metrics::protocols::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_SUCCESS.inc();
                if self.owner == self.me {
                    crate::metrics::protocols::NUM_TOTAL_HISTORICAL_PRESIGNATURE_GENERATORS_MINE_SUCCESS.inc();
                }
                Ok(presignature)
            }
            Err(err) => {
                crate::metrics::protocols::PRESIGNATURE_GENERATOR_FAILURES.inc();
                if self.owner == self.me {
                    crate::metrics::protocols::PRESIGNATURE_GENERATOR_MINE_FAILURES.inc();
                }
                Err(err)
            }
        }
    }
}
