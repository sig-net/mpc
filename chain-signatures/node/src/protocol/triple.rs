use super::message::{ArtifactMessage, MessageChannel, TripleMessage};
use crate::types::TripleProtocol;

use cait_sith::protocol::{Action, InitializationError, Participant};
use cait_sith::triples::{TriplePub, TripleShare};
use chrono::Utc;
use k256::Secp256k1;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

/// Unique number used to identify a specific ongoing triple generation protocol.
pub type TripleId = u64;

/// A completed triple.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Triple {
    pub share: TripleShare<Secp256k1>,
    pub public: TriplePub<Secp256k1>,
}

#[derive(Debug, thiserror::Error)]
pub enum TripleGenerationError {
    #[error("timeout or aborted")]
    TimeoutOrAborted,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("blocking task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("insufficient triples returned (expected 2)")]
    InsufficientTriples,
}

/// Standalone generator driving Stage 1 (Beaver triple pair generation in RAM).
pub struct TripleGenerator {
    pub id: TripleId,
    pub me: Participant,
    pub owner: Participant,
    pub participants: Vec<Participant>,
    protocol: TripleProtocol,
    timeout: Duration,
    created: Instant,
    msg: MessageChannel,
    ongoing_tx: watch::Sender<usize>,
    #[cfg(feature = "debug-page")]
    #[allow(dead_code)]
    debug_view: crate::web::debug::DebugPageTaskHandle,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TriplePair {
    pub id: TripleId,
    pub triple0: Triple,
    pub triple1: Triple,
    #[serde(skip, default)]
    pub holders: Option<Vec<Participant>>,
}

impl TripleGenerator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: TripleId,
        me: Participant,
        owner: Participant,
        threshold: usize,
        participants: &[Participant],
        timeout: Duration,
        msg: &MessageChannel,
        ongoing_tx: watch::Sender<usize>,
        _node_account_id: &str,
    ) -> Result<Self, InitializationError> {
        #[cfg(feature = "debug-page")]
        let node_account_id = _node_account_id;
        #[cfg(not(feature = "debug-page"))]
        let _ = _node_account_id;

        let mut participants = participants.to_vec();
        participants.sort();

        let protocol =
            cait_sith::triples::generate_triple_many::<Secp256k1, 2>(&participants, me, threshold)?;

        Ok(Self {
            id,
            me,
            owner,
            participants,
            protocol: Box::new(protocol),
            timeout,
            created: Instant::now(),
            msg: msg.clone(),
            ongoing_tx,
            #[cfg(feature = "debug-page")]
            debug_view: crate::web::debug::register_task(
                node_account_id.to_string(),
                format!("TripleGenerator {id:#?}"),
            ),
        })
    }

    /// Drive Beaver triple generation until a pair is produced.
    /// Any presignature messages received from faster peers are buffered and returned.
    pub async fn run(
        self,
        inbox: &mut mpsc::Receiver<ArtifactMessage>,
        epoch: u64,
    ) -> Result<([Triple; 2], Vec<super::message::PresignatureMessage>), TripleGenerationError> {
        struct OngoingGuard {
            tx: watch::Sender<usize>,
        }

        impl OngoingGuard {
            fn new(tx: watch::Sender<usize>) -> Self {
                tx.send_modify(|v| *v += 1);
                crate::metrics::protocols::NUM_TRIPLE_GENERATORS_TOTAL.inc();
                Self { tx }
            }
        }

        impl Drop for OngoingGuard {
            fn drop(&mut self) {
                self.tx.send_modify(|v| *v = v.saturating_sub(1));
                crate::metrics::protocols::NUM_TRIPLE_GENERATORS_TOTAL.dec();
            }
        }

        crate::metrics::protocols::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS.inc();
        let _guard = OngoingGuard::new(self.ongoing_tx.clone());

        let Self {
            id,
            me,
            owner,
            participants,
            mut protocol,
            timeout,
            created,
            msg,
            ..
        } = self;

        let mut early_presign_messages = Vec::new();
        let start_time = Instant::now();

        let res = async {
            loop {
                let poke_start = Instant::now();
                let (result, p) =
                    tokio::task::spawn_blocking(move || (protocol.poke(), protocol)).await?;
                protocol = p;

                crate::metrics::protocols::TRIPLE_POKE_CPU_TIME
                    .observe(poke_start.elapsed().as_millis() as f64);

                let action = result.map_err(|e| TripleGenerationError::Protocol(e.to_string()))?;
                match action {
                    Action::Wait => {
                        let remaining = timeout.saturating_sub(created.elapsed());
                        let item = match tokio::time::timeout(remaining, inbox.recv()).await {
                            Ok(Some(msg)) => msg,
                            Ok(None) | Err(_) => return Err(TripleGenerationError::TimeoutOrAborted),
                        };
                        match item {
                            ArtifactMessage::Triple(m) => {
                                protocol.message(m.from, m.data);
                            }
                            ArtifactMessage::Presignature(m) => {
                                early_presign_messages.push(m);
                            }
                        }
                    }
                    Action::SendMany(data) => {
                        for to in &participants {
                            if *to == me {
                                continue;
                            }
                            msg.send(
                                me,
                                *to,
                                TripleMessage {
                                    id,
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
                        msg.send(
                            me,
                            to,
                            TripleMessage {
                                id,
                                epoch,
                                from: me,
                                data,
                                timestamp: Utc::now().timestamp() as u64,
                            },
                        )
                        .await;
                    }
                    Action::Return(outputs) => {
                        let [first, second, ..] = &outputs[..] else {
                            return Err(TripleGenerationError::InsufficientTriples);
                        };
                        let pair = [
                            Triple {
                                share: first.0.clone(),
                                public: first.1.clone(),
                            },
                            Triple {
                                share: second.0.clone(),
                                public: second.1.clone(),
                            },
                        ];
                        return Ok(pair);
                    }
                }
            }
        }
        .await;

        match res {
            Ok(pair) => {
                crate::metrics::protocols::TRIPLE_LATENCY
                    .observe(start_time.elapsed().as_secs_f64());
                crate::metrics::protocols::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATORS_SUCCESS.inc();
                if owner == me {
                    crate::metrics::protocols::NUM_TOTAL_HISTORICAL_TRIPLE_GENERATIONS_OWNED_SUCCESS.inc();
                }
                Ok((pair, early_presign_messages))
            }
            Err(err) => {
                crate::metrics::protocols::TRIPLE_GENERATOR_FAILURES.inc();
                if owner == me {
                    crate::metrics::protocols::TRIPLE_GENERATOR_OWNED_FAILURES.inc();
                }
                Err(err)
            }
        }
    }
}
