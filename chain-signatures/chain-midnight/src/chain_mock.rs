//! Test-only chain mock for the watch path; the finalized head advances on
//! each read, so tests drive watching purely by polling.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use midnight_base_crypto::time::Timestamp;
use midnight_ledger_v9::structure::INITIAL_PARAMETERS;
use tokio::time::Instant;

use crate::rpc::publisher::PinnedReads;
use crate::rpc::submit::{Landing, SubmitChain, SubmitRefusal};
use crate::types::{BlockHash, LedgerTxHash, MidnightAddress};

pub(crate) const TX_HASH: [u8; 32] = [0x7a; 32];

/// A chain whose finalized head moves `step` blocks (one by default) per ask, from
/// `head` up to `last`, with blocks six seconds apart from time 1000.
pub(crate) struct ScriptedChain {
    head: Mutex<u64>,
    last: u64,
    step: u64,
    /// The blocks each head read asked about, by method.
    pub(crate) number_reads: Mutex<Vec<u64>>,
    pub(crate) time_reads: Mutex<Vec<u64>>,
    pub(crate) hash_lookups: Mutex<Vec<u64>>,
    /// What each submit answers, in turn; past the last, the node takes it.
    submit: Mutex<VecDeque<SubmitRefusal>>,
    /// When each submit was sent.
    submitted: Mutex<Vec<Instant>>,
    pub(crate) landing_reads: Mutex<VecDeque<u64>>,
    /// What the landing read of each scripted block answers, in order; a
    /// read the script's front does not name answers found-nothing.
    reads: Mutex<VecDeque<(u64, LandingRead)>>,
    /// A block whose first time read fails.
    failing_time: Mutex<Option<u64>>,
    /// A block `block_hash_at` answers nothing for.
    missing_hash_at: Mutex<Option<u64>>,
}

pub(crate) enum LandingRead {
    Found(Landing),
    Fail(anyhow::Error),
    Delayed {
        delay: Duration,
        then: Box<LandingRead>,
    },
}

impl ScriptedChain {
    pub(crate) fn new(head: u64, last: u64) -> Self {
        Self {
            head: Mutex::new(head),
            last,
            step: 1,
            number_reads: Mutex::new(Vec::new()),
            time_reads: Mutex::new(Vec::new()),
            hash_lookups: Mutex::new(Vec::new()),
            submit: Mutex::new(VecDeque::new()),
            submitted: Mutex::new(Vec::new()),
            landing_reads: Mutex::new(VecDeque::new()),
            reads: Mutex::new(VecDeque::new()),
            failing_time: Mutex::new(None),
            missing_hash_at: Mutex::new(None),
        }
    }

    pub(crate) fn stepping(mut self, step: u64) -> Self {
        self.step = step;
        self
    }

    pub(crate) fn landing_at(self, number: u64, landing: Landing) -> Self {
        self.reads
            .lock()
            .unwrap()
            .push_back((number, LandingRead::Found(landing)));
        self
    }

    pub(crate) fn failing_read_at(self, number: u64) -> Self {
        self.reads.lock().unwrap().push_back((
            number,
            LandingRead::Fail(anyhow::anyhow!(
                "the node dropped the read of block {number}"
            )),
        ));
        self
    }

    pub(crate) fn failing_read_with(self, number: u64, error: anyhow::Error) -> Self {
        self.reads
            .lock()
            .unwrap()
            .push_back((number, LandingRead::Fail(error)));
        self
    }

    pub(crate) fn delaying_read_at(self, number: u64, delay: Duration, then: LandingRead) -> Self {
        self.reads.lock().unwrap().push_back((
            number,
            LandingRead::Delayed {
                delay,
                then: Box::new(then),
            },
        ));
        self
    }

    pub(crate) fn missing_hash_at(self, number: u64) -> Self {
        *self.missing_hash_at.lock().unwrap() = Some(number);
        self
    }

    pub(crate) fn failing_time_once_at(self, number: u64) -> Self {
        *self.failing_time.lock().unwrap() = Some(number);
        self
    }
}

fn block_hash(number: u64) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&number.to_be_bytes());
    BlockHash::from_bytes(bytes)
}

fn block_number_of(hash: &BlockHash) -> u64 {
    u64::from_be_bytes(hash.as_bytes()[24..].try_into().unwrap())
}

/// A scan read rejection, attached like the `SubmitChain` boundary attaches its reads.
pub(crate) fn scan_read_rejected(status: u16) -> anyhow::Error {
    crate::rpc::reads::attach_read_carrier(
        crate::test_utils::rejected_http(status).context("failed to fetch midnight block events"),
    )
}

fn ledger_parameters() -> Vec<u8> {
    let mut bytes = Vec::new();
    midnight_serialize::tagged_serialize(&INITIAL_PARAMETERS, &mut bytes).unwrap();
    bytes
}

#[async_trait]
impl PinnedReads for ScriptedChain {
    async fn finalized_head(&self) -> anyhow::Result<BlockHash> {
        let mut head = self.head.lock().unwrap();
        *head = (*head + self.step).min(self.last);
        Ok(block_hash(*head))
    }

    async fn contract_state(
        &self,
        _: &MidnightAddress,
        _: &BlockHash,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        unimplemented!("the post path reads no contract state")
    }

    async fn ledger_parameters(&self, _: &BlockHash) -> anyhow::Result<Vec<u8>> {
        Ok(ledger_parameters())
    }
}

#[async_trait]
impl SubmitChain for ScriptedChain {
    async fn block_number(&self, at: &BlockHash) -> anyhow::Result<u64> {
        let number = block_number_of(at);
        self.number_reads.lock().unwrap().push(number);
        Ok(number)
    }

    async fn block_hash_at(&self, number: u64) -> anyhow::Result<Option<BlockHash>> {
        self.hash_lookups.lock().unwrap().push(number);
        if *self.missing_hash_at.lock().unwrap() == Some(number) {
            return Ok(None);
        }
        Ok(Some(block_hash(number)))
    }

    async fn block_time(&self, at: &BlockHash) -> anyhow::Result<Timestamp> {
        let number = block_number_of(at);
        self.time_reads.lock().unwrap().push(number);
        let mut failing = self.failing_time.lock().unwrap();
        if *failing == Some(number) {
            *failing = None;
            anyhow::bail!("the node dropped the time read of block {number}");
        }
        Ok(Timestamp::from_secs(1000 + 6 * number))
    }

    async fn submit(&self, transaction: &[u8]) -> Result<(), SubmitRefusal> {
        assert_eq!(
            transaction, b"tx",
            "every submit sends the same transaction"
        );
        self.submitted.lock().unwrap().push(Instant::now());
        self.submit.lock().unwrap().pop_front().map_or(Ok(()), Err)
    }

    async fn landing(
        &self,
        at: &BlockHash,
        tx_hash: LedgerTxHash,
    ) -> anyhow::Result<Option<Landing>> {
        assert_eq!(tx_hash, LedgerTxHash::from_bytes(TX_HASH));
        let number = block_number_of(at);
        self.landing_reads.lock().unwrap().push_back(number);
        let mut reply = {
            let mut scripted = self.reads.lock().unwrap();
            scripted
                .front()
                .is_some_and(|&(at, _)| at == number)
                .then(|| scripted.pop_front().expect("checked").1)
        };
        loop {
            match reply {
                Some(LandingRead::Fail(error)) => return Err(error),
                Some(LandingRead::Delayed { delay, then }) => {
                    tokio::time::sleep(delay).await;
                    reply = Some(*then);
                }
                Some(LandingRead::Found(landing)) => return Ok(Some(landing)),
                None => return Ok(None),
            }
        }
    }
}
