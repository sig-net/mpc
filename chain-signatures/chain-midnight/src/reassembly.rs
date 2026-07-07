//! (transactionId, requestId)-scoped reassembly of chunked SGN1 events, with
//! the resume-boundary rules: the progress cursor advances only at request
//! boundaries, reconnects over-fetch `MAX_PARTS - 1` ids and dedupe by
//! "group completes past the cursor".

use crate::graphql::RawContractEvent;
use crate::wire::{EventPart, RequestKind, MAX_PARTS};

#[derive(Debug, Clone)]
pub(crate) struct CompletedGroup {
    pub kind: RequestKind,
    pub request_id: [u8; 32],
    pub parts: Vec<EventPart>,
    pub last_id: u64,
    pub block_height: u64,
}

#[derive(Debug, Clone)]
pub(crate) enum ReassemblyOutput {
    Group(CompletedGroup),
    /// A position to advance past without forwarding anything (unknown names,
    /// dropped malformed groups) — becomes a bare `ChainEvent::Block`.
    Marker {
        id: u64,
        block_height: u64,
    },
}

struct Pending {
    kind: RequestKind,
    tx_id: u64,
    request_id: [u8; 32],
    parts: Vec<EventPart>,
    first_id: u64,
    last_id: u64,
    block_height: u64,
}

pub(crate) struct Reassembler {
    current: Option<Pending>,
    processed: u64,
}

impl Reassembler {
    pub fn new(processed: u64) -> Self {
        Self {
            current: None,
            processed,
        }
    }

    /// Subscription start id that re-covers a possibly split group (inclusive).
    pub fn overfetch_start(processed: u64) -> u64 {
        (processed + 1).saturating_sub(MAX_PARTS as u64 - 1)
    }

    pub fn processed(&self) -> u64 {
        self.processed
    }

    /// Drop any partial state (reconnect path — over-fetch re-delivers it).
    pub fn reset(&mut self) {
        if let Some(p) = self.current.take() {
            tracing::debug!(
                first_id = p.first_id,
                "clearing partial reassembly buffer on reconnect"
            );
        }
    }

    pub fn push(&mut self, ev: &RawContractEvent) -> Vec<ReassemblyOutput> {
        let mut out = Vec::new();

        let part = match EventPart::parse(&ev.name, &ev.payload) {
            Ok(part) => part,
            Err(err) => {
                // Foreign/unknown/malformed events can only appear from manual
                // emits or future SGN2 layouts — skip but advance past them.
                self.flush_malformed(&mut out, "interrupted by unparseable event");
                if ev.id > self.processed {
                    tracing::debug!(id = ev.id, %err, "skipping non-SGN1 event");
                    self.processed = ev.id;
                    out.push(ReassemblyOutput::Marker {
                        id: ev.id,
                        block_height: ev.block_height,
                    });
                }
                return out;
            }
        };

        // Does this event continue the pending group?
        let continues = self.current.as_ref().is_some_and(|p| {
            p.tx_id == ev.transaction_id
                && p.request_id == part.request_id
                && p.kind == part.kind
                && part.part_index == p.parts.len() + 1
        });

        if !continues {
            self.flush_malformed(&mut out, "interrupted by a non-continuing event");
            if part.part_index != 1 {
                // Mid-group entry: legal only for over-fetched, already-processed
                // ids; anything else is malformed on-chain (impossible from the
                // signer circuits).
                if ev.id > self.processed {
                    tracing::warn!(id = ev.id, index = part.part_index, "orphan mid-group part");
                    self.processed = ev.id;
                    out.push(ReassemblyOutput::Marker {
                        id: ev.id,
                        block_height: ev.block_height,
                    });
                }
                return out;
            }
            self.current = Some(Pending {
                kind: part.kind,
                tx_id: ev.transaction_id,
                request_id: part.request_id,
                parts: Vec::with_capacity(part.kind.part_count()),
                first_id: ev.id,
                last_id: ev.id,
                block_height: ev.block_height,
            });
        }

        let pending = self.current.as_mut().expect("pending group exists");
        pending.parts.push(part);
        pending.last_id = ev.id;
        pending.block_height = ev.block_height;

        if pending.parts.len() == pending.kind.part_count() {
            let done = self.current.take().expect("completed group");
            if done.last_id > self.processed {
                self.processed = done.last_id;
                out.push(ReassemblyOutput::Group(CompletedGroup {
                    kind: done.kind,
                    request_id: done.request_id,
                    parts: done.parts,
                    last_id: done.last_id,
                    block_height: done.block_height,
                }));
            } else {
                tracing::debug!(last_id = done.last_id, "dropping already-processed group");
            }
        }
        out
    }

    fn flush_malformed(&mut self, out: &mut Vec<ReassemblyOutput>, reason: &str) {
        if let Some(p) = self.current.take() {
            tracing::warn!(
                first_id = p.first_id,
                last_id = p.last_id,
                kind = ?p.kind,
                "dropping incomplete request group: {reason}"
            );
            if p.last_id > self.processed {
                self.processed = p.last_id;
                out.push(ReassemblyOutput::Marker {
                    id: p.last_id,
                    block_height: p.block_height,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_goldens::{golden, payload_bytes};

    fn golden_events(file: &str, case: usize) -> Vec<RawContractEvent> {
        golden(file)["cases"][case]["events"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, ev)| RawContractEvent {
                id: 10 + i as u64,
                max_id: 100,
                name: hex::decode(ev["name"].as_str().unwrap()).unwrap(),
                payload: payload_bytes(ev),
                transaction_id: 5,
                block_height: 42,
            })
            .collect()
    }

    #[test]
    fn single_part_sign_completes_immediately() {
        let mut r = Reassembler::new(0);
        let evs = golden_events("sign.json", 0);
        let out = r.push(&evs[0]);
        assert_eq!(out.len(), 1);
        let ReassemblyOutput::Group(g) = &out[0] else {
            panic!("expected group");
        };
        assert_eq!(g.kind, RequestKind::Sign);
        assert_eq!(g.last_id, 10);
        assert_eq!(r.processed(), 10);
    }

    #[test]
    fn five_part_group_completes_at_the_boundary() {
        let mut r = Reassembler::new(0);
        let evs = golden_events("sign_bidirectional.json", 0);
        for ev in &evs[..4] {
            assert!(r.push(ev).is_empty(), "no output before the last part");
            assert_eq!(r.processed(), 0, "cursor holds until the boundary");
        }
        let out = r.push(&evs[4]);
        assert!(matches!(&out[0], ReassemblyOutput::Group(g)
            if g.kind == RequestKind::SignBidirectional && g.parts.len() == 5 && g.last_id == 14));
        assert_eq!(r.processed(), 14);
    }

    #[test]
    fn overfetch_replay_is_deduped() {
        let mut r = Reassembler::new(14); // already processed through id 14
        let evs = golden_events("sign_bidirectional.json", 0); // ids 10..=14
        let outputs: Vec<_> = evs.iter().flat_map(|ev| r.push(ev)).collect();
        assert!(
            outputs.is_empty(),
            "fully processed group must not re-forward"
        );
        assert_eq!(r.processed(), 14);
    }

    #[test]
    fn orphan_mid_group_parts_from_overfetch_are_silent() {
        let mut r = Reassembler::new(14);
        let evs = golden_events("sign_bidirectional.json", 0);
        // Over-fetch starting mid-group (parts 3..5 of an already-processed group).
        let outputs: Vec<_> = evs[2..].iter().flat_map(|ev| r.push(ev)).collect();
        assert!(outputs.is_empty());
    }

    #[test]
    fn interrupted_group_is_dropped_with_marker() {
        let mut r = Reassembler::new(0);
        let bi = golden_events("sign_bidirectional.json", 0);
        assert!(r.push(&bi[0]).is_empty());
        // A fresh sign event in a different tx interrupts the pending group.
        let mut sign = golden_events("sign.json", 0);
        sign[0].id = 20;
        sign[0].transaction_id = 6;
        let out = r.push(&sign[0]);
        assert_eq!(out.len(), 2);
        assert!(matches!(&out[0], ReassemblyOutput::Marker { id: 10, .. }));
        assert!(matches!(&out[1], ReassemblyOutput::Group(g) if g.kind == RequestKind::Sign));
    }

    #[test]
    fn unknown_names_become_markers() {
        let mut r = Reassembler::new(0);
        let ev = RawContractEvent {
            id: 3,
            max_id: 3,
            name: b"SGN2:FUTURE".to_vec(),
            payload: vec![0u8; 256],
            transaction_id: 1,
            block_height: 7,
        };
        let out = r.push(&ev);
        assert!(matches!(
            &out[0],
            ReassemblyOutput::Marker {
                id: 3,
                block_height: 7
            }
        ));
        assert_eq!(r.processed(), 3);
    }

    #[test]
    fn overfetch_start_window() {
        assert_eq!(Reassembler::overfetch_start(0), 0);
        assert_eq!(Reassembler::overfetch_start(3), 0);
        assert_eq!(Reassembler::overfetch_start(14), 11);
    }

    #[test]
    fn reset_clears_partial_state() {
        let mut r = Reassembler::new(0);
        let evs = golden_events("sign_bidirectional.json", 0);
        r.push(&evs[0]);
        r.reset();
        // Over-fetch replays the whole group after reconnect.
        let outputs: Vec<_> = evs.iter().flat_map(|ev| r.push(ev)).collect();
        assert!(matches!(&outputs[0], ReassemblyOutput::Group(g) if g.parts.len() == 5));
    }
}
