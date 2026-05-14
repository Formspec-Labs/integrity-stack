// Rust guideline compliant 2026-02-21
//! Universal chain-hash continuity verification.
//!
//! Operates on [`crate::report::ChainEventView`] only — no profile
//! semantics. Catches three universal violations:
//!
//! 1. **Sequence-0 prev_hash present.** First event MUST have
//!    `previous_hash == None`.
//! 2. **prev_hash break.** Event at sequence N (N > 0) MUST have
//!    `previous_hash == events[N-1].canonical_event_hash`.
//! 3. **Sequence reorder.** Sequence numbers MUST be strictly increasing
//!    along the input order (offline check; assumes input order matches
//!    declared sequence order — Phase-1 fixture corpus convention).

use crate::report::ChainEventView;

/// One chain-continuity finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainFinding {
    pub kind: &'static str,
    pub event_index: usize,
    pub message: String,
}

/// Result of [`ChainContinuityCheck::run`].
///
/// `ChainContinuityCheck` is purely prev-hash linkage. WOS row payload
/// re-hash lives outside `integrity-verify`.
pub struct ChainContinuityCheck {
    pub findings: Vec<ChainFinding>,
}

impl ChainContinuityCheck {
    /// Verifies chain-hash continuity across the supplied events.
    #[must_use]
    pub fn run(events: &[ChainEventView]) -> Self {
        let mut findings = Vec::new();
        let mut prev_hash: Option<[u8; 32]> = None;
        let mut prev_sequence: Option<u64> = None;

        for (index, event) in events.iter().enumerate() {
            if event.sequence == 0 {
                if event.previous_hash.is_some() {
                    findings.push(ChainFinding {
                        kind: "genesis_has_prev_hash",
                        event_index: index,
                        message: "sequence 0 must have previous_hash == None".into(),
                    });
                }
            } else if event.previous_hash != prev_hash {
                findings.push(ChainFinding {
                    kind: "prev_hash_mismatch",
                    event_index: index,
                    message: "previous_hash does not match prior event's canonical_event_hash"
                        .into(),
                });
            }

            if let Some(prev_seq) = prev_sequence
                && event.sequence <= prev_seq
            {
                findings.push(ChainFinding {
                    kind: "sequence_reorder",
                    event_index: index,
                    message: format!(
                        "sequence {} does not strictly follow prior sequence {prev_seq}",
                        event.sequence
                    ),
                });
            }

            prev_hash = Some(event.canonical_event_hash);
            prev_sequence = Some(event.sequence);
        }

        Self { findings }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(seq: u64, hash: [u8; 32], prev: Option<[u8; 32]>) -> ChainEventView {
        ChainEventView {
            sequence: seq,
            canonical_event_hash: hash,
            previous_hash: prev,
        }
    }

    #[test]
    fn accepts_continuous_chain() {
        let h0 = [1u8; 32];
        let h1 = [2u8; 32];
        let h2 = [3u8; 32];
        let events = [ev(0, h0, None), ev(1, h1, Some(h0)), ev(2, h2, Some(h1))];
        let result = ChainContinuityCheck::run(&events);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn rejects_genesis_with_prev_hash() {
        let events = [ev(0, [1u8; 32], Some([9u8; 32]))];
        let result = ChainContinuityCheck::run(&events);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.kind == "genesis_has_prev_hash")
        );
    }

    #[test]
    fn rejects_prev_hash_break() {
        let h0 = [1u8; 32];
        let h1 = [2u8; 32];
        let events = [ev(0, h0, None), ev(1, h1, Some([9u8; 32]))];
        let result = ChainContinuityCheck::run(&events);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.kind == "prev_hash_mismatch")
        );
    }

    #[test]
    fn rejects_sequence_reorder() {
        let h0 = [1u8; 32];
        let h1 = [2u8; 32];
        let events = [ev(2, h0, None), ev(1, h1, Some(h0))];
        let result = ChainContinuityCheck::run(&events);
        assert!(result.findings.iter().any(|f| f.kind == "sequence_reorder"));
    }
}
