//! Per-request latency accounting for the signature state machine.

use super::*;

/// Per-request accumulator for the three looping phases in `SignTask::run`:
/// Organizing, Posit, Generating. Times are summed across attempts so each
/// histogram observation covers the full request even when the state machine
/// loops back. Indexing/AwaitingGeneration/Responding/Total are emitted
/// elsewhere and ignored by `add`.
///
/// Additivity caveat: without governance pauses, all five stages sum to
/// Total. Resharing or other transitions out of `Running` mid-request show
/// idle time only in Total, so the equality holds as `<=` in that case.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhaseDurations {
    organizing: Duration,
    posit: Duration,
    generating: Duration,
}

impl PhaseDurations {
    /// Accumulate `elapsed` into the bucket for `step` (no-op for non-phase steps).
    pub fn add(&mut self, step: SignRequestStep, elapsed: Duration) {
        match step {
            SignRequestStep::Organizing => self.organizing += elapsed,
            SignRequestStep::Posit => self.posit += elapsed,
            SignRequestStep::Generating => self.generating += elapsed,
            // Emitted elsewhere; listed explicitly so new variants force a decision here.
            SignRequestStep::Indexing
            | SignRequestStep::AwaitingGeneration
            | SignRequestStep::Responding
            | SignRequestStep::Total => {}
        }
    }

    /// Record per-phase totals as latency histograms. Call once on success.
    pub fn emit(self, chain: Chain) {
        record_request_latency(chain, SignRequestStep::Organizing, "ok", self.organizing);
        record_request_latency(chain, SignRequestStep::Posit, "ok", self.posit);
        record_request_latency(chain, SignRequestStep::Generating, "ok", self.generating);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_durations_sum_per_phase_across_attempts() {
        // Request that loops Organizing -> Posit -> Organizing -> Posit -> Generating.
        let mut d = PhaseDurations::default();
        d.add(SignRequestStep::Organizing, Duration::from_millis(100));
        d.add(SignRequestStep::Posit, Duration::from_millis(200));
        // back-edge: Posit failed and we re-entered Organizing
        d.add(SignRequestStep::Organizing, Duration::from_millis(50));
        d.add(SignRequestStep::Posit, Duration::from_millis(150));
        d.add(SignRequestStep::Generating, Duration::from_millis(500));

        assert_eq!(d.organizing, Duration::from_millis(150));
        assert_eq!(d.posit, Duration::from_millis(350));
        assert_eq!(d.generating, Duration::from_millis(500));
    }

    #[test]
    fn phase_durations_ignore_steps_not_part_of_sign_task() {
        // Non-SignTask variants must be no-ops in `add`, else they double-count.
        let mut d = PhaseDurations::default();
        d.add(SignRequestStep::Indexing, Duration::from_millis(100));
        d.add(
            SignRequestStep::AwaitingGeneration,
            Duration::from_millis(200),
        );
        d.add(SignRequestStep::Responding, Duration::from_millis(300));
        d.add(SignRequestStep::Total, Duration::from_millis(400));

        assert_eq!(d, PhaseDurations::default());
    }

    #[test]
    fn phase_durations_preserve_additivity_invariant() {
        // 2 attempts: first fails at posit, then restarts from organizing and finishes.
        let inputs = [
            (SignRequestStep::Organizing, Duration::from_millis(40)),
            (SignRequestStep::Posit, Duration::from_millis(120)),
            (SignRequestStep::Organizing, Duration::from_millis(35)),
            (SignRequestStep::Posit, Duration::from_millis(95)),
            (SignRequestStep::Generating, Duration::from_millis(710)),
        ];
        let expected: Duration = inputs.iter().map(|(_, d)| *d).sum();

        let mut d = PhaseDurations::default();
        for (step, elapsed) in inputs {
            d.add(step, elapsed);
        }

        assert_eq!(d.organizing + d.posit + d.generating, expected);
    }
}
