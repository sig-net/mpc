use crate::metrics::concurrency::{
    ADJUSTMENTS_TOTAL, CPU_UTILIZATION_PERCENT, DESIRED_SLOTS, PRESIG_ACTIVE, TRIPLE_ACTIVE,
    WAITING_PRESIGS, WAITING_TRIPLES,
};

use mpc_contract::config::ProtocolConfig;
use serde::Deserialize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::sync::{watch, Notify};

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct AdaptiveConcurrencyConfig {
    pub target_cpu_low: f64,
    pub target_cpu_high: f64,
    pub sample_interval_ms: u64,
    pub max_slots: usize,
    pub initial_slots: usize,
    pub aimd: AimdConfig,
}

impl Default for AdaptiveConcurrencyConfig {
    fn default() -> Self {
        Self {
            target_cpu_low: 0.50,
            target_cpu_high: 0.75,
            sample_interval_ms: 1000,
            max_slots: 0,
            initial_slots: 0,
            aimd: AimdConfig::default(),
        }
    }
}

impl AdaptiveConcurrencyConfig {
    pub fn from_protocol(protocol: &ProtocolConfig) -> Self {
        let mut cfg: Self = serde_json::to_value(protocol)
            .ok()
            .and_then(|value| value.get("adaptive_concurrency").cloned())
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or_default();

        if cfg.max_slots == 0 {
            cfg.max_slots = std::thread::available_parallelism()
                .map(|count| count.get())
                .unwrap_or(1)
                .max(1);
        }

        if cfg.initial_slots == 0 {
            let cpu_guess = std::thread::available_parallelism()
                .map(|count| count.get())
                .unwrap_or(1);
            cfg.initial_slots = cpu_guess.div_ceil(2).min(cfg.max_slots).max(1);
        }

        cfg
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct AimdConfig {
    pub enabled: bool,
    pub hysteresis: f64,
}

impl Default for AimdConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hysteresis: 0.03,
        }
    }
}

#[derive(Debug)]
struct ArbiterState {
    desired_slots: usize,
    presig_active: usize,
    triple_active: usize,
    waiting_presigs: usize,
    waiting_triples: usize,
}

impl ArbiterState {
    fn active_total(&self) -> usize {
        self.presig_active + self.triple_active
    }
}

fn publish_state(state: &ArbiterState) {
    DESIRED_SLOTS.set(state.desired_slots as i64);
    PRESIG_ACTIVE.set(state.presig_active as i64);
    TRIPLE_ACTIVE.set(state.triple_active as i64);
    WAITING_PRESIGS.set(state.waiting_presigs as i64);
    WAITING_TRIPLES.set(state.waiting_triples as i64);
}

#[derive(Debug)]
struct ConcurrencyArbiter {
    state: Mutex<ArbiterState>,
    notify: Notify,
}

impl ConcurrencyArbiter {
    fn new(initial_slots: usize) -> Self {
        let initial_state = ArbiterState {
            desired_slots: initial_slots.max(1),
            presig_active: 0,
            triple_active: 0,
            waiting_presigs: 0,
            waiting_triples: 0,
        };
        publish_state(&initial_state);

        Self {
            state: Mutex::new(initial_state),
            notify: Notify::new(),
        }
    }

    fn state(&self) -> MutexGuard<'_, ArbiterState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                // NOTE: if the mutex is poisoned, our code has panicked while holding the lock,
                // which likely means something is very wrong with our concurrency logic. This
                // only affects stockpiling logic, so it is fine to recover and keep the node
                // running, but we should log it.
                tracing::warn!("adaptive concurrency arbiter mutex poisoned; recovering");
                poisoned.into_inner()
            }
        }
    }

    fn active_total(&self) -> usize {
        self.state().active_total()
    }

    fn set_desired_slots(&self, desired_slots: usize) {
        let mut state = self.state();
        state.desired_slots = desired_slots.max(state.active_total()).max(1);
        publish_state(&state);
        drop(state);
        self.notify.notify_waiters();
    }

    async fn acquire_presig(self: &Arc<Self>) -> PresigPermit {
        let mut registration = WaitRegistration::new(Arc::clone(self), WaitKind::Presig);

        loop {
            if registration.try_acquire() {
                return PresigPermit {
                    arbiter: Arc::clone(self),
                };
            }

            self.notify.notified().await;
        }
    }

    async fn acquire_triple(self: &Arc<Self>) -> TriplePermit {
        let mut registration = WaitRegistration::new(Arc::clone(self), WaitKind::Triple);

        loop {
            if registration.try_acquire() {
                return TriplePermit {
                    arbiter: Arc::clone(self),
                };
            }

            self.notify.notified().await;
        }
    }

    fn release_presig(&self) {
        let mut state = self.state();
        state.presig_active = state.presig_active.saturating_sub(1);
        publish_state(&state);
        drop(state);
        self.notify.notify_waiters();
    }

    fn release_triple(&self) {
        let mut state = self.state();
        state.triple_active = state.triple_active.saturating_sub(1);
        publish_state(&state);
        drop(state);
        self.notify.notify_waiters();
    }
}

enum WaitKind {
    Presig,
    Triple,
}

struct WaitRegistration {
    arbiter: Arc<ConcurrencyArbiter>,
    kind: WaitKind,
    queued: bool,
}

impl WaitRegistration {
    fn new(arbiter: Arc<ConcurrencyArbiter>, kind: WaitKind) -> Self {
        {
            let mut state = arbiter.state();
            match kind {
                WaitKind::Presig => state.waiting_presigs += 1,
                WaitKind::Triple => state.waiting_triples += 1,
            }
            publish_state(&state);
        }

        Self {
            arbiter,
            kind,
            queued: true,
        }
    }

    fn try_acquire(&mut self) -> bool {
        let mut state = self.arbiter.state();
        let can_acquire = match self.kind {
            WaitKind::Presig => state.active_total() < state.desired_slots,
            WaitKind::Triple => {
                state.waiting_presigs == 0 && state.active_total() < state.desired_slots
            }
        };

        if !can_acquire {
            return false;
        }

        match self.kind {
            WaitKind::Presig => {
                state.waiting_presigs = state.waiting_presigs.saturating_sub(1);
                state.presig_active += 1;
            }
            WaitKind::Triple => {
                state.waiting_triples = state.waiting_triples.saturating_sub(1);
                state.triple_active += 1;
            }
        }
        self.queued = false;
        publish_state(&state);
        true
    }
}

impl Drop for WaitRegistration {
    fn drop(&mut self) {
        if !self.queued {
            return;
        }

        let mut state = self.arbiter.state();
        match self.kind {
            WaitKind::Presig => {
                state.waiting_presigs = state.waiting_presigs.saturating_sub(1);
            }
            WaitKind::Triple => {
                state.waiting_triples = state.waiting_triples.saturating_sub(1);
            }
        }
        publish_state(&state);
        drop(state);
        self.arbiter.notify.notify_waiters();
    }
}

#[derive(Clone)]
pub struct TriplePermits {
    arbiter: Arc<ConcurrencyArbiter>,
}

impl TriplePermits {
    pub async fn acquire(&self) -> TriplePermit {
        self.arbiter.acquire_triple().await
    }
}

#[derive(Clone)]
pub struct PresigPermits {
    arbiter: Arc<ConcurrencyArbiter>,
}

impl PresigPermits {
    pub async fn acquire(&self) -> PresigPermit {
        self.arbiter.acquire_presig().await
    }
}

pub struct TriplePermit {
    arbiter: Arc<ConcurrencyArbiter>,
}

impl Drop for TriplePermit {
    fn drop(&mut self) {
        self.arbiter.release_triple();
    }
}

pub struct PresigPermit {
    arbiter: Arc<ConcurrencyArbiter>,
}

impl Drop for PresigPermit {
    fn drop(&mut self) {
        self.arbiter.release_presig();
    }
}

pub struct ConcurrencyController {
    cfg: AdaptiveConcurrencyConfig,
    desired_slots: Arc<AtomicUsize>,
    arbiter: Arc<ConcurrencyArbiter>,
}

impl ConcurrencyController {
    pub fn from_protocol(protocol: &ProtocolConfig) -> Arc<Self> {
        let cfg = AdaptiveConcurrencyConfig::from_protocol(protocol);
        let desired_slots = Arc::new(AtomicUsize::new(cfg.initial_slots));
        let arbiter = Arc::new(ConcurrencyArbiter::new(cfg.initial_slots));
        Arc::new(Self {
            cfg,
            desired_slots,
            arbiter,
        })
    }

    pub fn start(self: &Arc<Self>, mut cpu_rx: watch::Receiver<f64>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                if cpu_rx.changed().await.is_err() {
                    break;
                }

                let Some(controller) = weak.upgrade() else {
                    break;
                };

                let cpu = *cpu_rx.borrow();
                controller.tick(cpu).await;
            }
        });
    }

    pub fn max_slots(&self) -> usize {
        self.cfg.max_slots
    }

    pub fn presig_permits(&self) -> PresigPermits {
        PresigPermits {
            arbiter: Arc::clone(&self.arbiter),
        }
    }

    pub fn triple_permits(&self) -> TriplePermits {
        TriplePermits {
            arbiter: Arc::clone(&self.arbiter),
        }
    }

    pub async fn tick(&self, cpu: f64) {
        CPU_UTILIZATION_PERCENT.set((cpu * 100.0).round() as i64);

        let current = self.desired_slots.load(Ordering::Relaxed);
        let active_floor = self.arbiter.active_total().max(1);
        let new = if self.cfg.aimd.enabled {
            if cpu < self.cfg.target_cpu_low - self.cfg.aimd.hysteresis {
                ADJUSTMENTS_TOTAL.with_label_values(&["up"]).inc();
                (current + 1).min(self.cfg.max_slots)
            } else if cpu > self.cfg.target_cpu_high + self.cfg.aimd.hysteresis {
                ADJUSTMENTS_TOTAL.with_label_values(&["down"]).inc();
                (current / 2).max(active_floor)
            } else {
                ADJUSTMENTS_TOTAL.with_label_values(&["hold"]).inc();
                current
            }
        } else if cpu < self.cfg.target_cpu_low {
            ADJUSTMENTS_TOTAL.with_label_values(&["up"]).inc();
            (current + 1).min(self.cfg.max_slots)
        } else if cpu > self.cfg.target_cpu_high {
            ADJUSTMENTS_TOTAL.with_label_values(&["down"]).inc();
            current.saturating_sub(1).max(active_floor)
        } else {
            ADJUSTMENTS_TOTAL.with_label_values(&["hold"]).inc();
            current
        };

        self.desired_slots.store(new, Ordering::Relaxed);
        self.arbiter.set_desired_slots(new);
    }

    #[cfg(test)]
    pub fn triple_active_for_test(&self) -> usize {
        self.arbiter.state().triple_active
    }

    #[cfg(test)]
    pub fn waiting_triples_for_test(&self) -> usize {
        self.arbiter.state().waiting_triples
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::oneshot;
    use tokio::time::{timeout, Duration};

    #[test]
    fn parses_node_local_adaptive_config() {
        let mut protocol = ProtocolConfig::default();
        protocol.other.insert(
            "adaptive_concurrency".to_string(),
            serde_json::json!({
                "enabled": true,
                "target_cpu_low": 0.4,
                "target_cpu_high": 0.8,
                "max_slots": 7,
                "initial_slots": 3,
            })
            .into(),
        );

        let cfg = AdaptiveConcurrencyConfig::from_protocol(&protocol);
        assert_eq!(cfg.max_slots, 7);
        assert_eq!(cfg.initial_slots, 3);
        assert_eq!(cfg.target_cpu_low, 0.4);
        assert_eq!(cfg.target_cpu_high, 0.8);
    }

    #[tokio::test]
    async fn presig_waiter_beats_new_triple() {
        let arbiter = Arc::new(ConcurrencyArbiter::new(1));
        let first_triple = arbiter.acquire_triple().await;

        let presig_arbiter = Arc::clone(&arbiter);
        let (presig_ready_tx, presig_ready_rx) = oneshot::channel();
        let presig_task = tokio::spawn(async move {
            let permit = presig_arbiter.acquire_presig().await;
            let _ = presig_ready_tx.send(());
            permit
        });

        tokio::task::yield_now().await;

        let triple_arbiter = Arc::clone(&arbiter);
        let second_triple = tokio::spawn(async move { triple_arbiter.acquire_triple().await });

        tokio::task::yield_now().await;
        drop(first_triple);

        timeout(Duration::from_secs(1), presig_ready_rx)
            .await
            .expect("presig should acquire first")
            .expect("presig sender should succeed");
        assert!(!second_triple.is_finished());

        drop(presig_task.await.unwrap());
        tokio::task::yield_now().await;
        let _ = timeout(Duration::from_secs(1), second_triple)
            .await
            .expect("triple should resume after presig completes");
    }

    #[tokio::test]
    async fn tick_never_shrinks_below_active_work() {
        let controller = Arc::new(ConcurrencyController {
            cfg: AdaptiveConcurrencyConfig {
                max_slots: 4,
                initial_slots: 2,
                ..AdaptiveConcurrencyConfig::default()
            },
            desired_slots: Arc::new(AtomicUsize::new(2)),
            arbiter: Arc::new(ConcurrencyArbiter::new(2)),
        });

        let _permit1 = controller.triple_permits().acquire().await;
        let _permit2 = controller.triple_permits().acquire().await;
        controller.tick(0.99).await;

        assert_eq!(controller.desired_slots.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn waiting_permit_wakes_when_capacity_increases() {
        let controller = Arc::new(ConcurrencyController {
            cfg: AdaptiveConcurrencyConfig {
                max_slots: 2,
                initial_slots: 1,
                ..AdaptiveConcurrencyConfig::default()
            },
            desired_slots: Arc::new(AtomicUsize::new(1)),
            arbiter: Arc::new(ConcurrencyArbiter::new(1)),
        });

        let _first = controller.triple_permits().acquire().await;
        let waiter = tokio::spawn({
            let controller = Arc::clone(&controller);
            async move { controller.triple_permits().acquire().await }
        });

        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        controller.tick(0.10).await;
        let _second = timeout(Duration::from_secs(1), waiter)
            .await
            .expect("permit waiter should wake after capacity increase")
            .expect("permit waiter task should succeed");
    }

    #[tokio::test]
    async fn canceled_waiters_release_queue_slots() {
        let controller = Arc::new(ConcurrencyController {
            cfg: AdaptiveConcurrencyConfig {
                max_slots: 1,
                initial_slots: 1,
                ..AdaptiveConcurrencyConfig::default()
            },
            desired_slots: Arc::new(AtomicUsize::new(1)),
            arbiter: Arc::new(ConcurrencyArbiter::new(1)),
        });

        let _held = controller.triple_permits().acquire().await;
        let triple_waiters_before = WAITING_TRIPLES.get();
        let presig_waiters_before = WAITING_PRESIGS.get();

        let triple_waiter = tokio::spawn({
            let controller = Arc::clone(&controller);
            async move { controller.triple_permits().acquire().await }
        });
        let presig_waiter = tokio::spawn({
            let controller = Arc::clone(&controller);
            async move { controller.presig_permits().acquire().await }
        });

        timeout(Duration::from_secs(1), async {
            loop {
                if WAITING_TRIPLES.get() == triple_waiters_before + 1
                    && WAITING_PRESIGS.get() == presig_waiters_before + 1
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("waiters should register before cancellation");
        assert_eq!(WAITING_TRIPLES.get(), triple_waiters_before + 1);
        assert_eq!(WAITING_PRESIGS.get(), presig_waiters_before + 1);

        triple_waiter.abort();
        presig_waiter.abort();
        match triple_waiter.await {
            Err(err) => assert!(err.is_cancelled()),
            Ok(_) => panic!("triple waiter should be cancelled"),
        }
        match presig_waiter.await {
            Err(err) => assert!(err.is_cancelled()),
            Ok(_) => panic!("presig waiter should be cancelled"),
        }
        timeout(Duration::from_secs(1), async {
            loop {
                if WAITING_TRIPLES.get() == triple_waiters_before
                    && WAITING_PRESIGS.get() == presig_waiters_before
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("waiters should unregister after cancellation");

        assert_eq!(WAITING_TRIPLES.get(), triple_waiters_before);
        assert_eq!(WAITING_PRESIGS.get(), presig_waiters_before);
    }

    #[tokio::test]
    async fn presig_priority_holds_on_capacity_increase() {
        let controller = Arc::new(ConcurrencyController {
            cfg: AdaptiveConcurrencyConfig {
                max_slots: 2,
                initial_slots: 1,
                ..AdaptiveConcurrencyConfig::default()
            },
            desired_slots: Arc::new(AtomicUsize::new(1)),
            arbiter: Arc::new(ConcurrencyArbiter::new(1)),
        });

        let _first_triple = controller.triple_permits().acquire().await;
        let presig_waiter = tokio::spawn({
            let controller = Arc::clone(&controller);
            async move { controller.presig_permits().acquire().await }
        });
        let triple_waiter = tokio::spawn({
            let controller = Arc::clone(&controller);
            async move { controller.triple_permits().acquire().await }
        });

        tokio::task::yield_now().await;
        controller.tick(0.10).await;

        let _presig = timeout(Duration::from_secs(1), presig_waiter)
            .await
            .expect("presig waiter should wake after capacity increase")
            .expect("presig waiter task should succeed");
        assert!(!triple_waiter.is_finished());

        triple_waiter.abort();
    }

    #[tokio::test]
    async fn tick_mixed_active_work_respects_floor() {
        let controller = Arc::new(ConcurrencyController {
            cfg: AdaptiveConcurrencyConfig {
                max_slots: 4,
                initial_slots: 2,
                ..AdaptiveConcurrencyConfig::default()
            },
            desired_slots: Arc::new(AtomicUsize::new(2)),
            arbiter: Arc::new(ConcurrencyArbiter::new(2)),
        });

        let _triple = controller.triple_permits().acquire().await;
        let _presig = controller.presig_permits().acquire().await;

        controller.tick(0.99).await;
        assert_eq!(controller.desired_slots.load(Ordering::Relaxed), 2);
    }
}
