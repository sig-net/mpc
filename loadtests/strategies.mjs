// Arrival-rate strategies, shared by the k6 script and plan.js so that a run is
// sized from the same definitions it is driven by. A plain ES module: k6 and
// Node both import it.

// How long a job holds its address, from the Solana request to the Ethereum
// transaction being buried. Measured on dev: about 48s typically, 73s at the
// slow end, 29s at the fast end.
//
// The pool is sized for slow leases, so it never runs out when they bunch up.
// The busiest address is sized for fast ones, since those let it serve the most
// jobs.
export const SLOW_LEASE_SECONDS = 73;
export const FAST_LEASE_SECONDS = 40;

const constant = (rate, timeUnit) => ({ kind: 'constant', rate, timeUnit });

export const strategies = {
  rpm_1: constant(1, '1m'),
  rpm_6: constant(6, '1m'),
  rps_1: constant(1, '1s'),
  rps_3: constant(3, '1s'),
  rps_10: constant(10, '1s'),
  // The stages of ramp_1_10 in sig-net/mpc's loadtests/k6-load-test.js. A ramp
  // runs its own stages, so a duration does not apply to it.
  ramp_1_10: {
    kind: 'ramp',
    startRate: 1,
    timeUnit: '1s',
    stages: [
      { target: 1, seconds: 180 },
      { target: 2, seconds: 180 },
      { target: 5, seconds: 180 },
      { target: 10, seconds: 180 },
    ],
  },
};

export const parseDuration = text => {
  const match = /^(\d+)([smh])$/.exec(text);
  if (!match) throw new Error(`Duration must look like 30s, 5m or 1h: ${text}`);
  return Number(match[1]) * { s: 1, m: 60, h: 3600 }[match[2]];
};

const perSecond = (rate, timeUnit) => rate / (timeUnit === '1m' ? 60 : 1);

/**
 * What a run will do, for sizing the pinger and funding before it starts.
 *
 * `jobs` is the most it will submit. `addressJobs` is the most the busiest
 * address could serve, which is what funding has to cover. `paths` is the
 * addresses needed to carry the peak rate.
 */
export const planFor = (name, durationSeconds) => {
  const strategy = strategies[name];
  if (!strategy) {
    throw new Error(
      `Unknown strategy: ${name}. Known: ${Object.keys(strategies).join(', ')}`
    );
  }

  let totalSeconds;
  let peakPerSecond;
  let expectedJobs;
  if (strategy.kind === 'ramp') {
    let previous = perSecond(strategy.startRate, strategy.timeUnit);
    totalSeconds = 0;
    peakPerSecond = previous;
    expectedJobs = 0;
    for (const { target, seconds } of strategy.stages) {
      const next = perSecond(target, strategy.timeUnit);
      // The rate moves in a straight line across a stage.
      expectedJobs += ((previous + next) / 2) * seconds;
      totalSeconds += seconds;
      peakPerSecond = Math.max(peakPerSecond, next);
      previous = next;
    }
  } else {
    totalSeconds = durationSeconds;
    peakPerSecond = perSecond(strategy.rate, strategy.timeUnit);
    expectedJobs = peakPerSecond * totalSeconds;
  }

  // One more than the area: an arrival lands at the very start.
  const jobs = Math.ceil(expectedJobs) + 1;
  return {
    totalSeconds,
    peakPerSecond,
    jobs,
    addressJobs: Math.min(jobs, Math.ceil(totalSeconds / FAST_LEASE_SECONDS)),
    paths: Math.max(1, Math.ceil(peakPerSecond * SLOW_LEASE_SECONDS)),
  };
};
