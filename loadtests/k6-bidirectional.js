import http from 'k6/http';
import { check, fail, sleep } from 'k6';
import exec from 'k6/execution';
import { Trend, Rate, Counter, Gauge } from 'k6/metrics';
import { parseDuration, planFor, strategies } from './strategies.mjs';

// Load test for the Solana -> Ethereum bidirectional round trip.
//
// A round trip lasts about twenty minutes, so a VU per job would need thousands
// at a few jobs a second. Two scenarios avoid that:
//
//   submit   POSTs at the strategy's arrival rate, each tagged with this run's id.
//            An iteration lasts milliseconds, so a few VUs cover the rate.
//   collect  one VU paging /sign_bidirectional/runs/:runId for settled jobs,
//            recording per-job metrics, until none of the run's jobs are live.
//
// Thresholds on the built-in HTTP metrics would pass while every round trip
// failed, so only the round-trip success rate is asserted.

// For local runs; the workflows set it.
const BASE_URL = __ENV.LT_PINGER_URL || 'http://localhost:3001';

// The service's own phase timings, not wall-clock around our polling.
// Seconds, not the milliseconds the API returns: Prometheus expects base units.
const SEC = 1000;
const leaseWait = new Trend('bidi_lease_wait_seconds');
const signature = new Trend('bidi_signature_seconds');
const confirmation = new Trend('bidi_confirmation_seconds');
const respond = new Trend('bidi_respond_seconds');
const total = new Trend('bidi_total_seconds');

const workersTotal = new Gauge('bidi_workers_total');
const workersUnderfunded = new Gauge('bidi_workers_underfunded');
const workerBalanceMin = new Gauge('bidi_worker_balance_min_eth');

const success = new Rate('bidi_success');
// Tagged with the service's own failure reason.
const failures = new Counter('bidi_failures');

// A rejection is not a failed round trip — the job never started. Tagged with
// which capacity ceiling was hit.
const rejectedCapacity = new Counter('bidi_rejected_capacity');

// Events the shared Solana poller dropped because it fell behind. Non-zero
// means respond timeouts in this run may be the driver's RPC, not the MPC.
const pollerExpired = new Gauge('bidi_solana_expired_transactions');
const pollerEvicted = new Gauge('bidi_solana_evicted_transactions');

const pollSeconds = Number(__ENV.LT_POLL_SECONDS || 10);
const jobTimeoutSeconds = Number(__ENV.LT_JOB_TIMEOUT_SECONDS || 2400);

const strategyName = __ENV.LT_STRATEGY;
const known = Object.keys(strategies).join(', ');
if (!strategyName) {
  throw new Error(`Missing LT_STRATEGY. Known strategies: ${known}`);
}
if (!strategies[strategyName]) {
  throw new Error(`Unknown LT_STRATEGY: ${strategyName}. Known: ${known}`);
}
const strategy = strategies[strategyName];

// Default short: at rps_10 an hour is 36,000 round trips and their gas.
const plan = planFor(strategyName, parseDuration(__ENV.LT_DURATION || '5m'));

// A VU is held only for the POST, so the pools are small; maxVUs covers a
// slow service, not a long round trip.
const vus = {
  preAllocatedVUs: Math.max(2, Math.ceil(plan.peakPerSecond * 2)),
  maxVUs: Math.max(10, Math.ceil(plan.peakPerSecond * 15)),
};

const submitScenario =
  strategy.kind === 'ramp'
    ? {
        executor: 'ramping-arrival-rate',
        startRate: strategy.startRate,
        timeUnit: strategy.timeUnit,
        stages: strategy.stages.map(({ target, seconds }) => ({
          target,
          duration: `${seconds}s`,
        })),
        ...vus,
      }
    : {
        executor: 'constant-arrival-rate',
        rate: strategy.rate,
        timeUnit: strategy.timeUnit,
        duration: `${plan.totalSeconds}s`,
        ...vus,
      };

export const options = {
  scenarios: {
    submit: { exec: 'submit', ...submitScenario },
    collect: {
      executor: 'per-vu-iterations',
      exec: 'collect',
      vus: 1,
      iterations: 1,
      // Submission, then the slowest job's whole budget, then slack for the
      // final pages.
      maxDuration: `${plan.totalSeconds + jobTimeoutSeconds + 300}s`,
    },
  },
  thresholds: {
    // A rate that is not met is not the rate being tested. k6 drops an arrival
    // when no VU is free, and nothing else would show it.
    dropped_iterations: ['count==0'],
    // The success rate, not a failure count: a count cannot tell four failures
    // out of four from four out of four hundred.
    bidi_success: ['rate>0.95'],
  },
};

const config = () => {
  const env = __ENV.LT_CHAIN_ENV;
  const mode = __ENV.LT_MODE || 'eth_self_transfer';
  const apiKey = __ENV.LT_PINGER_API_KEY;
  if (!env || !apiKey) {
    throw new Error(
      `Missing required environment: LT_CHAIN_ENV=${env}, LT_PINGER_API_KEY=${apiKey ? 'set' : 'unset'}`
    );
  }
  return { env, mode, apiKey };
};

const headers = apiKey => ({
  'Content-Type': 'application/json',
  'x-api-secret': apiKey,
});

/**
 * Refuse to start against a pool that cannot carry the rate, and mint the run
 * id every job is tagged with so the collector sees only this run's jobs.
 */
export function setup() {
  const { env, apiKey } = config();
  const res = http.get(`${BASE_URL}/sign_bidirectional/workers?env=${env}`, {
    headers: headers(apiKey),
  });
  if (res.status !== 200) {
    fail(`Could not read worker funding: ${res.status} ${res.body}`);
  }

  const workers = res.json('workers') || [];
  const short = workers.filter(w => w.underfunded);

  // Before the shortfall check, so an aborted run still records how short.
  const balances = workers.map(w => Number(w.balanceWei) / 1e18);
  workersTotal.add(workers.length);
  workersUnderfunded.add(short.length);
  if (balances.length > 0) workerBalanceMin.add(Math.min(...balances));

  console.log(
    `${workers.length} derived addresses, ${short.length} below the minimum`
  );
  // Bounded: an 800-address pool would otherwise bury the summary.
  for (const w of short.slice(0, 20)) {
    console.warn(
      `  underfunded: ${w.path} ${w.address} holds ${w.balanceWei} wei`
    );
  }
  if (short.length > 20) console.warn(`  ...and ${short.length - 20} more`);

  // Each job holds its address until its transaction is buried, so the pool
  // has to cover the peak rate. The service skips short addresses rather than
  // failing on them, so only funded ones count.
  const funded = workers.length - short.length;
  if (funded < plan.paths) {
    fail(
      `${funded}/${workers.length} addresses funded, ${plan.paths} needed at ` +
        `${plan.peakPerSecond}/s (raise SIG_BIDIRECTIONAL_PATHS and fund them)`
    );
  }

  const runId = `k6-${strategyName}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  console.log(`run id ${runId}`);

  // Read now so a restart at any point after this is visible: the pinger keeps
  // jobs in memory, and a restarted one reports a run it has never heard of as
  // simply empty.
  const run = http.get(`${BASE_URL}/sign_bidirectional/runs/${runId}`, {
    headers: headers(apiKey),
  });
  if (run.status !== 200) {
    fail(`Could not read the pinger's start time: ${run.status} ${run.body}`);
  }
  return { runId, startedAt: run.json('startedAt') };
}

export function submit({ runId }) {
  const { env, mode, apiKey } = config();
  const res = http.post(
    `${BASE_URL}/sign_bidirectional`,
    JSON.stringify({ env, mode, runId }),
    { headers: headers(apiKey) }
  );

  // 429 is a healthy service saying it is full. Not retried: retrying inside
  // an iteration would silently exceed the arrival rate being tested.
  if (res.status === 429) {
    rejectedCapacity.add(1, { limit: String(res.json('limit')) });
    return;
  }

  const accepted = check(res, {
    'submit accepted (202)': r => r.status === 202,
    'submit returned a jobId': r => !!r.json('jobId'),
  });
  if (!accepted) {
    failures.add(1, { reason: `submit_${res.status}` });
    success.add(false);
    console.error(`submit failed: ${res.status} ${res.body}`);
  }
}

const record = job => {
  const d = job.durations || {};
  if (d.leaseWaitMs !== undefined) leaseWait.add(d.leaseWaitMs / SEC);
  if (d.signatureMs !== undefined) signature.add(d.signatureMs / SEC);
  if (d.confirmationMs !== undefined) confirmation.add(d.confirmationMs / SEC);
  if (d.respondMs !== undefined) respond.add(d.respondMs / SEC);
  if (d.totalMs !== undefined) total.add(d.totalMs / SEC);

  if (job.state === 'responded') {
    success.add(true);
    return;
  }
  const reason = job.failureReason || 'unknown';
  success.add(false);
  failures.add(1, { reason: String(reason) });
  console.error(`job ${job.id} failed: ${reason} — ${job.error}`);
};

export function collect({ runId, startedAt }) {
  const { apiKey } = config();
  // Both scenarios start together, so submission ends one duration from now.
  const submitEndsAt = Date.now() + plan.totalSeconds * 1000;
  const deadline = submitEndsAt + jobTimeoutSeconds * 1000;
  let cursor = 0;
  let live = 0;
  let accepted = 0;
  let recorded = 0;

  for (;;) {
    sleep(pollSeconds);
    const res = http.get(
      `${BASE_URL}/sign_bidirectional/runs/${runId}?finishedAfter=${cursor}`,
      {
        headers: headers(apiKey),
        tags: { name: 'GET /sign_bidirectional/runs/{runId}' },
      }
    );
    // Only parsing can throw. A bad page is skipped and the cursor holds, so the
    // next poll fetches it again; recording happens after, so nothing is
    // recorded twice.
    let body;
    try {
      body = res.status === 200 ? res.json() : undefined;
    } catch (error) {
      console.warn(`collect ${runId}: unreadable page: ${error}`);
    }
    if (body) {
      if (body.startedAt !== startedAt) {
        exec.test.abort(
          `the pinger restarted during the run; its jobs are gone (${recorded}/${accepted} recorded)`
        );
      }
      for (const job of body.finished) record(job);
      recorded += body.finished.length;
      cursor = body.cursor;
      live = body.live;
      accepted = body.accepted;
      // Grace past the end of submission, for POSTs still in flight then.
      if (Date.now() > submitEndsAt + 30_000 && live === 0) break;
    } else if (res.status !== 200) {
      console.warn(`collect ${runId}: ${res.status}`);
    }
    if (Date.now() > deadline) {
      // The driver giving up while jobs may still be live, distinct from the
      // service's own respond_timeout: this judges LT_JOB_TIMEOUT_SECONDS.
      for (let i = 0; i < live; i++) success.add(false);
      if (live > 0) {
        failures.add(live, { reason: 'driver_timeout' });
        console.error(`${live} jobs still running after ${jobTimeoutSeconds}s`);
      }
      recorded += live;
      break;
    }
  }

  const polling = http.get(`${BASE_URL}/polling`, { headers: headers(apiKey) });
  if (polling.status === 200) {
    const pollers = polling.json('solana') || [];
    pollerExpired.add(
      pollers.reduce((n, p) => n + (p.expiredTransactions || 0), 0)
    );
    pollerEvicted.add(
      pollers.reduce((n, p) => n + (p.evictedTransactions || 0), 0)
    );
  }

  // Every job the pinger accepted must have been recorded, or counted as a
  // driver timeout above. A shortfall means jobs were dropped before they
  // could be collected, which no success rate would show.
  if (recorded < accepted) {
    exec.test.abort(
      `${accepted - recorded}/${accepted} jobs were never collected; raise SIG_BIDIRECTIONAL_RETAINED_JOBS to at least the run's job count`
    );
  }
}
