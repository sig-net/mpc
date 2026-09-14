import http from 'k6/http';
import { check, fail, sleep } from 'k6';
import { Trend, Rate, Counter, Gauge } from 'k6/metrics';

// Load test for the Solana -> Ethereum bidirectional round trip.
//
// POST /sign_bidirectional answers 202 with a job id in milliseconds and the
// round trip settles tens of minutes later, so thresholds on the built-in HTTP
// metrics would pass while every round trip failed. One iteration is one round
// trip: submit, then poll until the job reaches a terminal state.

const BASE_URL = __ENV.LT_PINGER_URL || 'https://contract-ping.sig.network';

// The service's own phase timings, not wall-clock around our polling, which
// would fold the poll interval into whichever phase ended between two polls.
//
// Seconds, not the milliseconds the API returns: Prometheus expects base units.
// That costs the summary's "17m30s" formatting, which only applies to ms.
const SEC = 1000;
const leaseWait = new Trend('bidi_lease_wait_seconds');
const signature = new Trend('bidi_signature_seconds');
const confirmation = new Trend('bidi_confirmation_seconds');
const respond = new Trend('bidi_respond_seconds');
const total = new Trend('bidi_total_seconds');

// Read once in setup(): the pool a run actually ran against, rather than a log
// line nothing can query later.
const workersTotal = new Gauge('bidi_workers_total');
const workersUnderfunded = new Gauge('bidi_workers_underfunded');
const workerBalanceMin = new Gauge('bidi_worker_balance_min_eth');

const success = new Rate('bidi_success');

// Tagged with the service's own failure reason: respond_timeout and
// all_workers_underfunded call for different remedies.
const failures = new Counter('bidi_failures');

// A rejection is not a failed round trip — the job never started — so a
// saturated service does not read as a broken one.
const rejectedRate = new Counter('bidi_rejected_rate_limit');
const rejectedCapacity = new Counter('bidi_rejected_capacity');

const pollSeconds = Number(__ENV.LT_POLL_SECONDS || 15);
const jobTimeoutSeconds = Number(__ENV.LT_JOB_TIMEOUT_SECONDS || 2400);

// Rates are per minute because the service caps arrivals at ten a minute;
// above that this would measure the 429 handler.
//
// preAllocatedVUs follows from Little's law — a VU is held for the whole round
// trip — so 1/min against a ~35 minute trip is ~35 VUs busy at steady state.
//
// gracefulStop is what lets the last jobs finish; the default 30s would
// discard most of the run's respond measurements.
const strategies = {
  rpm_1: {
    scenarios: {
      bidirectional: {
        executor: 'constant-arrival-rate',
        rate: 1,
        timeUnit: '1m',
        preAllocatedVUs: 50,
        maxVUs: 80,
        gracefulStop: '45m',
      },
    },
    // Only the success rate is asserted: a count threshold cannot tell four
    // failures out of four from four out of four hundred.
    thresholds: {
      bidi_success: ['rate>0.95'],
    },
  },
  rpm_6: {
    scenarios: {
      bidirectional: {
        executor: 'constant-arrival-rate',
        rate: 6,
        timeUnit: '1m',
        preAllocatedVUs: 250,
        maxVUs: 350,
        gracefulStop: '45m',
      },
    },
    thresholds: {
      bidi_success: ['rate>0.95'],
    },
  },
};

export const options = (() => {
  const key = __ENV.LT_STRATEGY;
  if (!key) {
    throw new Error(
      `Missing LT_STRATEGY. Known strategies: ${Object.keys(strategies).join(', ')}`
    );
  }
  const base = strategies[key];
  if (!base) {
    throw new Error(
      `Unknown LT_STRATEGY: ${key}. Known: ${Object.keys(strategies).join(', ')}`
    );
  }
  // Deep clone so setting the duration does not mutate the shared table.
  const opts = JSON.parse(JSON.stringify(base));
  const duration = __ENV.LT_DURATION || '1h';
  for (const name of Object.keys(opts.scenarios)) {
    opts.scenarios[name].duration = duration;
  }
  return opts;
})();

const config = () => {
  const env = __ENV.LT_CHAIN_ENV;
  // Not a CI input: the modes differ only in gas and in whether the respond
  // value is decoded or synthesized, neither of which this test measures.
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
 * Refuse to start against a pool that cannot broadcast.
 *
 * Every job spends gas from a derived address, and an underfunded pool fails
 * each one in seconds — otherwise reported only after an hour of submissions.
 */
export function setup() {
  const { env, apiKey } = config();
  const res = http.get(
    `${BASE_URL}/sign_bidirectional/workers?env=${env}`,
    { headers: headers(apiKey) }
  );

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
  for (const w of short) {
    console.warn(`  underfunded: ${w.path} ${w.address} holds ${w.balanceWei} wei`);
  }

  // Any shortfall, not merely a total one: the address count sets concurrency,
  // so a partly funded pool measures a narrower pool than the run claims.
  if (short.length > 0) {
    fail(
      `${short.length}/${workers.length} addresses underfunded; fund them before running`
    );
  }
  return { env };
}

export default function () {
  const { env, mode, apiKey } = config();

  const submit = http.post(
    `${BASE_URL}/sign_bidirectional`,
    JSON.stringify({ env, mode }),
    { headers: headers(apiKey) }
  );

  // 429 is a healthy service saying it is full. Not retried: retrying inside
  // an iteration would silently exceed the arrival rate being tested.
  if (submit.status === 429) {
    const limit = submit.json('limit');
    if (limit) {
      rejectedCapacity.add(1, { limit: String(limit) });
    } else {
      rejectedRate.add(1);
    }
    return;
  }

  const accepted = check(submit, {
    'submit accepted (202)': r => r.status === 202,
    'submit returned a jobId': r => !!r.json('jobId'),
  });
  if (!accepted) {
    failures.add(1, { reason: `submit_${submit.status}` });
    success.add(false);
    console.error(`submit failed: ${submit.status} ${submit.body}`);
    return;
  }

  const jobId = submit.json('jobId');
  const deadline = Date.now() + jobTimeoutSeconds * 1000;

  while (Date.now() < deadline) {
    sleep(pollSeconds);

    const view = http.get(`${BASE_URL}/sign_bidirectional/${jobId}`, {
      headers: headers(apiKey),
      tags: { name: 'GET /sign_bidirectional/{jobId}' },
    });
    if (view.status !== 200) {
      // A poll can fail transiently without the job being lost.
      console.warn(`poll ${jobId}: ${view.status}`);
      continue;
    }

    const state = view.json('state');
    if (state !== 'responded' && state !== 'failed') continue;

    const d = view.json('durations') || {};
    if (d.leaseWaitMs !== undefined) leaseWait.add(d.leaseWaitMs / SEC);
    if (d.signatureMs !== undefined) signature.add(d.signatureMs / SEC);
    if (d.confirmationMs !== undefined) confirmation.add(d.confirmationMs / SEC);
    if (d.respondMs !== undefined) respond.add(d.respondMs / SEC);
    if (d.totalMs !== undefined) total.add(d.totalMs / SEC);

    if (state === 'responded') {
      success.add(true);
    } else {
      const reason = view.json('failureReason') || 'unknown';
      success.add(false);
      failures.add(1, { reason: String(reason) });
      console.error(`job ${jobId} failed: ${reason} — ${view.json('error')}`);
    }
    return;
  }

  // Distinct from the service's own respond_timeout: this is the driver giving
  // up while the job may still be live, so it judges LT_JOB_TIMEOUT_SECONDS.
  success.add(false);
  failures.add(1, { reason: 'driver_timeout' });
  console.error(`job ${jobId} still running after ${jobTimeoutSeconds}s`);
}
