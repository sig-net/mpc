import http from 'k6/http';
import { check, fail, sleep } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

// Load test for the Solana -> Ethereum bidirectional round trip.
//
// Separate from k6-load-test.js because the endpoint is asynchronous. /ping
// answers with the finished sign request, so http_req_duration measures it;
// POST /sign_bidirectional answers 202 with a job id in milliseconds and the
// round trip settles tens of minutes later. Thresholds on the built-in HTTP
// metrics would pass while every round trip failed, so everything worth
// asserting here is a custom metric fed by the job's own record.
//
// One iteration is one round trip: submit, then poll until the job reaches a
// terminal state. Iterations are therefore long — budget for the respond leg,
// not for an HTTP call.

const BASE_URL = __ENV.LT_PINGER_URL || 'https://contract-ping.sig.network';

// The service reports its own phase timings, so these are its numbers rather
// than wall-clock around our polling, which would fold the poll interval into
// whichever phase happened to end between two polls.
const leaseWait = new Trend('bidi_lease_wait_ms', true);
const signature = new Trend('bidi_signature_ms', true);
const confirmation = new Trend('bidi_confirmation_ms', true);
const respond = new Trend('bidi_respond_ms', true);
const total = new Trend('bidi_total_ms', true);

const success = new Rate('bidi_success');

// Failures carry the service's own reason as a tag. The twelve reasons are
// distinct diagnoses — a respond_timeout is the MPC not reading results back,
// all_workers_underfunded is a treasury problem — and collapsing them into an
// error count loses the only part that says what to do next.
const failures = new Counter('bidi_failures');

// A rejection is not a failed round trip: the job never started. Kept apart so
// a saturated service does not read as a broken one, and split by cause, since
// the arrival cap and the capacity ceilings call for different remedies.
const rejectedRate = new Counter('bidi_rejected_rate_limit');
const rejectedCapacity = new Counter('bidi_rejected_capacity');

const pollSeconds = Number(__ENV.LT_POLL_SECONDS || 15);
const jobTimeoutSeconds = Number(__ENV.LT_JOB_TIMEOUT_SECONDS || 2400);

// The service caps arrivals at ten a minute and rejects the rest, so rates are
// expressed per minute here rather than per second. Anything above that cap
// measures the 429 handler instead of the flow.
//
// preAllocatedVUs follows from Little's law: a VU is held for the whole round
// trip, so concurrency is arrival rate times round-trip duration. At 1/min
// against a ~35 minute trip that is ~35 VUs busy at steady state.
//
// gracefulStop is what lets the last jobs finish. k6 abandons running
// iterations shortly after the duration elapses, and with a round trip this
// long the default 30s would discard most of the run's respond measurements —
// so a test configured for 1h occupies the runner for rather longer.
const strategies = {
  rate_1_min: {
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
    // Only the success rate is asserted. A count threshold cannot tell four
    // failures out of four from four out of four hundred, so it passes exactly
    // when a short run has gone entirely wrong. bidi_failures stays a counter,
    // read by its reason tag rather than gated on.
    thresholds: {
      bidi_success: ['rate>0.95'],
    },
  },
  rate_6_min: {
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
 * each one in seconds. Without this the run still reports that, but only after
 * an hour of submissions and as a wall of failures rather than one line.
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
  console.log(
    `${workers.length} derived addresses, ${short.length} below the minimum`
  );
  for (const w of short) {
    console.warn(`  underfunded: ${w.path} ${w.address} holds ${w.balanceWei} wei`);
  }

  // Any shortfall, not merely a total one: the address count sets concurrency,
  // so a partly funded pool quietly measures a narrower pool at a lower
  // arrival rate than the run claims to be applying.
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

  // 429 is a healthy service saying it is full. Recorded and abandoned rather
  // than retried: the arrival rate is the scenario's to control, and retrying
  // inside an iteration would silently exceed the rate being tested.
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
      // A poll can fail transiently without the job being lost, so keep
      // polling until the deadline rather than abandoning a live round trip.
      console.warn(`poll ${jobId}: ${view.status}`);
      continue;
    }

    const state = view.json('state');
    if (state !== 'responded' && state !== 'failed') continue;

    const d = view.json('durations') || {};
    if (d.leaseWaitMs !== undefined) leaseWait.add(d.leaseWaitMs);
    if (d.signatureMs !== undefined) signature.add(d.signatureMs);
    if (d.confirmationMs !== undefined) confirmation.add(d.confirmationMs);
    if (d.respondMs !== undefined) respond.add(d.respondMs);
    if (d.totalMs !== undefined) total.add(d.totalMs);

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
  // up while the job may still be live, which is a statement about
  // LT_JOB_TIMEOUT_SECONDS rather than about the flow.
  success.add(false);
  failures.add(1, { reason: 'driver_timeout' });
  console.error(`job ${jobId} still running after ${jobTimeoutSeconds}s`);
}
