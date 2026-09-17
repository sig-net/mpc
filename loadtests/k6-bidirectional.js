import http from 'k6/http';
import { check, fail, sleep } from 'k6';
import { Trend, Rate, Counter, Gauge } from 'k6/metrics';

// Each iteration submits and polls one Solana/Midnight -> Ethereum round trip.
// HTTP acceptance alone cannot measure whether the asynchronous job succeeded.

const BASE_URL = __ENV.LT_PINGER_URL || 'https://contract-ping.sig.network';

// Convert service timings to Prometheus seconds without including polling delay.
const SEC = 1000;
const durationMetrics = {
  leaseWaitMs: new Trend('bidi_lease_wait_seconds'),
  signatureMs: new Trend('bidi_signature_seconds'),
  confirmationMs: new Trend('bidi_confirmation_seconds'),
  respondMs: new Trend('bidi_respond_seconds'),
  totalMs: new Trend('bidi_total_seconds'),
};

const workersTotal = new Gauge('bidi_workers_total');
const workersUnderfunded = new Gauge('bidi_workers_underfunded');
const workerBalanceMin = new Gauge('bidi_worker_balance_min_eth');

const success = new Rate('bidi_success');
const completed = new Counter('bidi_completed');

const failures = new Counter('bidi_failures');

const rejectedRate = new Counter('bidi_rejected_rate_limit');
const rejectedCapacity = new Counter('bidi_rejected_capacity');

const pollSeconds = Number(__ENV.LT_POLL_SECONDS || 15);
// Midnight also needs time to prove and submit the caller request.
const jobTimeoutSeconds = Number(__ENV.LT_JOB_TIMEOUT_SECONDS ||
  (__ENV.LT_SOURCE_CHAIN === 'midnight' ? 5400 : 2400));

// Each VU stays busy for a full round trip; gracefulStop lets the last jobs finish.
function arrivalStrategy(rate, preAllocatedVUs, maxVUs) {
  return {
    scenarios: {
      bidirectional: {
        executor: 'constant-arrival-rate',
        rate,
        timeUnit: '1m',
        preAllocatedVUs,
        maxVUs,
        gracefulStop: '45m',
      },
    },
    thresholds: { bidi_success: ['rate>0.95'] },
  };
}

const strategies = {
  // Midnight holds one wallet until completion and must complete at least one job.
  serial: {
    scenarios: {
      bidirectional: {
        executor: 'constant-vus',
        vus: 1,
        gracefulStop: '90m',
      },
    },
    thresholds: {
      bidi_success: ['rate>0.95'],
      bidi_completed: ['count>0'],
    },
  },
  rpm_1: arrivalStrategy(1, 50, 80),
  rpm_6: arrivalStrategy(6, 250, 350),
};

export const options = (() => {
  const key = __ENV.LT_STRATEGY;
  const sourceChain = __ENV.LT_SOURCE_CHAIN || 'solana';
  if (!['solana', 'midnight'].includes(sourceChain)) {
    throw new Error(`Unknown LT_SOURCE_CHAIN: ${sourceChain}`);
  }
  if ((sourceChain === 'midnight') !== (key === 'serial')) {
    throw new Error('Midnight requires LT_STRATEGY=serial; Solana requires an rpm strategy');
  }
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
  const sourceChain = __ENV.LT_SOURCE_CHAIN || 'solana';
  const mode = __ENV.LT_MODE || 'eth_self_transfer';
  const apiKey = __ENV.LT_PINGER_API_KEY;
  if (!env || !apiKey) {
    throw new Error(
      `Missing required environment: LT_CHAIN_ENV=${env}, LT_PINGER_API_KEY=${apiKey ? 'set' : 'unset'}`
    );
  }
  const environments = sourceChain === 'midnight' ? ['stagenet'] : ['dev', 'testnet', 'mainnet'];
  if (!environments.includes(env)) {
    throw new Error(`Unsupported environment ${env} for ${sourceChain}`);
  }
  return { env, mode, apiKey, sourceChain };
};

const headers = apiKey => ({
  'Content-Type': 'application/json',
  'x-api-secret': apiKey,
});

// Refuse to start against a pool that cannot fund Ethereum broadcasts.
export function setup() {
  const { env, apiKey, sourceChain } = config();
  const res = http.get(
    `${BASE_URL}/sign_bidirectional/workers?env=${env}&sourceChain=${sourceChain}`,
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

  // Solana releases workers at confirmation; Midnight holds one until completion.
  const required = sourceChain === 'midnight'
    ? 1
    : strategies[__ENV.LT_STRATEGY].scenarios.bidirectional.rate;
  const funded = workers.length - short.length;
  if (funded < required) {
    fail(
      `${funded}/${workers.length} addresses funded, ${required} needed for ${__ENV.LT_STRATEGY}`
    );
  }
  return { env };
}

export default function () {
  const { sourceChain } = config();
  const started = Date.now();
  try {
    runRoundTrip();
  } finally {
    // A quick failure must not turn the serial canary into a tight retry loop.
    if (sourceChain === 'midnight') {
      const remaining = 60 - (Date.now() - started) / 1000;
      if (remaining > 0) sleep(remaining);
    }
  }
}

function runRoundTrip() {
  const { env, mode, apiKey, sourceChain } = config();
  completed.add(0);

  const submit = http.post(
    `${BASE_URL}/sign_bidirectional`,
    JSON.stringify({ env, mode, sourceChain }),
    { headers: headers(apiKey) }
  );

  // Never retry a 429: it would exceed the configured arrival rate.
  if (submit.status === 429) {
    const limit = submit.json('limit');
    if (limit) {
      rejectedCapacity.add(1, { limit: String(limit) });
    } else {
      rejectedRate.add(1);
    }
    // Only the serial canary counts rejection as failure: it should fit capacity.
    if (sourceChain === 'midnight') success.add(false);
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
    completed.add(1);

    const durations = view.json('durations') || {};
    for (const [field, metric] of Object.entries(durationMetrics)) {
      if (durations[field] !== undefined) metric.add(durations[field] / SEC);
    }

    success.add(state === 'responded');
    if (state === 'failed') {
      const reason = view.json('failureReason') || 'unknown';
      failures.add(1, { reason: String(reason) });
      console.error(`job ${jobId} failed: ${reason} — ${view.json('error')}`);
    }
    return;
  }

  // The driver deadline can expire while the service job is still live.
  success.add(false);
  failures.add(1, { reason: 'driver_timeout' });
  console.error(`job ${jobId} still running after ${jobTimeoutSeconds}s`);
}
