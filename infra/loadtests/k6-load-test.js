import http from 'k6/http';
import { check } from 'k6';

const PINGER_URL = "https://contract-ping.sig.network/ping";

const strategies = {
  "rps_0_1": {
    scenarios: {
      smoke: {
        executor: 'constant-arrival-rate',
        rate: 1,
        timeUnit: '10s',
        preAllocatedVUs: 2,
        maxVUs: 10,
      },
    },
    thresholds: {
      http_req_failed: ['rate<0.03'],
      http_req_duration: ['p(95)<10000'],
    },
  },
  "rps_1": {
    scenarios: {
      smoke: {
        executor: 'constant-arrival-rate',
        rate: 1,
        timeUnit: '1s',
        preAllocatedVUs: 5,
        maxVUs: 50,
      },
    },
    thresholds: {
      http_req_failed: ['rate<0.03'],
      http_req_duration: ['p(95)<10000'],
    },
  },
  "rps_5": {
    scenarios: {
      smoke: {
        executor: 'constant-arrival-rate',
        rate: 5,
        timeUnit: '1s',
        preAllocatedVUs: 20,
        maxVUs: 100,
      },
    },
    thresholds: {
      http_req_failed: ['rate<0.03'],
      http_req_duration: ['p(95)<10000'],
    },
  },
  "rps_10": {
    scenarios: {
      smoke: {
        executor: 'constant-arrival-rate',
        rate: 10,
        timeUnit: '1s',
        preAllocatedVUs: 40,
        maxVUs: 200,
      },
    },
    thresholds: {
      http_req_failed: ['rate<0.03'],
      http_req_duration: ['p(95)<10000'],
    },
  },

};

export const options = (() => {
  const key = __ENV.LT_STRATEGY;
  if (!key) {
    throw new Error(`Invalid or missing LT_STRATEGY environment variable: ${__ENV.LT_STRATEGY}`);
  }
  const base = strategies[key];
  if (!base) {
    throw new Error(`Unknown LT_STRATEGY: ${key}`);
  }
  const duration = __ENV.LT_DURATION || '1h';
  // Deep clone to avoid mutating the shared `strategies` object
  const opts = JSON.parse(JSON.stringify(base));
  for (const scen of Object.keys(opts.scenarios || {})) {
    opts.scenarios[scen].duration = duration;
  }
  return opts;
})();


export default function () {
  let chain = __ENV.LT_CHAIN;
  let env = __ENV.LT_CHAIN_ENV;
  // LT_CHECK_SIGNATURE should be provided as the literal string 'true' or 'false'.
  // Validate presence separately from its boolean value so that a deliberate 'false' is accepted.
  let checkRaw = __ENV.LT_CHECK_SIGNATURE;
  if (chain == null || env == null || checkRaw == null) {
    console.error(`One or more required environment variables are not set: chain ${chain}, env ${env}, check ${checkRaw}`);
    throw new Error("Missing required environment variables. Exiting script.");
  }
  let checkSignature = checkRaw === 'true';

  let params = JSON.stringify({
    chain: chain,
    env: env,
    check: checkSignature,
  });

  console.log(`Sending request to ${PINGER_URL} with params: ${params}`);

  let response = http.post(PINGER_URL, params, {
    headers: {
      'Content-Type': 'application/json',
      'x-api-secret': __ENV.LT_PINGER_API_KEY || 'default-secret-key',
    },
  });

  // Validate response content and status. Mark run as failed on critical validation failure.
  const ok = check(response, {
    'status is 2xx': (r) => r.status >= 200 && r.status < 300,
    'body not empty': (r) => !!(r.body && r.body.length > 0),
  });

  if (!ok) {
    console.error(`Validation failed for response. status=${response.status}, body=${response.body}`);
    fail(`Critical validation failed for k6 run (status ${response.status})`);
  }

  // Minimal success logging to avoid noisy CI logs for long runs
  console.log(`Status ${response.status}`);
}