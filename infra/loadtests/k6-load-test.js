import http from 'k6/http';
import { group } from 'k6';

const PINGER_URL = "https://contract-pinger-mainnet-1094058868047.europe-west1.run.app/ping";

const strategies = {
  constant_low_rate_1h: {
    scenarios: {
      ramping_smoke: {
        executor: 'ramping-arrival-rate',
        startRate: 1,
        timeUnit: '5m',
        preAllocatedVUs: 1,
        maxVUs: 10,
        stages: [
          { duration: '1m', target: 1 },
          { duration: '58m', target: 1 },
          { duration: '1m', target: 0 },
        ],
      },
    },
    thresholds: {
      http_req_failed: ['rate<0.03'],
      http_req_duration: ['p(95)<1500'],
    },
  },
  constant_medium_rate_1h: {
    scenarios: {
      ramping_smoke: {
        executor: 'ramping-arrival-rate',
        startRate: 1,
        timeUnit: '10s',
        preAllocatedVUs: 2,
        maxVUs: 10,
        stages: [
          { duration: '1m', target: 1 },
          { duration: '58m', target: 3 },
          { duration: '1m', target: 1 },
        ],
      },
    },
    thresholds: {
      http_req_failed: ['rate<0.03'],
      http_req_duration: ['p(95)<1500'],
    },
  },
  constant_high_rate_1h: {
    scenarios: {
      ramping_smoke: {
        executor: 'ramping-arrival-rate',
        startRate: 1,
        timeUnit: '1s',
        preAllocatedVUs: 5,
        maxVUs: 20,
        stages: [
          { duration: '1m', target: 2 },
          { duration: '58m', target: 5 },
          { duration: '1m', target: 2 },
        ],
      },
    },
    thresholds: {
      http_req_failed: ['rate<0.03'],
      http_req_duration: ['p(95)<1500'],
    },
  },
  ramping_low_rate_1h: {
    scenarios: {
      ramping_smoke: {
        executor: 'ramping-arrival-rate',
        startRate: 0,
        timeUnit: '1m',
        preAllocatedVUs: 1,
        maxVUs: 10,
        stages: [
          { duration: '10m', target: 1 },
          { duration: '10m', target: 3 },
          { duration: '10m', target: 1 },
          { duration: '10m', target: 3 },
          { duration: '10m', target: 1 },
          { duration: '10m', target: 0 },
        ],
      },
    },
    thresholds: {
      http_req_failed: ['rate<0.03'],
      http_req_duration: ['p(95)<1500'],
    },
  },
  ramping_medium_rate_1h: {
    scenarios: {
      ramping_smoke: {
        executor: 'ramping-arrival-rate',
        startRate: 1,
        timeUnit: '1s',
        preAllocatedVUs: 5,
        maxVUs: 50,
        stages: [
          { duration: '10m', target: 1 },
          { duration: '10m', target: 3 },
          { duration: '10m', target: 1 },
          { duration: '10m', target: 3 },
          { duration: '10m', target: 1 },
          { duration: '10m', target: 0 },
        ],
      },
    },
    thresholds: {
      http_req_failed: ['rate<0.03'],
      http_req_duration: ['p(95)<1500'],
    },
  },
  ramping_high_rate_1h: {
    scenarios: {
      ramping_smoke: {
        executor: 'ramping-arrival-rate',
        startRate: 1,
        timeUnit: '1s',
        preAllocatedVUs: 20,
        maxVUs: 100,
        stages: [
          { duration: '10m', target: 1 },
          { duration: '10m', target: 2 },
          { duration: '10m', target: 3 },
          { duration: '10m', target: 4 },
          { duration: '10m', target: 5 },
          { duration: '10m', target: 0 },
        ],
      },
    },
    thresholds: {
      http_req_failed: ['rate<0.03'],
      http_req_duration: ['p(95)<1500'],
    },
  },
};

export const options = strategies[__ENV.LT_STRATEGY] || (() => {
  throw new Error(`Invalid or missing LT_STRATEGY environment variable: ${__ENV.LT_STRATEGY}`);
})();


export default function () {
  let chain = __ENV.LT_CHAIN;
  let env = __ENV.LT_CHAIN_ENV;
  let check = __ENV.LT_CHECK_SIGNATURE === 'true'; // Convert string to boolean

  if (!chain || !env || !check) {
    console.error(`One or more required environment variables are not set: chain ${chain}, env ${env}, check ${check}`);
    throw new Error("Missing required environment variables. Exiting script.");
  }

  let params = JSON.stringify({
    chain: chain,
    env: env,
    check: check,
  });

  console.log(`Sending request to ${PINGER_URL} with params: ${params}`);

  let response = http.post(PINGER_URL, params, {
    headers: {
      'Content-Type': 'application/json',
      'x-api-secret': __ENV.LT_PINGER_API_KEY || 'default-secret-key',
    },
  });

  if (response.status >= 200 && response.status < 300) {
    console.log(`Status ${response.status}, Body: ${response.body}`);
  } else {
    console.error(`Request failed with status ${response.status}, Body: ${response.body}`);
  }
}