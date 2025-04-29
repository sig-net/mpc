import http from 'k6/http';
import { group } from 'k6';

export const options = {
  scenarios: {
    spiky_rps: {
      executor: 'ramping-arrival-rate', // docs: https://grafana.com/docs/k6/latest/using-k6/scenarios/executors/ramping-arrival-rate/
      startRate: 1, // Start with 1 request per second
      timeUnit: '1s', // Time unit for the rate
      preAllocatedVUs: 10, // Pre-allocated virtual users
      maxVUs: 100, // Maximum virtual users allowed
      stages: [
        // 20m time periods with rolling ramp up and down
        { duration: '10m', target: 1 },
        { duration: '1m', target: 2 },
        { duration: '8m', target: 2 },
        { duration: '1m', target: 1 },

        { duration: '10m', target: 1 },
        { duration: '1m', target: 3 },
        { duration: '8m', target: 3 },
        { duration: '1m', target: 1 },

        { duration: '10m', target: 1 },
        { duration: '1m', target: 4 },
        { duration: '8m', target: 4 },
        { duration: '1m', target: 1 },

        { duration: '10m', target: 1 },
        { duration: '1m', target: 5 },
        { duration: '8m', target: 5 },
        { duration: '1m', target: 1 },

        { duration: '10m', target: 1 },
        { duration: '1m', target: 4 },
        { duration: '8m', target: 4 },
        { duration: '1m', target: 1 },

        { duration: '10m', target: 1 },
        { duration: '1m', target: 3 },
        { duration: '8m', target: 3 },
        { duration: '1m', target: 1 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.03'], // http errors should be less than 3%
    http_req_duration: ['p(95)<1500'], // 95% of response times must be below 1500ms
  },
};

export default function () {
  group(`${__ENV.ENVIRONMENT} EVM`, function () {
    let evmContract = { "contractAddress": `${__ENV.EVM_CONTRACT}` } // dev contract EVM

    let response_evm = http.post('https://contract-pinger-mainnet-1094058868047.europe-west1.run.app/evm_no_check', JSON.stringify(evmContract), {
      headers: { 'Content-Type': 'application/json' },
    })
    console.log(`EVM Dev: Status ${response_evm.status}, Body: ${response_evm.body}`);

  })

  group(`${__ENV.ENVIRONMENT} solana`, function () {
    let solContract = { "contractAddress": `${__ENV.SOL_CONTRACT}` } // dev contract SOL

    let response_sol = http.post('https://contract-pinger-mainnet-1094058868047.europe-west1.run.app/solana_no_check', JSON.stringify(solContract), {
      headers: { 'Content-Type': 'application/json' },
    })

    console.log(`SOL Dev: Status ${response_sol.status}, Body: ${response_sol.body}`);
  });
}