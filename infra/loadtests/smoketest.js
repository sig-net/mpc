import http from 'k6/http';
import { group } from 'k6';

export const options = {
  scenarios: {
    ramping_smoke: {
      executor: 'ramping-arrival-rate',
      startRate: 1,
      timeUnit: '1s',
      preAllocatedVUs: 10,
      maxVUs: 100,
      stages: [
        { duration: '2m', target: 1 },
        { duration: '2m', target: 3 },
        { duration: '2m', target: 1 },
        { duration: '2m', target: 3 },
        { duration: '2m', target: 1 },
      ],
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.03'],
    http_req_duration: ['p(95)<1500'],
  },
};

export default function () {
  group(`${__ENV.ENVIRONMENT} EVM`, function () {
    let evmContract = { "contractAddress": `${__ENV.EVM_CONTRACT}` }
    let response_evm = http.post('https://contract-pinger-mainnet-1094058868047.europe-west1.run.app/evm_no_check', JSON.stringify(evmContract), {
      headers: { 'Content-Type': 'application/json' },
    })
    console.log(`EVM Dev: Status ${response_evm.status}, Body: ${response_evm.body}`);

  })

  group(`${__ENV.ENVIRONMENT} solana`, function () {
    let solContract = { "contractAddress": `${__ENV.SOL_CONTRACT}` }
    let response_sol = http.post('https://contract-pinger-mainnet-1094058868047.europe-west1.run.app/solana_no_check', JSON.stringify(solContract), {
      headers: { 'Content-Type': 'application/json' },
    })
    console.log(`SOL Dev: Status ${response_sol.status}, Body: ${response_sol.body}`);
  });
}