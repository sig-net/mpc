import http from 'k6/http';
import { sleep } from 'k6';

export const options = {
  duration: '1m', // duration of tests
  vus: 100,  // 100 virtual users
  thresholds: {
    http_req_failed: ['rate<0.01'], // http errors should be less than 1%
    http_req_duration: ['p(95)<600'], // 95 percent of response times must be below 600ms
  },
};

export default function () {
  let data_evm = {"contractAddress":"0x69C6b28Fdc74618817fa380De29a653060e14009"} // dev contract EVM
  
  let response_evm = http.post('https://contract-pinger-mainnet-1094058868047.europe-west1.run.app/evm_no_check', JSON.stringify(data_evm), {
    headers: { 'Content-Type': 'application/json' },
  }) 

  let data_sol = {"contractAddress":"<add_sol_contract>"} // dev contract SOL
  
  let response_sol = http.post('https://contract-pinger-mainnet-1094058868047.europe-west1.run.app/solana_no_check', JSON.stringify(data_sol), {
    headers: { 'Content-Type': 'application/json' },
  })

  console.log("EVM: " + response_evm, "SOL: " + response_sol)
}