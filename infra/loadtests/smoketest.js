import http from 'k6/http';
import { group } from 'k6';

export const options = {
  stages: [
    { duration: '2m', target: 1},  // 1 virtual users
    { duration: '2m', target: 3},
    { duration: '2m', target: 1},
    { duration: '2m', target: 3},
    { duration: '2m', target: 1},
  ],
  thresholds: {
    http_req_failed: ['rate<0.01'], // http errors should be less than 1%
    http_req_duration: ['p(95)<1500'], // 95 percent of response times must be below 1500ms
  },
};

export default function () {
  group(`${__ENV.ENVIRONMENT} EVM`, function() {
    let evmContract = {"contractAddress":`${__ENV.EVM_CONTRACT}`} // dev contract EVM
    
    let response_evm = http.post('https://contract-pinger-mainnet-1094058868047.europe-west1.run.app/evm_no_check', JSON.stringify(evmContract), {
      headers: { 'Content-Type': 'application/json' },
    }) 
    console.log("EVM Dev: " + response_evm)

  })

  group(`${__ENV.ENVIRONMENT} solana`, function() {
    let solContract = {"contractAddress":`${__ENV.SOL_CONTRACT}`} // dev contract SOL
    
    let response_sol = http.post('https://contract-pinger-mainnet-1094058868047.europe-west1.run.app/solana_no_check', JSON.stringify(solContract), {
      headers: { 'Content-Type': 'application/json' },
    })
  
    console.log("SOL Dev: " + response_sol)
  });
}