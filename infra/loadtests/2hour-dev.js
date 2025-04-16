import http from 'k6/http';
import { group } from 'k6';

export const options = {
  stages: [
    { duration: '10m', target: 1},  // 1 virtual users
    { duration: '10m', target: 2},
    { duration: '10m', target: 1},
    { duration: '10m', target: 3},
    { duration: '10m', target: 1},
    { duration: '10m', target: 4},
    { duration: '10m', target: 1},
    { duration: '10m', target: 5},
    { duration: '10m', target: 1},
    { duration: '10m', target: 6},
  ],
  thresholds: {
    http_req_failed: ['rate<0.01'], // http errors should be less than 1%
    http_req_duration: ['p(95)<1500'], // 95 percent of response times must be below 1500ms
  },
};

export default function () {
  group("dev EVM", function() {
    let devEvmContract = {"contractAddress":"0x69C6b28Fdc74618817fa380De29a653060e14009"} // dev contract EVM
    
    let response_evm_dev = http.post('https://contract-pinger-mainnet-1094058868047.europe-west1.run.app/evm_no_check', JSON.stringify(devEvmContract), {
      headers: { 'Content-Type': 'application/json' },
    }) 
    console.log("EVM Dev: " + response_evm_dev)

  })

  group("dev solana", function() {
    let devSolContract = {"contractAddress":"<add_sol_contract>"} // dev contract SOL
    
    let response_sol_dev = http.post('https://contract-pinger-mainnet-1094058868047.europe-west1.run.app/solana_no_check', JSON.stringify(devSolContract), {
      headers: { 'Content-Type': 'application/json' },
    })
  
    console.log("SOL Dev: " + response_sol_dev)
  });
}