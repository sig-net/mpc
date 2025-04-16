import http from 'k6/http';
import { group } from 'k6';

export const options = {
  duration: '30m', // duration of tests
  vus: 100,  // 100 virtual users
  thresholds: {
    http_req_failed: ['rate<0.01'], // http errors should be less than 1%
    http_req_duration: ['p(95)<600'], // 95 percent of response times must be below 600ms
  },
};

export default function () {
  group("testnet EVM", function() {
    let testnetEvmContract = {"contractAddress":"0x83458E8Bf8206131Fe5c05127007FA164c0948A2"} // testnet contract EVM
    
    let response_evm_testnet = http.post('https://contract-pinger-mainnet-1094058868047.europe-west1.run.app/evm_no_check', JSON.stringify(testnetEvmContract), {
      headers: { 'Content-Type': 'application/json' },
    }) 

    console.log("EVM Testnet: " + response_evm_testnet)
  });

  group("testnet Solana", function() {
    let testnetSolContract = {"contractAddress":"<add_sol_contract>"} // testnet contract SOL
    
    let response_sol_testnet = http.post('https://contract-pinger-mainnet-1094058868047.europe-west1.run.app/solana_no_check', JSON.stringify(testnetSolContract), {
      headers: { 'Content-Type': 'application/json' },
    })

    console.log("SOL Testnet: " + response_sol_testnet)
  });

  group("mainnet EVM", function() {
    let mainnetEvmContract = {"contractAddress":"0xf8bdC0612361a1E49a8E01423d4C0cFc5dF4791A"} // mainnet contract EVM
    
    let response_evm_mainnet = http.post('https://contract-pinger-mainnet-1094058868047.europe-west1.run.app/evm_no_check', JSON.stringify(mainnetEvmContract), {
      headers: { 'Content-Type': 'application/json' },
    }) 

    console.log("EVM Testnet: " + response_evm_mainnet)
  });

  group("mainnet Solana", function() {
    let mainnetSolContract = {"contractAddress":"<add_sol_contract>"} // mainnet contract SOL
    
    let response_sol_mainnet = http.post('https://contract-pinger-mainnet-1094058868047.europe-west1.run.app/solana_no_check', JSON.stringify(mainnetSolContract), {
      headers: { 'Content-Type': 'application/json' },
    })

    console.log("SOL mainnet: " + response_sol_mainnet)
  });
}