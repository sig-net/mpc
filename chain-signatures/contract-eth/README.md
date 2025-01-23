# Chain Signatures Contract on Ethereum

## Overview

This repository contains the Solidity code for the Chain Signatures contract, which is deployed on the Ethereum blockchain.

## Setup

To setup the project, you can use the following command:

```bash
npm install
```

## Compile

To compile the contract, you can use the following command:

```bash
npx hardhat compile
```

## Testing

To unit test the contract, you can use the following command:

```bash
npx hardhat test
```

## Run it locally end to end

To do a local end-to-end test, following these steps.

1. Run the following command to spin up a local Ethereum node:
```bash
npx hardhat node
```

2. Figure out the contract address. Run and copy the "Future contract address" from the output:
```bash
npx hardhat --network localhost run scripts/findAddress.js
```

3. Make sure you have docker daemon running. Open another terminal window, go to `integration-tests/chain-signatures` and run the following command to start the MPC cluster:
```bash
cargo run -- setup-env --eth-contract-address <future-contract-address>
```

4. In MPC cluster log, search for log `voting for public key public_key=secp256k1:` and copy the public key after `secp256k1:`

5. Open another terminal window, Then run the following command to config the mpc public key for deploying ethereum contract:
```bash
node scripts/convertPk.js <public_key>
```
For example:
```bash
node scripts/convertPk.js 37xNKgg4LvhuaMBPThHEZNp6VJHu8KsATkPrCKrsfbwQEas1erep8otiB37F99tvY5aM3s78uzix49t5BjxuBYzD
```

6. Then run the following command to deploy the contract:
```bash
npx hardhat ignition deploy ignition/modules/chainSignatures.js --parameters ignition/params.json --network localhost
```

7. Then run the following command to request a signature from MPC:
```bash
npx hardhat run scripts/requestSign.js --network localhost
```

In a few seconds,you should see the signature response from MPC printed by requestSign.js.

## Run it on Ethereum Sepolia Testnet from end to end
1. Get a Sepolia testnet ETH wallet with some ETH and a infura (MetaMask Developer) API key. You can also ping Bo for using his keys.
2. Config hardhat with the infura api key and ethereum account secret key, enter as is and it will ask you the key interactively:
```bash
npx hardhat vars set INFURA_API_KEY
npx hardhat vars set SEPOLIA_PRIVATE_KEY
```
3. Figure out the contract address. Run and copy the "Future contract address" from the output:
```bash
npx hardhat --network sepolia run scripts/findAddress.js
```

4. Go to Etherscan Sepolia: https://sepolia.etherscan.io/, check the latest block number.

5. Make sure you have docker daemon running. Go to `integration-tests` and run the following command to start the MPC cluster connected to Ethereum Sepolia Testnet:
```bash
cargo run -- setup-env --eth-rpc-http-url https://sepolia.infura.io/v3/<infura-api-key> --eth-rpc-ws-url wss://sepolia.infura.io/ws/v3/<infura-api-key> --eth-account-sk <eth-account-secret-key-without-0x-prefix> --eth-contract-address <future-contract-address>
```

6. In MPC cluster log, search for log `voting for public key public_key=secp256k1:` and copy the public key after `secp256k1:`

7. Open another terminal window, Then run the following command to config the mpc public key for deploying ethereum contract:
```bash
node scripts/convertPk.js <public_key>
```
For example:
```bash
node scripts/convertPk.js pkqFQkRgYsZx4pNwuitXSDYAKsGML1P6JboVKP5qSG4HVatFHUqA8Fzcan49uxBZFyNwCHvr1tJo5KNJMcuWCQ6
```

8. Then run the following command to deploy the contract to Ethereum Sepolia Testnet:
```bash
npx hardhat ignition deploy ignition/modules/chainSignatures.js --parameters ignition/params.json --network sepolia
```

9. Then run the following command to request a signature from MPC:
```bash
npx hardhat run scripts/requestSign.js --network sepolia
```

Wait a moment, you should see the signature response from MPC printed by requestSign.js.

Note that everything is slower on Sepolia compared to local. Expect more than 10 seconds to deploy the contract and request a signature.

## Gas Optimization

Contract before [this commit](https://github.com/sig-net/mpc/pull/58/commits/b4fab2a22195efef8c86dd7e620a130b76d6708c) uses 3.8M unit of gas to respond, which is too high, about 10x of a uniswap swap. It was using the most gas efficient [implementation](https://github.com/witnet/elliptic-curve-solidity) of Secp256k1 curve and strictly follows the verification logic of the NEAR contract.

After [this commit](https://github.com/sig-net/mpc/pull/58/commits/f2308fe3c7352aa0fb6cec6eb868895e6c5bd4ed), the gas cost is reduced to only 53k, this is only 1/7 of a uniswap swap, or only 2.5x of a eth transfer. (Uniswap swap is about 356k gas, eth transfer is about 21k gas). The optimizations are making the contract not the same logic and not the same interface as the NEAR version, described below:

1. Use eth precompiled ecrecover instead of library implemented ecrecover. The precompiled ecrecover is considered as native version and use very little gas. However, it doesn't recover a public key, but an address, which you can consider as a hash of the public key. Previously we compare recovered public key with expected public key. Now we verify the recover by comparing the recovered addresswith the expected public key's hash address.

2. Use ecrecover to hack the ECMUL operation. Ethereum has a ECMUL precompiled contract, but it is not for Secp256k1 curve. Based on [this calculation](https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384), we can verify a ECMUL on Secp256k1 curve cheaply by using ecrecover. Note that it is a verify of ECMUL, not ECMUL itself, therefore user has to calculate the ECMUL result and pass to the contract.

After 1, the respond gas cost is reduced to 1.2M. After 2, the respond gas cost is reduced to 260K. Then we can further reduce the respond gas cost by moving the verify ECMUL operation to sign, so sign gas cost increased from 140k to 350k, and respond gas cost reduced to 53k. The sign gas cost, paid by user, is similar to a uniswap swap and the respond gas, which is paid by the mpc node runner to a very cheap level.

There are certain small gas optimizations possible to reduce a little more gas, but at this stage I think it is not a priority.
