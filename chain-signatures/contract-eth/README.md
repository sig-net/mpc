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

2. Figure out the contract address, admin address and receiver address(receiver of contract balance). Run and copy the "Future contract address" from the output:

```bash
npx hardhat --network localhost run scripts/findAddress.js
```

3. Make sure you have docker daemon running. Open another terminal window, go to `integration-tests` and run the following command to start the MPC cluster:

```bash
cargo run -- setup-env --eth-contract-address <eth-contract-address-without-0x-prefix>
```

4. Populate the ignition/params.json with admin address:

```bash
node scripts/populateParams.js <adminAddress> <deposit required in wei>
```

5. Then run the following command to deploy the contract:

```bash
npx hardhat ignition deploy ignition/modules/chainSignatures.js --parameters ignition/params.json --network localhost
```

6. Then run the following command to request a signature from MPC:

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
npx hardhat vars set MAINNET_PRIVATE_KEY
```

3. Populate the ignition/params.json with admin address:

```bash
node scripts/populateParams.js <adminAddress> <deposit required in wei>
```

4. Deploy the contract with right public key configured in `params.json`.

```bash
npx hardhat ignition deploy ignition/modules/chainSignatures.js --parameters ignition/params.json --network sepolia
```

5. Make sure you have docker daemon running. Go to `integration-tests` and run the following command to start the MPC cluster connected to Ethereum Sepolia Testnet:

```bash
cargo run -- setup-env --eth-rpc-ws-url wss://sepolia.infura.io/ws/v3/<api-key> --eth-rpc-http-url https://sepolia.infura.io/v3/<api-key> --eth-account-sk <eth-account-sk> --eth-contract-address <eth-contract-address-without-0x-prefix>
```

6. Then run the following command to request a signature from MPC:

```bash
npx hardhat run scripts/requestSign.js --network sepolia
```

Wait a moment, you should see the signature response from MPC printed by requestSign.js.

Note that everything is slower on Sepolia compared to local. Expect more than 10 seconds to deploy the contract and request a signature.

## Deploy on Ethereum Mainnet

1. Get a mainnet ETH wallet with some ETH and a infura (MetaMask Developer) API key. You can also ping Bo for using his keys.
2. Config hardhat with the infura api key and ethereum account secret key, enter as is and it will ask you the key interactively:

```bash
npx hardhat vars set INFURA_API_KEY
npx hardhat vars set SEPOLIA_PRIVATE_KEY
npx hardhat vars set MAINNET_PRIVATE_KEY
```

3. Populate the ignition/params.json with admin address:

```bash
node scripts/populateParams.js <adminAddress> <deposit required in wei>
```

4. Deploy the contract with right public key configured in `params.json`.

```bash
npx hardhat ignition deploy ignition/modules/chainSignatures.js --parameters ignition/params.json --network mainnet
```
