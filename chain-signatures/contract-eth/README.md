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

2. Make sure you have docker daemon running. Open another terminal window, go to `integration-tests/chain-signatures` and run the following command to start the MPC cluster:
```bash
cargo run -- setup-env
```

3. In MPC cluster log, search for log `voting for public key public_key=secp256k1:` and copy the public key after `secp256k1:`

4. Open another terminal window, Then run the following command to config the mpc public key for deploying ethereum contract:
```bash
node scripts/convertPk.js <public_key>
```
For example:
```bash
node scripts/convertPk.js 46sdkzwo46ga8B3K2J9i57akBsfgtFYbj4JzdnTuyhWiNaorz96qkExE3ei7djX25bzV6rmLJ435FJMpAYUs9JRg
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
```
3. Figure out the contract address. Run and copy the "Future contract address" from the output:
```bash
npx hardhat --network sepolia run scripts/findAddress.js
```

4. Go to Etherscan Sepolia: https://sepolia.etherscan.io/, check the latest block number.

5. Make sure you have docker daemon running. Go to `integration-tests` and run the following command to start the MPC cluster connected to Ethereum Sepolia Testnet:
```bash
cargo run -- setup-env --eth-rpc-url https://sepolia.infura.io/v3/<infura-api-key> --eth-account-sk <eth-account-secret-key-without-0x-prefix> --eth-contract-address <future-contract-address> --eth-start-block-height <latest-block-number>
```

6. In MPC cluster log, search for log `voting for public key public_key=secp256k1:` and copy the public key after `secp256k1:`

7. Open another terminal window, Then run the following command to config the mpc public key for deploying ethereum contract:
```bash
node scripts/convertPk.js <public_key>
```
For example:
```bash
node scripts/convertPk.js 46sdkzwo46ga8B3K2J9i57akBsfgtFYbj4JzdnTuyhWiNaorz96qkExE3ei7djX25bzV6rmLJ435FJMpAYUs9JRg
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