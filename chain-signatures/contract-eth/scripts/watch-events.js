const hre = require("hardhat");

async function main() {
  // Get the deployed contract address
  const deployments = require('../ignition/deployments/chain-31337/deployed_addresses.json');
  const contractAddress = deployments[Object.keys(deployments).pop()];
  
  const chainSignatures = await hre.ethers.getContractFactory("ChainSignatures")
    .then(factory => factory.attach(contractAddress));

  console.log("Watching for SignatureRequested events...");
  
  // Set up event listener
  chainSignatures.on("SignatureRequested", (requestId, epsilon, payloadHash, event) => {
    console.log("\nNew SignatureRequested event detected!");
    console.log({
      requestId: requestId.toString(),
      epsilon: epsilon.toString(),
      payloadHash: payloadHash.toString(),
      blockNumber: event.blockNumber,
      transactionHash: event.transactionHash
    });
  });

  // Keep the script running
  process.stdin.resume();
}

main().catch(console.error);