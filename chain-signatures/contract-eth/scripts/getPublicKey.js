const hre = require("hardhat");

async function main() {
  let contractAddress;
  let network = hre.network.name;
  if (network === 'localhost') {
    const deployments = require('../deployments/localhost.json');
    contractAddress = deployments.proxy;
  } else if (network === 'sepolia') {
    const deployments = require('../deployments/sepolia.json');
    contractAddress = deployments.proxy;
  } else {
    throw new Error('Unsupported network specified. Use "localhost" or "sepolia"');
  }
  console.log("network", network, "contractAddress", contractAddress);

  
  const chainSignatures = await hre.ethers.getContractFactory("ChainSignatures")
    .then(factory => factory.attach(contractAddress));

  try {
    // Verify contract exists
    const code = await hre.ethers.provider.getCode(contractAddress);
    if (code === "0x") throw new Error("No contract deployed at this address");

    // Get public key data
    const publicKey = await chainSignatures.getPublicKey();
    console.log("Public key:", {
      x: publicKey.x?.toString() || 'undefined',
      y: publicKey.y?.toString() || 'undefined'
    });

  } catch (error) {
    console.error("Error:", error.message);
  }

  // Keep script running to wait for event
  await new Promise(() => {});

}

main().catch(console.error);