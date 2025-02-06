const { ethers, upgrades } = require('hardhat');
const fs = require('fs');

async function main() {
  // Get network info
  const network = await ethers.provider.getNetwork();
  const networkName = network.name;
  const deploymentPath = `deployments/${networkName}.json`;
  const params = require('./params.json');
  const pkey = params.ChainSignaturesModule.publicKey;

  // Check if deployment file exists
  if (!fs.existsSync(deploymentPath)) {
    console.log(`No deployment found for network ${networkName}`);
    console.log('Please run initialDeploy.js first');
    process.exit(1);
  }

  // Load deployment info
  const deployment = JSON.parse(fs.readFileSync(deploymentPath));
  const proxyAddress = deployment.proxy;

  // Check if contract exists at proxy address
  const code = await ethers.provider.getCode(proxyAddress);
  if (code === "0x") {
    console.log(`No contract found at proxy address ${proxyAddress}`);
    fs.unlinkSync(deploymentPath);
    console.log('Please run initialDeploy.js first');
    process.exit(1);
  }

  console.log('Found proxy contract at:', proxyAddress);
  console.log('Upgrading implementation...');

  const ChainSignatures = await ethers.getContractFactory('ChainSignatures');
  // Get old implementation address before upgrade
  const oldImplementationAddress = await upgrades.erc1967.getImplementationAddress(proxyAddress);
  // await upgrades.upgradeProxy(proxyAddress, ChainSignatures);
  await upgrades.upgradeProxy(proxyAddress, ChainSignatures, {call: {fn: 'upgradeToV2', args: [pkey, 0]}});

  // Compare old and new implementation addresses
  const newImplementationAddress = await upgrades.erc1967.getImplementationAddress(proxyAddress);
  
  if (oldImplementationAddress === newImplementationAddress) {
    console.log('Contract unchanged. Nothing upgraded');
  } else {
    deployment.implementation = newImplementationAddress;
    deployment.timestamp = new Date().toISOString();
    fs.writeFileSync(deploymentPath, JSON.stringify(deployment, null, 2));
    console.log('Contract upgraded successfully');
    console.log('Old implementation:', oldImplementationAddress);
    console.log('New implementation address:', newImplementationAddress);
  }

}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
