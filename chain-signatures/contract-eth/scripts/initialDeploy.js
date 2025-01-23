const { ethers, upgrades } = require('hardhat');
const fs = require('fs');

async function main () {
  const ChainSignatures = await ethers.getContractFactory('ChainSignatures');
  console.log('Deploying ChainSignatures proxy contract ...');
  const params = require('./params.json');
  const pkey = params.ChainSignaturesModule.publicKey;

  const network = await ethers.provider.getNetwork();
  const networkName = network.name;
  // Check if deployment already exists
  const deploymentPath = `${__dirname}/../deployments/${networkName}.json`;
  
  if (fs.existsSync(deploymentPath)) {
    const existingDeployment = JSON.parse(fs.readFileSync(deploymentPath));
    const proxyAddress = existingDeployment.proxy;
    
    // Check if contract exists at proxy address
    const code = await ethers.provider.getCode(proxyAddress);
    if (code !== "0x") {
      console.log("Proxy contract already deployed at:", proxyAddress);
      console.log('Use upgradeContract.js to upgrade the implementation');
      
      process.exit(1);
    }
  }

  const chainSignatures = await upgrades.deployProxy(ChainSignatures, [pkey], { initializer: 'initialize' });
  
  await chainSignatures.waitForDeployment();
  const proxyAddress = await chainSignatures.getAddress();
  const implementationAddress = await upgrades.erc1967.getImplementationAddress(proxyAddress);
  const signer = await ethers.provider.getSigner();
  const signerAddress = await signer.getAddress();

  console.log('Contract deployed by:', signerAddress);
  console.log('Proxy contract address:', proxyAddress);
  console.log('Implementation contract address:', implementationAddress);

  // Save deployment addresses to a JSON file
  const deploymentInfo = {
    network: networkName,
    proxy: proxyAddress,
    implementation: implementationAddress,
    deployer: signerAddress,
    timestamp: new Date().toISOString()
  };

  // Create deployments directory if it doesn't exist
  if (!fs.existsSync('deployments')){
    fs.mkdirSync('deployments');
  }

  fs.writeFileSync(deploymentPath, JSON.stringify(deploymentInfo, null, 2));
  console.log(`Deployment info saved to ${deploymentPath}`);
}

main();