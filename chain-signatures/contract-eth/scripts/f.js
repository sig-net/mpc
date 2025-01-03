const { ethers } = require("hardhat");

async function getContractAddress() {
    // Get the deployer's signer
    const [deployer] = await ethers.getSigners();
    
    // Get the nonce
    const nonce = await deployer.getNonce();
    
    // Calculate the future contract address
    const futureAddress = ethers.getCreateAddress({
        from: deployer.address,
        nonce: nonce
    });

    console.log("Deployer address:", deployer.address);
    console.log("Current nonce:", nonce);
    console.log("Future contract address:", futureAddress);
}

// You can either run this as a standalone script
// or add it to your deploy script
getContractAddress()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });