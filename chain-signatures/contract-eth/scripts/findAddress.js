const { ethers } = require("hardhat");

async function main() {
    // Get the deployer's signer
    [deployer] = await ethers.getSigners();

    // Get the nonce
    const nonce = await deployer.getNonce();

    // Calculate the future contract address
    const futureAddress = ethers.getCreateAddress({
        from: deployer.address,
        nonce: nonce
    });

    const deployer_addr = deployer.address;
    console.log("Deployer address:", deployer_addr);
    console.log("Current nonce:", nonce);
    console.log("Future contract address:", futureAddress);
}

main().catch(console.error);