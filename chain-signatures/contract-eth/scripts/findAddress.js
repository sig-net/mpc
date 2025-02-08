const { ethers } = require("hardhat");

async function main() {
    // Get the deployer's signer
    [deployer, addr1, addr2] = await ethers.getSigners();

    // Get the nonce
    const nonce = await deployer.getNonce();

    // Calculate the future contract address
    const futureAddress = ethers.getCreateAddress({
        from: deployer.address,
        nonce: nonce
    });

    const admin_addr = deployer.address;
    const receiver_addr = addr1.address;
    console.log("Admin address:", admin_addr);
    console.log("Receiver address:", receiver_addr);
    console.log("Current nonce:", nonce);
    console.log("Future contract address:", futureAddress);

    // Save to params.json
    const fs = require('fs');
    const path = require('path');
        
    const params = {
        ChainSignaturesModule: {
            admin: admin_addr,
            receiver: receiver_addr
        }
    };

    const paramsPath = path.join(__dirname, '../ignition/params.json');
    fs.writeFileSync(paramsPath, JSON.stringify(params, null, 4));
    console.log('Saved admin address and receiver address to', paramsPath);
}

main().catch(console.error);