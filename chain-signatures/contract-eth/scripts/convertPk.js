const base58 = require('bs58');
const secp256k1 = require('secp256k1');
const { ethers } = require("hardhat");

function convertPublicKey(base58PublicKey) {
    // Remove the "secp256k1:" prefix
    const cleanKey = base58PublicKey.replace('secp256k1:', '');

    // Decode base58 string to buffer
    const decoded = base58.decode(cleanKey);

    // Extract x and y coordinates
    const x = '0x' + Buffer.from(decoded.slice(0, 32)).toString('hex');
    const y = '0x' + Buffer.from(decoded.slice(32)).toString('hex');
    
    return { x, y };
}

// Your public key
if (process.argv.length < 3) {
    console.error("Please provide a public key as argument");
    process.exit(1);
}
const publicKey = process.argv[2].startsWith('secp256k1:') ? process.argv[2] : `secp256k1:${process.argv[2]}`;

// Convert it
const coordinates = convertPublicKey(publicKey);
console.log(coordinates);

// Save to params.json
const fs = require('fs');
const path = require('path');

const paramsPath = path.join(__dirname, '../ignition/params.json');
fs.readFile(paramsPath, 'utf8', (err, data) => {
    if (err) {
        console.error('Error reading file:', err);
        return;
    }

    try {
        // Parse JSON string to object
        let jsonData = JSON.parse(data);

        jsonData.ChainSignaturesModule.publicKey = coordinates;

        // Write updated JSON back to file
        fs.writeFileSync(paramsPath, JSON.stringify(jsonData, null, 4));
        console.log('Saved public key to', paramsPath);
    } catch (parseErr) {
        console.error('Error parsing JSON:', parseErr);
    }
});