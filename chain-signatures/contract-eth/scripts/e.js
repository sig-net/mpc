const fs = require('fs');
const bs58 = require('bs58');
const path = require('path');

// Read and convert public key to bs58
async function convertPubKeyToBS58() {
    try {
        // Read the params.json file
        const paramsPath = path.join(__dirname, '../ignition/params.json');
        const paramsRaw = fs.readFileSync(paramsPath, 'utf8');
        const params = JSON.parse(paramsRaw);

        // Get the x and y coordinates from the public key
        const x = params.ChainSignaturesModule.publicKey.x;
        const y = params.ChainSignaturesModule.publicKey.y;

        // Remove '0x' prefix and concatenate x and y coordinates
        const cleanX = x.startsWith('0x') ? x.slice(2) : x;
        const cleanY = y.startsWith('0x') ? y.slice(2) : y;
        const fullPubKey = cleanX + cleanY;
        
        // Convert hex to buffer
        const pubKeyBuffer = Buffer.from(fullPubKey, 'hex');
        
        // Convert to bs58
        const bs58PublicKey = bs58.encode(pubKeyBuffer);
        
        console.log('Original public key x:', x);
        console.log('Original public key y:', y);
        console.log('BS58 encoded public key:', bs58PublicKey);
        
        return bs58PublicKey;
    } catch (error) {
        console.error('Error converting public key:', error);
        throw error;
    }
}

// Execute the conversion
convertPubKeyToBS58()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });