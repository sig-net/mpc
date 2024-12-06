const base58 = require('bs58');
const secp256k1 = require('secp256k1');

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
const publicKey = "secp256k1:2Ysz9jhCcem4wmfGpx2z57kCaorgiFhNZ1NDyDDJJDau5zuQh3afcQvYQfHMdTZ4Ax91j2NhE4qpsCXN4BUwzFwk";

// Convert it
const coordinates = convertPublicKey(publicKey);
console.log(coordinates);