if (process.argv.length < 3) {
    console.error("Please provide an admin address as argument");
    process.exit(1);
}
if (process.argv.length < 4) {
    console.error("Please provide the signature deposit amount as argument");
    process.exit(1);
}

const admin_address = process.argv[2];
const signature_deposit = parseInt(process.argv[3], 10);

console.log(`Will set as DEFAULT_ADMIN_ROLE: ${admin_address}, signatureDeposit: ${signature_deposit} gwei`);

const fs = require('fs');
const path = require('path');

const params = {
    ChainSignaturesModule: {
        admin: admin_address, // for mainnet, use the mpc network derived address
        deposit_amount: signature_deposit  // for mainnet, 30,000 * 40 gwei in wei = 1200000000000000
    }
};

const paramsPath = path.join(__dirname, '../ignition/params.json');
fs.writeFileSync(paramsPath, JSON.stringify(params, null, 4));
console.log('Saved admin address to', paramsPath);
