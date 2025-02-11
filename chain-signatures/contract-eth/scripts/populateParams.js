if (process.argv.length < 3) {
    console.error("Please provide an admin address as argument");
    process.exit(1);
}
const admin_address = process.argv[2];

console.log("Will set as DEFAULT_ADMIN_ROLE: ", admin_address);

// Save to params.json
const fs = require('fs');
const path = require('path');

const params = {
    ChainSignaturesModule: {
        admin: admin_address
    }
};

const paramsPath = path.join(__dirname, '../ignition/params.json');
fs.writeFileSync(paramsPath, JSON.stringify(params, null, 4));
console.log('Saved admin address to', paramsPath);