const hre = require("hardhat");

async function main() {
  // Convert array of numbers to hex string
  const requestIdArray = [214, 188, 174, 77, 254, 76, 252, 28, 195, 208, 12, 188, 158, 28, 123, 76, 133, 158, 111, 72, 23, 8, 167, 45, 79, 132, 193, 72, 198, 250, 170, 93];
  const covRequestId = '0x' + Buffer.from(requestIdArray).toString('hex');
  console.log("requestId:", covRequestId);
  const requestId = "0xd6bcae4dfe4cfc1cc3d00cbc9e1c7b4c859e6f481708a72d4f84c148c6faaa5d";
  console.log("requestId:", requestId);
  // Decode base58 big_r value
  const bs58 = require('bs58');
  const bigRBytes = bs58.decode("PNv4eHTzMjoNCBN81j3fxEzc4GNzinq4NKJ4EMNDSXon2Dxfc4cYzY1sh4DDGUWSTMsfCdCmCXGypTt8styCpcB");
  console.log("bigRBytes length:", bigRBytes.length);
  const signature = {
    bigR: {
      x: '0x' + Buffer.from(bigRBytes.slice(0,32)).toString('hex'),
      y: '0x' + Buffer.from(bigRBytes.slice(32,64)).toString('hex')
    },
    s: "0x19644F453028EB4E32016E0494DA804DB762A17D09D248C09BE008A1B93DF22F",
    recoveryId: 1
  };

  // Get the deployed contract address from deployments file
  const deployments = require('../ignition/deployments/chain-31337/deployed_addresses.json');
  const contractAddress = deployments[Object.keys(deployments).pop()];
  
  const contract = await hre.ethers.getContractFactory("ChainSignatures")
    .then(factory => factory.attach(contractAddress));

  console.log("Responding to request...");
  const tx = await contract.respond(requestId, signature);
  await tx.wait();
  console.log("Response submitted! Transaction:", tx.hash);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
