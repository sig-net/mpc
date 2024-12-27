const hre = require("hardhat");

// 2024-12-27T03:13:32.848468Z  INFO ThreadId(06) mpc_node::protocol::signature: completed signature generation sign_request_identifier=SignRequestIdentifier { request_id: [214, 188, 174, 77, 254, 76, 252, 28, 195, 208, 12, 188, 158, 28, 123, 76, 133, 158, 111, 72, 23, 8, 167, 45, 79, 132, 193, 72, 198, 250, 170, 93], epsilon: [12, 56, 71, 158, 128, 83, 166, 50, 204, 62, 28, 172, 5, 237, 51, 215, 115, 60, 144, 143, 220, 37, 106, 254, 187, 147, 150, 32, 106, 5, 216, 109], payload: [185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218, 125, 171, 250, 196, 132, 239, 227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205, 233] } me=Participant(2) presignature_id=16014988000931262210 big_r="4LWWkWtDb8Fe6TikLAzHoP5NoExEhifoqpAnqc6zzdjrj1FqonvJR8o5FgSzfJeM2259nDLHRsVL6Q6YHkbLioNG" s=Scalar(Uint(0x4ADF22106EE973FC5BC570CB7B9A0AB281EAC2342D47A77186D4763678FB4C1D))


async function main() {
  // Convert array of numbers to hex string
  const requestIdArray = [214, 188, 174, 77, 254, 76, 252, 28, 195, 208, 12, 188, 158, 28, 123, 76, 133, 158, 111, 72, 23, 8, 167, 45, 79, 132, 193, 72, 198, 250, 170, 93];
  const covRequestId = '0x' + Buffer.from(requestIdArray).toString('hex');
  console.log("requestId:", covRequestId);
  const requestId = "0xd6bcae4dfe4cfc1cc3d00cbc9e1c7b4c859e6f481708a72d4f84c148c6faaa5d";
  console.log("requestId:", requestId);
  // Decode base58 big_r value
  const bs58 = require('bs58');
  const bigRBytes = bs58.decode("4LWWkWtDb8Fe6TikLAzHoP5NoExEhifoqpAnqc6zzdjrj1FqonvJR8o5FgSzfJeM2259nDLHRsVL6Q6YHkbLioNG");
  console.log("bigRBytes length:", bigRBytes.length);
  const x = '0x' + Buffer.from(bigRBytes.slice(0,32)).toString('hex');
  const y = '0x' + Buffer.from(bigRBytes.slice(32,64)).toString('hex');
  const signature = {
    bigR: {
     x,y
    },
    s: "0x4ADF22106EE973FC5BC570CB7B9A0AB281EAC2342D47A77186D4763678FB4C1D",
    recoveryId: (BigInt(y) & 1n) === 1n ? 1 : 0
  };

  console.log(signature);

  console.log("recoveryId:", signature.recoveryId);

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
