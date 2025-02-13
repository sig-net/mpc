const hre = require("hardhat");
const { generateRequestId } = require("../utils/utils");

async function main() {
  let contractAddress;
  let network = hre.network.name;
  if (network === 'localhost') {
    const deployments = require('../ignition/deployments/chain-31337/deployed_addresses.json');
    contractAddress = deployments[Object.keys(deployments).pop()];
    console.log(contractAddress)
  } else if (network === 'sepolia') {
    const deployments = require('../ignition/deployments/chain-11155111/deployed_addresses.json'); 
    contractAddress = deployments[Object.keys(deployments).pop()];
  } else {
    throw new Error('Unsupported network specified. Use "localhost" or "sepolia"');
  }
  console.log("network", network, "contractAddress", contractAddress);

  
  const chainSignatures = await hre.ethers.getContractFactory("ChainSignatures")
    .then(factory => factory.attach(contractAddress));

  try {
    // Verify contract exists
    const code = await hre.ethers.provider.getCode(contractAddress);
    if (code === "0x") throw new Error("No contract deployed at this address");
  } catch (error) {
    console.error("Error:", error.message);
  }


  // Request to ign a test message
  try {
    const testMessage = "0xB94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9";
    const testPath = "test5";
    const signatureDeposit = await chainSignatures.getSignatureDeposit();
    const signer = (await hre.ethers.getSigners())[0];
    
    console.log("Requesting signature for message:", testMessage);
    console.log("Using path:", testPath);
    console.log("Required deposit:", signatureDeposit.toString(), "wei");

    const chainSignaturesWithSigner = chainSignatures.connect(signer);
    
    const tx = await chainSignaturesWithSigner.sign({payload: testMessage, path: testPath, keyVersion: 0, algo: "", dest:"", params: ""}, {
      value: signatureDeposit
    });
    const receipt = await tx.wait();

    const requestEvent = receipt.logs.find(log => 
      chainSignatures.interface.parseLog(log)?.name === "SignatureRequested"
    );

    if (requestEvent) {
      const parsedEvent = chainSignatures.interface.parseLog(requestEvent);
      console.log("Signature requested successfully!");
      console.log("Payload Hash:", parsedEvent.args.payload.toString());
      
      const requestId = generateRequestId(parsedEvent.args.sender, parsedEvent.args.payload, parsedEvent.args.path, parsedEvent.args.keyVersion, parsedEvent.args.chainId, parsedEvent.args.algo, parsedEvent.args.dest, parsedEvent.args.params);
      console.log("Request ID:", requestId);

      // Add event listener for SignatureResponded
      console.log("Waiting for signature response...");
      const filter = chainSignatures.filters.SignatureResponded(requestId);
      
      chainSignatures.once(filter, (event) => {
        console.log("\nSignature response received!");
        console.log("Request ID:", requestId);
        console.log("Response:")
        console.log("  bigR:", event.args.response.bigR);
        console.log("  s:", event.args.response.s);
        console.log("  recoveryId:", event.args.response.recoveryId);
      });
    }

  } catch (error) {
    console.error("Error requesting signature:", error.message);
  }

  // Keep script running to wait for event
  await new Promise(() => {});

}

main().catch(console.error);