const hre = require("hardhat");

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

    // Get public key data
    const publicKey = await chainSignatures.getPublicKey();
    console.log("Public key:", {
      x: publicKey.x?.toString() || 'undefined',
      y: publicKey.y?.toString() || 'undefined'
    });

  } catch (error) {
    console.error("Error:", error.message);
  }


  // Request to ign a test message
  try {
    const testMessage = "0xB94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9";
    const testPath = "test2";
    const signatureDeposit = await chainSignatures.getSignatureDeposit();
    const signer = (await hre.ethers.getSigners())[0];
    const derivedPublicKey = await chainSignatures.derivedPublicKey(testPath, signer.address);
    
    console.log("Requesting signature for message:", testMessage);
    console.log("Using path:", testPath);
    console.log("Required deposit:", signatureDeposit.toString(), "wei");

    const chainSignaturesWithSigner = chainSignatures.connect(signer);
    
    const tx = await chainSignaturesWithSigner.sign({payload: testMessage, path: testPath, keyVersion: 0, derivedPublicKey: {x: derivedPublicKey.x, y: derivedPublicKey.y}}, {
      value: signatureDeposit
    });
    const receipt = await tx.wait();

    const requestEvent = receipt.logs.find(log => 
      chainSignatures.interface.parseLog(log)?.name === "SignatureRequested"
    );

    if (requestEvent) {
      const parsedEvent = chainSignatures.interface.parseLog(requestEvent);
      console.log("Signature requested successfully!");
      console.log("Request ID:", parsedEvent.args.requestId);
      console.log("Epsilon:", parsedEvent.args.epsilon.toString());
      console.log("Payload Hash:", parsedEvent.args.payloadHash.toString());

      // Add event listener for SignatureResponded
      console.log("Waiting for signature response...");
      const filter = chainSignatures.filters.SignatureResponded(parsedEvent.args.requestId);
      
      chainSignatures.once(filter, (event) => {
        console.log("\nSignature response received!");
        console.log("Request ID:", event.args.requestId);
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