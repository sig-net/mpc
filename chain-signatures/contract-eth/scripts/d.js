const hre = require("hardhat");

async function main() {
  // Get the contract instance
  const chainSignatures = await hre.ethers.getContractAt(
    "ChainSignatures",
    "0x5fbdb2315678afecb367f032d93f642f64180aa3" // Replace with your deployed contract address
  );

  try {
    // Call getPublicKey
    const publicKey = await chainSignatures.getPublicKey();
    console.log("Public Key:");
    console.log("X:", publicKey.x.toString());
    console.log("Y:", publicKey.y.toString());
  } catch (error) {
    console.error("Error fetching public key:", error);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });