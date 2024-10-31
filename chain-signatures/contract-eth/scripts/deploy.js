const hre = require("hardhat");

async function main() {
  const ChainSignatures = await hre.ethers.getContractFactory("ChainSignatures");
  const chainSignatures = await ChainSignatures.deploy();

  await chainSignatures.deployed();

  console.log("ChainSignatures deployed to:", chainSignatures.address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
