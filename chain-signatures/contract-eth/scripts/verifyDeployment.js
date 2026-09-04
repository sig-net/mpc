const { ethers } = require("hardhat");

async function main() {
    const contractAddress = "0x83458E8Bf8206131Fe5c05127007FA164c0948A2";

    console.log("Verifying ChainSignatures contract deployment...");
    console.log("Contract Address:", contractAddress);

    try {
        const contract = await ethers.getContractAt("ChainSignatures", contractAddress);

        const signatureDeposit = await contract.getSignatureDeposit();
        console.log("Signature Deposit Required:", ethers.formatEther(signatureDeposit), "ETH");

        // Get the deployer address (should be your address)
        const [deployer] = await ethers.getSigners();
        console.log("Deployer Address:", deployer.address);
        console.log("Deployer Balance:", ethers.formatEther(await ethers.provider.getBalance(deployer.address)), "ETH");

        console.log("✅ Contract deployed and verified successfully!");

    } catch (error) {
        console.error("❌ Error verifying contract:", error.message);
    }
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
