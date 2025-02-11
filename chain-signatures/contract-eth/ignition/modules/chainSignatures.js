const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");
const DEFAULT_ADMIN = "0x3Aa5ebB10DC797CAC828524e59A333d0A371443c";

module.exports = buildModule("ChainSignaturesModule", (m) => {
  const admin_address = m.getParameter("admin", DEFAULT_ADMIN);
  console.log("Deploying with admin address:", admin_address);
  const chainSignatures = m.contract("ChainSignatures", [admin_address]);


  return { chainSignatures };
});