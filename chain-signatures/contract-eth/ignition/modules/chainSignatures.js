const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

const DEFAULT_ADMIN = "0x3Aa5ebB10DC797CAC828524e59A333d0A371443c";
const DEFAULT_DEPOSIT_AMOUNT = "1200000000000000";

module.exports = buildModule("ChainSignaturesModule", (m) => {
  const adminAddress = m.getParameter("admin", DEFAULT_ADMIN);
  const deposit_amount = m.getParameter("deposit_amount", DEFAULT_DEPOSIT_AMOUNT);
  const chainSignatures = m.contract("ChainSignatures", [adminAddress, deposit_amount]);

  return { chainSignatures };
});