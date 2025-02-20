const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

const DEFAULT_ADMIN = "0x3c0f802d66ac9fe56fa90afb0714dbc65b05a445";
const DEFAULT_DEPOSIT_AMOUNT = "1200000000000000";

module.exports = buildModule("ChainSignaturesModule", (m) => {
  const adminAddress = m.getParameter("admin", DEFAULT_ADMIN);
  const deposit_amount = m.getParameter("deposit_amount", DEFAULT_DEPOSIT_AMOUNT);
  const chainSignatures = m.contract("ChainSignatures", [adminAddress, deposit_amount]);

  return { chainSignatures };
});