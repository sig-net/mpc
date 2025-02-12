const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ChainSignatures", function () {
  let ChainSignatures;
  let chainSignatures;
  let owner;
  let addr1;

  beforeEach(async function () {
    [owner, addr1, addr2] = await ethers.getSigners();
    ChainSignatures = await ethers.getContractFactory("ChainSignatures");
    const depositExpectedInWei = ethers.parseUnits("50000", "gwei"); 
    chainSignatures = await ChainSignatures.deploy(owner, depositExpectedInWei);
  });

  describe("Changing signatureDeposit", function () {
    it("Should change signatureDeposit by setSignatureDeposit", async function () {
      const requiredDepositBeforeChange = await chainSignatures.getSignatureDeposit();
      const depositExpectedInWei = ethers.parseUnits("50000", "gwei"); 
      expect(requiredDepositBeforeChange).to.equal(depositExpectedInWei);
      const depositToSetInWei = ethers.parseUnits("100000", "gwei"); 
      await chainSignatures.connect(owner).setSignatureDeposit(depositToSetInWei);
      const requiredDepositAfterChange = await chainSignatures.getSignatureDeposit();
      expect(requiredDepositAfterChange).to.equal(depositToSetInWei);
    });
  });

  describe("Withdraw function", function () {
    it("Should be able to withdraw", async function () {
      const payload = ethers.keccak256(ethers.toUtf8Bytes("Test payload"));
      const path = "test/path";
      const requiredDeposit = await chainSignatures.getSignatureDeposit();

      await chainSignatures.connect(addr1).sign({payload, path, keyVersion: 0, algo: "", dest: "", params: ""}, { value: requiredDeposit });
      
      const path2 = "test/path2";
      await chainSignatures.connect(addr1).sign({payload, path: path2, keyVersion: 0, algo: "", dest: "", params: ""}, { value: requiredDeposit });
      
      const balanceEth = await ethers.provider.getBalance(chainSignatures.getAddress());
      const balanceExpectedInWei = ethers.parseUnits("100000", "gwei"); 
      expect(balanceEth).to.equal(balanceExpectedInWei);
      const withdrawlAmountInWei = ethers.parseUnits("30000", "gwei"); 
      await chainSignatures.connect(owner).withdraw(withdrawlAmountInWei, addr1);
      const balanceEthAfterWithdraw = await ethers.provider.getBalance(chainSignatures.getAddress());
      const balanceExpectedAfterInWei = ethers.parseUnits("70000", "gwei"); 
      expect(balanceEthAfterWithdraw).to.equal(balanceExpectedAfterInWei);
    });
  });

  describe("Signing requests", function () {
    it("Should create a signature request", async function () {
      const payload = ethers.keccak256(ethers.toUtf8Bytes("Test payload"));
      const path = "test/path";
      const requiredDeposit = await chainSignatures.getSignatureDeposit();

      await expect(chainSignatures.connect(addr1).sign({payload, path, keyVersion: 0, algo: "", dest: "", params: ""}, { value: requiredDeposit }))
        .to.emit(chainSignatures, "SignatureRequested")
        .withArgs(addr1.address, payload, 0, requiredDeposit, 31337, path, "", "", "");
    });

    it("Respond to a signature request", async function () {
      const payload = "0xB94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9"
      const path = "test";
      const requiredDeposit = await chainSignatures.getSignatureDeposit();

      const tx = await chainSignatures.connect(addr1).sign({payload, path, keyVersion: 0, algo: "", dest: "", params: ""}, { value: requiredDeposit });
      const receipt = await tx.wait();
      const requestEvent = receipt.logs.find(log => 
        chainSignatures.interface.parseLog(log)?.name === "SignatureRequested"
      );
      const parsedRequestEvent = chainSignatures.interface.parseLog(requestEvent);
      console.log(parsedRequestEvent);

      const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
        ["address", "bytes", "string", "uint32", "uint256", "string", "string", "string"],
        [addr1.address, payload, path, 0, 31337, "", "", ""]
      );
      const requestId = ethers.keccak256(encoded);

      const bigR = [4, 235, 32, 243, 182, 197, 136, 46, 1, 139, 239, 143, 68, 206, 69, 33, 21, 197, 53, 152, 61, 231, 35, 110, 41, 52, 59, 59, 197, 198, 72, 248, 149, 64, 216, 248, 234, 27, 102, 47, 185, 225, 141, 23, 254, 91, 155, 253, 111, 45, 62, 172, 73, 217, 254, 251, 168, 191, 184, 149, 228, 119, 12, 209, 248];
      const bigRX = '0x' + bigR.slice(1, 33).map(byte => byte.toString(16).padStart(2, '0')).join('');
      const bigRY = '0x' + bigR.slice(33).map(byte => byte.toString(16).padStart(2, '0')).join('');
      const s = "0x5F06F4BC377E509EDA49EC73074D62962CB0C5D48C0800580FAD3E19EC620C09".toLowerCase();
      const response = { bigR: { x: bigRX, y: bigRY }, s: s, recoveryId: 0 };
      console.log("===", requestId, response);
      // This form doesn't work, possible hardhat bug
      // await expect(chainSignatures.connect(owner).respond(requestId, response))
      //   .to.emit(chainSignatures, "SignatureResponded")
      //   .withArgs(requestId, [[ethers.BigNumber.from(bigRX), ethers.BigNumber.from(bigRY)], ethers.BigNumber.from(s), 0]);
      const tx2 = await chainSignatures.connect(addr2).respond([{ requestId: requestId, response: response }]);
      const receipt2 = await tx2.wait();
      const responseEvent = receipt2.logs.find(log => 
        chainSignatures.interface.parseLog(log)?.name === "SignatureResponded"
      );
      console.log("Gas used for signature response:", receipt2.gasUsed.toString());
      const parsedEvent = chainSignatures.interface.parseLog(responseEvent);
      console.log(parsedEvent);
      
      expect(parsedEvent.args[0]).to.equal(requestId);
      expect(parsedEvent.args[1]).to.equal(addr2.address);
      expect(parsedEvent.args[2][0][0]).to.equal(bigRX);
      expect(parsedEvent.args[2][0][1]).to.equal(bigRY);
      expect(parsedEvent.args[2][1]).to.equal(s);
      expect(parsedEvent.args[2][2]).to.equal(0);
    });
  });
});
