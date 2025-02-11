// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract ChainSignatures is AccessControl {
    struct SignRequest {
        bytes32 payload;
        string path;
        uint32 keyVersion;
        string algo;
        string dest;
        string params;
    }

    struct AffinePoint {
        uint256 x;
        uint256 y;
    }

    struct SignatureResponse {
        AffinePoint bigR;
        uint256 s;
        uint8 recoveryId;
    }

    struct ResponseWithId {
        bytes32 requestId;
        SignatureResponse response;
    }

    uint256 signatureDeposit;

    event SignatureRequested(bytes32 indexed requestId, address requester, bytes32 payload, uint32 keyVersion, uint256 deposit, string path, string algo, string dest, string params);
    event SignatureResponded(bytes32 indexed requestId, SignatureResponse response);

    constructor(address _admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        signatureDeposit = 50000 gwei;
    }

    function sign(SignRequest memory _request) external payable returns (bytes32) {
        bytes32 payload = _request.payload;
        string memory chainIdStr = Strings.toString(block.chainid);
        string memory path = string.concat(_request.path, "/", chainIdStr);
        uint32 keyVersion = _request.keyVersion;
        string memory algo = _request.algo;
        string memory dest = _request.dest;
        string memory params = _request.params;

        bytes32 requestId = keccak256(abi.encodePacked(payload, msg.sender, path, keyVersion, algo, dest, params));

        emit SignatureRequested(requestId, msg.sender, payload, keyVersion, msg.value, path, algo, dest, params);

        return requestId;
    }
    
    function respond(ResponseWithId[] calldata _responses) external {
        for (uint256 i = 0; i < _responses.length; i++) {
            emit SignatureResponded(_responses[i].requestId, _responses[i].response);
        }
    }

    function getSignatureDeposit() external view returns (uint256) {
        return signatureDeposit;
    }

    function setSignatureDeposit(uint256 _amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        signatureDeposit = _amount;
    }

    function withdraw(uint256 _amount, address _receiver) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 totalBalanceInContract = address(this).balance;
        require(_amount <= totalBalanceInContract, "withdraw amount must be smaller than total balance in contract");
        address payable to = payable(_receiver);
        to.transfer(_amount);
    }
}