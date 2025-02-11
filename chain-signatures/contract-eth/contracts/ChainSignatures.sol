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

    event SignatureRequested(
        bytes32 indexed requestId,
        address sender,
        bytes32 payload,
        string path,
        uint32 keyVersion,
        string algo,
        string dest,
        string params,
        uint256 deposit,
        uint256 chainId,
        uint256 timestamp
    );

    event SignatureResponded(
        bytes32 indexed requestId,
        address responder,
        SignatureResponse response
    );

    event Withdraw(address indexed owner, uint amount);

    constructor(address _admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        signatureDeposit = 50000 gwei;
    }

    function sign(
        SignRequest memory _request
    ) external payable returns (bytes32) {
        require(msg.value >= signatureDeposit, "Insufficient deposit");

        bytes32 requestId = keccak256(
            abi.encodePacked(
                msg.sender,
                ":",
                _request.payload,
                ":",
                _request.path,
                ":",
                _request.keyVersion,
                ":",
                _request.algo,
                ":",
                _request.dest,
                ":",
                _request.params,
                ":",
                msg.value,
                ":",
                block.chainid,
                ":",
                block.timestamp
            )
        );

        emit SignatureRequested(
            requestId,
            msg.sender,
            _request.payload,
            _request.path,
            _request.keyVersion,
            _request.algo,
            _request.dest,
            _request.params,
            msg.value,
            block.chainid,
            block.timestamp
        );

        return requestId;
    }

    function respond(ResponseWithId[] calldata _responses) external {
        for (uint256 i = 0; i < _responses.length; i++) {
            emit SignatureResponded(
                _responses[i].requestId,
                msg.sender,
                _responses[i].response
            );
        }
    }

    function getSignatureDeposit() external view returns (uint256) {
        return signatureDeposit;
    }

    function setSignatureDeposit(
        uint256 _amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        signatureDeposit = _amount;
    }

    function withdraw(
        uint256 _amount,
        address _receiver
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            _amount <= address(this).balance,
            "Withdraw amount must be smaller than total balance in contract"
        );
        address payable to = payable(_receiver);
        to.transfer(_amount);
        emit Withdraw(_receiver, _amount);
    }
}
