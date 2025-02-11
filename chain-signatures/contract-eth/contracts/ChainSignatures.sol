// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/AccessControl.sol";

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

    struct Signature {
        AffinePoint bigR;
        uint256 s;
        uint8 recoveryId;
    }

    struct Response {
        bytes32 requestId;
        Signature response;
    }

    uint256 signatureDeposit;

    event SignatureRequested(
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
        Signature response
    );

    event Withdraw(address indexed owner, uint amount);

    constructor(address _mpc_network, uint256 _signatureDeposit) {
        _grantRole(DEFAULT_ADMIN_ROLE, _mpc_network);
        signatureDeposit = _signatureDeposit;
    }

    function sign(
        SignRequest memory _request
    ) external payable {
        require(msg.value >= signatureDeposit, "Insufficient deposit");

        emit SignatureRequested(
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
    }

    function respond(Response[] calldata _responses) external {
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
