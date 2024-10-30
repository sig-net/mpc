// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./EllipticCurve.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "hardhat/console.sol"; // Import Hardhat's console library


contract ChainSignatures {
    // Generator point G of secp256k1
    uint256 constant Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 constant Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

    struct SignRequest {
        bytes32 payload;
        string path;
    }

    struct SignatureRequest {
        uint256 epsilon;
        uint256 payloadHash;
        address requester;
    }

    struct SignatureResponse {
        PublicKey bigR;
        uint256 s;
        uint8 recoveryId;
    }

    // public key in affine form
    struct PublicKey {
        uint256 x;
        uint256 y;
    }

    uint256 public threshold;
    mapping(bytes32 => SignatureRequest) public pendingRequests;
    uint256 public requestCounter;
    PublicKey public publicKey;

    mapping(bytes32 => uint256) public depositToRefund;

    event SignatureRequested(bytes32 indexed requestId, address requester, uint256 epsilon, uint256 payloadHash, string path);
    event SignatureResponded(bytes32 indexed requestId, SignatureResponse response);

    constructor(PublicKey memory _publicKey) {
        publicKey = _publicKey;
    }

    function getPublicKey() public view returns (PublicKey memory) {
        return publicKey;
    }

    function derivedPublicKey(string memory path, address _predecessor) public view returns (PublicKey memory) {
        address predecessor = _predecessor == address(0) ? msg.sender : _predecessor;
        uint256 epsilon = deriveEpsilon(path, predecessor);
        PublicKey memory _derivedPublicKey = deriveKey(publicKey, epsilon);
        return _derivedPublicKey;
    }

    function deriveKey(PublicKey memory _publicKey, uint256 epsilon) public pure returns (PublicKey memory) {
        // G * epsilon + publicKey
        (uint256 epsilonGx, uint256 epsilonGy) = ecMul(epsilon, Gx, Gy);
        (uint256 resultX, uint256 resultY) = ecAdd(epsilonGx, epsilonGy, _publicKey.x, _publicKey.y);
        return PublicKey(resultX, resultY);
    }

    function deriveEpsilon(string memory path, address requester) public pure returns (uint256) {
        string memory requesterStr = Strings.toHexString(uint256(uint160(requester)), 20);
        string memory epsilonString = string.concat("near-mpc-recovery v0.2.0 epsilon derivation:", requesterStr, ",", path);
        console.log("Epsilon String:", epsilonString);
        bytes32 epsilonBytes = keccak256(bytes(epsilonString));
        uint256 epsilon = uint256(epsilonBytes);
        return epsilon;
    }

    function sign(bytes32 payload, string memory path) external payable returns (bytes32) {
        uint256 requiredDeposit = getSignatureDeposit();
        require(msg.value >= requiredDeposit, "Insufficient deposit");

        // Concert payload to int as big-endian, check if payload is than the secp256k1 curve order
        uint256 payloadHash = uint256(payload);
        require(
            payloadHash < 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
            "Payload exceeds secp256k1 curve order"
        );

        bytes32 requestId = keccak256(abi.encodePacked(payload, msg.sender, path));
        require(pendingRequests[requestId].requester == address(0), "Request already exists");

        uint256 epsilon = deriveEpsilon(path, msg.sender);
        SignatureRequest memory request = SignatureRequest(epsilon, payloadHash, msg.sender);
        pendingRequests[requestId] = request;
        depositToRefund[requestId] = msg.value - requiredDeposit;
        requestCounter++;

        emit SignatureRequested(requestId, msg.sender, epsilon, payloadHash, path);

        return requestId;
    }
    
    function respond(bytes32 _requestId, SignatureResponse memory _response) external {        
        SignatureRequest storage request = pendingRequests[_requestId];
        require(request.requester != address(0), "Request not found");

        PublicKey memory expectedPublicKey = deriveKey(publicKey, request.epsilon);

        // Check the signature
        require(
            checkECSignature(
                expectedPublicKey,
                _response.bigR,
                uint256(_response.s),
                request.payloadHash,
                _response.recoveryId
            ),
            "Invalid signature"
        );

        emit SignatureResponded(_requestId, _response);

        // Refund excess deposit
        uint256 refund = depositToRefund[_requestId];

        // Clean up
        delete pendingRequests[_requestId];
        delete depositToRefund[_requestId];
        requestCounter--;

        if (refund > 0) {
            payable(request.requester).transfer(refund);
        }
    }

    function getSignatureDeposit() public view returns (uint256) {
        // Simplified deposit calculation
        if (requestCounter <= 3) {
            return 1 wei;
        } else {
            return (requestCounter - 3) * 4 * 1e15; // 0.004 ETH (~1 USD) first request after the first 3
        }
    }

    function checkECSignature(
        PublicKey memory _expectedPk,
        PublicKey memory _bigR,
        uint256 _s,
        uint256 _msgHash,
        uint8 _recoveryId
    ) internal pure returns (bool) {
        // // Reconstruct the signature
        // bytes32 r = bytes32(_bigR);
        // bytes32 s = bytes32(_s);
    
        // // Recover the signer's address
        // // TODO ethereum ecrecover returns an address, but we need a curve point
        // PublicKey memory foundPk = ecrecover(_msgHash, _recoveryId, r, s);
        
        // // If recovery fails with the given recovery ID, try the alternative
        // uint8 alternativeRecoveryId = _recoveryId ^ 1;
        // address alternativeRecoveredAddress = ecrecover(_msgHash, alternativeRecoveryId, r, s);
        
        // if (alternativeRecoveredAddress == _expectedPk) {
        //     return true;
        // }
        
        // // If both recovery attempts fail, return false
        return false;
    }

    // Helper function for elliptic curve point multiplication
    function ecMul(uint256 _k, uint256 _x, uint256 _y) internal pure returns (uint256, uint256) {
        return EllipticCurve.ecMul(_k, _x, _y, 0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F);
    }

    // Helper function for elliptic curve point addition
    function ecAdd(uint256 _x1, uint256 _y1, uint256 _x2, uint256 _y2) internal pure returns (uint256, uint256) {
        return EllipticCurve.ecAdd(_x1, _y1, _x2, _y2, 0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F);
    }
}
