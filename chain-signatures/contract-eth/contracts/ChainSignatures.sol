// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./Secp256k1.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "hardhat/console.sol";

contract ChainSignatures {
    struct SignRequest {
        bytes32 payload;
        string path;
        uint32 keyVersion;
    }

    struct SignatureResponse {
        AffinePoint bigR;
        uint256 s;
        uint8 recoveryId;
    }

    struct PublicKey {
        uint256 x;
        uint256 y;
    }

    struct AffinePoint {
        uint256 x;
        uint256 y;
    }

    PublicKey public publicKey;

    event SignatureRequested(bytes32 indexed requestId, address requester, bytes32 payload, uint256 deposit, string path);
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
        (uint256 epsilonGx, uint256 epsilonGy) = Secp256k1.ecMul(epsilon, Secp256k1.GX, Secp256k1.GY);
        (uint256 resultX, uint256 resultY) = Secp256k1.ecAdd(epsilonGx, epsilonGy, _publicKey.x, _publicKey.y);
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

    function sign(SignRequest memory _request) external payable returns (bytes32) {
        bytes32 payload = _request.payload;
        string memory path = _request.path;

        bytes32 requestId = keccak256(abi.encodePacked(payload, msg.sender, path));

        emit SignatureRequested(requestId, msg.sender, payload, msg.value, path);

        return requestId;
    }
    
    function respond(bytes32 _requestId, SignatureResponse memory _response) external {        
        emit SignatureResponded(_requestId, _response);
    }

    function getSignatureDeposit() public pure returns (uint256) {
        // Simplified deposit calculation
        return 1 wei;
    }
}