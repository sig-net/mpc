// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./Secp256k1.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "hardhat/console.sol";

contract ChainSignatures is Initializable {
    struct SignRequest {
        bytes32 payload;
        string path;
        uint32 keyVersion;
        PublicKey derivedPublicKey;
    }

    struct SignatureRequest {
        uint256 epsilon;
        uint256 payloadHash;
        address requester;
        PublicKey derivedPublicKey;
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

    uint256 public threshold;
    mapping(bytes32 => SignatureRequest) public pendingRequests;
    uint256 public requestCounter;
    PublicKey public publicKey;

    mapping(bytes32 => uint256) public depositToRefund;

    uint32 public keyVersion;

    event SignatureRequested(bytes32 indexed requestId, address requester, uint256 epsilon, uint256 payloadHash, string path);
    event SignatureResponded(bytes32 indexed requestId, SignatureResponse response);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(PublicKey calldata _publicKey, uint32 _keyVersion) public initializer {
        publicKey = _publicKey;
        keyVersion = _keyVersion;
    }

    function upgradeToV2(PublicKey calldata _publicKey, uint32 _keyVersion) public reinitializer(2) {
        publicKey = _publicKey;
        keyVersion = _keyVersion;
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

    function verifyDerivedKey(uint256 epsilon, PublicKey memory derivedPk) private view returns (bool) {
        (uint256 epsilonGx, uint256 epsilonGy) = Secp256k1.ecSub(derivedPk.x, derivedPk.y, publicKey.x, publicKey.y);
        // verify epsilonGx, epsilonGy is G * epsilon, based on:
        // https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384
        address recovered = ecrecover(bytes32(0), 27, bytes32(Secp256k1.GX), bytes32(mulmod(Secp256k1.GX, epsilon, Secp256k1.N)));

        // epsilonG should match recovered
        bytes32 epsilonGHash = keccak256(abi.encodePacked(epsilonGx, epsilonGy));
        address epsilonGAddr = address(uint160(uint256(epsilonGHash)));
        return epsilonGAddr == recovered;
    }

    function deriveEpsilon(string memory path, address requester) public pure returns (uint256) {
        string memory requesterStr = Strings.toHexString(uint256(uint160(requester)), 20);
        string memory epsilonString = string.concat("near-mpc-recovery v0.2.0 epsilon derivation:", requesterStr, ",", path);
        console.log("Epsilon String:", epsilonString);
        bytes32 epsilonBytes = keccak256(bytes(epsilonString));
        uint256 epsilon = uint256(epsilonBytes);
        return epsilon;
    }

    function getLatestKeyVersion() public view returns (uint32) {
        return keyVersion;
    }

    function sign(SignRequest memory _request) external payable returns (bytes32) {
        bytes32 payload = _request.payload;
        string memory path = _request.path;
        uint32 requestKeyVersion = _request.keyVersion;

        if (requestKeyVersion > getLatestKeyVersion()) {
            revert("this key version is unsupported. Call getLatestKeyVersion() to get the latest supported version");
        }

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
        PublicKey memory derivedPk = _request.derivedPublicKey;
        require(verifyDerivedKey(epsilon, derivedPk), "Derived key verification failed");
        SignatureRequest memory request = SignatureRequest(epsilon, payloadHash, msg.sender, derivedPk);
        pendingRequests[requestId] = request;
        depositToRefund[requestId] = msg.value - requiredDeposit;
        requestCounter++;

        emit SignatureRequested(requestId, msg.sender, epsilon, payloadHash, path);

        return requestId;
    }
    
    function respond(bytes32 _requestId, SignatureResponse memory _response) external {        
        SignatureRequest storage request = pendingRequests[_requestId];
        require(request.requester != address(0), "Request not found");

        PublicKey memory expectedPublicKey = request.derivedPublicKey;
        // Derive Ethereum address from public key
        bytes32 pkHash = keccak256(abi.encodePacked(expectedPublicKey.x, expectedPublicKey.y));
        address expectedSigner = address(uint160(uint256(pkHash)));
        // Verify the virtual signer is the derived address using ecrecover
        address recoveredSigner = ecrecover(bytes32(request.payloadHash), _response.recoveryId+27, bytes32(_response.bigR.x), bytes32(_response.s));
        require(recoveredSigner == expectedSigner, "Invalid signature");

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
}