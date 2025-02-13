// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title Sig.Network signing contract
 * @dev Contract for accepting signature requests and providing responses from the Sig.Network.
 */
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
        Signature signature;
    }

    uint256 signatureDeposit;

    /**
     * @dev Emitted when a signature is requested.
     * @param sender The address of the sender.
     * @param payload The payload to be signed.
     * @param keyVersion The version of the key used for signing.
     * @param deposit The deposit amount.
     * @param chainId The ID of the blockchain.
     * @param path The derivation path for the user account.
     * @param algo The algorithm used for signing.
     * @param dest The response destination.
     * @param params Additional parameters.
     */
    event SignatureRequested(
        address sender,
        bytes32 payload,
        uint32 keyVersion,
        uint256 deposit,
        uint256 chainId,
        string path,
        string algo,
        string dest,
        string params
    );

    /**
     * @dev Emitted when a signature response is received.
     * @param requestId The ID of the request. Must be calculated off-chain.
     * @param responder The address of the responder.
     * @param signature The signature response.
     */
    event SignatureResponded(
        bytes32 indexed requestId,
        address responder,
        Signature signature
    );

    /**
     * @dev Emitted when a withdrawal is made.
     * @param owner The address of the owner.
     * @param amount The amount withdrawn.
     */
    event Withdraw(address indexed owner, uint amount);

    /**
     * @dev Constructor for the ChainSignatures contract.
     * @param _mpc_network The address of the account controlled by the MPC network.
     * @param _signatureDeposit The deposit required for signature requests.
     */
    constructor(address _mpc_network, uint256 _signatureDeposit) {
        _grantRole(DEFAULT_ADMIN_ROLE, _mpc_network);
        signatureDeposit = _signatureDeposit;
    }

    /**
     * @dev Function to request a signature.
     * @param _request The signature request details.
     */
    function sign(SignRequest memory _request) external payable {
        require(msg.value >= signatureDeposit, "Insufficient deposit");

        emit SignatureRequested(
            msg.sender,
            _request.payload,
            _request.keyVersion,
            msg.value,
            block.chainid,
            _request.path,
            _request.algo,
            _request.dest,
            _request.params
        );
    }

    /**
     * @dev Function to respond to signature requests.
     * @param _responses The array of signature responses.
     */
    function respond(Response[] calldata _responses) external {
        for (uint256 i = 0; i < _responses.length; i++) {
            emit SignatureResponded(
                _responses[i].requestId,
                msg.sender,
                _responses[i].signature
            );
        }
    }

    /**
     * @dev Function to get the current signature deposit amount.
     * @return The current signature deposit amount.
     */
    function getSignatureDeposit() external view returns (uint256) {
        return signatureDeposit;
    }

    /**
     * @dev Function to set the signature deposit amount.
     * @param _amount The new deposit amount.
     */
    function setSignatureDeposit(
        uint256 _amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        signatureDeposit = _amount;
    }

    /**
     * @dev Function to withdraw funds from the contract.
     * @param _amount The amount to withdraw.
     * @param _receiver The address to receive the withdrawn funds.
     */
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
