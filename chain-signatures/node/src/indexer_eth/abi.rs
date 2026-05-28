alloy::sol! {
    #[sol(rpc)]
    contract ChainSignatures {
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

        struct ErrorResponse {
            bytes32 requestId;
            string errorMessage;
        }

        function sign(SignRequest memory _request) external payable;
        function respond(Response[] calldata _responses) external;
        function respondError(ErrorResponse[] calldata _errors) external;
        function getSignatureDeposit() external view returns (uint256);

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

        event SignatureResponded(
            bytes32 indexed requestId,
            address responder,
            Signature signature
        );

        event SignatureError(
            bytes32 indexed requestId,
            address responder,
            string error
        );
    }

    event SignatureRequestedEncoding(
        address sender,
        bytes payload,
        string path,
        uint32 keyVersion,
        uint256 chainId,
        string algo,
        string dest,
        string params
    );

    struct ChainSignaturesConstructor {
        address mpcNetwork;
        uint256 signatureDeposit;
    }
}
