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

        struct SignBidirectionalRequest {
            bytes serializedTransaction;
            string caip2Id;
            uint32 keyVersion;
            string path;
            string algo;
            string dest;
            string params;
            bytes outputDeserializationSchema;
            bytes respondSerializationSchema;
        }

        function signBidirectional(SignBidirectionalRequest memory _request) external payable;
        function respondBidirectional(
            bytes32 _requestId,
            bytes calldata _serializedOutput,
            Signature calldata _signature
        ) external;

        event SignBidirectional(
            address sender,
            bytes serializedTransaction,
            string caip2Id,
            uint32 keyVersion,
            uint256 deposit,
            uint256 chainId,
            string path,
            string algo,
            string dest,
            string params,
            bytes outputDeserializationSchema,
            bytes respondSerializationSchema
        );

        event RespondBidirectional(
            bytes32 indexed requestId,
            address responder,
            bytes serializedOutput,
            Signature signature
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

#[cfg(test)]
mod tests {
    use super::ChainSignatures;
    use alloy::primitives::b256;
    use alloy::sol_types::SolEvent;

    #[test]
    fn bidirectional_event_topics_match_contract() {
        // keccak256("SignBidirectional(address,bytes,string,uint32,uint256,uint256,string,string,string,string,bytes,bytes)")
        assert_eq!(
            ChainSignatures::SignBidirectional::SIGNATURE_HASH,
            b256!("27f9d88f0144f82d39d07d3e314ac47018991ad27af3fb62129dd7cd725846e8"),
        );
        // keccak256("RespondBidirectional(bytes32,address,bytes,((uint256,uint256),uint256,uint8))")
        assert_eq!(
            ChainSignatures::RespondBidirectional::SIGNATURE_HASH,
            b256!("23a9a92895272f15b4a10136e9902bae33c369c40c448b2d184f9a06e33fc3df"),
        );
    }
}
