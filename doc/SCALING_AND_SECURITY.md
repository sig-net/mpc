## Scaling capabilities
Currently chain signatures operates using one signature genertion network and can handle up to 16 concurent requests. Average response time including all network delays is ~4 seconds on Solana. We are planning to improve both metrics wich will allow to handle more requests and reduce response time.

## Security properties
Chain signatures uses threshold ECDSA and EdDSA protocols through configurable backends. Currently our network consist of 8 nodes with threshold 5. This means that at least 5 nodes must collaborate in order to create a valid signature.

The system supports two threshold signing backends:
- **CaitSithAdapter**: Legacy backend supporting threshold ECDSA signatures using the `cait-sith` library
- **NearThresholdSigner**: Modern backend supporting both threshold ECDSA and EdDSA signatures using the `near/threshold-signatures` library

Backend selection is controlled via feature flags, allowing for gradual migration while maintaining security properties.