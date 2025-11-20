## Scaling capabilities
Currently chain signatures operates using one signature genertion network and can handle up to 16 concurent requests. Average response time including all network delays is ~4 seconds on Solana. We are planning to improve both metrics wich will allow to handle more requests and reduce response time.

## Security properties
Chain signatures is using threshold-signatures threshold ECDSA protocol. Currently our network consist of 8 nodes with threshold 5. This means that at least 5 nodes must collaborate in order to create a valid signature.