env        = "testnet"
project_id = "<your-project-id>"
network    = "default"
subnetwork = "default"
image      = "europe-west1-docker.pkg.dev/near-cs-testnet/multichain-public/multichain-testnet:latest"
region     = "europe-west1"
zone       = "europe-west1-b"
# These will be specific to your node
node_configs = [
  {
    # Each node has a unique account ID
    account   = "{your_near_account_id}"
    # These 3 values below should match your secret names in google secrets manager
    account_sk_secret_id = "multichain-account-sk-testnet-0"
    cipher_sk_secret_id  = "multichain-cipher-sk-testnet-0"
    sign_sk_secret_id    = "multichain-sign-sk-testnet-0"
    sk_share_secret_id   = "multichain-sk-share-testnet-0"
    eth_account_sk_secret_id = "multichain-eth-account-sk-testnet-0"
    eth_consensus_rpc_url_secret_id = "multichain-eth-consensus-rpc-url-testnet"
    eth_execution_rpc_url_secret_id = "multichain-eth-execution-rpc-url-testnet"
    eth_contract_address = "83458E8Bf8206131Fe5c05127007FA164c0948A2"
  },
]