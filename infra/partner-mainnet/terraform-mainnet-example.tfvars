env        = "mainnet"
project_id = "<your-project-id>"
network    = "default"
subnetwork = "default"
image      = "europe-west1-docker.pkg.dev/near-cs-mainnet/multichain-public/multichain-mainnet:latest"
region     = "europe-west1"
zone       = "europe-west1-b" # Feel free to choose other zones in the region for HA purposes between nodes
# These will be specific to your node
node_configs = [
  {
    # Each node has a unique account ID
    account   = "{your_near_account_id}"
    cipher_pk = "<your_cipher_pk>"
    # These 3 values below should match your secret names in google secrets manager
    account_sk_secret_id = "multichain-account-sk-mainnet-0"
    cipher_sk_secret_id  = "multichain-cipher-sk-mainnet-0"
    sign_sk_secret_id    = "multichain-sign-sk-mainnet-0"
    sk_share_secret_id   = "multichain-sk-share-mainnet-0"
    domain               = "{your-domain-or-subdomain}"
    eth_account_sk_secret_id = "multichain-eth-account-sk-mainnet-0"
    eth_rpc_ws_url_secret_id = "multichain-eth-rpc-ws-url-0"
    eth_rpc_http_url_secret_id = "multichain-eth-rpc-http-url-0"
    eth_contract_address = "<eth-contract-address>"
  },
]