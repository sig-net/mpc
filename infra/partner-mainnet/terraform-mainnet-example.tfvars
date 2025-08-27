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
    # These 3 values below should match your secret names in google secrets manager
    account_sk_secret_id = "multichain-account-sk-mainnet-0"
    cipher_sk_secret_id  = "multichain-cipher-sk-mainnet-0"
    sign_sk_secret_id    = "multichain-sign-sk-mainnet-0"
    sk_share_secret_id   = "multichain-sk-share-mainnet-0"
    domain               = "{your-domain-or-subdomain}"
    eth_account_sk_secret_id = "multichain-eth-account-sk-mainnet-0"
    eth_consensus_rpc_http_url = "https://ethereum.operationsolarstorm.org/"
    eth_execution_rpc_url_secret_id = "multichain-eth-execution-rpc-url-mainnet"
    eth_contract_address = "D39b0aBc0acab7d48aC6DFC9612543f035233b68"
    sol_account_sk_secret_id = "multichain-sol-account-sk-mainnet"
    sol_rpc_http_url_secret_id = "multichain-sol-rpc-http-url-mainnet"
    sol_rpc_ws_url_secret_id = "multichain-sol-rpc-ws-url-mainnet"
    sol_program_address = "<mainnet-sol-program-address>"
  },
]