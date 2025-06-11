terraform {
  backend "gcs" {
    bucket = "multichain-terraform-{your_entity_name}"
    prefix = "state/mainnet"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.73.0"
    }
  }
}

# These data blocks grab the values from your GCP secret manager, please adjust secret names as desired
data "google_secret_manager_secret_version" "account_sk_secret_id" {
  count   = length(var.node_configs)
  secret  = var.node_configs[0].account_sk_secret_id
  project = var.project_id
}

data "google_secret_manager_secret_version" "cipher_sk_secret_id" {
  count   = length(var.node_configs)
  secret  = var.node_configs[0].cipher_sk_secret_id
  project = var.project_id
}

data "google_secret_manager_secret_version" "sign_sk_secret_id" {
  count   = length(var.node_configs)
  secret  = var.node_configs[0].sign_sk_secret_id
  project = var.project_id
}

data "google_secret_manager_secret_version" "sk_share_secret_id" {
  count   = length(var.node_configs)
  secret  = var.node_configs[0].sk_share_secret_id
  project = var.project_id
}

# This is the AWS access key and secret key for our public S3 bucket with Lake data
data "google_secret_manager_secret_version" "aws_access_key_secret_id" {
  secret = "multichain-mainnet-indexer-aws-access-key"
}

data "google_secret_manager_secret_version" "aws_secret_key_secret_id" {
  secret = "multichain-mainnet-indexer-aws-secret-key"
}

data "google_secret_manager_secret_version" "eth_account_sk_secret_id" {
  count   = length(var.node_configs)
  secret  = var.node_configs[0].eth_account_sk_secret_id
  project = var.project_id
}

data "google_secret_manager_secret_version" "eth_execution_rpc_url_secret_id" {
  count   = length(var.node_configs)
  secret  = var.node_configs[0].eth_execution_rpc_url_secret_id
  project = var.project_id
}

data "google_secret_manager_secret_version" "sol_account_sk_secret_id" {
  count   = length(var.node_configs)
  secret  = var.node_configs[0].sol_account_sk_secret_id
  project = var.project_id
}

data "google_secret_manager_secret_version" "sol_rpc_http_url_secret_id" {
  count   = length(var.node_configs)
  secret  = var.node_configs[0].sol_rpc_http_url_secret_id
  project = var.project_id
}

data "google_secret_manager_secret_version" "sol_rpc_ws_url_secret_id" {
  count   = length(var.node_configs)
  secret  = var.node_configs[0].sol_rpc_ws_url_secret_id
  project = var.project_id
}