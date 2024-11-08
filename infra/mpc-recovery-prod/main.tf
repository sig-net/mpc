terraform {
  backend "gcs" {
    bucket = "near-multichain-state-mainnet"
    prefix = "state/mpc-recovery"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.73.0"
    }
  }
}

locals {

  workspace = {
    near_rpc          = "https://rpc.mainnet.near.org"
    near_root_account = "near"
  }
}

data "external" "git_checkout" {
  program = ["${path.module}/../scripts/get_sha.sh"]
}

provider "google" {

  project = var.project
  region  = var.region
  zone    = var.zone
}

/*
 * Create brand new service account with basic IAM
 */
resource "google_service_account" "service_account" {
  account_id   = "mpc-recovery-mainnet"
  display_name = "MPC Recovery mainnet Account"
}


resource "google_project_iam_member" "service-account-datastore-user" {
  project = var.project
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.service_account.email}"
}

/*
 * Ensure service account has access to Secret Manager variables
 */
resource "google_secret_manager_secret_iam_member" "cipher_key_secret_access" {
  count = length(var.signer_configs)

  secret_id = var.signer_configs[count.index].cipher_key_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.service_account.email}"
}

resource "google_secret_manager_secret_iam_member" "secret_share_secret_access" {
  count = length(var.signer_configs)

  secret_id = var.signer_configs[count.index].sk_share_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.service_account.email}"
}

resource "google_secret_manager_secret_iam_member" "account_creator_secret_access" {
  secret_id = var.account_creator_sk_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.service_account.email}"
}

resource "google_secret_manager_secret_iam_member" "fast_auth_partners_secret_access" {
  secret_id = var.fast_auth_partners_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.service_account.email}"
}

module "mpc-leader-lb-mainnet" {
  source        = "../modules/internal_cloudrun_lb"
  name          = "mpc-leader-mainnet"
  network_id    = data.google_compute_network.prod_network.id
  subnetwork_id = data.google_compute_subnetwork.prod_subnetwork.id
  project_id    = var.project
  region        = var.region
  service_name  = "mpc-recovery-leader-mainnet"
}

/*
 * Create multiple signer nodes
 */
module "signer-mainnet" {
  count  = length(var.signer_configs)
  source = "../modules/signer"

  env                   = "mainnet"
  service_name          = "mpc-recovery-signer-${count.index}-mainnet"
  project               = var.project
  region                = var.region
  zone                  = var.zone
  service_account_email = google_service_account.service_account.email
  docker_image          = var.docker_image
  connector_id          = var.prod-connector
  jwt_signature_pk_url  = var.jwt_signature_pk_url

  node_id = count.index

  cipher_key_secret_id = var.signer_configs[count.index].cipher_key_secret_id
  sk_share_secret_id   = var.signer_configs[count.index].sk_share_secret_id

  depends_on = [
    google_secret_manager_secret_iam_member.cipher_key_secret_access,
    google_secret_manager_secret_iam_member.secret_share_secret_access,
  ]
}

/*
 * Create leader node
 */
module "leader-mainnet" {
  source = "../modules/leader"

  env                   = "mainnet"
  service_name          = "mpc-recovery-leader-mainnet"
  project               = var.project
  region                = var.region
  zone                  = var.zone
  service_account_email = google_service_account.service_account.email
  docker_image          = var.docker_image
  connector_id          = var.prod-connector
  jwt_signature_pk_url  = var.jwt_signature_pk_url
  opentelemetry_level   = var.opentelemetry_level
  otlp_endpoint         = var.otlp_endpoint

  signer_node_urls   = concat(module.signer-mainnet.*.node.uri, var.external_signer_node_urls)
  near_rpc           = local.workspace.near_rpc
  near_root_account  = local.workspace.near_root_account
  account_creator_id = var.account_creator_id

  account_creator_sk_secret_id = var.account_creator_sk_secret_id
  fast_auth_partners_secret_id = var.fast_auth_partners_secret_id

  depends_on = [
    google_secret_manager_secret_iam_member.account_creator_secret_access,
    google_secret_manager_secret_iam_member.fast_auth_partners_secret_access,
    module.signer-mainnet
  ]
}
