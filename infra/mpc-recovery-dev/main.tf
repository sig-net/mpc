terraform {
  backend "gcs" {
    bucket = "mpc-recovery-terraform-dev"
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
  credentials  = var.credentials != null ? var.credentials : file(var.credentials_file)
  client_email = jsondecode(local.credentials).client_email
  client_id    = jsondecode(local.credentials).client_id

  env = {
    defaults = {
      near_rpc          = "https://rpc.testnet.near.org"
      near_root_account = "testnet"
    }
    testnet = {
    }
    mainnet = {
      near_rpc          = "https://rpc.mainnet.near.org"
      near_root_account = "near"
    }
  }

  workspace = merge(local.env["defaults"], contains(keys(local.env), terraform.workspace) ? local.env[terraform.workspace] : local.env["defaults"])
}

data "external" "git_checkout" {
  program = ["${path.module}/../scripts/get_sha.sh"]
}

provider "google" {
  credentials = local.credentials
  # credentials = file("~/.config/gcloud/application_default_credentials.json")

  project = var.project
  region  = var.region
  zone    = var.zone
}

/*
 * Create brand new service account with basic IAM
 */
resource "google_service_account" "service_account" {
  account_id   = "mpc-recovery-${var.env}"
  display_name = "MPC Recovery ${var.env} Account"
}

resource "google_service_account_iam_binding" "serivce-account-iam" {
  service_account_id = google_service_account.service_account.name
  role               = "roles/iam.serviceAccountUser"

  members = [
    "serviceAccount:${local.client_email}",
    # "serviceAccount:mpc-recovery@pagoda-discovery-platform-dev.iam.gserviceaccount.com"
  ]
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

/*
 * Create multiple signer nodes
 */
module "signer" {
  count  = length(var.signer_configs)
  source = "../modules/signer"

  env                   = var.env
  service_name          = "mpc-recovery-signer-${count.index}-${var.env}"
  project               = var.project
  region                = var.region
  zone                  = var.zone
  service_account_email = google_service_account.service_account.email
  docker_image          = var.docker_image
  connector_id          = var.dev-connector

  node_id = count.index

  cipher_key_secret_id = var.signer_configs[count.index].cipher_key_secret_id
  sk_share_secret_id   = var.signer_configs[count.index].sk_share_secret_id

  jwt_signature_pk_url = var.jwt_signature_pk_url

  depends_on = [
    google_secret_manager_secret_iam_member.cipher_key_secret_access,
    google_secret_manager_secret_iam_member.secret_share_secret_access,
  ]
}

/*
 * Create leader node
 */
module "leader" {
  source = "../modules/leader"

  env                   = var.env
  service_name          = "mpc-recovery-leader-${var.env}"
  project               = var.project
  region                = var.region
  zone                  = var.zone
  service_account_email = google_service_account.service_account.email
  docker_image          = var.docker_image
  connector_id          = var.dev-connector

  signer_node_urls   = concat(module.signer.*.node.uri, var.external_signer_node_urls)
  near_rpc           = local.workspace.near_rpc
  near_root_account  = local.workspace.near_root_account
  account_creator_id = var.account_creator_id

  account_creator_sk_secret_id = var.account_creator_sk_secret_id
  fast_auth_partners_secret_id = var.fast_auth_partners_secret_id

  jwt_signature_pk_url = var.jwt_signature_pk_url

  otlp_endpoint       = var.otlp_endpoint
  opentelemetry_level = var.opentelemetry_level

  depends_on = [
    google_secret_manager_secret_iam_member.account_creator_secret_access,
    google_secret_manager_secret_iam_member.fast_auth_partners_secret_access,
    module.signer
  ]
}
