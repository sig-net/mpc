terraform {
  backend "gcs" {
    prefix = "state/mpc-recovery"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.73.0"
    }
    docker = {
      source  = "kreuzwerker/docker"
      version = "3.0.2"
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
      relayer_api_key   = null
      relayer_url       = "http://34.70.226.83:3030"
      near_root_account = "testnet"
    }
    testnet = {
    }
    mainnet = {
      near_rpc = "https://rpc.mainnet.near.org"
      // TODO: move relayer API key to secrets
      relayer_api_key   = "dfadcb16-2293-4649-896b-4bc4224adea0"
      relayer_url       = "http://near-relayer-mainnet.api.pagoda.co"
      near_root_account = "near"
    }
  }

  workspace = merge(local.env["defaults"], contains(keys(local.env), terraform.workspace) ? local.env[terraform.workspace] : local.env["defaults"])
}

data "external" "git_checkout" {
  program = ["${path.module}/scripts/get_sha.sh"]
}

provider "google" {
  credentials = local.credentials

  project = var.project
  region  = var.region
  zone    = var.zone
}

provider "docker" {
  registry_auth {
    address  = "${var.region}-docker.pkg.dev"
    username = "_json_key"
    password = local.credentials
  }
}

resource "google_service_account" "service_account" {
  account_id   = "mpc-recovery-${var.env}"
  display_name = "MPC Recovery ${var.env} Account"
}

resource "google_service_account_iam_binding" "serivce-account-iam" {
  service_account_id = google_service_account.service_account.name
  role               = "roles/iam.serviceAccountUser"

  members = [
    "serviceAccount:${local.client_email}",
  ]
}

resource "google_project_iam_member" "service-account-datastore-user" {
  project = var.project
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.service_account.email}"
}

resource "google_artifact_registry_repository" "mpc_recovery" {
  repository_id = "mpc-recovery-${var.env}"
  format        = "DOCKER"
}

resource "docker_registry_image" "mpc_recovery" {
  name          = docker_image.mpc_recovery.name
  keep_remotely = true
}

resource "docker_image" "mpc_recovery" {
  name = "${var.region}-docker.pkg.dev/${var.project}/${google_artifact_registry_repository.mpc_recovery.name}/mpc-recovery-${var.env}:${data.external.git_checkout.result.sha}"
  build {
    context = "${path.cwd}/.."
  }
}

module "signer" {
  count  = length(var.cipher_keys)
  source = "./modules/signer"

  env                   = var.env
  project               = var.project
  region                = var.region
  zone                  = var.zone
  service_account_email = google_service_account.service_account.email
  docker_image          = docker_image.mpc_recovery.name

  node_id                = count.index
  allowed_oidc_providers = var.allowed_oidc_providers

  cipher_key = var.cipher_keys[count.index]
  sk_share   = var.sk_shares[count.index]

  depends_on = [docker_registry_image.mpc_recovery]
}

module "leader" {
  source = "./modules/leader"

  env                   = var.env
  project               = var.project
  region                = var.region
  zone                  = var.zone
  service_account_email = google_service_account.service_account.email
  docker_image          = docker_image.mpc_recovery.name

  signer_node_urls       = concat(module.signer.*.node.uri, var.external_signer_node_urls)
  near_rpc               = local.workspace.near_rpc
  relayer_api_key        = local.workspace.relayer_api_key
  relayer_url            = local.workspace.relayer_url
  near_root_account      = local.workspace.near_root_account
  account_creator_id     = var.account_creator_id
  allowed_oidc_providers = var.allowed_oidc_providers

  account_creator_sk = var.account_creator_sk

  depends_on = [docker_registry_image.mpc_recovery, module.signer]
}

module "security_policy" {
  source = "GoogleCloudPlatform/cloud-armor/google"

  project_id                           = var.project
  name                                 = "my-test-ca-policy"
  description                          = "Test Cloud Armor security policy with preconfigured rules, security rules and custom rules"
  default_rule_action                  = "deny(403)"
  type                                 = "CLOUD_ARMOR"
  layer_7_ddos_defense_enable          = true
  layer_7_ddos_defense_rule_visibility = "STANDARD"
  json_parsing                         = "STANDARD"
  log_level                            = "VERBOSE"

  pre_configured_rules      = {}
  security_rules            = {}
  custom_rules              = {}
  threat_intelligence_rules = {}
}

resource "google_compute_region_network_endpoint_group" "serverless_neg_leader" {
  provider              = google-beta
  name                  = "serverless-neg-leader"
  network               = "dev"
  network_endpoint_type = "SERVERLESS"
  region                = var.region
  create_url_map        = false
  url_map               = google_compute_url_map.url_map.name
  cloud_run {
    service = "mpc-recovery-leader-${var.env}"
  }
}

resource "google_compute_url_map" "urlmap" {
  name        = "url-map-name"
  description = "a description"

  host_rule {
    hosts        = ["mysite.com"]
    path_matcher = "allpaths"
  }

  path_matcher {
    name = "allpaths"

    path_rule {
      paths = ["/home"]
      route_action {
        cors_policy {
          allow_credentials    = true
          allow_headers        = ["Allowed content"]
          allow_methods        = ["GET"]
          allow_origin_regexes = ["abc.*"]
          allow_origins        = ["Allowed origin"]
          expose_headers       = ["Exposed header"]
          max_age              = 30
          disabled             = false
        }
        fault_injection_policy {
          abort {
            http_status = 234
            percentage  = 5.6
          }
          delay {
            fixed_delay {
              seconds = 0
              nanos   = 50000
            }
            percentage = 7.8
          }
        }
        request_mirror_policy {
          backend_service = google_compute_backend_service.home.id
        }
        retry_policy {
          num_retries = 4
          per_try_timeout {
            seconds = 30
          }
          retry_conditions = ["5xx", "deadline-exceeded"]
        }
        timeout {
          seconds = 20
          nanos   = 750000000
        }
        url_rewrite {
          host_rewrite        = "dev.example.com"
          path_prefix_rewrite = "/v1/api/"
        }
        weighted_backend_services {
          backend_service = google_compute_backend_service.home.id
          weight          = 400
          header_action {
            request_headers_to_remove = ["RemoveMe"]
            request_headers_to_add {
              header_name  = "AddMe"
              header_value = "MyValue"
              replace      = true
            }
            response_headers_to_remove = ["RemoveMe"]
            response_headers_to_add {
              header_name  = "AddMe"
              header_value = "MyValue"
              replace      = false
            }
          }
        }
      }
    }
  }

  test {
    host = "hi.com"
    path = "/home"
  }
}

module "loadbalancer" {
  source  = "GoogleCloudPlatform/lb-http/google//modules/serverless_negs"
  version = "~> 9.0"

  project                         = var.project
  security_policy                 = module.security_policy.policy
  region                          = var.region
  ssl                             = true
  https_redirect                  = true
  managed_ssl_certificate_domains = ["your-domain.com"]
  labels                          = {}


  # Can have multiple back ends for signers
  backends = {
    default = {
      description = null
      groups = [
        {
          group = google_compute_region_network_endpoint_group.serverless_neg_leader.id
        }
      ]
      enable_cdn = false

      iap_config = {
        enable = false
      }
      log_config = {
        enable = false
      }
    }
  }
}