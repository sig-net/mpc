variable "project_id" {
  description = "The project ID to deploy resource into"
  type        = string
}

variable "subnetwork" {
  description = "The name of the subnetwork to deploy instances into"
  type        = string
}

variable "mig_name" {
  description = "The desired name to assign to the deployed managed instance group"
  type        = string
  default     = "mpc-mig"
}

variable "image" {
  description = "The Docker image to deploy to GCE instances. Note: This is a public image repository used for updating your nodes, please do not change this"
  type        = string
  default     = "us-east1-docker.pkg.dev/pagoda-discovery-platform-prod/multichain-public/multichain-testnet:latest"
}

variable "image_port" {
  description = "The port the image exposes for HTTP requests"
  type        = number
  default     = 3000
}

variable "region" {
  description = "The GCP region to deploy instances into"
  type        = string
}

variable "zone" {
  type = string
}

variable "network" {
  description = "The GCP network"
  type        = string
}

variable "additional_metadata" {
  type        = map(any)
  description = "Additional metadata to attach to the instance"
  default     = {}
}

variable "service_account" {
  type = object({
    email  = string,
    scopes = list(string)
  })
  default = {
    email  = ""
    scopes = ["cloud-platform"]
  }
}

variable "env_variables" {
  type    = map(any)
  default = null
}

variable "node_configs" {
  type = list(object({
    account              = string
    cipher_pk            = string
    account_sk_secret_id = string
    cipher_sk_secret_id  = string
    sign_sk_secret_id    = string
    sk_share_secret_id   = string
  }))
}

variable "env" {
  type = string
  default = "dev"
}

variable "static_env" {
  type = list(object({
    name  = string
    value = string
  }))
  default = [
    {
      name  = "MPC_RECOVERY_NEAR_RPC"
      value = "https://rpc.testnet.near.org"
    },
    {
      name  = "MPC_RECOVERY_CONTRACT_ID"
      value = "v2.multichain-mpc.testnet"
    },
    {
      name  = "MPC_RECOVERY_INDEXER_S3_BUCKET"
      value = "near-lake-data-testnet"
    },
    {
      name  = "MPC_RECOVERY_INDEXER_START_BLOCK_HEIGHT"
      value = 158767549
    },
    {
      name  = "AWS_DEFAULT_REGION"
      value = "eu-central-1"
    },
    {
      name  = "MPC_RECOVERY_GCP_PROJECT_ID"
      value = "<your-project-id>"
    },
    {
      name  = "MPC_RECOVERY_WEB_PORT"
      value = "3000"
    },
    {
      name  = "RUST_LOG"
      value = "mpc_recovery_node=debug"
    },
    {
      name  = "MPC_RECOVERY_INDEXER_S3_REGION"
      value = "eu-central-1"
    }
  ]
}

variable "create_network" {
  default = false
  description = "Do you want to create a new VPC network (true) or use default GCP network (false)?"
}