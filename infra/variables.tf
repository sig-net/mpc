variable "env" {
}

variable "project" {
}

variable "credentials_file" {
  default = null
}

variable "credentials" {
  default = null
}

variable "region" {
  default = "us-east1"
}

variable "zone" {
  default = "us-east1-c"
}

# Application variables
variable "account_creator_id" {
}

variable "firebase_audience_id" {
  default = "pagoda-oboarding-dev"
}

variable "external_signer_node_urls" {
  type    = list(string)
  default = []
}

# Secrets
variable "account_creator_sk" {
}

variable "cipher_keys" {
  type = list(string)
}

variable "sk_shares" {
  type = list(string)
}