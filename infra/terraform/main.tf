# infra/terraform/main.tf
#
# Phase 2 - Google Cloud provider configuration and local state backend.
# The google provider minimum is locked to >= 5.0.0 as specified by the build
# plan. `terraform init` resolves the constraint and pins the exact provider
# version in the lockfile (.terraform.lock.hcl) for reproducibility.
#
# State: local backend - state stays on the operator machine (repo .gitignore
# already excludes *.tfstate / *.tfstate.* / .terraform/).

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0"
    }
  }

  backend "local" {}
}

# Provider configuration wired to the input variables (variables.tf).
# Project and region come from variables - never hardcoded here.
provider "google" {
  project = var.project_id
  region  = var.region
}
