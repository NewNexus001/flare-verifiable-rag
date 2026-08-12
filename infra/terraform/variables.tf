# infra/terraform/variables.tf
#
# Input variables for the Confidential VM deployment. Fail-fast validation:
# wrong-shaped inputs (especially the container digest) are rejected here,
# before they can ever reach the cloud - the same principle as the repo's
# zero-mock audit gate.

variable "project_id" {
  type        = string
  description = "GCP project ID where the Confidential VM and supporting resources are deployed."
}

variable "region" {
  type        = string
  description = "GCP region for regional resources (Confidential VM, WIF, KMS)."
  default     = "us-central1"
}

variable "zone" {
  type        = string
  description = "GCP zone within the region for zonal resources (the Confidential VM)."
  default     = "us-central1-a"
}

variable "container_image_digest" {
  type        = string
  description = "SHA-256 digest of the enclave container image, recorded by build-tee.yml into .teedigest. This binds the Workload Identity to exactly one image."
  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.container_image_digest))
    error_message = "container_image_digest must be a SHA-256 digest in the form sha256:<64 lowercase hex characters> (e.g. sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08)."
  }
}

variable "workload_identity_pool_id" {
  type        = string
  description = "ID of the Workload Identity Pool that holds the TEE (Confidential Space) identity provider."
  default     = "flare-tee-pool"
}

variable "enable_tdx" {
  type        = bool
  description = "Select Intel TDX Confidential Computing (c3-standard-4, Intel Sapphire Rapids, no live migration) instead of the default AMD SEV-SNP (n2d-standard-2, AMD Milan, live migration). Both are attested by Google Cloud Attestation; the workload identity binds to the container digest regardless of technology."
  default     = false
}

variable "container_image_reference" {
  type        = string
  description = "Full reference of the enclave container image the Confidential Space launcher runs inside the TEE (registry path plus tag, e.g. us-docker.pkg.dev/my-project/enclave/enclave:v1). The exact SHA-256 digest is carried separately in container_image_digest; the workload identity provider binds to that digest."
  validation {
    condition     = can(regex("^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)+(:[a-zA-Z0-9._-]+)?(@sha256:[0-9a-f]{64})?$", var.container_image_reference))
    error_message = "container_image_reference must be a valid container image reference with a repository path, e.g. us-docker.pkg.dev/my-project/enclave/enclave:v1."
  }
}
