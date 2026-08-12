# infra/terraform/workload_identity.tf
#
# WORKLOAD IDENTITY FEDERATION - the TEE identity anchor.
#
# A Workload Identity Pool (WIP) that holds the Confidential Space
# attestation identity. When the enclave container runs inside the
# Confidential VM, its vTPM attestation token is exchanged here for a
# Google Cloud identity - but only if the token satisfies the provider
# attribute condition. The provider below binds the identity to the
# Google Cloud Attestation service, requires swname ==
# CONFIDENTIAL_SPACE, and locks the workload to the exact container
# digest recorded in .teedigest by build-tee.yml via attribute_condition.
#
# Resource arguments verified against the google provider 7.42.0 schema
# (terraform providers schema -json): workload_identity_pool_id is the
# only REQUIRED argument. Display name is capped at 32 characters.

resource "google_iam_workload_identity_pool" "flare_tee_pool" {
  workload_identity_pool_id = var.workload_identity_pool_id
  project                   = var.project_id
  display_name              = "Flare TEE Pool"
  description               = "Holds the Confidential Space attestation identity for the Flare Verifiable RAG enclave. Tokens are exchanged only when the vTPM attestation matches the exact container digest recorded by build-tee.yml."
}

# OIDC provider bound to the Google Cloud Attestation service.
#
# Ground truth (live-fetched 2026-08-04):
#   - token claims reference: issuer is https://confidentialcomputing.googleapis.com
#     (documented WITHOUT a trailing slash - the value below matches the docs
#     exactly; the issuer_uri must equal the iss claim of the attestation token)
#   - aud claim for the default pool token: https://sts.googleapis.com
#   - container image reference/digest live under submods.container.*
#   - swname values: CONFIDENTIAL_SPACE | GCE
# Resource arguments verified against the google provider 7.42.0 schema
# (terraform providers schema -json): oidc.issuer_uri REQUIRED;
# attribute_mapping / attribute_condition top-level attributes.
resource "google_iam_workload_identity_pool_provider" "confidential_space" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.flare_tee_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "confidential-space-attestation"
  project                            = var.project_id
  display_name                       = "Confidential Space Attestation"
  description                        = "OIDC provider for Google Cloud Attestation. Accepts tokens only from Confidential Space VMs (swname) whose container digest matches the recorded SHA-256 digest and which run as the TEE service account (attribute_condition)."

  oidc {
    issuer_uri        = "https://confidentialcomputing.googleapis.com"
    allowed_audiences = ["https://sts.googleapis.com"]
  }

  # Canonical Confidential Space mappings (google.subject is required for
  # OIDC providers per the WIF docs; the image claims are nested under
  # submods.container per the token claims reference - there is NO
  # top-level assertion.image_digest claim, so the prompt's literal path
  # is corrected to the documented one).
  attribute_mapping = {
    "google.subject"                      = "assertion.sub"
    "attribute.swname"                    = "assertion.swname"
    "attribute.swversion"                 = "assertion.swversion"
    "attribute.hwmodel"                   = "assertion.hwmodel"
    "attribute.container_image_reference" = "assertion.submods.container.image_reference"
    "attribute.image_digest"              = "assertion.submods.container.image_digest"
  }

  # Attestation guard - ground truth: Google's attestation-assertions
  # reference (fetched live) documents assertion.submods.container.image_digest
  # as the digest claim and assertion.swname == "CONFIDENTIAL_SPACE" as the
  # software guard; Google's create-and-grant example also requires the VM's
  # service account in assertion.google_service_accounts. The digest lock ANDs
  # into the existing swname guard (it does not replace it) and pins the
  # workload to the exact SHA-256 digest recorded in .teedigest by
  # build-tee.yml, running as the dedicated TEE service account.
  attribute_condition = "assertion.swname == \"CONFIDENTIAL_SPACE\" && assertion.submods.container.image_digest == \"${var.container_image_digest}\" && \"${google_service_account.tee_service_account.email}\" in assertion.google_service_accounts"
}

# The enclave's identity: the service account the Confidential VM runs as.
#
# Schema-verified against the google provider 7.42.0 binary: account_id is
# REQUIRED (6-30 chars, [a-z]([-a-z0-9]*[a-z0-9])); display_name/description/
# project are optional. Per Google's deploy-workloads guide the attached SA
# needs roles/confidentialcomputing.workloadUser, roles/artifactregistry.reader
# and roles/logging.logWriter - granted as IAM bindings in the next step.
resource "google_service_account" "tee_service_account" {
  account_id   = "flare-tee-sa"
  project      = var.project_id
  display_name = "Flare TEE Enclave"
  description  = "Identity of the Confidential Space enclave VM: runs the workload, pulls the attested container from Artifact Registry, and is the target of the WIP token exchange."
}

# Project NUMBER lookup - the WIF docs require the numeric project number,
# not the project ID, in principal URLs: "use your project number, not your
# project ID".
data "google_project" "project" {
  project_id = var.project_id
}

# WIP -> SA impersonation grant.
#
# Google's create-and-grant example binds roles/iam.workloadIdentityUser on
# the service account to the whole-pool principalSet (wildcard /*) and lets
# the provider attribute_condition do the restricting. Followed exactly:
#   member = principalSet://iam.googleapis.com/projects/{NUMBER}/locations/
#            global/workloadIdentityPools/{POOL_ID}/*
resource "google_service_account_iam_member" "wip_impersonation" {
  service_account_id = google_service_account.tee_service_account.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/projects/${data.google_project.project.number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.flare_tee_pool.workload_identity_pool_id}/*"
}
