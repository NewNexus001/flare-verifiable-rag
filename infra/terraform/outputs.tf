# infra/terraform/outputs.tf
#
# Post-apply values consumed by CI/CD and the operator:
#   - confidential_vm_ip      : the enclave VM's PRIVATE IP. There is no public
#                               IP by design (the TEE never exposes a public
#                               endpoint - see ConfidentialSpace.tf). Schema
#                               (7.42.0): network_interface.network_ip is "The
#                               private IP address assigned to the instance".
#   - service_account_email   : the enclave's identity, used by CI to wire the
#                               WIP token exchange and by the enclave itself.
#   - wip_provider_name       : the full resource name of the attestation
#                               provider, used by gcloud/API consumers to
#                               reference the provider after apply.
#   - instance_id             : the server-assigned unique instance identifier,
#                               used to correlate VM lifecycle in ops tooling.

output "confidential_vm_ip" {
  description = "Private IP address of the Confidential Space enclave VM (no public IP is provisioned by design - the TEE never exposes a public endpoint)."
  value       = google_compute_instance.confidential_vm.network_interface[0].network_ip
}

output "service_account_email" {
  description = "Email of the TEE service account the enclave VM runs as (the WIP token-exchange target)."
  value       = google_service_account.tee_service_account.email
}

output "wip_provider_name" {
  description = "Full resource name of the Confidential Space attestation provider: projects/{project_number}/locations/global/workloadIdentityPools/{pool_id}/providers/{provider_id}."
  value       = google_iam_workload_identity_pool_provider.confidential_space.name
}

output "instance_id" {
  description = "Server-assigned unique identifier of the Confidential VM instance."
  value       = google_compute_instance.confidential_vm.instance_id
}
