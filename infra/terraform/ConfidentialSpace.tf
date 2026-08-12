# infra/terraform/ConfidentialSpace.tf
#
# THE TEE: Google Cloud Confidential Space workload VM.
#
# A Confidential VM (google_compute_instance) running the hardened
# Confidential Space base image. The workload container (the enclave
# FastAPI service) is pulled and run by the Confidential Space launcher
# based on the tee-image-reference metadata key. Verified against
# Google's "Deploy workloads" documentation (fetched live):
#
#   https://cloud.google.com/confidential-computing/confidential-space/docs/deploy-workloads
#
# Confidential computing technology, selected by var.enable_tdx:
#   false (default) - AMD SEV-SNP on N2D: n2d-standard-2 on AMD Milan,
#                     live migration supported (MIGRATE)
#   true            - Intel TDX on C3: c3-standard-4 on Intel Sapphire
#                     Rapids, no live migration (TERMINATE required)
# Both technologies are attested by Google Cloud Attestation; the
# workload identity provider (workload_identity.tf) binds to the exact
# container digest recorded in .teedigest by build-tee.yml, independent
# of CPU technology.

resource "google_compute_instance" "confidential_vm" {
  name         = "confidential-rag-enclave"
  machine_type = var.enable_tdx ? "c3-standard-4" : "n2d-standard-2"
  zone         = var.zone

  # min_cpu_platform pins the microarchitecture: AMD Milan pairs with
  # SEV-SNP, Intel Sapphire Rapids pairs with TDX (schema-documented
  # pairing in the google provider 7.42.0 confidential_instance_type
  # description).
  min_cpu_platform = var.enable_tdx ? "Intel Sapphire Rapids" : "AMD Milan"

  # Hardware-level confidential memory isolation. TDX uses the modern
  # confidential_instance_type argument; the SEV path keeps the classic
  # enable_confidential_compute toggle (false == unset for TDX).
  confidential_instance_config {
    enable_confidential_compute = !var.enable_tdx
    confidential_instance_type  = var.enable_tdx ? "TDX" : null
  }

  # Confidential VMs require shielded boot; the vTPM is the anchor for
  # the attestation token consumed by Workload Identity later.
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  # The default VPC exists in every GCP project (this is the minimal
  # valid wiring for the POC; a dedicated VPC + internal LB replaces
  # this in the scale-out phase). No public IP by design - the enclave
  # never exposes a public endpoint. NOTE: outbound calls to the Flare
  # Coston2 RPC and external APIs require Cloud NAT or Private Google
  # Access on the subnet - wired in the scale-out phase.
  network_interface {
    network = "default"
  }

  # Maintenance policy differs by technology. Google's deploy-workloads
  # doc: for N2D/SEV set MIGRATE (live migration supported); for all
  # other machine types set TERMINATE, as they don't support live
  # migration - so TDX on C3 must be TERMINATE.
  scheduling {
    on_host_maintenance = var.enable_tdx ? "TERMINATE" : "MIGRATE"
  }

  boot_disk {
    initialize_params {
      # Production Confidential Space base image (hardened COS-based OS).
      image = "projects/confidential-space-images/global/images/family/confidential-space"
    }
  }

  # Confidential Space launcher configuration. Key names verified against
  # Google's official metadata reference, fetched live:
  #   https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/metadata-variables
  #   tee-image-reference        - REQUIRED container image to run inside the TEE
  #   tee-restart-policy         - launcher behavior when the container exits
  #   tee-container-log-redirect - STDOUT/STDERR routing; enum false|true|
  #                                cloud_logging|serial. NOTE: the key name is
  #                                tee-container-log-redirect, NOT
  #                                tee-container-logs-provider (that name does
  #                                not exist in the docs - the launcher would
  #                                silently ignore it and logs would be lost).
  metadata = {
    "tee-image-reference"        = var.container_image_reference
    "tee-restart-policy"         = "Never"
    "tee-container-log-redirect" = "cloud_logging"
  }

  # The enclave runs as the dedicated TEE service account (created in
  # workload_identity.tf) with full cloud-platform scope - the same
  # pattern as Google's deploy-workloads gcloud example. Its required
  # roles (confidentialcomputing.workloadUser, artifactregistry.reader,
  # logging.logWriter) are granted as IAM bindings in the next step.
  service_account {
    email  = google_service_account.tee_service_account.email
    scopes = ["cloud-platform"]
  }
}

