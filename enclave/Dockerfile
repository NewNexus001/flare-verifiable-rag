# enclave/Dockerfile — Secure Enclave container image
# Phase 4 / Prompt 062.
#
# ────────────────────────────────────────────────────────────────────────────
# BASE IMAGE DECISION (researched 2026-08-06 — user-provided research, not
# guessed): the prompt says "distroless minimal base image (python:3.11-slim)".
# The parenthetical is the operative instruction: `python:3.11-slim` (Debian
# bookworm) is used, NOT gcr.io/distroless/python3-debian12, because:
#   • The official GCP Confidential Space docs require the workload container
#     to be an OCI-compliant image; the "Debian 11/12 required" rule applies
#     to Google's signed HOST image, not to the workload container.
#   • `python:3.11-slim` (bookworm) satisfies that requirement and matches the
#     prompt's parenthetical exactly.
#   • The builder stage must compile the Rust engine, which needs apt + a
#     toolchain — impossible on true distroless (no shell/apt).
# Tag pinned to `-bookworm` for deterministic rebuilds (digest lock-in).
#
# ────────────────────────────────────────────────────────────────────────────
# DETERMINISTIC BUILD CHAIN (ties into build-tee.yml + workload_identity.tf):
#   build-tee.yml builds with context ./enclave, `no-cache: true`,
#   `provenance: false`, and records the image digest to .teedigest. THAT
#   digest is what the Workload Identity Pool attribute condition in
#   workload_identity.tf binds to. Any change to this Dockerfile,
#   requirements.txt, or the Rust engine changes the digest and breaks
#   attestation — by design.
#
# The Rust symbolic engine (indexer_rs, Prompt 041–060) is compiled INSIDE the
# builder stage for Linux: the wheel in the repo is cp311-win_amd64
# (Windows-only, built locally for development). A Linux image needs a Linux
# wheel, and compiling in-image keeps the digest bound to the exact source.
# The `python` Cargo feature (PyO3 bindings, Prompt 054) is enabled via
# maturin; the deprecated `extension-module` Cargo feature is NOT used (maturin
# >= 1.9.4 injects PYO3_BUILD_EXTENSION_MODULE itself, per the PyO3 book).

# ────────────────────────────────────────────────────────────────────────────
# STAGE 1: builder — resolves dependencies, compiles the Rust engine
# ────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS builder

# RAM-only + non-buffered from the very first Python invocation.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Minimal build toolchain: compilers for any C-extension deps, curl for rustup.
# --no-install-recommends + apt-list purge keeps the BUILDER lean; the final
# stage strips all of this away in the multi-stage handoff.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Shell form with pipefail for the rustup pipe (hadolint DL4006): a failure
# in the curl stage must abort the build, not silently continue.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Rust toolchain pinned to the crate's declared MSRV floor (Cargo.toml
# rust-version = 1.85) — a pinned toolchain is part of the deterministic
# digest contract. --no-modify-path keeps PATH fully explicit below.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain 1.85.0 --no-modify-path
ENV PATH="/root/.cargo/bin:${PATH}" \
    CARGO_HOME="/root/.cargo"

# Isolated venv + pinned maturin. requirements.txt is copied FIRST so Docker
# layer caching keeps the (slow) dependency install isolated from source edits.
COPY requirements.txt /build/requirements.txt
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir "maturin==1.9.4"

# Build the Rust engine as a cp311 Linux wheel (python feature = PyO3 bindings).
COPY src/rag_engine /build/rag_engine
WORKDIR /build/rag_engine
RUN /opt/venv/bin/maturin build --release --features python --out /build/wheels
WORKDIR /build

# Install application dependencies + the compiled engine wheel into the venv.
RUN /opt/venv/bin/pip install --no-cache-dir -r /build/requirements.txt /build/wheels/*.whl

# ────────────────────────────────────────────────────────────────────────────
# STAGE 2: final — minimal runtime, non-root, RAM-only
# ────────────────────────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS final

# RAM-only execution contract (blueprint: "zero local disk writes"):
#   • PYTHONDONTWRITEBYTECODE=1 — never write .pyc bytecode to disk
#   • PYTHONUNBUFFERED=1        — no buffered log spooling to disk
#   • ENCLAVE_RAM_WORKSPACE     — scratch dir; /dev/shm is tmpfs (RAM) by
#     default under containerd/Docker, so the app's scratch space is RAM-only
#     without any mount. The production launcher additionally mounts /tmp and
#     /dev/shm as tmpfs and may run the rootfs read-only — that is enforced at
#     RUNTIME (launcher args), not here: a Dockerfile cannot mount filesystems.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    ENCLAVE_RAM_WORKSPACE="/dev/shm/enclave"

# Non-root user (UID/GID 10001) — least privilege inside the TEE. The
# Confidential Space launcher honors the image's USER directive; research
# (user-provided, 2026-08-06) recommends a high non-system UID such as 10001.
RUN groupadd -g 10001 appgroup \
    && useradd -u 10001 -g appgroup -s /bin/false -M appuser

WORKDIR /app

# venv (all deps + the compiled engine wheel) from the builder, owned by the
# app user. Application source follows: FastAPI gateway, src.main:app.
COPY --from=builder --chown=10001:10001 /opt/venv /opt/venv
# TODO(Prompt 161+ FastAPI layout): prune the Rust engine SOURCES
# (src/rag_engine/{Cargo.toml,src/*.rs}) from this final stage — the runtime
# image only needs the compiled wheel already inside /opt/venv. Kept for now
# because src/main.py does not exist yet; a whole-`src` copy is forward-safe.
COPY --chown=10001:10001 src/ /app/src/

# RAM-only scratch space owned by the app user.
RUN mkdir -p /dev/shm/enclave \
    && chown -R 10001:10001 /dev/shm/enclave

USER 10001:10001

EXPOSE 8000

# Exec-form ENTRYPOINT (proper signal handling in the TEE: no /bin/sh as PID 1,
# so SIGTERM reaches uvicorn and the launcher restart policy works). Explicit
# absolute path, single process — per Confidential Space recommended structure.
# Uvicorn workers: default (1) — the Confidential Space launcher supervises and
# restarts the process; the blueprint SRE section specifies a single supervised
# worker.
ENTRYPOINT ["/opt/venv/bin/uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]

# Healthcheck against the FastAPI /health endpoint (blueprint SRE posture).
# Exec form (hadolint DL3025): urlopen raises on failure → non-zero exit →
# unhealthy, with no shell wrapper. Requires the app to expose GET /health
# (arrives with the FastAPI gateway, next prompts).
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/opt/venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]
