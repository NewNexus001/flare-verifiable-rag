"""Secure enclave gateway package (Phase 4).

Contains the FastAPI application (`src.main:app`) plus the crypto and
flare_client submodules introduced in later Phase 4 prompts. The package
marker makes the Dockerfile ENTRYPOINT (`uvicorn src.main:app`) importable
from `/app`.
"""
