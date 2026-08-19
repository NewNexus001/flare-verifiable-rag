"""Shared constants for the enclave unit suite (Prompt 073).

Kept in a dedicated module (not ``conftest``) so both ``conftest.py`` and
``test_processor.py`` can import them without the fragile
``from conftest import ...`` pattern (which pytest discourages).
"""

# A real 32-byte key (64 hex chars) used for REAL encrypt/decrypt round trips
# throughout the suite — identical convention to the .tools/0XX_verify.py
# harnesses. Not test text: every payload is actually encrypted with it.
TEST_KEY_HEX = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

# Small, real context text for fast deterministic tests.
DOC = (
    "Flare Network operates FTSO v2 price oracles. Section 3.1 of the "
    "service agreement requires real-time data verification."
)
PROMPT = "does flare operate ftso v2?"
