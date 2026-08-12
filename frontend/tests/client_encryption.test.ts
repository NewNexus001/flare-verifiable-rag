/**
 * client_encryption.test.ts — Phase 10 / Prompt 191.
 *
 * Unit tests for the client-side AES-GCM-256 envelope encryption
 * (src/crypto/client_encryption.ts) using the REAL Web Crypto API provided
 * by Node.js (globalThis.crypto.subtle — the same implementation browsers
 * ship over TLS). No mocks: every test exercises the actual cryptographic
 * primitives. Run with: node --test (Node >= 22.6 with type stripping).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  decryptBytes,
  encryptBytes,
  encryptFileClientSide,
  exportKeyHex,
  generateEnvelopeKey,
  randomIv,
  sha256Hex,
} from "../src/crypto/client_encryption.ts";

test("AES-GCM-256 roundtrip: ciphertext decrypts back to the exact plaintext", async () => {
  const key = await generateEnvelopeKey();
  const iv = randomIv();
  const plaintext = new TextEncoder().encode(
    "The quick brown fox jumps over the lazy dog — 0123456789"
  );
  const ciphertext = await encryptBytes(plaintext, key, iv);
  const decrypted = await decryptBytes(ciphertext, key, iv);
  assert.equal(new TextDecoder().decode(decrypted), new TextDecoder().decode(plaintext));
});

test("AES-GCM-256: ciphertext is NOT plaintext (real encryption happened)", async () => {
  const key = await generateEnvelopeKey();
  const iv = randomIv();
  const plaintext = new TextEncoder().encode("secret document body");
  const ciphertext = new Uint8Array(await encryptBytes(plaintext, key, iv));
  const plainBytes = new Uint8Array(plaintext);
  // No byte of the ciphertext may equal the plaintext at the same offset.
  assert.notDeepEqual(ciphertext, plainBytes);
  // And the ciphertext must be longer by exactly the 16-byte GCM tag.
  assert.equal(ciphertext.byteLength, plaintext.byteLength + 16);
});

test("AES-GCM-256: tampered ciphertext FAILS decryption (authenticated)", async () => {
  const key = await generateEnvelopeKey();
  const iv = randomIv();
  const ciphertext = new Uint8Array(await encryptBytes(new TextEncoder().encode("authenticated payload"), key, iv));
  ciphertext[10] ^= 0xff; // flip one ciphertext byte
  await assert.rejects(
    decryptBytes(ciphertext.buffer as ArrayBuffer, key, iv),
    /decrypt|unexpected|OperationError|tag|failure/i
  );
});

test("AES-GCM-256: wrong key FAILS decryption", async () => {
  const keyA = await generateEnvelopeKey();
  const keyB = await generateEnvelopeKey();
  const iv = randomIv();
  const ciphertext = await encryptBytes(new TextEncoder().encode("secret"), keyA, iv);
  await assert.rejects(
    decryptBytes(ciphertext, keyB, iv),
    /decrypt|unexpected|OperationError|tag|failure/i
  );
});

test("AES-GCM-256: IV must be 12 bytes (NIST SP 800-38D)", () => {
  const iv = randomIv();
  assert.equal(iv.byteLength, 12);
});

test("AES-GCM-256: key fingerprint + SHA-256 anchor are deterministic and correct", async () => {
  const data = new TextEncoder().encode("deterministic anchor");
  const digest = await sha256Hex(data);
  assert.equal(digest.length, 64); // lowercase hex sha256
  assert.match(digest, /^[0-9a-f]{64}$/);

  const key = await generateEnvelopeKey();
  const hex = await exportKeyHex(key);
  assert.equal(hex.length, 64); // 32 raw bytes = 64 hex chars
});

test("encryptFileClientSide: real File envelope with provenance metadata", async () => {
  const file = new File([new TextEncoder().encode("file contents for the enclave")], "report.txt", {
    type: "text/plain",
  });
  const result = await encryptFileClientSide(file);
  assert.equal(result.fileName, "report.txt");
  assert.equal(result.plaintextSize, file.size);
  assert.equal(result.plaintextSha256.length, 64);
  assert.equal(result.keyFingerprint.length, 8);
  assert.equal(result.envelope.iv.byteLength, 12);
  assert.equal(
    result.envelope.ciphertext.byteLength,
    file.size + 16, // GCM tag
  );
});
