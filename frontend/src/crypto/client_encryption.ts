/**
 * client_encryption.ts — client-side envelope encryption (Phase 9 / Prompt 168).
 *
 * Documents and query payloads are encrypted in the BROWSER with AES-GCM-256
 * (Web Crypto API) BEFORE any transport. The enclave — and the ephemeral
 * Diffie-Hellman key exchange wired in later prompts — is the only party that
 * ever derives the envelope key; this module guarantees raw plaintext never
 * sits on a network path. Zero dependencies: the platform Crypto.subtle
 * implementation, available in every modern browser over TLS.
 *
 * Security notes (NIST SP 800-38D):
 *  - AES-GCM with a fresh 96-bit (12-byte) IV per encryption — the ONLY
 *    nonce size the standard recommends with 256-bit keys.
 *  - The envelope key is generated non-extractable-by-default? NO — it MUST
 *    be extractable here so the raw key can be wrapped for the enclave
 *    handshake (later prompts). Extraction happens only in-browser.
 *  - GCM authenticates the ciphertext: any tampering fails decryption.
 */

const ALGORITHM = "AES-GCM" as const;
const KEY_LENGTH = 256;
/** NIST SP 800-38D recommended nonce size for AES-GCM. */
const IV_LENGTH = 12;

export interface EncryptedEnvelope {
  /** AES-GCM-256 ciphertext (plaintext length + 16-byte GCM tag). */
  ciphertext: ArrayBuffer;
  /** 12-byte random IV — must be unique per encryption with the same key. */
  iv: Uint8Array<ArrayBuffer>;
  /** The AES-GCM-256 envelope key (extractable, in-browser only). */
  key: CryptoKey;
}

export interface EncryptedFileResult {
  envelope: EncryptedEnvelope;
  fileName: string;
  plaintextSize: number;
  /** SHA-256 of the PLAINTEXT — provenance anchor for later verification. */
  plaintextSha256: string;
  /** First 8 hex chars of the key fingerprint (safe to show; not the key). */
  keyFingerprint: string;
}

/** Generate a fresh AES-GCM-256 envelope key (256-bit, random). */
export async function generateEnvelopeKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: ALGORITHM, length: KEY_LENGTH },
    true,
    ["encrypt", "decrypt"]
  );
}

/** A fresh 12-byte random IV for AES-GCM. */
export function randomIv(): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(IV_LENGTH));
}

/** Encrypt raw bytes with the envelope key. */
export async function encryptBytes(
  data: ArrayBuffer | Uint8Array,
  key: CryptoKey,
  iv: Uint8Array<ArrayBuffer>
): Promise<ArrayBuffer> {
  // Normalize to a fresh standalone ArrayBuffer: a Uint8Array view may wrap a
  // SharedArrayBuffer (crypto.subtle rejects it) or a larger backing buffer.
  const view = data instanceof Uint8Array ? data : new Uint8Array(data);
  const plain = new Uint8Array(view.byteLength);
  plain.set(view);
  // plain is a freshly allocated Uint8Array<ArrayBuffer> (never SharedArrayBuffer).
  return crypto.subtle.encrypt({ name: ALGORITHM, iv }, key, plain.buffer);
}

/** Decrypt AES-GCM ciphertext (throws on tampered/forged ciphertext). */
export async function decryptBytes(
  ciphertext: ArrayBuffer,
  key: CryptoKey,
  iv: Uint8Array<ArrayBuffer>
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt({ name: ALGORITHM, iv }, key, ciphertext);
}

/** Export the raw key bytes as lowercase hex (for the enclave handshake). */
export async function exportKeyHex(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return Array.from(new Uint8Array(raw))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** SHA-256 of arbitrary bytes (provenance anchor for encrypted payloads). */
export async function sha256Hex(data: ArrayBuffer | Uint8Array): Promise<string> {
  const view = data instanceof Uint8Array ? data : new Uint8Array(data);
  const copy = new Uint8Array(view.byteLength);
  copy.set(view);
  // copy is a freshly allocated Uint8Array<ArrayBuffer> — always digest-safe.
  const digest = await crypto.subtle.digest("SHA-256", copy.buffer);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Encrypt a File client-side, end-to-end (Prompt 169 path).
 * Reads the file bytes in the browser, wraps them in AES-GCM-256 with a
 * fresh key + IV, and returns the envelope plus provenance metadata.
 */
export async function encryptFileClientSide(file: File): Promise<EncryptedFileResult> {
  const data = await file.arrayBuffer();
  const key = await generateEnvelopeKey();
  const iv = randomIv();
  const ciphertext = await encryptBytes(data, key, iv);
  const [plaintextSha256, keyHex] = await Promise.all([
    sha256Hex(data),
    exportKeyHex(key),
  ]);
  return {
    envelope: { ciphertext, iv, key },
    fileName: file.name,
    plaintextSize: file.size,
    plaintextSha256,
    keyFingerprint: keyHex.slice(0, 8),
  };
}
