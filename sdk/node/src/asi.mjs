/**
 * Agent Skill Identity (ASI) v0.1 — Reference SDK (Node)
 *
 * MIT License
 * No telemetry. No remote calls. All operations are local.
 *
 * Dependencies:
 *  - @noble/ed25519  — RFC 8032 deterministic Ed25519
 *  - @noble/hashes   — SHA-256 (and SHA-512 for noble config)
 *  - canonicalize    — JCS (RFC 8785)
 */

import * as ed from "@noble/ed25519";
import { randomBytes as nodeRandomBytes, webcrypto } from "node:crypto";
import { sha512 } from "@noble/hashes/sha2.js";
import { sha256 as sha256Hash } from "@noble/hashes/sha2.js";
import canonicalize from "canonicalize";
import { readFileSync, readdirSync, lstatSync } from "fs";
import { join, relative, resolve, sep } from "path";

// noble/ed25519 v3 requires sha512 to be configured
ed.hashes.sha512 = sha512;

// Node 18 compatibility: ensure WebCrypto exists and wire noble RNG.
if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}
ed.etc.randomBytes = (len) => new Uint8Array(nodeRandomBytes(len));

// ─── Constants ───────────────────────────────────────────────────────────────

export const ASI_VERSION = "0.1";
export const DOMAIN_TAG_PUBLISHER = "ASI-SKILL-MANIFEST/v0.1";
export const DOMAIN_TAG_INVOKE = "ASI-INVOKE/v0.1";
export const NULL_SEPARATOR = new Uint8Array([0x00]);
export const DEFAULT_TIMESTAMP_SKEW = 300; // seconds

// ─── Utility Functions ───────────────────────────────────────────────────────

export function utf8Encode(str) {
  return new TextEncoder().encode(str);
}

export function utf8Decode(bytes) {
  return new TextDecoder().decode(bytes);
}

export function uint64BE(n) {
  // n is expected to be a safe JS integer (Unix seconds fits)
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  // high 32, low 32
  const hi = Math.floor(n / 0x100000000);
  const lo = n >>> 0;
  view.setUint32(0, hi);
  view.setUint32(4, lo);
  return new Uint8Array(buf);
}

function assertUint64(name, n) {
  if (!Number.isInteger(n) || n < 0 || n > Number.MAX_SAFE_INTEGER) {
    throw new Error(`${name} must be a non-negative safe integer`);
  }
}

function isValidManifestFilePath(filePath) {
  if (typeof filePath !== "string" || filePath.length === 0) return false;
  if (filePath.startsWith("/") || filePath.endsWith("/")) return false;
  if (filePath.includes("\\") || filePath.includes("\0")) return false;

  const segments = filePath.split("/");
  return !segments.some((segment) => segment === "" || segment === "." || segment === "..");
}

function isWithinBundleRoot(bundlePath, targetPath) {
  const root = resolve(bundlePath);
  const target = resolve(targetPath);
  return target === root || target.startsWith(root + sep);
}

export function concatBytes(...arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

export function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function fromHex(hex) {
  if (hex.length % 2 !== 0) throw new Error("Hex string must have even length");
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

// Base64url encoding/decoding (RFC 4648 §5, no padding)
export function base64urlEncode(bytes) {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function base64urlDecode(str) {
  const padded = str + "=".repeat((4 - (str.length % 4)) % 4);
  const b64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  return new Uint8Array(Buffer.from(b64, "base64"));
}

// Multicodec prefix for Ed25519 public key: 0xed01
export const ED25519_MULTICODEC = new Uint8Array([0xed, 0x01]);

// Multibase base58btc encoding (prefix 'z')
const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Encode(bytes) {
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let result = "";
  for (const byte of bytes) {
    if (byte === 0) result += "1";
    else break;
  }
  for (let i = digits.length - 1; i >= 0; i--) {
    result += BASE58_ALPHABET[digits[i]];
  }
  return result;
}

export function base58Decode(str) {
  const bytes = [];
  for (const ch of str) {
    let carry = BASE58_ALPHABET.indexOf(ch);
    if (carry < 0) throw new Error(`Invalid base58 character: ${ch}`);
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const ch of str) {
    if (ch === "1") bytes.push(0);
    else break;
  }
  return new Uint8Array(bytes.reverse());
}

// ─── Core ASI Functions ──────────────────────────────────────────────────────

/**
 * generateKeypair() → { publicKey: Uint8Array(32), privateKeySeed: Uint8Array(32) }
 *
 * NOTE: We expose a 32-byte seed as canonical private key format.
 */
export function generateKeypair() {
  const { secretKey, publicKey } = ed.keygen();
  // noble returns Uint8Array already
  return { privateKeySeed: secretKey, publicKey };
}

/**
 * deriveIdentity(publicKey) → string (did:key)
 */
export function deriveIdentity(publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
    throw new Error(`Invalid public key length: expected 32, got ${publicKey?.length}`);
  }
  const multicodecKey = concatBytes(ED25519_MULTICODEC, publicKey);
  const encoded = base58Encode(multicodecKey);
  return `did:key:z${encoded}`;
}

/**
 * publicKeyFromIdentity(didKey) → Uint8Array(32)
 */
export function publicKeyFromIdentity(didKey) {
  if (typeof didKey !== "string" || !didKey.startsWith("did:key:z")) {
    throw new Error("Invalid DID:key format: must start with did:key:z");
  }
  const encoded = didKey.slice("did:key:z".length);
  const decoded = base58Decode(encoded);
  if (decoded.length < 2 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error("Invalid multicodec prefix: expected Ed25519 (0xed01)");
  }
  const pk = decoded.slice(2);
  if (pk.length !== 32) throw new Error(`Invalid public key length in DID:key: ${pk.length}`);
  return pk;
}

/**
 * sign(signingInput, privateKeySeed) → Uint8Array(64)
 */
export function sign(signingInput, privateKeySeed) {
  return ed.sign(signingInput, privateKeySeed);
}

/**
 * verify(signingInput, signature, publicKey) → boolean
 */
export function verify(signingInput, signature, publicKey) {
  try {
    return ed.verify(signature, signingInput, publicKey);
  } catch {
    return false;
  }
}

/**
 * canonicalize(json: object) → Uint8Array (JCS per RFC 8785)
 */
export function canonicalizeJson(obj) {
  const canon = canonicalize(obj);
  if (!canon) throw new Error("JCS canonicalization failed");
  return utf8Encode(canon);
}

/**
 * sha256(data: Uint8Array) → Uint8Array(32)
 */
export function sha256(data) {
  return sha256Hash(data);
}

/**
 * Display hash: "sha256:<hex>"
 */
export function sha256Display(digest) {
  if (!(digest instanceof Uint8Array) || digest.length !== 32) {
    throw new Error(`Invalid digest length: expected 32, got ${digest?.length}`);
  }
  return `sha256:${toHex(digest)}`;
}

/**
 * Parse display hash to raw bytes
 */
export function sha256Parse(display) {
  if (typeof display !== "string" || !display.startsWith("sha256:")) {
    throw new Error("Invalid hash format: must start with sha256:");
  }
  const hex = display.slice(7);
  if (hex.length !== 64) {
    throw new Error(`Invalid hash length: expected 64 hex chars, got ${hex.length}`);
  }
  return fromHex(hex);
}

// ─── Signing Input Builders ──────────────────────────────────────────────────

export function buildPublisherSigningInput(manifestHash, signedAt) {
  if (!(manifestHash instanceof Uint8Array) || manifestHash.length !== 32) {
    throw new Error(`Invalid manifest hash length: expected 32, got ${manifestHash?.length}`);
  }
  assertUint64("signedAt", signedAt);
  return concatBytes(
    utf8Encode(DOMAIN_TAG_PUBLISHER),
    NULL_SEPARATOR,
    manifestHash,
    uint64BE(signedAt)
  );
}

export function buildInvocationSigningInput(agentId, timestamp, payloadHash) {
  if (!(payloadHash instanceof Uint8Array) || payloadHash.length !== 32) {
    throw new Error(`Invalid payload hash length: expected 32, got ${payloadHash?.length}`);
  }
  assertUint64("timestamp", timestamp);
  return concatBytes(
    utf8Encode(DOMAIN_TAG_INVOKE),
    NULL_SEPARATOR,
    utf8Encode(agentId),
    NULL_SEPARATOR,
    uint64BE(timestamp),
    payloadHash
  );
}

// ─── Bundle Operations ───────────────────────────────────────────────────────

function enumerateFiles(dir, base = dir) {
  const results = [];
  const entries = readdirSync(dir);
  for (const entry of entries) {
    const fullPath = join(dir, entry);
    const st = lstatSync(fullPath); // don't follow symlinks
    if (st.isSymbolicLink()) {
      throw new Error(`Symlink detected and rejected: ${relative(base, fullPath)}`);
    }
    if (st.isDirectory()) {
      results.push(...enumerateFiles(fullPath, base));
    } else if (st.isFile()) {
      const relPath = relative(base, fullPath).split("\\").join("/");
      results.push(relPath);
    }
  }
  return results;
}

/**
 * hashBundle(bundlePath) → { files: Record<string,string> }
 *
 * Excludes: asi/ directory and manifest.json
 */
export function hashBundle(bundlePath) {
  const allFiles = enumerateFiles(bundlePath);
  const files = {};
  for (const filePath of allFiles) {
    if (filePath.startsWith("asi/") || filePath === "manifest.json") continue;
    const content = readFileSync(join(bundlePath, filePath));
    files[filePath] = sha256Display(sha256(content));
  }
  return { files };
}

/**
 * createSignedManifest(manifest, bundlePath, privateKeySeed)
 * → { manifest: object, signature: object }
 *
 * NOTE: Does not write to disk; caller decides where to persist.
 */
export function createSignedManifest(manifest, bundlePath, privateKeySeed) {
  const { files } = hashBundle(bundlePath);
  const fullManifest = { ...manifest, files };

  const canonicalBytes = canonicalizeJson(fullManifest);
  const manifestHash = sha256(canonicalBytes);

  const signedAt = Math.floor(Date.now() / 1000);
  const signingInput = buildPublisherSigningInput(manifestHash, signedAt);

  const publicKey = ed.getPublicKey(privateKeySeed);
  const sig = sign(signingInput, privateKeySeed);

  return {
    manifest: fullManifest,
    signature: {
      asi_version: ASI_VERSION,
      publisher_id: deriveIdentity(publicKey),
      public_key: base64urlEncode(publicKey),
      algorithm: "ed25519",
      manifest_hash: sha256Display(manifestHash),
      signed_at: signedAt,
      signature: base64urlEncode(sig),
    },
  };
}

/**
 * verifySkillBundle(bundlePath) → { status, publisherId, errors }
 */
export function verifySkillBundle(bundlePath) {
  // Step 1: read asi/signature.json
  let sigJson;
  try {
    const sigPath = join(bundlePath, "asi", "signature.json");
    sigJson = JSON.parse(readFileSync(sigPath, "utf-8"));
  } catch {
    return { status: "UNSIGNED", publisherId: null, errors: ["No asi/signature.json found"] };
  }

  // Step 2: version
  if (sigJson.asi_version !== ASI_VERSION) {
    return {
      status: "UNKNOWN_VERSION",
      publisherId: null,
      errors: [`Unrecognized asi_version: ${sigJson.asi_version}`],
    };
  }

  if (sigJson.algorithm !== "ed25519") {
    return {
      status: "TAMPERED",
      publisherId: null,
      errors: [`Unsupported algorithm: ${sigJson.algorithm}`],
    };
  }

  // Step 3: public_key matches publisher_id
  let publicKey;
  try {
    publicKey = base64urlDecode(sigJson.public_key);
    if (publicKey.length !== 32) {
      return { status: "TAMPERED", publisherId: null, errors: [`Invalid public key length: ${publicKey.length}`] };
    }
    const derived = deriveIdentity(publicKey);
    if (derived !== sigJson.publisher_id) {
      return { status: "TAMPERED", publisherId: null, errors: ["publisher_id does not match public_key"] };
    }
  } catch (e) {
    return { status: "TAMPERED", publisherId: null, errors: [`Public key error: ${e.message}`] };
  }

  // Step 4: load manifest.json
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(join(bundlePath, "manifest.json"), "utf-8"));
  } catch (e) {
    return { status: "TAMPERED", publisherId: null, errors: [`Cannot read manifest.json: ${e.message}`] };
  }

  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    return { status: "TAMPERED", publisherId: null, errors: ["manifest.json must be an object"] };
  }
  if (!manifest.files || typeof manifest.files !== "object" || Array.isArray(manifest.files)) {
    return { status: "TAMPERED", publisherId: null, errors: ["manifest.json must include files object"] };
  }

  // Step 5: hash manifest (JCS)
  const canonicalBytes = canonicalizeJson(manifest);
  const computedHash = sha256(canonicalBytes);
  const computedHashDisplay = sha256Display(computedHash);

  if (computedHashDisplay !== sigJson.manifest_hash) {
    return { status: "TAMPERED", publisherId: null, errors: ["manifest_hash does not match computed hash"] };
  }

  // Step 6: verify signature
  const signingInput = buildPublisherSigningInput(computedHash, sigJson.signed_at);
  const signatureBytes = base64urlDecode(sigJson.signature);
  if (!verify(signingInput, signatureBytes, publicKey)) {
    return { status: "TAMPERED", publisherId: null, errors: ["Signature verification failed"] };
  }

  // Step 7: enumerate files; reject undeclared; reject symlinks
  let bundleFiles;
  try {
    bundleFiles = enumerateFiles(bundlePath);
  } catch (e) {
    return { status: "TAMPERED", publisherId: null, errors: [e.message] };
  }

  const declared = new Set(Object.keys(manifest.files));
  for (const filePath of bundleFiles) {
    if (filePath.startsWith("asi/") || filePath === "manifest.json") continue;
    if (!declared.has(filePath)) {
      return { status: "TAMPERED", publisherId: null, errors: [`Undeclared file: ${filePath}`] };
    }
  }

  // Step 8: verify each declared file hash
  for (const [filePath, expectedHash] of Object.entries(manifest.files)) {
    if (!isValidManifestFilePath(filePath)) {
      return { status: "TAMPERED", publisherId: null, errors: [`Invalid manifest file path: ${filePath}`] };
    }
    if (typeof expectedHash !== "string") {
      return { status: "TAMPERED", publisherId: null, errors: [`Invalid hash entry type for ${filePath}`] };
    }

    const absoluteFilePath = join(bundlePath, filePath);
    if (!isWithinBundleRoot(bundlePath, absoluteFilePath)) {
      return { status: "TAMPERED", publisherId: null, errors: [`Path escapes bundle root: ${filePath}`] };
    }

    try {
      const st = lstatSync(absoluteFilePath);
      if (st.isSymbolicLink() || !st.isFile()) {
        return { status: "TAMPERED", publisherId: null, errors: [`Declared path is not a regular file: ${filePath}`] };
      }

      const content = readFileSync(absoluteFilePath);
      const actual = sha256Display(sha256(content));
      if (actual !== expectedHash) {
        return { status: "TAMPERED", publisherId: null, errors: [`File hash mismatch: ${filePath}`] };
      }
    } catch (e) {
      return { status: "TAMPERED", publisherId: null, errors: [`Cannot read declared file ${filePath}: ${e.message}`] };
    }
  }

  return { status: "VERIFIED", publisherId: sigJson.publisher_id, errors: [] };
}

// ─── Invocation Envelope Operations ──────────────────────────────────────────

function shouldTreatAsJson(contentType) {
  if (!contentType) return false;
  // minimal: treat application/json as JSON
  return contentType.toLowerCase().includes("application/json");
}

/**
 * createInvocationEnvelope(payloadBody, contentType, privateKeySeed) → envelope object
 */
export function createInvocationEnvelope(payloadBody, contentType, privateKeySeed) {
  const publicKey = ed.getPublicKey(privateKeySeed);
  const agentId = deriveIdentity(publicKey);
  const timestamp = Math.floor(Date.now() / 1000);

  let payloadToHash;
  if (shouldTreatAsJson(contentType)) {
    // Spec says: do not auto-detect JSON if content type missing/unknown.
    // If content type says JSON but parse fails, fall back to raw bytes.
    try {
      const parsed = JSON.parse(utf8Decode(payloadBody));
      payloadToHash = canonicalizeJson(parsed);
    } catch {
      payloadToHash = payloadBody;
    }
  } else {
    payloadToHash = payloadBody;
  }

  const payloadHash = sha256(payloadToHash);
  const signingInput = buildInvocationSigningInput(agentId, timestamp, payloadHash);
  const sig = sign(signingInput, privateKeySeed);

  return {
    asi_version: ASI_VERSION,
    agent_id: agentId,
    timestamp,
    payload_hash: sha256Display(payloadHash),
    signature: base64urlEncode(sig),
  };
}

/**
 * verifyInvocationEnvelope(envelope, payloadBody, contentType, options?)
 * → { valid, agentId, errors }
 */
export function verifyInvocationEnvelope(envelope, payloadBody, contentType, options = {}) {
  const maxSkew = options.maxSkew ?? DEFAULT_TIMESTAMP_SKEW;

  if (envelope.asi_version !== ASI_VERSION) {
    return { valid: false, agentId: null, errors: [`Unrecognized asi_version: ${envelope.asi_version}`] };
  }

  const now = Math.floor(Date.now() / 1000);
  const drift = Math.abs(now - envelope.timestamp);
  if (drift > maxSkew) {
    return { valid: false, agentId: null, errors: [`Timestamp drift ${drift}s exceeds max skew ${maxSkew}s`] };
  }

  let payloadToHash;
  if (shouldTreatAsJson(contentType)) {
    try {
      const parsed = JSON.parse(utf8Decode(payloadBody));
      payloadToHash = canonicalizeJson(parsed);
    } catch {
      payloadToHash = payloadBody;
    }
  } else {
    payloadToHash = payloadBody;
  }

  const computedHash = sha256(payloadToHash);
  const computedDisplay = sha256Display(computedHash);
  if (computedDisplay !== envelope.payload_hash) {
    return { valid: false, agentId: null, errors: ["Payload hash mismatch"] };
  }

  const signingInput = buildInvocationSigningInput(envelope.agent_id, envelope.timestamp, computedHash);

  let publicKey;
  try {
    publicKey = publicKeyFromIdentity(envelope.agent_id);
  } catch (e) {
    return { valid: false, agentId: null, errors: [`Invalid agent_id: ${e.message}`] };
  }

  const signatureBytes = base64urlDecode(envelope.signature);
  if (!verify(signingInput, signatureBytes, publicKey)) {
    return { valid: false, agentId: null, errors: ["Signature verification failed"] };
  }

  return { valid: true, agentId: envelope.agent_id, errors: [] };
}

// ─── Internal exports for tests ──────────────────────────────────────────────

export const _internal = {
  shouldTreatAsJson,
};
