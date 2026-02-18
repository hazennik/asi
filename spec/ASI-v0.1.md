# Agent Skill Identity (ASI) v0.1

**A Minimal Cryptographic Identity Standard for Agent Skill Ecosystems**

-----

**Status:** Draft v0.1  
**Authors:** Open Proposal  
**License:** MIT (Spec + Reference SDK)  
**Date:** February 2026

-----

## Abstract

Agent ecosystems are rapidly evolving toward composable, skill-based infrastructures. As skills begin to resemble APIs — invoked across agents, gateways, and economic systems — the absence of a cryptographic identity layer creates significant supply-chain, impersonation, and accountability risks.

Agent Skill Identity (ASI) v0.1 defines a minimal, framework-agnostic cryptographic identity primitive for:

1. Skill publisher authenticity
1. Skill bundle integrity
1. Runtime agent identity verification

ASI deliberately excludes governance, registry infrastructure, and reputation systems in v0.1. It provides only the cryptographic foundation necessary to enable future trust layers.

This document defines:

- Identity format
- Signing requirements and domain separation
- Verification procedures
- Canonical encoding rules
- Integration patterns
- Forward compatibility rules
- Security considerations
- Reference SDK structure

-----

## 1. Motivation

### 1.1 The Shift to Skill-Based Infrastructure

Modern agent systems increasingly support modular skills and plugins, cross-agent invocation, skill-to-skill composition, and economic execution including payments, wallets, and services. Skills are becoming the functional equivalent of APIs.

Unlike traditional APIs, skill ecosystems lack vendor-controlled authentication layers, OAuth-equivalent trust delegation, signed artifact guarantees, and portable runtime identity verification.

Without cryptographic identity, malicious skills can impersonate publishers, skill bundles can be tampered with after publication, agents can spoof identity during invocation, economic abuse becomes trivial, and supply-chain attacks scale quickly.

### 1.2 Ecosystem Evidence

The urgency of this problem is established by documented incidents across agent skill ecosystems:

- Public skill registries have repeatedly contained malicious packages, including typosquats, credential exfiltration tools, and skills that hijack agent behavior through prompt injection embedded in metadata.[^1][^2][^3]
- Security researchers have found that a significant percentage of audited community skills contain critical vulnerabilities or are actively malicious, with attack patterns including obfuscated payloads, hidden webhooks, and instructions to download and execute untrusted binaries.[^4][^5]
- Agent-to-agent platforms have observed extreme bot-to-human ratios with no mechanism to distinguish verified agents from automated scripts, enabling Sybil attacks, reputation laundering, and cognitive injection at scale.[^6]
- Agent commerce systems now process real financial transactions — micropayments, wallet operations, service procurement — without any identity verification of the transacting agent.[^7]

These are not edge cases. They are structural consequences of building an execution ecosystem without an identity layer.

ASI addresses these risks with minimal coordination overhead.

[^1]: Koi Security. “ClawHavoc: Malicious Skills on ClawHub.” January 2026. https://koi.security/research/clawhavoc
[^2]: Snyk. “ToxicSkills: Malicious AI Agent Skills on ClawHub.” February 2026. https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/
[^3]: VirusTotal. “From Automation to Infection: How OpenClaw AI Agent Skills Are Being Weaponized.” February 2026. https://blog.virustotal.com/2026/02/from-automation-to-infection-how.html
[^4]: Semgrep. “OpenClaw Security Engineer’s Cheat Sheet.” February 2026. https://semgrep.dev/blog/2026/openclaw-security-engineers-cheat-sheet/
[^5]: arXiv:2601.10338. “Agent Skills in the Wild: An Empirical Study of Security Vulnerabilities at Scale.” January 2026.
[^6]: Zenity Labs. “Agent-to-Agent Exploitation in the Wild: Observed Attacks on Moltbook.” February 2026. https://labs.zenity.io/p/agent-to-agent-exploitation-in-the-wild-observed-attacks-on-moltbook-b929
[^7]: RNWY. “The OpenClaw Ecosystem Is Growing Fast — Who’s Verifying These Agents?” February 2026. https://rnwy.com/blog/openclaw-ecosystem-agent-verification

-----

## 2. Design Principles

ASI v0.1 adheres to the following principles:

**Self-Sovereign Identity.** No central registry required. Identity is derived from a cryptographic keypair. Any agent or publisher can generate an identity without permission from any authority.

**Minimal Surface Area.** Cryptographic primitives only. ASI defines signing, verification, and identity derivation. It does not define governance, reputation, revocation, or policy.

**Framework-Agnostic.** ASI integrates into any agent system — OpenClaw, Claude Code, LangChain, AutoGPT, or custom frameworks. The spec imposes no runtime dependencies.

**No Governance Layer.** No revocation authorities, trust roots, or certification bodies in v0.1. These are explicitly deferred to future extensions.

**Optional Adoption.** Backwards compatible with unsigned skills. ASI is additive. Existing ecosystems continue to function. Verification is available where desired, not mandated globally.

**Deterministic Verification.** Canonical encoding rules and domain separation strings prevent signature ambiguity. Two independent implementations verifying the same bundle MUST produce the same result.

-----

## 3. Identity Model

ASI defines two identity layers:

**Publisher Identity** authenticates the skill author. It answers: who published this skill, and has the bundle been modified since publication?

**Agent Runtime Identity** authenticates the invoking agent. It answers: who is making this request, and is the request payload authentic?

These layers are independent. A skill may have a verified publisher identity without the invoking agent presenting runtime identity, and vice versa. Implementations may enforce either, both, or neither.

-----

## 4. Cryptographic Specification

### 4.1 Key Algorithm

ASI v0.1 uses Ed25519 exclusively.

Rationale: Ed25519 produces deterministic signatures (no nonce-related vulnerabilities), uses compact 32-byte public keys suitable for embedding in manifests and envelopes, is widely supported across languages and platforms (Node.js, Swift, Python, Rust, Go), and has no patent encumbrances.

Implementations MUST NOT support other algorithms in v0.1. Algorithm agility is deferred to future versions to avoid downgrade attacks and reduce implementation complexity.

Implementations MUST use deterministic Ed25519 as defined in RFC 8032. Randomized Ed25519 variants (such as Ed25519ctx or non-deterministic nonce generation schemes) are not permitted. The deterministic property of RFC 8032 Ed25519 ensures that signing the same input with the same key always produces the same signature, which simplifies testing and eliminates nonce-related vulnerabilities.

### 4.2 Identity Format

Identity MUST be derived from the public key using the DID:key method.

Format:

```
did:key:z6Mk...
```

This follows the W3C DID specification (did:key method). The `z6Mk` prefix identifies an Ed25519 public key encoded in multibase/multicodec format.

Rationale for selecting DID:key as the sole format: a single canonical format eliminates ambiguity. Verifiers need to support exactly one identity derivation path. DID:key is an established W3C specification with existing library support. It is self-describing (the key type is embedded in the identifier) and does not require a resolver or registry lookup.

Implementations MUST reject identities that do not conform to the DID:key format.

### 4.3 Encoding Rules

The following encoding rules apply throughout this specification:

- **Public keys:** Raw 32-byte Ed25519 public key, base64url-encoded (RFC 4648 §5, no padding).
- **Signatures:** Raw 64-byte Ed25519 signature, base64url-encoded (RFC 4648 §5, no padding).
- **Hashes for display and storage:** SHA-256 digest as lowercase hex string with `sha256:` prefix (e.g., `sha256:a1b2c3...`). The hex string MUST be exactly 64 characters (representing 32 bytes).
- **Hashes for signing input:** Raw 32-byte SHA-256 digest. Signing operations MUST NOT sign the hex-encoded string; they MUST sign the raw digest bytes.

This distinction between display format (hex string) and signing format (raw bytes) is critical. Implementations that sign the hex-encoded string rather than the raw digest will produce signatures that are valid but incompatible with correct implementations.

### 4.4 Canonical Identity

The canonical identity of a publisher or agent is the `publisher_id` or `agent_id` (DID:key string). The `public_key` field in signature envelopes is a convenience copy that allows verification without DID:key parsing.

Implementations MUST verify that `public_key` matches the key encoded in the DID:key identifier. If they differ, verification MUST fail.

-----

## 5. Skill Publisher Identity

### 5.1 Skill Bundle Structure

A signed skill bundle contains the following:

```
skill/
  manifest.json        # Skill metadata and file inventory
  SKILL.md             # Skill instructions (if applicable)
  index.js             # Skill code (if applicable)
  [additional files]
  asi/
    signature.json     # ASI signature envelope
```

The `asi/` directory is reserved for ASI metadata. Implementations MUST NOT use this directory for other purposes.

### 5.2 manifest.json Requirements

The manifest MUST include a `files` object that declares the relative path and SHA-256 hash of every file in the bundle except files under the `asi/` directory.

```json
{
  "name": "example-skill",
  "version": "1.0.0",
  "description": "An example signed skill",
  "files": {
    "SKILL.md": "sha256:a1b2c3d4...",
    "index.js": "sha256:e5f6a7b8...",
    "config/defaults.json": "sha256:c9d0e1f2..."
  }
}
```

File enumeration rules:

- `manifest.json` MUST list every file in the bundle directory tree except files under `asi/` and `manifest.json` itself.
- `manifest.json` MUST NOT include an entry for itself. The manifest’s integrity is covered by the signature over its canonicalized content, not by self-referential hashing.
- Verifiers MUST fail if any file exists in the bundle directory tree (outside `asi/`, and excluding `manifest.json`) that is not declared in `manifest.json`. This prevents hidden payload injection.
- Verifiers MUST ignore files under `asi/` (future ASI versions may add additional metadata files to this directory).
- File paths MUST use forward slashes (`/`) as separators, MUST be relative to the bundle root, and MUST NOT contain `..` segments. File paths MUST NOT begin with `/` and MUST NOT end with `/`. Only regular files are permitted in the `files` object; directory entries MUST NOT appear.

Bundle filesystem rules:

- Verifiers MUST reject bundles containing symbolic links. Symlinks MUST NOT be followed during file enumeration or hashing. This prevents symlink-based attacks where a link targets a sensitive file outside the bundle (e.g., `~/.ssh/id_ed25519`) or where a symlink is substituted for a regular file after signing.
- File hashes are computed over raw file content bytes. No newline normalization (e.g., CRLF to LF) is applied. Signers and verifiers MUST hash identical bytes.
- File permissions, ownership, modification times, and executable bits are NOT covered by ASI v0.1. These metadata are platform-dependent and are not included in the manifest or signature. Future versions may optionally address executable bit verification.

### 5.3 asi/signature.json Format

```json
{
  "asi_version": "0.1",
  "publisher_id": "did:key:z6Mk...",
  "public_key": "<base64url-encoded-32-byte-ed25519-public-key>",
  "algorithm": "ed25519",
  "manifest_hash": "sha256:abc123...",
  "signed_at": 1739140000,
  "signature": "<base64url-encoded-64-byte-ed25519-signature>"
}
```

Field definitions:

- `asi_version`: MUST be `"0.1"` for this specification.
- `publisher_id`: DID:key derived from the public key. Verifiers MUST confirm that `publisher_id` matches `public_key` (see §4.4).
- `public_key`: The raw 32-byte Ed25519 public key, base64url-encoded (RFC 4648 §5, no padding).
- `algorithm`: MUST be `"ed25519"`.
- `manifest_hash`: SHA-256 hash of the canonicalized manifest.json (see §5.4), lowercase hex with `sha256:` prefix. This value MUST equal the SHA-256 digest of the JCS-canonicalized manifest, computed before constructing the signing input. The `manifest_hash` is not derived from or recomputed from the signing input; the signing input incorporates the raw digest that `manifest_hash` represents.
- `signed_at`: Unix epoch seconds at time of signing. Timestamps MUST represent the signer’s wall-clock time in UTC. This field IS covered by the signature (see §5.4) and MAY be used for audit display.
- `signature`: Ed25519 signature over the domain-separated signing input (see §5.4), base64url-encoded (RFC 4648 §5, no padding).

### 5.4 Signing Procedure

The signing input for a publisher signature uses domain separation to prevent cross-context signature reuse.

**Step 1.** Canonicalize `manifest.json` using JCS (RFC 8785). Compute the SHA-256 digest of the canonical bytes. This produces a 32-byte raw digest.

**Step 2.** Construct the signing input by concatenating the following byte sequences in order:

```
domain_tag     = UTF-8("ASI-SKILL-MANIFEST/v0.1")
separator      = 0x00                              (single null byte)
manifest_hash  = SHA-256(JCS(manifest.json))        (32 bytes, raw digest)
signed_at      = big-endian uint64(unix_timestamp)  (8 bytes)
```

Signing input = `domain_tag || separator || manifest_hash || signed_at`

**Step 3.** Sign the signing input with the publisher’s Ed25519 private key. This produces a 64-byte signature.

**Step 4.** Encode the signature as base64url (no padding) and construct `asi/signature.json` with all required fields.

The domain tag `ASI-SKILL-MANIFEST/v0.1` ensures that a valid publisher signature cannot be reinterpreted as a valid invocation signature (see §7), even if the same keypair is used for both purposes. The null byte separator prevents ambiguity if the domain tag is extended in future versions.

### 5.5 Verification Procedure

1. Read `asi/signature.json`. If absent, mark skill as `UNSIGNED` and stop.
1. Validate `asi_version` is `"0.1"`. If unrecognized, mark as `UNKNOWN_VERSION` and stop. Implementations MUST NOT attempt to verify signatures with unrecognized version strings.
1. Verify that `public_key` decodes to a valid 32-byte Ed25519 public key. Derive DID:key from it. If it does not match `publisher_id`, mark as `TAMPERED` and stop.
1. Canonicalize `manifest.json` using JCS (RFC 8785). Compute the SHA-256 digest of the canonical bytes.
1. Compare the hex-encoded digest (with `sha256:` prefix) to `manifest_hash`. If mismatch, mark as `TAMPERED` and stop.
1. Reconstruct the signing input per §5.4 using the raw manifest digest and `signed_at`.
1. Verify `signature` against the signing input using the public key. If invalid, mark as `TAMPERED` and stop.
1. Enumerate all files in the bundle directory tree, excluding files under `asi/` and `manifest.json` itself. For each file not declared in `manifest.json`’s `files` object, mark as `TAMPERED` and stop (undeclared file detected).
1. For each entry in `manifest.json`’s `files` object, compute the SHA-256 hash of the file at the declared path. If any hash does not match, mark as `TAMPERED` and stop.
1. Mark skill as `VERIFIED` with `publisher_id` as the verified publisher.

Verification status MUST be one of:

- `VERIFIED` — Signature valid, all file hashes match, publisher identity confirmed.
- `UNSIGNED` — No `asi/signature.json` present. Skill may still be loaded depending on policy.
- `TAMPERED` — Signature present but verification failed at any step. Skill SHOULD NOT be loaded.
- `UNKNOWN_VERSION` — `asi_version` is not recognized. Skill SHOULD NOT be treated as verified.

### 5.6 Status Semantics

Verification statuses carry distinct policy implications:

- `TAMPERED` is a **cryptographic failure**. The signature was present but did not pass verification. This indicates either bundle modification, key mismatch, or corruption. Implementations SHOULD block loading by default. This is a security event, not a policy decision.
- `UNSIGNED` is a **policy decision**. No signature was present. The skill may be legitimate but cannot be cryptographically verified. Whether to load unsigned skills is a deployment policy choice (see §9.2).
- `UNKNOWN_VERSION` is an **incompatibility signal**. The signature may be valid under a newer ASI version that this implementation does not support. Implementations MUST NOT treat this as verified. It SHOULD be surfaced to the user as “unverifiable by this implementation” rather than “tampered.”
- `VERIFIED` is a **positive cryptographic confirmation**. The publisher identity is authentic and the bundle is intact. This does NOT imply the skill is safe, trustworthy, or non-malicious — only that the publisher’s identity claim is valid and the bundle has not been modified since signing.

Implementations MUST NOT mark a skill as `VERIFIED` if any verification step has failed or been skipped. Partial verification states are not permitted. The verification procedure (§5.5) is an ordered sequence; failure at any step terminates verification with a non-`VERIFIED` status.

-----

## 6. Canonical JSON (JCS — RFC 8785)

All JSON subject to signing MUST be canonicalized using JSON Canonicalization Scheme (JCS) as defined in RFC 8785.

JCS specifies:

- UTF-8 encoding with no BOM.
- Lexicographic sorting of object keys by Unicode code point.
- No insignificant whitespace.
- Deterministic number serialization (no trailing zeros, no positive sign, exponential notation for magnitudes outside a defined range).

Rationale for selecting JCS: it is an IETF-published standard (not a custom algorithm), has reference implementations in JavaScript, Python, Java, Go, Rust, and Swift, and eliminates the class of canonicalization bugs that have affected PGP, JWT, and XML-DSig signing systems.

Implementations MUST use a JCS-compliant library. Custom canonicalization routines are explicitly discouraged.

-----

## 7. Runtime Agent Identity

When invoking a skill or interacting with another agent or service, agents SHOULD present a signed invocation envelope that proves their identity and the integrity of the request payload.

### 7.1 Invocation Envelope

```json
{
  "asi_version": "0.1",
  "agent_id": "did:key:z6Mk...",
  "timestamp": 1739140000,
  "payload_hash": "sha256:def456...",
  "signature": "<base64url-encoded-64-byte-ed25519-signature>"
}
```

Field definitions:

- `asi_version`: MUST be `"0.1"`.
- `agent_id`: DID:key of the invoking agent.
- `timestamp`: Unix epoch seconds at time of invocation. Timestamps MUST represent the sender’s wall-clock time in UTC. Monotonic clocks, boot time, or local timezone offsets MUST NOT be used.
- `payload_hash`: SHA-256 hash of the canonical request body, lowercase hex with `sha256:` prefix.
- `signature`: Ed25519 signature over the domain-separated signing input (see §7.2).

### 7.2 Payload Hashing Rules

The `payload_hash` in an invocation envelope covers the request body. The hashing procedure depends on the content type:

- If the payload is JSON (`Content-Type: application/json` or equivalent), the payload MUST be canonicalized with JCS (RFC 8785) before hashing. The hash is computed over the canonical bytes, not the raw transmitted bytes. This ensures that semantically identical JSON payloads produce identical hashes regardless of whitespace or key ordering differences in transmission.
- For all other content types (multipart, plain text, binary, protobuf, etc.), the hash MUST be computed over the raw bytes exactly as transmitted. No normalization is applied.

Implementations MUST document which content types they treat as JSON for canonicalization purposes. At minimum, `application/json` MUST be canonicalized. If the content type is absent or cannot be determined, implementations MUST treat the payload as raw bytes. Implementations MUST NOT attempt to auto-detect JSON by parsing heuristics, as this causes signature divergence across implementations.

### 7.3 Signing Rules

The signing input for an invocation signature uses domain separation to prevent cross-context signature reuse.

Construct the signing input by concatenating the following byte sequences in order:

```
domain_tag     = UTF-8("ASI-INVOKE/v0.1")
separator      = 0x00                              (single null byte)
agent_id       = UTF-8(agent_id_string)            (variable length, no normalization)
separator      = 0x00                              (single null byte)
timestamp      = big-endian uint64(unix_timestamp) (8 bytes)
payload_hash   = SHA-256(canonical_or_raw_payload) (32 bytes, raw digest)
```

Signing input = `domain_tag || 0x00 || agent_id || 0x00 || timestamp || payload_hash`

The domain tag `ASI-INVOKE/v0.1` ensures that a valid invocation signature cannot be reinterpreted as a valid publisher signature. The null byte separators between variable-length fields prevent concatenation ambiguity. The `agent_id` MUST be encoded as its exact UTF-8 byte representation. Unicode normalization (NFC, NFD, NFKC, NFKD) MUST NOT be applied. DID:key strings are already ASCII-safe, but this rule prevents normalization-based signature invalidation if future identity formats include non-ASCII characters.

Implementations MUST NOT sign the JSON envelope itself. They MUST sign the derived byte sequence defined above.

### 7.4 Verification

The receiver MUST perform the following steps:

1. Validate `asi_version` is `"0.1"`. If unrecognized, reject. Implementations MUST NOT attempt to verify envelopes with unrecognized version strings.
1. Validate `timestamp` is within ±300 seconds of the receiver’s current time. Implementations MAY configure a different skew tolerance but MUST default to 300 seconds if unconfigured. Receivers SHOULD use a monotonic system clock where available; if system time is unknown or untrusted, verification MAY operate in advisory mode.
1. Compute the SHA-256 hash of the request body per §7.2 (JCS-canonicalized if JSON, raw bytes otherwise). Compare the hex-encoded digest (with `sha256:` prefix) to `payload_hash`. Reject on mismatch.
1. Reconstruct the signing input per §7.3 using the raw payload digest.
1. Derive the Ed25519 public key from `agent_id` (DID:key decoding). If `agent_id` is not a valid DID:key, reject.
1. Verify `signature` against the reconstructed signing input using the derived public key.

If verification fails at any step, the receiver MAY reject the request, flag the request for audit, log the verification failure with the specific step that failed, or accept with reduced trust (if operating in advisory mode).

### 7.5 Envelope Delivery

The invocation envelope SHOULD be delivered as an HTTP header or as a wrapper field in the request body, depending on the transport. ASI does not mandate a specific transport binding in v0.1.

Recommended HTTP header:

```
ASI-Envelope: <base64url-encoded-UTF-8-JSON>
```

The envelope JSON in the header is UTF-8 encoded and then base64url-encoded. Invocation envelopes SHOULD NOT exceed 4KB in total serialized size (before base64url encoding). This prevents header abuse in HTTP contexts and ensures compatibility with common proxy and server header size limits. The envelope itself is not canonicalized (JCS is not applied to the envelope — it is applied to the request body for payload hashing, and to manifests for publisher signing). The envelope is a transport wrapper; its integrity is protected by the signature over the derived byte sequence, not by canonicalization of the envelope JSON.

-----

## 8. Forward Compatibility

ASI v0.1 defines the following rules for forward compatibility:

**Unknown fields.** Implementations MUST ignore unknown fields in `asi/signature.json` and invocation envelopes. Future ASI versions may add fields. Existing v0.1 verifiers MUST NOT reject a signature or envelope solely because it contains fields not defined in this specification.

**Unknown asi_version.** Implementations MUST reject any `asi/signature.json` or invocation envelope with an `asi_version` value other than `"0.1"`. This prevents a v0.1 verifier from incorrectly validating a v0.2 signature whose signing input may differ.

**Unknown files in asi/.** Verifiers MUST ignore files under the `asi/` directory that are not defined in this specification. Future ASI versions may add additional metadata files (e.g., revocation attestations, audit logs).

**Envelope extensions.** Future versions may define additional fields in invocation envelopes (e.g., `nonce`). These fields will be incorporated into the signing input in a version-specific manner. The `asi_version` field ensures that the correct signing input construction is used for verification.

-----

## 9. Integration Model

ASI adoption follows a phased approach that allows ecosystems to adopt incrementally without breaking existing workflows.

### 9.1 Phase 1 — Passive Verification

The framework verifies signatures if present but does not require them. Unsigned skills are still loaded and executed normally. The UI surfaces verification status:

- **Verified Publisher** — `asi/signature.json` present and valid.
- **Unsigned Skill** — No signature present.
- **Tampered Skill** — Signature present but verification failed.
- **Unknown Version** — `asi_version` not recognized by this implementation.

This phase provides immediate value with zero disruption. Users gain visibility into which skills are signed without any skill being blocked.

### 9.2 Phase 2 — Configurable Enforcement

The framework exposes policy configuration:

```json
{
  "security": {
    "asi": {
      "requireSignedSkills": false,
      "requireSignedInvocation": false,
      "allowUnsigned": true,
      "blockTampered": true
    }
  }
}
```

- `requireSignedSkills`: When `true`, unsigned skills are not loaded.
- `requireSignedInvocation`: When `true`, unsigned invocation envelopes are rejected.
- `allowUnsigned`: When `false`, equivalent to `requireSignedSkills: true`.
- `blockTampered`: When `true` (recommended default), skills with failed verification are never loaded regardless of other settings.

### 9.3 Phase 3 — Ecosystem Adoption

Skill registries surface verification status in search results and skill detail pages. Marketplaces may require signing for publication. Framework maintainers may change defaults to require signatures for community-sourced skills while exempting built-in and local skills.

ASI does not prescribe Phase 3 policies. It provides the cryptographic foundation that makes them possible.

-----

## 10. Reference SDK

The reference SDK MUST implement the following functions:

```
generateKeypair() → { publicKey: Uint8Array(32), privateKeySeed: Uint8Array(32) }
deriveIdentity(publicKey: Uint8Array(32)) → string (did:key)
sign(signingInput: Uint8Array, privateKeySeed: Uint8Array(32)) → Uint8Array(64)
verify(signingInput: Uint8Array, signature: Uint8Array(64), publicKey: Uint8Array(32)) → boolean
canonicalize(json: object) → Uint8Array (JCS per RFC 8785)
sha256(data: Uint8Array) → Uint8Array(32)
hashBundle(bundlePath: string) → { files: Record<string, string> }
buildPublisherSigningInput(manifestHash: Uint8Array(32), signedAt: number) → Uint8Array
buildInvocationSigningInput(agentId: string, timestamp: number, payloadHash: Uint8Array(32)) → Uint8Array
createSignedManifest(manifest: object, bundlePath: string, privateKeySeed: Uint8Array(32)) → signature.json object
verifySkillBundle(bundlePath: string) → { status, publisherId, errors }
createInvocationEnvelope(payloadBody: Uint8Array, contentType: string, privateKeySeed: Uint8Array(32)) → envelope object
verifyInvocationEnvelope(envelope: object, payloadBody: Uint8Array, contentType: string) → { valid, agentId, errors }
```

Key material format:

- The canonical private key representation is a **32-byte seed** (`privateKeySeed`). Ed25519 libraries internally expand the seed to a 64-byte expanded key for signing, but this expansion is an implementation detail. The seed is the portable, storable, and interoperable format.
- Rationale: Ed25519 libraries differ in how they represent private keys. Some use 32-byte seeds (Swift CryptoKit, Go `crypto/ed25519`), some use 64-byte expanded keys (libsodium), and some use seed+pubkey concatenations (NaCl). Standardizing on the 32-byte seed avoids cross-language incompatibilities. Libraries that require a different internal format MUST accept the 32-byte seed and expand it internally.
- `publicKey` is always the raw 32-byte Ed25519 public key.

SDK requirements:

- MIT licensed.
- No telemetry.
- No remote calls. All operations are local.
- Reference implementations provided in TypeScript and Python.
- No dependencies beyond Ed25519, SHA-256, and JCS primitives. JCS implementations may be vendored or declared as a single dependency.
- `buildPublisherSigningInput` and `buildInvocationSigningInput` MUST be exposed as public functions so that implementations can inspect and test the exact byte sequences being signed.

-----

## 11. Security Considerations

### 11.1 Key Storage

Private keys MUST never be embedded in skill bundles, committed to version control, transmitted over unencrypted channels, or logged.

Private keys SHOULD be stored in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service) or an equivalent secure storage mechanism. If file-based storage is used, the file MUST have permissions restricted to the owner (mode 0600 on Unix systems).

### 11.2 Domain Separation

ASI uses distinct domain tags for publisher signatures (`ASI-SKILL-MANIFEST/v0.1`) and invocation signatures (`ASI-INVOKE/v0.1`). This ensures that a valid signature in one context cannot be replayed in another, even if the same keypair is used for both publishing and runtime invocation.

Implementations MUST construct signing inputs exactly as specified in §5.4 and §7.3. Deviations from the specified byte layout will produce valid Ed25519 signatures that fail cross-implementation verification.

### 11.3 Replay Attacks

Timestamp validation mitigates basic replay attacks on invocation envelopes. The default ±300 second window balances clock skew tolerance against replay risk.

For high-value operations (financial transactions, destructive actions), implementations SHOULD add a nonce field to the invocation envelope. Nonce-based replay protection is defined as an optional extension in v0.2, not in v0.1.

Publisher signatures do not include replay protection beyond `signed_at` because skill bundles are static artifacts, not transactional requests. A valid publisher signature remains valid indefinitely (until the key is revoked, which is out of scope for v0.1).

### 11.4 Sybil Attacks

ASI v0.1 does not mitigate Sybil attacks. Any entity can generate unlimited keypairs and thus unlimited identities. Sybil resistance requires reputation, stake, or external verification — all of which are explicitly out of scope for v0.1.

Future extensions (reputation layers, identity registries) can build Sybil resistance on top of ASI identities.

### 11.5 Key Compromise

If a publisher’s private key is compromised, all skills signed with that key should be treated as suspect. ASI v0.1 does not define a revocation mechanism.

Future versions may include key rotation via chained signatures:

```json
{
  "previous_key": "<base64url-encoded-old-public-key>",
  "new_key": "<base64url-encoded-new-public-key>",
  "rotation_signature": "<base64url-signed-by-old-key>",
  "rotated_at": 1739200000
}
```

Until revocation is specified, ecosystems relying on ASI should maintain out-of-band revocation lists if key compromise is a concern.

### 11.6 Canonicalization Attacks

JCS (RFC 8785) is resistant to known canonicalization attacks, but implementations MUST use a compliant library rather than hand-rolling canonicalization logic. Common failure modes in custom implementations include inconsistent Unicode normalization, floating-point serialization differences, and key ordering that does not follow Unicode code point order.

### 11.7 Downgrade Attacks

Because ASI v0.1 supports only Ed25519 and requires strict `asi_version` checking, there is no algorithm negotiation and therefore no downgrade attack surface. Future versions introducing algorithm agility MUST specify explicit algorithm negotiation rules and MUST NOT allow fallback to weaker algorithms.

### 11.8 Undeclared File Injection

The requirement that verifiers MUST fail when undeclared files exist outside `asi/` (§5.5, step 8) prevents an attacker from injecting additional executable code into a signed bundle without detection. Without this rule, an attacker could add a malicious helper script to a verified bundle and have it executed by the skill’s primary code.

### 11.9 Symlink Attacks

The requirement that verifiers MUST reject bundles containing symbolic links (§5.2) prevents two classes of attack: exfiltration attacks where a symlink targets a sensitive file outside the bundle (e.g., `~/.ssh/id_ed25519`, `~/.openclaw/credentials/`) causing the skill to read or transmit sensitive data at runtime, and TOCTOU attacks where a regular file is replaced with a symlink between signing and verification, causing the verified hash to cover the original file while runtime execution follows the symlink to a different target.

-----

## 12. Backwards Compatibility

ASI is fully additive. Unsigned skills remain valid. Frameworks that do not implement ASI verification ignore the `asi/` directory. Skills signed with ASI work in frameworks that do not understand ASI — the signature is simply not checked.

No existing skill format is modified. No existing API contract is changed. No existing configuration is invalidated.

-----

## 13. Threat Model

### 13.1 Threats Mitigated by ASI

**Skill tampering.** An attacker modifies a skill bundle after publication (man-in-the-middle, compromised registry, local filesystem manipulation). ASI verification detects the modification because file hashes will not match the signed manifest.

**Publisher impersonation.** An attacker publishes a skill under a name similar to a trusted publisher. ASI does not prevent publication (that requires a registry), but it does allow users to verify the publisher’s cryptographic identity. A user who has previously trusted `did:key:z6MkABC...` can detect that a lookalike skill is signed by a different key.

**Agent impersonation.** A script or unauthorized agent attempts to invoke a skill or service while claiming to be a different agent. The invocation envelope signature binds the request to the agent’s private key. Without the key, the signature cannot be forged.

**Payload modification.** An intermediary modifies the request body between the agent and the skill/service. The payload hash in the invocation envelope detects the modification.

**Cross-context signature replay.** An attacker captures a valid publisher signature and attempts to present it as an invocation signature, or vice versa. Domain separation (§5.4, §7.3) ensures that signatures are context-bound and cannot be reinterpreted.

### 13.2 Threats NOT Mitigated by ASI

**Malicious but properly signed skills.** A publisher with a valid keypair can sign a skill that steals credentials, exfiltrates data, or performs prompt injection. ASI verifies identity, not intent. Addressing this requires behavioral analysis, sandboxing, and reputation — all out of scope for v0.1.

**Social engineering.** An attacker convinces a user to trust a malicious publisher’s identity. ASI provides the identity primitive but does not enforce trust decisions.

**Sybil identity proliferation.** An attacker generates thousands of identities to flood a registry or manipulate reputation systems. ASI provides no cost or barrier to identity creation by design.

**Economic fraud without enforcement.** An agent with a valid ASI identity can still engage in fraudulent transactions if no external enforcement mechanism checks behavior against policy.

**Key compromise.** If a publisher’s private key is stolen, the attacker can sign malicious skills that will pass ASI verification. Revocation is out of scope for v0.1.

-----

## 14. Comparison with Existing Approaches

**ERC-8004 (Ethereum Agent Identity).** ERC-8004 provides on-chain agent discovery via an NFT-based identity registry. ASI and ERC-8004 are complementary, not competing. ERC-8004 defines where to find agents. ASI defines how agents prove they are who they claim to be cryptographically. An agent could register its ASI DID:key in an ERC-8004 identity record, bridging on-chain discovery with off-chain verification.

**Signed Instruction Envelopes (SIE).** SIE proposals in the OpenClaw ecosystem focus on verifying skill instruction integrity at loader time. ASI encompasses this use case (publisher identity + bundle integrity) and extends it to runtime invocation identity. SIE implementations could adopt ASI as their underlying cryptographic format.

**VirusTotal / ClawHub Scanning.** Malware scanning detects known malicious patterns. ASI does not detect malicious behavior — it establishes identity and integrity. These are complementary layers: scanning catches known-bad payloads, ASI ensures you know who published the payload and that it hasn’t been modified.

**Capability-Based Security (ajs-clawbot, OpenClaw skill capabilities).** Capability systems control what a skill can do at runtime. ASI controls who the skill claims to be and whether that claim is authentic. A skill can be ASI-verified and still require capability declarations before it is granted tool access.

**TLS / HTTPS.** TLS secures the transport channel. ASI secures the identity of the endpoints. A skill downloaded over HTTPS is protected from network tampering during download, but TLS says nothing about who published the skill or whether it was modified before being hosted. ASI covers the artifact-level identity that TLS does not.

-----

## 15. Adoption Strategy

### Step 1 — Publish Spec and SDK

Release this specification and the reference SDK (TypeScript + Python) under MIT license. Host on GitHub. Invite review from the security and agent development communities.

### Step 2 — Ship an OpenClaw Skill

Build and publish an OpenClaw skill that performs ASI signing and verification. The skill enables any OpenClaw user to sign their own skills and verify skills from others. This is the initial distribution mechanism — ASI enters the largest agent ecosystem through its native extension system.

### Step 3 — Surface Verification in UI

Work with framework maintainers and skill registries to display ASI verification status in skill listings, installation prompts, and agent configuration interfaces. The goal is visibility: users should see whether a skill is verified, unsigned, or tampered every time they encounter one.

### Step 4 — Encourage Marketplace Adoption

Skill registries (ClawHub and equivalents) adopt ASI as a publication standard. Signed skills are surfaced preferentially. Unsigned skills carry a visible indicator. Registry maintainers may eventually require signing for publication.

### Step 5 — Cross-Framework Adoption

Publish integration guides and reference plugins for additional agent frameworks. ASI’s framework-agnostic design means the same identity works across OpenClaw, Claude Code, LangChain, CrewAI, AutoGPT, and custom implementations. An agent’s ASI identity is portable.

-----

## 16. Why Minimalism Matters

Standards spread when they are simple, require no permission, require no central authority, and solve visible pain.

ASI v0.1 intentionally avoids registry systems, trust anchors, governance layers, paid verification, token models, blockchain dependencies, and reputation scoring.

Every successful identity primitive started minimal. PGP defined key generation and signing before the Web of Trust emerged. X.509 defined certificate format before certificate authorities organized. TLS defined the handshake before Let’s Encrypt made adoption frictionless. DID defined the identifier format before verifiable credentials defined what you could prove with one.

ASI follows this pattern. Define the primitive. Ship the tooling. Let the ecosystem build the layers above.

-----

## 17. Future Extensions (Non-Normative)

The following capabilities are explicitly deferred to future ASI versions. They are listed here to demonstrate that the v0.1 foundation supports them without modification.

- **Key revocation lists.** Publishers declare compromised keys. Verifiers check against the list.
- **Reputation graphs.** Agents accumulate reputation scores based on verified behavior over time.
- **Transparency logs.** Append-only logs of all signed skill publications, enabling auditability.
- **Cross-framework identity bridging.** Mapping ASI identities to platform-specific identity systems.
- **Wallet integration.** Binding ASI identities to blockchain wallets for agent commerce.
- **Enterprise compliance reporting.** Generating audit trails of which agents accessed which skills with which identities.
- **Nonce-based replay protection.** Extending invocation envelopes with unique nonces for high-value operations.
- **Multi-signature skills.** Requiring signatures from multiple publishers (e.g., author + auditor) before a skill is considered verified.
- **Delegated signing.** Allowing a publisher to authorize a CI/CD system to sign on their behalf with a scoped sub-key.

These are v2+ concerns. They build on ASI v0.1. They do not replace it.

-----

## 18. Conclusion

Agent Skill Identity (ASI) v0.1 provides cryptographic publisher authenticity, skill bundle integrity verification, and runtime agent identity primitives.

It establishes the foundation for trust in skill-based ecosystems without imposing governance, centralization, or economic barriers to adoption.

The agent ecosystem’s most urgent problem is not capability — it is accountability. Skills execute code. Agents take actions. Money moves. Identity must exist at this layer.

ASI provides that identity as a primitive — not a platform, not a registry, not a token. A primitive that any framework can adopt, any publisher can use, and any verifier can check.

Identity must begin as a primitive. Everything else is built on top.

-----

## Appendix A: Example Signed Skill Bundle

### Directory Structure

```
weather-skill/
  manifest.json
  SKILL.md
  src/
    fetch-weather.js
  asi/
    signature.json
```

### manifest.json

```json
{
  "name": "weather-skill",
  "version": "1.2.0",
  "description": "Fetch current weather conditions by location",
  "files": {
    "SKILL.md": "sha256:3f2b1a9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a",
    "src/fetch-weather.js": "sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
  }
}
```

### asi/signature.json

```json
{
  "asi_version": "0.1",
  "publisher_id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
  "public_key": "Lm8wq9R3...",
  "algorithm": "ed25519",
  "manifest_hash": "sha256:7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e",
  "signed_at": 1739140000,
  "signature": "kH7gT4bN2..."
}
```

### Signing Input (Hex Representation)

```
4153492d534b494c4c2d4d414e49464553542f76302e31   # "ASI-SKILL-MANIFEST/v0.1"
00                                                   # null separator
7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a...   # raw SHA-256 of JCS(manifest)
00000000679f3940                                     # signed_at as big-endian uint64
```

-----

## Appendix B: Example Invocation Envelope

An agent invoking the weather skill presents:

```json
{
  "asi_version": "0.1",
  "agent_id": "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
  "timestamp": 1739140500,
  "payload_hash": "sha256:9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a",
  "signature": "xN3mP8qR5..."
}
```

### Signing Input (Hex Representation)

```
4153492d494e564f4b452f76302e31                       # "ASI-INVOKE/v0.1"
00                                                   # null separator
6469643a6b65793a7a364d6b724a566e615a6b65467a64...   # UTF-8(agent_id)
00                                                   # null separator
00000000679f3b14                                     # timestamp as big-endian uint64
9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c...   # raw SHA-256 of request body
```

The receiving service verifies the timestamp is within 300 seconds, recomputes the payload hash from the request body, reconstructs the signing input per §7.2, and verifies the signature against the public key derived from `agent_id`.

-----

## Appendix C: Reference Canonicalization Test Vector

Input JSON:

```json
{
  "version": "1.0.0",
  "name": "test-skill",
  "files": {
    "b.js": "sha256:bbb",
    "a.js": "sha256:aaa"
  },
  "description": "A test"
}
```

JCS canonical output (keys sorted, no whitespace):

```
{"description":"A test","files":{"a.js":"sha256:aaa","b.js":"sha256:bbb"},"name":"test-skill","version":"1.0.0"}
```

Implementations MUST produce byte-identical output for this input. This test vector SHOULD be included in SDK test suites.

-----

## Appendix D: Domain Separation Test Vector

To verify that an implementation constructs publisher signing inputs correctly:

Given:

- `manifest_hash` (raw bytes): `0x7d8e9f0a...` (32 bytes)
- `signed_at`: `1739140000` (decimal) = `0x00000000679f3940` (big-endian uint64)

The signing input MUST be the concatenation of:

```
UTF-8("ASI-SKILL-MANIFEST/v0.1")  →  24 bytes
0x00                               →   1 byte
manifest_hash                      →  32 bytes
signed_at                          →   8 bytes
                                   ─────────
Total                              →  65 bytes
```

To verify that an implementation constructs invocation signing inputs correctly:

Given:

- `agent_id`: `"did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"` (54 characters = 54 bytes UTF-8)
- `timestamp`: `1739140500` = `0x00000000679f3b14`
- `payload_hash` (raw bytes): `0x9f0a1b2c...` (32 bytes)

The signing input MUST be the concatenation of:

```
UTF-8("ASI-INVOKE/v0.1")          →  16 bytes
0x00                               →   1 byte
UTF-8(agent_id)                    →  54 bytes
0x00                               →   1 byte
timestamp                          →   8 bytes
payload_hash                       →  32 bytes
                                   ─────────
Total                              → 112 bytes
```

SDK test suites MUST include these test vectors to verify correct domain separation and byte layout.
