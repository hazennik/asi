# ASI Design Decisions (v0.1)

This document explains why ASI v0.1 makes the choices it does, and what tradeoffs were accepted to keep the protocol minimal, deterministic, and easy to implement across ecosystems.

---

## Why Ed25519 only (no algorithm agility in v0.1)

**Decision:** Support Ed25519 exclusively.

**Why:**
- Widely supported across languages and platforms.
- Compact keys (32 bytes) and signatures (64 bytes).
- Deterministic signing (RFC 8032) avoids nonce pitfalls.
- Eliminates downgrade/negotiation complexity.

**Tradeoff:**
- No flexibility for organizations that require alternate curves or hardware-backed algorithms.
- Deferred to a future version with explicit negotiation rules.

---

## Why DID:key as the identity format

**Decision:** Identity is `did:key` derived from the public key.

**Why:**
- No resolver, registry, or network calls required.
- Self-describing key type via multicodec.
- Already standardized and has ecosystem tooling.

**Tradeoff:**
- Identity is not human-friendly by default.
- Names, domains, and discovery are intentionally out of scope.

---

## Why JCS (RFC 8785) for canonical JSON

**Decision:** Canonicalize JSON using JCS before hashing/signing.

**Why:**
- Deterministic across implementations.
- Avoids the classic “same JSON, different bytes” problem.
- Standardized by IETF (reduces ambiguity and spec drift).

**Tradeoff:**
- Requires a correct JCS implementation/library.
- JSON number representation pitfalls exist if hand-rolled.

---

## Why sign the manifest hash (raw bytes) instead of the manifest JSON directly

**Decision:** The signing input includes the **raw 32-byte SHA-256 digest** of `JCS(manifest.json)`.

**Why:**
- Keeps signing input fixed-size and consistent.
- Easier to test and reason about.
- Prevents accidental signing of hex strings or non-canonical JSON.

**Tradeoff:**
- Requires careful separation of “display hash string” vs “raw digest bytes”.
- Implementations must be explicit.

---

## Why the manifest lists every file and verifiers reject undeclared files

**Decision:** `manifest.json` must include every file (except `asi/` and itself), and verifiers must fail on any undeclared file.

**Why:**
- Prevents “hidden payload” injection where an attacker adds an extra script/binary after signing.
- Avoids ambiguity about what the bundle contains.

**Tradeoff:**
- Adds friction for publishers (must update manifest for every new file).
- Requires deterministic directory traversal rules in tooling.

---

## Why `manifest.json` does not hash itself

**Decision:** `manifest.json` MUST NOT include an entry for itself.

**Why:**
- Self-referential hashing complicates creation and verification.
- The manifest’s integrity is already covered by the publisher signature.

**Tradeoff:**
- The manifest is only integrity-protected when a signature exists.
- Unsigned bundles rely on policy, not cryptography.

---

## Why symlinks are rejected entirely

**Decision:** Bundles containing symlinks must be rejected.

**Why:**
- Prevents symlink exfiltration (linking to secrets outside the bundle).
- Prevents TOCTOU substitution where a file becomes a symlink between signing and verification.
- Keeps hashing rules simple and portable.

**Tradeoff:**
- Some legitimate packaging workflows use symlinks.
- Those workflows must be adapted for ASI-signed bundles.

---

## Why file hashing is raw bytes (no newline normalization)

**Decision:** Hash file content exactly as bytes on disk.

**Why:**
- Normalization creates cross-platform ambiguity and subtle mismatches.
- Raw bytes is the simplest deterministic definition.

**Tradeoff:**
- A CRLF↔LF change will break verification.
- Publishers should build on a consistent environment, or treat this as expected behavior.

---

## Why timestamps exist in signatures and envelopes

**Publisher signature (`signed_at`):**
- Included for auditing and debugging.
- Helps ecosystem tooling (“signed last week”, “signed before incident”, etc.).
- Not meant as replay protection.

**Invocation envelope (`timestamp`):**
- Enables basic replay mitigation with a skew window.
- Avoids nonce infrastructure in v0.1.

**Tradeoff:**
- Requires reasonably correct clocks.
- Strong replay protection deferred (nonces in future versions).

---

## Why the invocation envelope signs derived bytes (not the envelope JSON)

**Decision:** The signature covers a domain-separated byte sequence derived from:
- agent_id
- timestamp
- payload hash

**Why:**
- Prevents canonicalization disputes of the envelope itself.
- The envelope is a transport wrapper; integrity comes from the signature, not JSON formatting.
- Works across non-JSON transports.

**Tradeoff:**
- Implementers must be careful to match byte layout exactly.
- Test vectors are required to prevent subtle drift.

---

## Why `asi_version` is strict

**Decision:** Reject signatures/envelopes with unknown `asi_version`.

**Why:**
- Prevents “verifying the wrong thing” when signing inputs change in later versions.
- Eliminates unsafe “best-effort” verification.

**Tradeoff:**
- Older verifiers cannot validate future versions.
- This is intentional: unknown != invalid, but unknown != verified.

---

## Why ASI is intentionally not a trust system

**Decision:** ASI v0.1 provides identity and integrity only.

**Why:**
- Trust layers (reputation, governance, registry policy) require coordination and politics.
- Cryptographic primitives can be adopted immediately, independently.

**Tradeoff:**
- Signed does not mean safe.
- Ecosystems must still sandbox, scan, and apply capability/policy controls.

---

## Versioning philosophy

ASI versions are **protocol versions**, not package versions:
- v0.1 defines exact byte layouts and required primitives.
- Future versions may extend envelopes or add optional artifacts under `asi/`.
- Backward-compatible behavior: ignore unknown fields, ignore unknown files under `asi/`.

---

## Summary

ASI v0.1 optimizes for:
- deterministic verification,
- minimal implementation surface,
- zero network dependencies,
- portability across frameworks.

Everything else builds on top.
