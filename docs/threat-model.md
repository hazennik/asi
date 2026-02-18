# ASI Threat Model (v0.1)

This document defines the threat model for Agent Skill Identity (ASI) v0.1 and clarifies what ASI *does* and *does not* protect against.

ASI is an **identity + integrity primitive** for skill bundles and runtime invocation payloads. It is not a malware scanner, sandbox, reputation system, or governance layer.

---

## Goals

ASI v0.1 aims to provide:

1. **Publisher authenticity**  
   Cryptographically bind a skill bundle to a publisher identity (DID:key derived from an Ed25519 public key).

2. **Bundle integrity**  
   Detect modification to any file in the bundle after publication/signing.

3. **Runtime invocation authenticity**  
   Allow a receiving service or skill runtime to verify that a request payload was produced by a specific agent identity and has not been modified in transit.

---

## Entities

- **Publisher**: party that signs a skill bundle for distribution.
- **Skill bundle**: directory tree containing `manifest.json` and skill files, optionally `asi/signature.json`.
- **Agent**: runtime entity invoking skills/services and optionally signing invocation envelopes.
- **Verifier/Receiver**: the runtime, gateway, or service that verifies publisher signatures and/or invocation envelopes.
- **Registry/Marketplace** (optional): third-party skill distribution system (out of scope for ASI v0.1).

---

## Trust Assumptions

- Verifiers correctly implement:
  - JCS canonicalization (RFC 8785)
  - SHA-256 hashing
  - Ed25519 verification (RFC 8032)
  - DID:key parsing for Ed25519 keys
- The verifier’s local filesystem reads are not being actively subverted at verification time (ASI helps with integrity, not OS compromise).
- The verifier has a reasonably accurate clock for timestamp checks (invocation envelopes).

---

## In-Scope Adversaries

### A. Skill bundle tamperer (supply-chain attacker)
Capabilities:
- Can modify bundle files after signing
- Can inject additional files into a bundle directory
- Can replace or reorder JSON fields
- Can attempt path tricks (`../`, absolute paths)
- Can attempt symlink abuse

ASI protections:
- Signed manifest hash binds canonical `manifest.json` to publisher signature
- `manifest.files` enumerates every file except `asi/` + `manifest.json`
- Verifier rejects any undeclared file (outside `asi/`)
- Verifier rejects symlinks entirely

### B. Publisher impersonator
Capabilities:
- Publishes a lookalike skill under a similar name
- Attempts to claim a trusted publisher identity without the private key

ASI protections:
- Publisher identity is derived from public key (DID:key)
- Signature verification requires possession of private key
- Consumers can pin/trust specific publisher DIDs

### C. On-path payload modifier (MITM)
Capabilities:
- Modifies request payload bytes between agent and receiver

ASI protections:
- Invocation envelope binds payload hash + timestamp + agent_id to signature
- Receiver recomputes hash and rejects on mismatch

### D. Agent impersonator
Capabilities:
- Claims to be another agent_id but does not possess that private key

ASI protections:
- Receiver derives public key from DID:key and verifies signature
- Without private key, impersonation fails cryptographically

---

## Out of Scope (Explicitly Not Solved in v0.1)

### 1) Malicious but correctly signed skills
A publisher can sign malware or prompt-injection content. ASI does not judge intent.

Recommended complementary controls:
- sandboxing / capability gating
- static scanning (SAST)
- registry malware scanning
- runtime policy enforcement

### 2) Sybil resistance
Any attacker can generate unlimited identities (keypairs). ASI provides no scarcity.

Recommended complementary controls:
- reputation systems
- stake/fees
- external identity verification
- transparency logs / audits

### 3) Key compromise + revocation
If a private key is stolen, attackers can sign bundles or envelopes that verify successfully.

Recommended complementary controls:
- OS keychain storage
- key rotation (future ASI versions)
- out-of-band revocation lists (ecosystem policy)

### 4) Replay attacks beyond timestamp window
Invocation envelopes use timestamp skew checks. Without nonces, short-window replay is possible if transport is replayable.

Recommended complementary controls:
- nonces (future ASI versions)
- idempotency keys for sensitive APIs
- server-side replay caches

### 5) OS-level compromise
If the verifier’s machine is compromised, it can be tricked into accepting or executing anything.

---

## Security Properties (What “VERIFIED” Means)

When a skill bundle is `VERIFIED`, it means:

- The `asi/signature.json` is valid for ASI v0.1
- `publisher_id` matches the public key
- `manifest.json` canonical hash matches the signed hash
- All declared file hashes match exact bytes on disk
- No undeclared files exist outside `asi/`
- No symlinks exist in the bundle

It does **not** mean:
- the skill is safe
- the publisher is reputable
- the code is non-malicious
- the skill complies with policy

---

## Default Policy Guidance

Suggested defaults for most runtimes:

- **Block `TAMPERED` always**
- Allow `UNSIGNED` only for:
  - local development
  - built-in/first-party skills
  - explicitly whitelisted sources
- Treat `UNKNOWN_VERSION` as unverifiable and block by default, unless user explicitly opts in.

---

## Appendix: Attack Coverage Matrix

| Attack | Covered by ASI v0.1? | Notes |
|-------|------------------------|------|
| Post-signing file modification | ✅ | Hash mismatch |
| Extra file injected into bundle | ✅ | Undeclared file rule |
| Symlink exfiltration / TOCTOU | ✅ | Symlink rejection |
| Publisher identity spoofing | ✅ | Key-bound DID + signature |
| Payload tampering in transit | ✅ | Payload hash binding |
| Agent identity spoofing | ✅ | DID-derived pubkey verification |
| Malicious signed skill | ❌ | Requires other layers |
| Sybil flooding | ❌ | Out of scope |
| Private key compromise | ❌ | Needs revocation/rotation |
| Long-term replay | ❌ | Nonce extension in future |
