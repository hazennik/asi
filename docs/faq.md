# ASI FAQ (v0.1)

Frequently asked questions about Agent Skill Identity (ASI) v0.1.

---

## What is ASI in one sentence?

ASI is a minimal cryptographic identity and integrity layer for agent skill bundles and runtime invocations.

---

## Does ASI make skills safe?

No.

ASI guarantees:
- The bundle has not been modified since signing.
- The publisher identity matches the signing key.
- The invocation payload was signed by the claimed agent identity.

ASI does **not** guarantee:
- The code is safe.
- The publisher is trustworthy.
- The skill complies with policy.
- The skill is free of prompt injection.

ASI is an identity + integrity primitive, not a malware scanner or sandbox.

---

## Why not use TLS instead?

TLS protects the transport channel between two endpoints.

ASI protects:
- The artifact (skill bundle) itself.
- The identity of the publisher.
- The identity of the invoking agent.
- The integrity of the request payload.

They solve different layers of the problem.

---

## Why not use JWT?

JWT:
- Requires algorithm negotiation.
- Often signs JSON that is not canonicalized.
- Has a history of implementation pitfalls (e.g., `alg=none`, algorithm confusion).

ASI:
- Fixes the algorithm (Ed25519).
- Uses deterministic canonicalization (JCS).
- Uses explicit domain separation.
- Avoids algorithm negotiation in v0.1.

---

## Why not use blockchain for identity?

Blockchain identity systems (e.g., NFT-based identity registries) are compatible with ASI.

ASI deliberately:
- Requires no chain.
- Requires no token.
- Requires no registry.
- Requires no network access.

You can layer blockchain identity on top of ASI, but ASI itself is chain-agnostic.

---

## What happens if a private key is stolen?

If a publisher’s private key is compromised:
- Attackers can sign malicious bundles that will verify as `VERIFIED`.

ASI v0.1 does not define revocation.

Mitigation strategies:
- Use OS keychains for private key storage.
- Rotate keys periodically.
- Maintain out-of-band revocation lists.
- Future ASI versions may define key rotation and revocation primitives.

---

## Why reject symlinks?

Symlinks enable:

- Exfiltration attacks (e.g., linking to `~/.ssh/id_ed25519`).
- TOCTOU attacks (replace file with symlink after signing).

Rejecting symlinks simplifies security guarantees and removes an entire class of attack.

---

## Why fail on undeclared files?

If a signed bundle allows undeclared files:
- An attacker could add a malicious script after signing.
- The bundle would still appear “verified”.

Requiring full file enumeration ensures the signed manifest defines the complete execution surface.

---

## What does `UNSIGNED` mean?

The bundle has no `asi/signature.json`.

This is not a cryptographic failure — it is a policy decision.

Runtimes may:
- Allow unsigned skills (development mode).
- Block unsigned skills (production policy).

---

## What does `TAMPERED` mean?

Cryptographic verification failed.

Examples:
- `manifest_hash` mismatch.
- Signature invalid.
- File hash mismatch.
- Undeclared file present.
- Symlink detected.

This is a security event, not a policy decision.

---

## What does `UNKNOWN_VERSION` mean?

The bundle or envelope specifies an `asi_version` that this verifier does not support.

It may be valid under a newer protocol version.

`UNKNOWN_VERSION` must never be treated as `VERIFIED`.

---

## Why use domain separation strings?

Domain separation prevents cross-context replay.

Without it:
- A publisher signature could potentially be reused as an invocation signature.
- Or vice versa.

By binding signatures to:
- `"ASI-SKILL-MANIFEST/v0.1"`
- `"ASI-INVOKE/v0.1"`

the protocol ensures signatures are context-specific.

---

## Does ASI support multi-signature bundles?

Not in v0.1.

Future versions may support:
- Multiple publisher signatures.
- Auditor co-signatures.
- CI/CD delegated signatures.

v0.1 intentionally defines the minimal viable primitive.

---

## Can ASI work outside OpenClaw?

Yes.

ASI is framework-agnostic and can be integrated into:
- Any agent runtime
- Any skill/plugin system
- Any API gateway
- Any distributed agent ecosystem

It has no dependency on OpenClaw specifically.

---

## Why is ASI minimal?

Because primitives spread.

Complex governance systems do not get adopted quickly.
Cryptographic primitives with zero coordination overhead do.

ASI defines:
- Identity
- Integrity
- Verification rules

Everything else is ecosystem policy.
