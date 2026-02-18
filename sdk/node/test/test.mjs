import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  ASI_VERSION,
  DOMAIN_TAG_PUBLISHER,
  DOMAIN_TAG_INVOKE,
  NULL_SEPARATOR,
  DEFAULT_TIMESTAMP_SKEW,
  generateKeypair,
  deriveIdentity,
  publicKeyFromIdentity,
  sign,
  verify,
  canonicalizeJson,
  sha256,
  sha256Display,
  buildPublisherSigningInput,
  buildInvocationSigningInput,
  hashBundle,
  createSignedManifest,
  verifySkillBundle,
  createInvocationEnvelope,
  verifyInvocationEnvelope,
  base64urlEncode,
  base64urlDecode,
  _internal,
} from "../src/asi.mjs";

// Helpers
const enc = new TextEncoder();

function u64beHex(n) {
  const u8 = new Uint8Array(8);
  const dv = new DataView(u8.buffer);
  const hi = Math.floor(n / 0x100000000);
  const lo = n >>> 0;
  dv.setUint32(0, hi);
  dv.setUint32(4, lo);
  return Buffer.from(u8).toString("hex");
}

function mkTmpDir() {
  return mkdtempSync(join(tmpdir(), "asi-test-"));
}

function writeJson(path, obj) {
  writeFileSync(path, JSON.stringify(obj, null, 2), "utf-8");
}

function canonicalizeStringForTest(obj) {
  // canonicalizeJson returns bytes; tests sometimes want string
  return new TextDecoder().decode(canonicalizeJson(obj));
}

// ─────────────────────────────────────────────────────────────────────────────
// Appendix C — Canonicalization Test Vector
// ─────────────────────────────────────────────────────────────────────────────

test("JCS canonicalization matches Appendix C test vector", () => {
  const input = {
    version: "1.0.0",
    name: "test-skill",
    files: { "b.js": "sha256:bbb", "a.js": "sha256:aaa" },
    description: "A test",
  };

  const expected =
    '{"description":"A test","files":{"a.js":"sha256:aaa","b.js":"sha256:bbb"},"name":"test-skill","version":"1.0.0"}';

  const out = canonicalizeStringForTest(input);
  assert.equal(out, expected);
});

// ─────────────────────────────────────────────────────────────────────────────
// DID:key roundtrip
// ─────────────────────────────────────────────────────────────────────────────

test("DID:key derive/extract roundtrip", () => {
  const { publicKey } = generateKeypair();
  const id = deriveIdentity(publicKey);
  const extracted = publicKeyFromIdentity(id);
  assert.deepEqual(extracted, publicKey);
  const id2 = deriveIdentity(extracted);
  assert.equal(id2, id);
});

// ─────────────────────────────────────────────────────────────────────────────
// Appendix D — Domain separation test vectors (structure/length/layout)
// ─────────────────────────────────────────────────────────────────────────────

test("Publisher signing input layout matches Appendix D", () => {
  // Use fixed bytes for hash and timestamp
  const manifestHash = new Uint8Array(32).fill(0x7d);
  const signedAt = 1739140000;

  const input = buildPublisherSigningInput(manifestHash, signedAt);

  const domainBytes = enc.encode(DOMAIN_TAG_PUBLISHER);
  assert.equal(input.length, domainBytes.length + 1 + 32 + 8);

  // domain tag
  assert.deepEqual(input.slice(0, domainBytes.length), domainBytes);
  // null separator
  assert.equal(input[domainBytes.length], 0x00);
  // manifest hash
  assert.deepEqual(
    input.slice(domainBytes.length + 1, domainBytes.length + 1 + 32),
    manifestHash
  );
  // uint64 BE
  const tailHex = Buffer.from(input.slice(input.length - 8)).toString("hex");
  assert.equal(tailHex, u64beHex(signedAt));
});

test("Invocation signing input layout matches Appendix D", () => {
  const agentId =
    "did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
  const timestamp = 1739140500;
  const payloadHash = new Uint8Array(32).fill(0x9f);

  const input = buildInvocationSigningInput(agentId, timestamp, payloadHash);

  const domainBytes = enc.encode(DOMAIN_TAG_INVOKE);
  const agentBytes = enc.encode(agentId);

  assert.equal(input.length, domainBytes.length + 1 + agentBytes.length + 1 + 8 + 32);

  let off = 0;
  assert.deepEqual(input.slice(off, off + domainBytes.length), domainBytes);
  off += domainBytes.length;
  assert.equal(input[off], 0x00);
  off += 1;

  assert.deepEqual(input.slice(off, off + agentBytes.length), agentBytes);
  off += agentBytes.length;
  assert.equal(input[off], 0x00);
  off += 1;

  const tsHex = Buffer.from(input.slice(off, off + 8)).toString("hex");
  assert.equal(tsHex, u64beHex(timestamp));
  off += 8;

  assert.deepEqual(input.slice(off, off + 32), payloadHash);
});

// ─────────────────────────────────────────────────────────────────────────────
// Deterministic signature for same input
// ─────────────────────────────────────────────────────────────────────────────

test("Ed25519 signatures are deterministic for same input + key", async () => {
  const { privateKeySeed, publicKey } = generateKeypair();
  const msg = enc.encode("hello");
  const s1 = await sign(msg, privateKeySeed);
  const s2 = await sign(msg, privateKeySeed);
  assert.deepEqual(s1, s2);
  assert.equal(await verify(msg, s1, publicKey), true);
});

// ─────────────────────────────────────────────────────────────────────────────
// Cross-context replay protection (publisher sig != invocation sig)
// ─────────────────────────────────────────────────────────────────────────────

test("Domain separation prevents cross-context replay", async () => {
  const { privateKeySeed, publicKey } = generateKeypair();
  const agentId = deriveIdentity(publicKey);

  const mh = new Uint8Array(32).fill(0xaa);
  const signedAt = 1739140000;
  const pubInput = buildPublisherSigningInput(mh, signedAt);
  const pubSig = await sign(pubInput, privateKeySeed);

  // Try to verify publisher signature against invocation input
  const ph = new Uint8Array(32).fill(0xbb);
  const invInput = buildInvocationSigningInput(agentId, signedAt, ph);

  const ok = await verify(invInput, pubSig, publicKey);
  assert.equal(ok, false);
});

// ─────────────────────────────────────────────────────────────────────────────
// Bundle lifecycle: sign + verify
// ─────────────────────────────────────────────────────────────────────────────

test("Skill bundle sign + verify roundtrip -> VERIFIED", () => {
  const dir = mkTmpDir();
  try {
    // bundle structure
    mkdirSync(join(dir, "asi"), { recursive: true });
    mkdirSync(join(dir, "src"), { recursive: true });

    writeFileSync(join(dir, "SKILL.md"), "# Skill\n", "utf-8");
    writeFileSync(join(dir, "src", "example.js"), "console.log('ok')\n", "utf-8");

    const manifestBase = {
      name: "example-skill",
      version: "1.0.0",
      description: "Example",
    };

    const { privateKeySeed } = generateKeypair();

    const { manifest, signature } = createSignedManifest(manifestBase, dir, privateKeySeed);

    // write manifest.json and signature.json to disk
    writeJson(join(dir, "manifest.json"), manifest);
    writeJson(join(dir, "asi", "signature.json"), signature);

    const res = verifySkillBundle(dir);
    assert.equal(res.status, "VERIFIED");
    assert.equal(res.publisherId, signature.publisher_id);
    assert.deepEqual(res.errors, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Tamper detection: file content modified -> TAMPERED", () => {
  const dir = mkTmpDir();
  try {
    mkdirSync(join(dir, "asi"), { recursive: true });
    mkdirSync(join(dir, "src"), { recursive: true });

    writeFileSync(join(dir, "SKILL.md"), "# Skill\n", "utf-8");
    writeFileSync(join(dir, "src", "example.js"), "console.log('ok')\n", "utf-8");

    const manifestBase = { name: "example-skill", version: "1.0.0", description: "Example" };
    const { privateKeySeed } = generateKeypair();

    const { manifest, signature } = createSignedManifest(manifestBase, dir, privateKeySeed);
    writeJson(join(dir, "manifest.json"), manifest);
    writeJson(join(dir, "asi", "signature.json"), signature);

    // Modify a declared file after signing
    writeFileSync(join(dir, "src", "example.js"), "console.log('pwned')\n", "utf-8");

    const res = verifySkillBundle(dir);
    assert.equal(res.status, "TAMPERED");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Undeclared file injection is blocked -> TAMPERED", () => {
  const dir = mkTmpDir();
  try {
    mkdirSync(join(dir, "asi"), { recursive: true });
    mkdirSync(join(dir, "src"), { recursive: true });

    writeFileSync(join(dir, "SKILL.md"), "# Skill\n", "utf-8");
    writeFileSync(join(dir, "src", "example.js"), "console.log('ok')\n", "utf-8");

    const manifestBase = { name: "example-skill", version: "1.0.0", description: "Example" };
    const { privateKeySeed } = generateKeypair();

    const { manifest, signature } = createSignedManifest(manifestBase, dir, privateKeySeed);
    writeJson(join(dir, "manifest.json"), manifest);
    writeJson(join(dir, "asi", "signature.json"), signature);

    // Add a new file (not in manifest.files)
    writeFileSync(join(dir, "src", "evil.js"), "console.log('evil')\n", "utf-8");

    const res = verifySkillBundle(dir);
    assert.equal(res.status, "TAMPERED");
    assert.ok(res.errors.some((e) => e.includes("Undeclared file")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Extra files under asi/ are ignored (forward compat) -> VERIFIED", () => {
  const dir = mkTmpDir();
  try {
    mkdirSync(join(dir, "asi"), { recursive: true });
    mkdirSync(join(dir, "src"), { recursive: true });

    writeFileSync(join(dir, "SKILL.md"), "# Skill\n", "utf-8");
    writeFileSync(join(dir, "src", "example.js"), "console.log('ok')\n", "utf-8");

    const manifestBase = { name: "example-skill", version: "1.0.0", description: "Example" };
    const { privateKeySeed } = generateKeypair();

    const { manifest, signature } = createSignedManifest(manifestBase, dir, privateKeySeed);
    writeJson(join(dir, "manifest.json"), manifest);
    writeJson(join(dir, "asi", "signature.json"), signature);

    // Add extra file under asi/
    writeFileSync(join(dir, "asi", "notes.txt"), "future metadata", "utf-8");

    const res = verifySkillBundle(dir);
    assert.equal(res.status, "VERIFIED");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Symlinks are rejected -> TAMPERED", () => {
  const dir = mkTmpDir();
  try {
    mkdirSync(join(dir, "asi"), { recursive: true });
    mkdirSync(join(dir, "src"), { recursive: true });

    writeFileSync(join(dir, "SKILL.md"), "# Skill\n", "utf-8");
    writeFileSync(join(dir, "src", "example.js"), "console.log('ok')\n", "utf-8");

    const manifestBase = { name: "example-skill", version: "1.0.0", description: "Example" };
    const { privateKeySeed } = generateKeypair();
    const { manifest, signature } = createSignedManifest(manifestBase, dir, privateKeySeed);

    writeJson(join(dir, "manifest.json"), manifest);
    writeJson(join(dir, "asi", "signature.json"), signature);

    // Add a symlink anywhere in the bundle tree
    symlinkSync(join(dir, "SKILL.md"), join(dir, "src", "link.md"));

    const res = verifySkillBundle(dir);
    assert.equal(res.status, "TAMPERED");
    assert.ok(res.errors.some((e) => e.toLowerCase().includes("symlink")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Status codes: UNSIGNED / UNKNOWN_VERSION
// ─────────────────────────────────────────────────────────────────────────────

test("Missing asi/signature.json -> UNSIGNED", () => {
  const dir = mkTmpDir();
  try {
    mkdirSync(join(dir, "src"), { recursive: true });
    writeFileSync(join(dir, "SKILL.md"), "# Skill\n", "utf-8");
    writeFileSync(join(dir, "src", "example.js"), "console.log('ok')\n", "utf-8");
    writeJson(join(dir, "manifest.json"), {
      name: "x",
      version: "1.0.0",
      description: "x",
      files: {
        "SKILL.md": "sha256:".padEnd(71, "0"),
      },
    });

    const res = verifySkillBundle(dir);
    assert.equal(res.status, "UNSIGNED");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("Unrecognized asi_version -> UNKNOWN_VERSION", () => {
  const dir = mkTmpDir();
  try {
    mkdirSync(join(dir, "asi"), { recursive: true });
    writeJson(join(dir, "manifest.json"), { name: "x", version: "1.0.0", files: {} });
    writeJson(join(dir, "asi", "signature.json"), {
      asi_version: "9.9",
      publisher_id: "did:key:z6Mk...",
      public_key: "AA",
      algorithm: "ed25519",
      manifest_hash: "sha256:" + "00".repeat(32),
      signed_at: 0,
      signature: "AA",
    });

    const res = verifySkillBundle(dir);
    assert.equal(res.status, "UNKNOWN_VERSION");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("signature algorithm must be ed25519", () => {
  const dir = mkTmpDir();
  try {
    mkdirSync(join(dir, "asi"), { recursive: true });
    mkdirSync(join(dir, "src"), { recursive: true });

    writeFileSync(join(dir, "SKILL.md"), "# Skill\n", "utf-8");
    writeFileSync(join(dir, "src", "example.js"), "console.log('ok')\n", "utf-8");

    const { privateKeySeed } = generateKeypair();
    const { manifest, signature } = createSignedManifest(
      { name: "example-skill", version: "1.0.0", description: "Example" },
      dir,
      privateKeySeed
    );

    signature.algorithm = "rsa";

    writeJson(join(dir, "manifest.json"), manifest);
    writeJson(join(dir, "asi", "signature.json"), signature);

    const res = verifySkillBundle(dir);
    assert.equal(res.status, "TAMPERED");
    assert.ok(res.errors.some((e) => e.toLowerCase().includes("algorithm")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("manifest path traversal is rejected", async () => {
  const dir = mkTmpDir();
  try {
    mkdirSync(join(dir, "asi"), { recursive: true });
    mkdirSync(join(dir, "src"), { recursive: true });

    writeFileSync(join(dir, "SKILL.md"), "# Skill\n", "utf-8");
    writeFileSync(join(dir, "src", "example.js"), "console.log('ok')\n", "utf-8");

    const { privateKeySeed } = generateKeypair();
    const { manifest, signature } = createSignedManifest(
      { name: "example-skill", version: "1.0.0", description: "Example" },
      dir,
      privateKeySeed
    );

    // Keep signature cryptographically valid while injecting invalid declared path.
    manifest.files["../outside.txt"] = manifest.files["src/example.js"];

    const canonical = canonicalizeJson(manifest);
    const digest = sha256(canonical);
    signature.manifest_hash = sha256Display(digest);
    const signingInput = buildPublisherSigningInput(digest, signature.signed_at);
    signature.signature = base64urlEncode(await sign(signingInput, privateKeySeed));

    writeJson(join(dir, "manifest.json"), manifest);
    writeJson(join(dir, "asi", "signature.json"), signature);

    const res = verifySkillBundle(dir);
    assert.equal(res.status, "TAMPERED");
    assert.ok(res.errors.some((e) => e.toLowerCase().includes("invalid manifest file path")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Invocation envelopes
// ─────────────────────────────────────────────────────────────────────────────

test("Invocation envelope: JSON canonicalization makes equivalent JSON hash same", () => {
  const { privateKeySeed } = generateKeypair();

  const a = enc.encode(JSON.stringify({ b: 2, a: 1 }));
  const b = enc.encode('{"a":1,"b":2}');

  const envA = createInvocationEnvelope(a, "application/json", privateKeySeed);
  const envB = createInvocationEnvelope(b, "application/json", privateKeySeed);

  // timestamps differ; compare payload_hash only
  assert.equal(envA.payload_hash, envB.payload_hash);
});

test("Invocation envelope verifies end-to-end (JSON)", () => {
  const { privateKeySeed } = generateKeypair();
  const body = enc.encode(JSON.stringify({ hello: "world", n: 1 }));
  const env = createInvocationEnvelope(body, "application/json", privateKeySeed);

  const res = verifyInvocationEnvelope(env, body, "application/json");
  assert.equal(res.valid, true);
  assert.equal(res.agentId, env.agent_id);
});

test("Invocation envelope verifies end-to-end (raw bytes, no content-type)", () => {
  const { privateKeySeed } = generateKeypair();
  const body = enc.encode("raw-payload");
  const env = createInvocationEnvelope(body, null, privateKeySeed);

  const res = verifyInvocationEnvelope(env, body, null);
  assert.equal(res.valid, true);
});

test("Invocation envelope timestamp skew enforced", () => {
  const { privateKeySeed } = generateKeypair();
  const body = enc.encode("raw-payload");
  const env = createInvocationEnvelope(body, null, privateKeySeed);

  // Force timestamp far in the past
  env.timestamp = env.timestamp - (DEFAULT_TIMESTAMP_SKEW + 300);

  const res = verifyInvocationEnvelope(env, body, null);
  assert.equal(res.valid, false);
  assert.ok(res.errors.some((e) => e.toLowerCase().includes("timestamp drift")));
});

test("Invocation envelope timestamp skew can be relaxed", async () => {
  const { privateKeySeed } = generateKeypair();
  const body = enc.encode("raw-payload");
  const env = createInvocationEnvelope(body, null, privateKeySeed);

  // Simulate drift by mutating timestamp, then re-sign envelope so signature remains valid.
  env.timestamp = env.timestamp - 600;
  const payloadHashBytes = sha256(body);
  const signingInput = buildInvocationSigningInput(env.agent_id, env.timestamp, payloadHashBytes);
  env.signature = base64urlEncode(await sign(signingInput, privateKeySeed));

  const strict = verifyInvocationEnvelope(env, body, null);
  assert.equal(strict.valid, false);
  assert.ok(strict.errors.some((e) => e.toLowerCase().includes("timestamp drift")));

  const res = verifyInvocationEnvelope(env, body, null, { maxSkew: 700 });
  assert.equal(res.valid, true);
});
