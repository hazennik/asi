# Agent Skill Identity (ASI) v0.1 — Reference SDK

Minimal, framework-agnostic cryptographic identity primitives for agent skill ecosystems.

This repo contains a **TypeScript/JavaScript (Node)** reference implementation and tests for:

- Skill publisher authenticity (bundle signing + verification)
- Skill bundle integrity (manifest file inventory + hashes)
- Runtime agent identity verification (invocation envelopes)

## Status
Draft v0.1 (February 2026)

## Guarantees
- MIT licensed
- No telemetry
- No remote calls
- All operations are local

## Crypto + canonicalization
- Ed25519 (RFC 8032) via `@noble/ed25519`
- SHA-256 via `@noble/hashes`
- JCS (RFC 8785) via `canonicalize`

## Quick start
```bash
npm install
npm test