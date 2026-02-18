# Contributing to ASI

Thank you for contributing to Agent Skill Identity (ASI).

ASI is a minimal cryptographic primitive. Contributions should prioritize:

- Determinism
- Interoperability
- Simplicity
- Spec compliance
- Security correctness over feature expansion

---

## Development Principles

1. Do not change cryptographic primitives casually.
2. Do not introduce new algorithms without version bump.
3. Do not weaken verification requirements for convenience.
4. All changes must maintain deterministic behavior across implementations.

---

## Development Workflow

1. Fork the repository.
2. Create a feature branch.
3. Add or modify code.
4. Add or update tests.
5. Ensure `npm test` passes in `sdk/node`.
6. Submit a Pull Request.

---

## Spec Changes

If modifying `spec/ASI-v0.1.md`:

- Clearly mark the section changed.
- Update `CHANGELOG.md`.
- Add new test vectors if applicable.
- Explain security implications.

---

## Code Style

Node SDK:

- ESM modules
- No telemetry
- No remote calls
- Minimal dependencies
- Deterministic output

Python SDK (future):

- Pure Python implementation
- No network calls
- Clear separation of crypto utilities and spec logic
