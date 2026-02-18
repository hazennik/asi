# Bundle Example Skill

This is a minimal, non-malicious example skill bundle used as an ASI test vector.

It exists only to validate:

- Manifest file inventory rules
- SHA-256 file hashing (raw bytes)
- Undeclared file injection detection
- Publisher signature envelope structure (`asi/signature.json`)

No network calls. No external dependencies. No runtime execution assumptions.
