asi/
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── package.json
├── package-lock.json
├── .gitignore
│
├── spec/
│   ├── ASI-v0.1.md
│   ├── CHANGELOG.md
│   └── roadmap.md
│
├── sdk/
│   ├── node/
│   │   ├── package.json
│   │   ├── src/
│   │   │   └── asi.mjs
│   │   ├── test/
│   │   │   └── test.mjs
│   │   └── README.md
│   │
│   └── python/              # optional but recommended early
│       ├── pyproject.toml
│       ├── asi/
│       │   ├── __init__.py
│       │   ├── core.py
│       │   └── utils.py
│       └── tests/
│           └── test_asi.py
│
├── test-vectors/
│   ├── canonicalization.json
│   ├── publisher-signing-input.json
│   ├── invocation-signing-input.json
│   └── bundle-example/
│       ├── manifest.json
│       ├── SKILL.md
│       ├── src/
│       │   └── example.js
│       └── asi/
│           └── signature.json
│
├── examples/
│   ├── minimal-skill/
│   │   ├── manifest.json
│   │   ├── SKILL.md
│   │   └── asi/
│   │       └── signature.json
│   │
│   └── invocation/
│       └── example-envelope.json
│
└── docs/
    ├── threat-model.md
    ├── design-decisions.md
    └── faq.md