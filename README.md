# OSIVault

OSIVault is One Smarter's shared security core: a single versioned Python package that every One Smarter application imports for encryption at rest, tamper-evident audit trail integrity, cryptographic signing and verification, token issuance, and strong multi-factor authentication adapters. Extracted from proven primitives in Concorde and MeshKor alongside healthcare EDI security requirements, OSIVault provides a unified, crypto-agile interface designed to ensure that cryptographic algorithm upgrades occur centrally without requiring application code changes.

For full architectural details, module inventories, provenance, governance rules, and monthly audit rituals, please consult the [OSIVault Core Charter](docs/charter.md).

## Installation

```bash
pip install osivault
```

## Module Surface

- `osivault.fields`: Field-level encryption at rest (AES-256-GCM) and blind-index search hashing.
- `osivault.audit`: Keyed, chained, tamper-evident audit records with database immutability guards.
- `osivault.sign`: Self-describing signatures over arbitrary bytes with post-quantum readiness.
- `osivault.tokens`: Session and service tokens with published verification keys.
- `osivault.auth`: Multi-factor authentication adapters (TOTP and WebAuthn/FIDO2 hardware keys).
- `osivault.watch`: Machine-readable algorithm inventory and compliance reporting.
