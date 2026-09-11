# OSIVault Core Charter

Version 0.1, September 8, 2026. Working draft for Vikram Sethi, Rushikesh (owner), and Prajval (reviewer).

## What OSIVault is

OSIVault is One Smarter's shared security core: a single versioned Python package that every One Smarter application imports for encryption at rest, audit trail integrity, cryptographic signing and verification, token issuance, and strong authentication. It is extracted from what already exists in Concorde and MeshKor and from the better half of the MIR portal's audit implementation, and it is the one place those primitives are maintained from now on. Concorde is the ticketing system, MeshKor is the agentic trust and identity system, and the MIR portal and the claims adjudication platform are healthcare EDI applications. OSIVault is not a product. It is the thing under all of them.

The charter exists to make one design goal hold over years rather than sprints. When the monthly audit says an algorithm, a library, a key size, or a mode should change, that change is made once inside OSIVault, OSIVault ships a new version, each application bumps its pin and runs the conformance suite, and no application code changes. If an upgrade ever requires editing application code, the interface was wrong and the fix is to the interface, not to the application. Everything else in this document serves that goal.

## The interface surface

The public API is deliberately small, because every symbol in it is a promise that has to survive algorithm changes. Applications import from these six namespaces and nothing else. Anything not listed is internal and may change without notice.

| Namespace | Public operations | Purpose |
| --- | --- | --- |
| osivault.fields | encrypt, decrypt, EncryptedTextField, EncryptedJSONField, rotate_dek, SearchHash | Field-level encryption at rest and blind-index search hashing |
| osivault.audit | append, verify_entry, verify_chain, rotate_key, checkpoint | Keyed, chained, tamper-evident audit records |
| osivault.sign | sign, verify, Envelope | Self-describing signatures over arbitrary bytes |
| osivault.tokens | issue, verify, jwks_document, rotate | Session and service tokens with published verification keys |
| osivault.auth | TOTPVerifier, WebAuthnRegistrar, WebAuthnAsserter, RecoveryCodes | Second-factor adapters for privileged and ordinary accounts |
| osivault.watch | inventory, baseline, report | Machine-readable statement of what algorithms and libraries are in use |

Every function that produces ciphertext, a checksum, a signature, or a token emits a self-describing envelope that names the algorithm, the format version, and where relevant the hash algorithm and key identifier, inside the authenticated or signed bytes. Every function that consumes one reads those identifiers first, checks them against an allowlist, and refuses anything not on it. This rule, worked out on MeshKor, is what makes the interface stable while the algorithms underneath move.

## Crypto-agility rules

These are binding on every module. First, every artifact is self-describing: algorithm and format identifiers travel inside the authenticated bytes, never alongside them where they could be swapped. Second, verification is allowlist-first: a verifier reads the identifiers, checks them against the configured allowlist, and rejects before doing any cryptographic work if they are not present. Third, algorithms are configured per class, not globally, so audit checksums, field encryption, token signing, and long-lived signatures can move on different schedules with different margins. Fourth, cutovers are hard: when an algorithm leaves the allowlist it leaves on a date, artifacts under it are re-encrypted or re-signed before that date, and there is no silent fallback in production. Development environments may fall back with a logged warning; production fails closed.
