# Changelog

All notable changes to OSIVault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-12

### Added
- **`osivault.fields`**: Field-level authenticated encryption at rest using AES-256-GCM with fresh 256-bit DEK per encrypt, pluggable KMS provider (`LocalKeyringProvider` and `AWSKMSProvider`), context binding (AAD), `rotate_dek`, HMAC-SHA-256 `SearchHash` blind indexing, and Django `EncryptedTextField` and `EncryptedJSONField` model fields.
- **`osivault.sign`**: Self-describing digital signature envelopes (`sig_alg`, `fmt_ver`, `hash_alg`, `key_id`) with allowlist-first verification for `Ed25519`, `RS256`, and Post-Quantum `ML-DSA-65` schemes.
- **`osivault.tokens`**: JWT token issuance and verification wrapped behind `osivault.sign`, claim validation (`exp`, `iat`, `iss`, `nbf`), RFC 7517 compliant `jwks_document` generator, and token key rotation.

## [0.1.0] - 2026-09-11

### Added
- Initial repository bootstrap and package structure.
- Implementation of `osivault.audit` merged audit module featuring HMAC-SHA-256 signatures, previous-hash chaining, self-describing envelopes, key rotation, and immutability guards.
