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
- `osivault.sign`: Self-describing signatures over arbitrary bytes with post-quantum readiness (`RS256`, `Ed25519`, `ML-DSA-65`).
- `osivault.tokens`: Session and service tokens with published verification keys and JWKS endpoints.
- `osivault.auth`: Multi-factor authentication adapters (TOTP and WebAuthn/FIDO2 hardware keys).
- `osivault.watch`: Machine-readable algorithm inventory and compliance reporting.

---

## Usage Examples

### 1. Field-Level Encryption & Blind Indexing (`osivault.fields`)

```python
from osivault.fields import encrypt, decrypt, SearchHash, EncryptedTextField, EncryptedJSONField
from django.db import models

# AES-256-GCM encryption at rest (fresh 256-bit DEK per encrypt)
ciphertext = encrypt("Patient SSN: 123-45-6789", context="tenant_101")
plaintext = decrypt(ciphertext, context="tenant_101")

# Deterministic blind index search hashing
blind_index = SearchHash("123-45-6789")

# Encrypted Django Model Fields
class PatientRecord(models.Model):
    patient_ssn = EncryptedTextField()
    ssn_search = models.CharField(max_length=64, db_index=True)
    medical_history = EncryptedJSONField()
```

### 2. Self-Describing Signatures (`osivault.sign`)

```python
from osivault.sign import sign, verify, Envelope

# Produce self-describing signature envelope (RS256, Ed25519, ML-DSA-65)
envelope_str = sign(b"Attestation Payload", key=private_key, alg="RS256", key_id="key-1")

# Verify with allowlist-first algorithm check
envelope = verify(envelope_str, public_key=public_key)
print(envelope.payload, envelope.sig_alg)
```

### 3. JWT Tokens & JWKS (`osivault.tokens`)

```python
from osivault.tokens import issue, verify, jwks_document

# Issue signed JWT token
token = issue({"sub": "service_user_99", "role": "admin"}, private_key=priv_key, alg="RS256")

# Verify token & claims (exp, nbf, iss)
claims = verify(token, public_key_or_jwks=pub_key)

# Generate RFC 7517 JWKS document for /.well-known/jwks.json endpoint
jwks = jwks_document(keys=[(pub_key, "key-1", "RS256")])
```

### 4. Tamper-Evident Audit Trail (`osivault.audit`)

```python
from osivault.audit import append, verify_chain

# Append tamper-evident audit record with keyed HMAC signature
append(model_class=AuditLog, actor="admin_user", tenant="tenant_1", action="CLAIM_CONVERT")

# Verify chain integrity across all records
report = verify_chain(AuditLog)
assert report.is_intact is True
```
