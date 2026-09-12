"""
Cryptographic operations for field-level encryption and blind-index search hashing.
"""

import os
import json
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from osivault.fields.kms import LocalKeyringProvider

ALLOWED_FIELD_ALGORITHMS = {"AES-256-GCM"}
HEADER_PREFIX = "OSV1"


class FieldEncryptionError(Exception):
    """Raised when field encryption, decryption, or envelope verification fails."""
    pass


def _get_master_key(key: bytes | str | None = None, key_id: str | None = None) -> bytes:
    if key is not None:
        provider = LocalKeyringProvider(fallback_key=key)
    else:
        provider = LocalKeyringProvider()
    return provider.get_master_key(key_id=key_id)


def encrypt(plaintext: str | bytes, key: bytes | str | None = None, context: str | None = None, key_id: str = "default") -> str:
    """
    Encrypt plaintext string or bytes using AES-256-GCM envelope encryption.
    Generates a fresh 256-bit DEK per encryption.
    Embeds self-describing algorithm and format identifiers in the envelope.
    """
    if isinstance(plaintext, str):
        data_bytes = plaintext.encode("utf-8")
    elif isinstance(plaintext, bytes):
        data_bytes = plaintext
    else:
        raise TypeError(f"Plaintext must be str or bytes, got {type(plaintext)}")

    master_key = _get_master_key(key=key, key_id=key_id)

    # 1. Fresh 256-bit DEK per encryption
    dek = os.urandom(32)

    # 2. Encrypt DEK under Master Key
    master_gcm = AESGCM(master_key)
    iv_dek = os.urandom(12)
    encrypted_dek = master_gcm.encrypt(iv_dek, dek, b"DEK-ENVELOPE-V1")

    # 3. Encrypt Payload under DEK with Context AAD
    dek_gcm = AESGCM(dek)
    iv_payload = os.urandom(12)
    aad_bytes = context.encode("utf-8") if context else b""
    ciphertext = dek_gcm.encrypt(iv_payload, data_bytes, aad_bytes)

    # 4. Format self-describing envelope
    payload_dict = {
        "v": 1,
        "alg": "AES-256-GCM",
        "kid": key_id,
        "iv_dek": base64.b64encode(iv_dek).decode("ascii"),
        "edek": base64.b64encode(encrypted_dek).decode("ascii"),
        "iv": base64.b64encode(iv_payload).decode("ascii"),
        "ct": base64.b64encode(ciphertext).decode("ascii"),
    }

    json_bytes = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
    b64_payload = base64.urlsafe_b64encode(json_bytes).decode("ascii").rstrip("=")

    return f"{HEADER_PREFIX}$AES-256-GCM${key_id}${b64_payload}"


def decrypt(ciphertext_envelope: str, key: bytes | str | None = None, context: str | None = None) -> str:
    """
    Decrypt self-describing field ciphertext envelope.
    Reads algorithm header first and verifies against allowlist prior to crypto operations.
    """
    if not isinstance(ciphertext_envelope, str):
        raise FieldEncryptionError(f"Ciphertext envelope must be str, got {type(ciphertext_envelope)}")

    parts = ciphertext_envelope.split("$")
    if len(parts) < 4 or parts[0] != HEADER_PREFIX:
        raise FieldEncryptionError("Invalid field encryption envelope header format")

    alg = parts[1]
    key_id = parts[2]
    b64_payload = parts[3]

    # Crypto-Agility Rule 2: Allowlist-first algorithm verification
    if alg not in ALLOWED_FIELD_ALGORITHMS:
        raise FieldEncryptionError(
            f"Allowlist check failed: Algorithm '{alg}' is disallowed. Allowed algorithms: {ALLOWED_FIELD_ALGORITHMS}"
        )

    try:
        # Re-pad base64
        padding = "=" * (-len(b64_payload) % 4)
        json_bytes = base64.urlsafe_b64decode(b64_payload + padding)
        payload_dict = json.loads(json_bytes.decode("utf-8"))

        iv_dek = base64.b64decode(payload_dict["iv_dek"])
        encrypted_dek = base64.b64decode(payload_dict["edek"])
        iv_payload = base64.b64decode(payload_dict["iv"])
        ciphertext = base64.b64decode(payload_dict["ct"])
    except Exception as e:
        raise FieldEncryptionError(f"Corrupted ciphertext envelope JSON or base64 structure: {str(e)}") from e

    master_key = _get_master_key(key=key, key_id=key_id)

    try:
        # Decrypt DEK
        master_gcm = AESGCM(master_key)
        dek = master_gcm.decrypt(iv_dek, encrypted_dek, b"DEK-ENVELOPE-V1")

        # Decrypt Payload with AAD context
        dek_gcm = AESGCM(dek)
        aad_bytes = context.encode("utf-8") if context else b""
        plaintext_bytes = dek_gcm.decrypt(iv_payload, ciphertext, aad_bytes)

        return plaintext_bytes.decode("utf-8")
    except Exception as e:
        raise FieldEncryptionError(f"Decryption or MAC tag authentication failure: {str(e)}") from e


def rotate_dek(ciphertext_envelope: str, new_key: bytes | str | None = None, old_key: bytes | str | None = None, context: str | None = None, key_id: str = "default") -> str:
    """
    Re-encrypt payload under a new master key or fresh DEK.
    """
    plaintext = decrypt(ciphertext_envelope, key=old_key, context=context)
    return encrypt(plaintext, key=new_key, context=context, key_id=key_id)


def SearchHash(value: str | bytes, salt: str | bytes | None = None) -> str:
    """
    Generate deterministic HMAC-SHA-256 blind-index hash for querying encrypted database columns.
    """
    if isinstance(value, str):
        data_bytes = value.encode("utf-8")
    else:
        data_bytes = value

    if salt is None:
        salt = os.environ.get("OSIVAULT_SEARCH_SALT", "osivault-default-blind-index-salt-2026").encode("utf-8")
    elif isinstance(salt, str):
        salt = salt.encode("utf-8")

    return hmac.new(salt, data_bytes, hashlib.sha256).hexdigest()
