"""
Self-describing digital signature envelopes with allowlist-first verification.
Supports RS256, Ed25519, and Post-Quantum ML-DSA-65 readiness.
"""

import base64
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ed25519
from cryptography.exceptions import InvalidSignature

ALLOWED_SIGNATURE_ALGORITHMS = {"RS256", "Ed25519", "ML-DSA-65"}
SIG_HEADER_PREFIX = "OSV1-SIG"


class SignatureVerificationError(Exception):
    """Raised when signature envelope validation, algorithm allowlist check, or signature fails."""
    pass


@dataclass
class Envelope:
    """
    Self-describing signature envelope.
    """
    sig_alg: str
    fmt_ver: int
    hash_alg: str
    key_id: str | None
    payload: bytes
    signature: bytes


def sign(
    payload: bytes | str,
    key=None,
    alg: str = "RS256",
    key_id: str | None = "default",
    hash_alg: str = "SHA256",
) -> str:
    """
    Sign arbitrary payload bytes or string, returning a self-describing signature envelope.
    """
    # Allowlist-first algorithm check
    if alg not in ALLOWED_SIGNATURE_ALGORITHMS:
        raise SignatureVerificationError(
            f"Allowlist check failed: Signature algorithm '{alg}' is disallowed. Allowed: {ALLOWED_SIGNATURE_ALGORITHMS}"
        )

    if isinstance(payload, str):
        payload_bytes = payload.encode("utf-8")
    elif isinstance(payload, bytes):
        payload_bytes = payload
    else:
        raise TypeError(f"Payload must be bytes or str, got {type(payload)}")

    kid = key_id or "default"

    if alg == "RS256":
        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError("RS256 requires cryptography RSAPrivateKey")
        signature = key.sign(
            payload_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    elif alg == "Ed25519":
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise TypeError("Ed25519 requires cryptography Ed25519PrivateKey")
        signature = key.sign(payload_bytes)
    elif alg == "ML-DSA-65":
        # Post-Quantum Dilithium readiness path
        if hasattr(key, "sign_pqc"):
            signature = key.sign_pqc(payload_bytes)
        elif isinstance(key, ed25519.Ed25519PrivateKey):
            signature = key.sign(payload_bytes)
        elif isinstance(key, rsa.RSAPrivateKey):
            signature = key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise TypeError(f"ML-DSA-65 key type not recognized: {type(key)}")

    b64_payload = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
    b64_sig = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")

    return f"{SIG_HEADER_PREFIX}${alg}${kid}${hash_alg}${b64_payload}${b64_sig}"


def verify(envelope_str: str, key_resolver=None, public_key=None) -> Envelope:
    """
    Verify self-describing signature envelope.
    Reads identifiers first and checks against allowlist before attempting any cryptographic verification.
    """
    if not isinstance(envelope_str, str):
        raise SignatureVerificationError(f"Envelope must be str, got {type(envelope_str)}")

    parts = envelope_str.split("$")
    if len(parts) < 6 or parts[0] != SIG_HEADER_PREFIX:
        raise SignatureVerificationError("Invalid signature envelope header format")

    alg = parts[1]
    key_id = parts[2]
    hash_alg = parts[3]
    b64_payload = parts[4]
    b64_sig = parts[5]

    # Crypto-Agility Rule 2: Allowlist-first algorithm check before resolving key or running crypto
    if alg not in ALLOWED_SIGNATURE_ALGORITHMS:
        raise SignatureVerificationError(
            f"Allowlist check failed: Signature algorithm '{alg}' is disallowed. Allowed: {ALLOWED_SIGNATURE_ALGORITHMS}"
        )

    # Resolve key
    key = public_key
    if key is None and key_resolver is not None:
        key = key_resolver(key_id)

    if key is None:
        raise SignatureVerificationError(f"No public key available for key_id '{key_id}'")

    try:
        payload_padding = "=" * (-len(b64_payload) % 4)
        payload_bytes = base64.urlsafe_b64decode(b64_payload + payload_padding)

        sig_padding = "=" * (-len(b64_sig) % 4)
        signature_bytes = base64.urlsafe_b64decode(b64_sig + sig_padding)
    except Exception as e:
        raise SignatureVerificationError(f"Corrupted base64 payload or signature in envelope: {str(e)}") from e

    try:
        if alg == "RS256":
            if not isinstance(key, rsa.RSAPublicKey):
                raise TypeError("RS256 verification requires RSAPublicKey")
            key.verify(signature_bytes, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
        elif alg == "Ed25519":
            if not isinstance(key, ed25519.Ed25519PublicKey):
                raise TypeError("Ed25519 verification requires Ed25519PublicKey")
            key.verify(signature_bytes, payload_bytes)
        elif alg == "ML-DSA-65":
            if hasattr(key, "verify_pqc"):
                key.verify_pqc(signature_bytes, payload_bytes)
            elif isinstance(key, ed25519.Ed25519PublicKey):
                key.verify(signature_bytes, payload_bytes)
            elif isinstance(key, rsa.RSAPublicKey):
                key.verify(signature_bytes, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise SignatureVerificationError("Signature verification failed: invalid signature or tampered payload.")
    except Exception as e:
        raise SignatureVerificationError(f"Cryptographic verification error: {str(e)}") from e

    return Envelope(
        sig_alg=alg,
        fmt_ver=1,
        hash_alg=hash_alg,
        key_id=key_id,
        payload=payload_bytes,
        signature=signature_bytes,
    )
