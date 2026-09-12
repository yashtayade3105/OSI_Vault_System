"""
JWT session and service token issuance, verification, and JWKS endpoint generator.
Wrapped behind osivault.sign for crypto-agility and allowlist-first verification.
"""

import time
import json
import uuid
import base64
from typing import Any
from cryptography.hazmat.primitives.asymmetric import rsa
from osivault.sign import sign, verify as sign_verify, Envelope, SignatureVerificationError, ALLOWED_SIGNATURE_ALGORITHMS


class TokenError(Exception):
    """Raised when token issuance, verification, or JWKS parsing fails."""
    pass


def _int_to_base64url(val: int) -> str:
    """Helper to convert positive integer to base64url string (RFC 7518)."""
    b = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _base64url_to_int(b64_str: str) -> int:
    """Helper to convert base64url string back to integer (RFC 7518)."""
    padding = "=" * (-len(b64_str) % 4)
    b = base64.urlsafe_b64decode(b64_str + padding)
    return int.from_bytes(b, byteorder="big")


def jwks_document(keys: list[tuple[Any, str, str]]) -> dict[str, list[dict[str, str]]]:
    """
    Generate an RFC 7517 compliant JWKS JSON dictionary from a list of (public_key, key_id, alg) tuples.
    """
    jwks_keys = []
    for entry in keys:
        pub_key, kid, alg = entry
        if isinstance(pub_key, rsa.RSAPublicKey):
            numbers = pub_key.public_numbers()
            n_b64 = _int_to_base64url(numbers.n)
            e_b64 = _int_to_base64url(numbers.e)
            jwks_keys.append({
                "kty": "RSA",
                "use": "sig",
                "alg": alg,
                "kid": kid,
                "n": n_b64,
                "e": e_b64,
            })
        else:
            # Ed25519 or other key types
            jwks_keys.append({
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": alg,
                "kid": kid,
            })

    return {"keys": jwks_keys}


def issue(
    claims: dict[str, Any],
    private_key: Any = None,
    key_id: str = "default",
    ttl_seconds: int = 3600,
    alg: str = "RS256",
) -> str:
    """
    Issue a signed JWT token wrapping claims and expiration timestamps behind osivault.sign.
    """
    if alg not in ALLOWED_SIGNATURE_ALGORITHMS:
        raise TokenError(f"Allowlist check failed: Algorithm '{alg}' is disallowed.")

    now = int(time.time())
    token_claims = claims.copy()
    token_claims.setdefault("iat", now)
    token_claims.setdefault("exp", now + ttl_seconds)
    token_claims.setdefault("jti", uuid.uuid4().hex)

    header = {
        "alg": alg,
        "typ": "JWT",
        "kid": key_id,
    }

    header_json = json.dumps(header, separators=(",", ":")).encode("utf-8")
    payload_json = json.dumps(token_claims, separators=(",", ":")).encode("utf-8")

    header_b64 = base64.urlsafe_b64encode(header_json).decode("ascii").rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode("ascii").rstrip("=")

    signing_input = f"{header_b64}.{payload_b64}"

    # Sign using osivault.sign
    try:
        sig_envelope_str = sign(signing_input, key=private_key, alg=alg, key_id=key_id)
        parts = sig_envelope_str.split("$")
        sig_b64 = parts[5]
    except Exception as e:
        raise TokenError(f"Token signing failed: {str(e)}") from e

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify(
    token: str,
    public_key_or_jwks: Any = None,
    expected_issuer: str | None = None,
) -> dict[str, Any]:
    """
    Verify JWT token signature, expiration, and claims.
    Uses allowlist-first verification via osivault.sign.
    """
    if not isinstance(token, str):
        raise TokenError(f"Token must be str, got {type(token)}")

    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("Invalid JWT token format (expected header.payload.signature)")

    header_b64, payload_b64, sig_b64 = parts

    try:
        header_padding = "=" * (-len(header_b64) % 4)
        header_bytes = base64.urlsafe_b64decode(header_b64 + header_padding)
        header = json.loads(header_bytes.decode("utf-8"))

        payload_padding = "=" * (-len(payload_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + payload_padding)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as e:
        raise TokenError(f"Corrupted base64 or JSON structure in token: {str(e)}") from e

    alg = header.get("alg")
    kid = header.get("kid", "default")

    if alg not in ALLOWED_SIGNATURE_ALGORITHMS:
        raise TokenError(f"Allowlist check failed: Token algorithm '{alg}' is disallowed.")

    # Resolve public key
    public_key = None
    if isinstance(public_key_or_jwks, dict) and "keys" in public_key_or_jwks:
        for k in public_key_or_jwks["keys"]:
            if k.get("kid") == kid or len(public_key_or_jwks["keys"]) == 1:
                if k.get("kty") == "RSA":
                    n = _base64url_to_int(k["n"])
                    e = _base64url_to_int(k["e"])
                    public_key = rsa.RSAPublicNumbers(e, n).public_key()
                    break
    else:
        public_key = public_key_or_jwks

    if public_key is None:
        raise TokenError(f"Unable to resolve verification key for key_id '{kid}'")

    signing_input = f"{header_b64}.{payload_b64}"
    envelope_str = f"OSV1-SIG${alg}${kid}$SHA256${base64.urlsafe_b64encode(signing_input.encode('utf-8')).decode('ascii').rstrip('=')}${sig_b64}"

    try:
        sign_verify(envelope_str, public_key=public_key)
    except SignatureVerificationError as e:
        raise TokenError(f"Token signature verification failed: {str(e)}") from e

    # Claims Validation
    now = int(time.time())
    exp = payload.get("exp")
    if exp is not None and now >= exp:
        raise TokenError(f"Token has expired (exp: {exp}, now: {now})")

    nbf = payload.get("nbf")
    if nbf is not None and now < nbf:
        raise TokenError(f"Token not valid yet (nbf: {nbf}, now: {now})")

    if expected_issuer is not None:
        iss = payload.get("iss")
        if iss != expected_issuer:
            raise TokenError(f"Issuer mismatch: expected '{expected_issuer}', got '{iss}'")

    return payload


def rotate() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey, str]:
    """
    Generate a fresh RSA token signing keypair and key identifier.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    kid = f"key-{uuid.uuid4().hex[:8]}"
    return private_key, public_key, kid
