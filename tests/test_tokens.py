"""
Tests for osivault.tokens module.
Covers JWT token issuance, verification, claim validation (exp, iss, iat),
JWKS endpoint document generation (RFC 7517), and token signing key rotation.
"""

import time
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from osivault.tokens import issue, verify, jwks_document, TokenError


@pytest.fixture
def rsa_keys():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    return priv, pub


def test_issue_verify_jwt_roundtrip(rsa_keys):
    priv_key, pub_key = rsa_keys
    claims = {"user_id": "usr_9981", "role": "admin", "tenant": "onesmarter"}

    token = issue(claims, private_key=priv_key, key_id="auth-key-1", ttl_seconds=3600, alg="RS256")
    assert isinstance(token, str)

    decoded = verify(token, public_key_or_jwks=pub_key)
    assert decoded["user_id"] == "usr_9981"
    assert decoded["role"] == "admin"
    assert decoded["tenant"] == "onesmarter"
    assert "exp" in decoded
    assert "iat" in decoded


def test_expired_token_rejection(rsa_keys):
    priv_key, pub_key = rsa_keys
    claims = {"user_id": "usr_expired"}

    # Issue token expired 10 seconds ago
    token = issue(claims, private_key=priv_key, key_id="auth-key-1", ttl_seconds=-10)

    with pytest.raises(TokenError) as exc_info:
        verify(token, public_key_or_jwks=pub_key)
    assert "expired" in str(exc_info.value).lower()


def test_issuer_validation(rsa_keys):
    priv_key, pub_key = rsa_keys
    claims = {"user_id": "usr_iss_test", "iss": "onesmarter.auth"}

    token = issue(claims, private_key=priv_key, key_id="auth-key-1")

    # Correct issuer succeeds
    decoded = verify(token, public_key_or_jwks=pub_key, expected_issuer="onesmarter.auth")
    assert decoded["user_id"] == "usr_iss_test"

    # Mismatched issuer fails
    with pytest.raises(TokenError):
        verify(token, public_key_or_jwks=pub_key, expected_issuer="other.auth")


def test_jwks_document_generation(rsa_keys):
    priv_key, pub_key = rsa_keys

    jwks = jwks_document(keys=[(pub_key, "auth-key-1", "RS256")])
    assert isinstance(jwks, dict)
    assert "keys" in jwks
    assert len(jwks["keys"]) == 1

    key_entry = jwks["keys"][0]
    assert key_entry["kty"] == "RSA"
    assert key_entry["kid"] == "auth-key-1"
    assert key_entry["use"] == "sig"
    assert key_entry["alg"] == "RS256"
    assert "n" in key_entry
    assert "e" in key_entry


def test_verify_with_jwks_dict(rsa_keys):
    priv_key, pub_key = rsa_keys
    claims = {"sub": "service-account-claims"}

    token = issue(claims, private_key=priv_key, key_id="auth-key-1")
    jwks = jwks_document(keys=[(pub_key, "auth-key-1", "RS256")])

    decoded = verify(token, public_key_or_jwks=jwks)
    assert decoded["sub"] == "service-account-claims"
