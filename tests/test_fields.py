"""
Tests for osivault.fields module.
Covers AES-256-GCM encryption, fresh DEK generation, context (AAD) binding,
allowlist-first self-describing header verification, DEK rotation, SearchHash blind indexing,
and Django EncryptedTextField / EncryptedJSONField.
"""

import os
import pytest
from django.db import models
from osivault.fields import (
    encrypt,
    decrypt,
    rotate_dek,
    SearchHash,
    EncryptedTextField,
    EncryptedJSONField,
)
from osivault.fields.crypto import FieldEncryptionError


def test_encrypt_decrypt_basic_roundtrip():
    """Test basic string and bytes encryption and decryption."""
    plaintext = "Patient John Doe SSN: 123-45-6789"
    key = os.urandom(32)
    
    ciphertext = encrypt(plaintext, key=key)
    assert ciphertext != plaintext
    assert ciphertext.startswith("OSV1$AES-256-GCM$") or "OSV1" in ciphertext
    
    decrypted = decrypt(ciphertext, key=key)
    assert decrypted == plaintext


def test_context_aad_binding():
    """Test that context (AAD) mismatch causes decryption authentication failure."""
    plaintext = "Sensitive PHI Record"
    key = os.urandom(32)
    context_correct = "tenant_101:patient_999"
    context_wrong = "tenant_101:patient_888"

    ciphertext = encrypt(plaintext, key=key, context=context_correct)

    # Decrypting with wrong context must fail
    with pytest.raises(FieldEncryptionError):
        decrypt(ciphertext, key=key, context=context_wrong)

    # Decrypting with correct context succeeds
    assert decrypt(ciphertext, key=key, context=context_correct) == plaintext


def test_fresh_dek_randomness():
    """Test that encrypting the same text twice generates different ciphertexts (fresh DEK & IV)."""
    plaintext = "Identical Input Text"
    key = os.urandom(32)

    ct1 = encrypt(plaintext, key=key)
    ct2 = encrypt(plaintext, key=key)

    assert ct1 != ct2
    assert decrypt(ct1, key=key) == plaintext
    assert decrypt(ct2, key=key) == plaintext


def test_allowlist_header_rejection():
    """Test that ciphertext with non-allowlisted algorithm header is rejected before crypto ops."""
    key = os.urandom(32)
    # Fabricate envelope with disallowed algorithm
    bad_envelope = "OSV1$DES-CBC$kid=default$iv=12345678$payload=abcdef"

    with pytest.raises(FieldEncryptionError) as exc_info:
        decrypt(bad_envelope, key=key)
    assert "Allowlist" in str(exc_info.value) or "disallowed" in str(exc_info.value).lower() or "unsupported" in str(exc_info.value).lower()


def test_tampered_ciphertext_detection():
    """Test that tampered ciphertext or MAC tag causes decryption failure."""
    plaintext = "Confidential Claim Data"
    key = os.urandom(32)

    ciphertext = encrypt(plaintext, key=key)
    # Corrupt last character of ciphertext envelope
    corrupted = ciphertext[:-2] + ("0" if ciphertext[-1] != "0" else "1")

    with pytest.raises(FieldEncryptionError):
        decrypt(corrupted, key=key)


def test_rotate_dek():
    """Test re-encrypting ciphertext envelope under new key or fresh DEK."""
    plaintext = "Data to be re-keyed"
    old_key = os.urandom(32)
    new_key = os.urandom(32)

    ct_old = encrypt(plaintext, key=old_key)
    ct_new = rotate_dek(ct_old, new_key=new_key, old_key=old_key)

    assert ct_old != ct_new
    # Old key fails on new ciphertext
    with pytest.raises(FieldEncryptionError):
        decrypt(ct_new, key=old_key)

    # New key decrypts new ciphertext
    assert decrypt(ct_new, key=new_key) == plaintext


def test_search_hash_blind_index():
    """Test SearchHash deterministic blind index hashing for querying encrypted fields."""
    ssn = "123-45-6789"
    salt = "system-blind-index-salt-2026"

    hash1 = SearchHash(ssn, salt=salt)
    hash2 = SearchHash(ssn, salt=salt)
    hash_diff_salt = SearchHash(ssn, salt="different-salt")

    assert hash1 == hash2
    assert hash1 != ssn
    assert hash1 != hash_diff_salt
    assert len(hash1) == 64  # SHA-256 hex string


def test_django_encrypted_fields():
    """Test EncryptedTextField and EncryptedJSONField model integration."""
    from tests.models import PatientRecord

    record = PatientRecord.objects.create(
        patient_name="Alice Smith",
        ssn="987-65-4321",
        ssn_search=SearchHash("987-65-4321"),
        medical_history={"allergies": ["Penicillin"], "blood_type": "O+"},
    )

    # Query from DB
    retrieved = PatientRecord.objects.get(id=record.id)
    assert retrieved.patient_name == "Alice Smith"
    assert retrieved.ssn == "987-65-4321"
    assert retrieved.medical_history == {"allergies": ["Penicillin"], "blood_type": "O+"}

    # Query using SearchHash
    queried = PatientRecord.objects.get(ssn_search=SearchHash("987-65-4321"))
    assert queried.id == record.id
