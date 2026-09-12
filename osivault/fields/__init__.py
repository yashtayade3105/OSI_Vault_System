"""
osivault.fields: Field-level encryption at rest and blind-index search hashing.
"""

from osivault.fields.crypto import encrypt, decrypt, rotate_dek, SearchHash, FieldEncryptionError
from osivault.fields.fields import EncryptedTextField, EncryptedJSONField
from osivault.fields.kms import BaseKMSProvider, LocalKeyringProvider, AWSKMSProvider

__all__ = [
    "encrypt",
    "decrypt",
    "rotate_dek",
    "SearchHash",
    "EncryptedTextField",
    "EncryptedJSONField",
    "FieldEncryptionError",
    "BaseKMSProvider",
    "LocalKeyringProvider",
    "AWSKMSProvider",
]
