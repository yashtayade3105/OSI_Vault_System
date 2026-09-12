"""
Django model field subclasses for encrypted text and encrypted JSON storage.
"""

import json
from django.db import models
from osivault.fields.crypto import encrypt, decrypt, HEADER_PREFIX


class EncryptedTextField(models.TextField):
    """
    Django TextField subclass that automatically encrypts text on save and decrypts on retrieve.
    """

    def __init__(self, *args, key=None, context=None, **kwargs):
        self.key = key
        self.context = context
        super().__init__(*args, **kwargs)

    def get_prep_value(self, value):
        prep_value = super().get_prep_value(value)
        if prep_value is None:
            return None
        if isinstance(prep_value, str) and prep_value.startswith(f"{HEADER_PREFIX}$AES-256-GCM$"):
            return prep_value
        return encrypt(str(prep_value), key=self.key, context=self.context)

    def from_db_value(self, value, expression, connection):
        if value is None:
            return None
        if isinstance(value, str) and value.startswith(f"{HEADER_PREFIX}$AES-256-GCM$"):
            return decrypt(value, key=self.key, context=self.context)
        return value

    def to_python(self, value):
        if value is None:
            return None
        if isinstance(value, str) and value.startswith(f"{HEADER_PREFIX}$AES-256-GCM$"):
            try:
                return decrypt(value, key=self.key, context=self.context)
            except Exception:
                return value
        return super().to_python(value)


class EncryptedJSONField(models.TextField):
    """
    Django model field for encrypting JSON data structures at rest.
    """

    def __init__(self, *args, key=None, context=None, **kwargs):
        self.key = key
        self.context = context
        super().__init__(*args, **kwargs)

    def get_prep_value(self, value):
        if value is None:
            return None
        if isinstance(value, str) and value.startswith(f"{HEADER_PREFIX}$AES-256-GCM$"):
            return value
        json_str = json.dumps(value)
        return encrypt(json_str, key=self.key, context=self.context)

    def from_db_value(self, value, expression, connection):
        if value is None:
            return None
        if isinstance(value, str) and value.startswith(f"{HEADER_PREFIX}$AES-256-GCM$"):
            decrypted_str = decrypt(value, key=self.key, context=self.context)
            return json.loads(decrypted_str)
        if isinstance(value, str):
            try:
                return json.loads(value)
            except Exception:
                return value
        return value

    def to_python(self, value):
        if value is None or isinstance(value, (dict, list)):
            return value
        if isinstance(value, str) and value.startswith(f"{HEADER_PREFIX}$AES-256-GCM$"):
            try:
                decrypted_str = decrypt(value, key=self.key, context=self.context)
                return json.loads(decrypted_str)
            except Exception:
                return value
        if isinstance(value, str):
            try:
                return json.loads(value)
            except Exception:
                return value
        return super().to_python(value)
