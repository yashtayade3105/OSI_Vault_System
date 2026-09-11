"""
osivault.fields: Field-level encryption at rest and blind-index search hashing.
"""


def encrypt(*args, **kwargs):
    raise NotImplementedError("osivault.fields.encrypt is not implemented in round 1.")


def decrypt(*args, **kwargs):
    raise NotImplementedError("osivault.fields.decrypt is not implemented in round 1.")


class EncryptedTextField:
    def __init__(self, *args, **kwargs):
        raise NotImplementedError("osivault.fields.EncryptedTextField is not implemented in round 1.")


class EncryptedJSONField:
    def __init__(self, *args, **kwargs):
        raise NotImplementedError("osivault.fields.EncryptedJSONField is not implemented in round 1.")


def rotate_dek(*args, **kwargs):
    raise NotImplementedError("osivault.fields.rotate_dek is not implemented in round 1.")


def SearchHash(*args, **kwargs):
    raise NotImplementedError("osivault.fields.SearchHash is not implemented in round 1.")
