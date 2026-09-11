"""
osivault.tokens: Session and service tokens with published verification keys.
"""


def issue(*args, **kwargs):
    raise NotImplementedError("osivault.tokens.issue is not implemented in round 1.")


def verify(*args, **kwargs):
    raise NotImplementedError("osivault.tokens.verify is not implemented in round 1.")


def jwks_document(*args, **kwargs):
    raise NotImplementedError("osivault.tokens.jwks_document is not implemented in round 1.")


def rotate(*args, **kwargs):
    raise NotImplementedError("osivault.tokens.rotate is not implemented in round 1.")
