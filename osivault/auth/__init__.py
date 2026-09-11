"""
osivault.auth: Second-factor adapters for privileged and ordinary accounts.
"""


class TOTPVerifier:
    def __init__(self, *args, **kwargs):
        raise NotImplementedError("osivault.auth.TOTPVerifier is not implemented in round 1.")


class WebAuthnRegistrar:
    def __init__(self, *args, **kwargs):
        raise NotImplementedError("osivault.auth.WebAuthnRegistrar is not implemented in round 1.")


class WebAuthnAsserter:
    def __init__(self, *args, **kwargs):
        raise NotImplementedError("osivault.auth.WebAuthnAsserter is not implemented in round 1.")


class RecoveryCodes:
    def __init__(self, *args, **kwargs):
        raise NotImplementedError("osivault.auth.RecoveryCodes is not implemented in round 1.")
