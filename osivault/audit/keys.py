"""
Key management and providers for osivault.audit.
"""

import os
import logging
from typing import Tuple, Optional
from django.conf import settings
from osivault.audit.crypto import ConfigurationError

logger = logging.getLogger("osivault.audit")

DEV_FALLBACK_KEY = "DEVELOPMENT_FALLBACK_KEY_OSIVAULT_AUDIT_32BYTES_LONG!"
DEFAULT_KEY_ID = "k1-default"


class KeyProvider:
    """Base interface for audit key providers."""

    def get_current_key(self) -> Tuple[bytes, str]:
        """Returns tuple of (key_bytes, key_id)."""
        raise NotImplementedError

    def get_previous_key(self) -> Tuple[Optional[bytes], Optional[str]]:
        """Returns tuple of (key_bytes, key_id) or (None, None)."""
        raise NotImplementedError


class EnvVarKeyProvider(KeyProvider):
    """
    Reads HMAC keys from environment variables OSIVAULT_AUDIT_CURRENT_KEY and OSIVAULT_AUDIT_PREVIOUS_KEY.
    In production (DEBUG=False), fails closed if no key is configured.
    In development (DEBUG=True), logs warning and uses fallback key if unconfigured.
    """

    def __init__(
        self,
        current_env_var: str = "OSIVAULT_AUDIT_CURRENT_KEY",
        previous_env_var: str = "OSIVAULT_AUDIT_PREVIOUS_KEY",
    ):
        self.current_env_var = current_env_var
        self.previous_env_var = previous_env_var

    def get_current_key(self) -> Tuple[bytes, str]:
        val = os.environ.get(self.current_env_var)
        if val:
            key_id = os.environ.get("OSIVAULT_AUDIT_CURRENT_KEY_ID", "key-current")
            return val.encode("utf-8"), key_id

        # Missing key handling
        is_debug = getattr(settings, "DEBUG", False)
        if is_debug:
            logger.warning(
                "DEVELOPMENT FALLBACK KEY IN USE - DO NOT USE IN PRODUCTION! "
                "No OSIVAULT_AUDIT_CURRENT_KEY configured in environment."
            )
            return DEV_FALLBACK_KEY.encode("utf-8"), "dev-fallback-key"
        else:
            raise ConfigurationError(
                f"Production fails closed: missing required environment variable '{self.current_env_var}'"
            )

    def get_previous_key(self) -> Tuple[Optional[bytes], Optional[str]]:
        val = os.environ.get(self.previous_env_var)
        if val:
            key_id = os.environ.get("OSIVAULT_AUDIT_PREVIOUS_KEY_ID", "key-previous")
            return val.encode("utf-8"), key_id
        return None, None


class InMemoryKeyProvider(KeyProvider):
    """
    In-memory key provider for testing and explicit runtime key rotation.
    """

    def __init__(self, current_key: bytes, current_key_id: str = "k1", previous_key: Optional[bytes] = None, previous_key_id: Optional[str] = None):
        self.current_key = current_key if isinstance(current_key, bytes) else current_key.encode("utf-8")
        self.current_key_id = current_key_id
        self.previous_key = (previous_key if isinstance(previous_key, bytes) else previous_key.encode("utf-8")) if previous_key else None
        self.previous_key_id = previous_key_id

    def get_current_key(self) -> Tuple[bytes, str]:
        return self.current_key, self.current_key_id

    def get_previous_key(self) -> Tuple[Optional[bytes], Optional[str]]:
        return self.previous_key, self.previous_key_id

    def rotate(self, new_current_key: bytes, new_current_key_id: str = "k2"):
        """Move current to previous, install new current key."""
        self.previous_key = self.current_key
        self.previous_key_id = self.current_key_id
        self.current_key = new_current_key if isinstance(new_current_key, bytes) else new_current_key.encode("utf-8")
        self.current_key_id = new_current_key_id


# Default global key provider instance
_default_provider = EnvVarKeyProvider()


def get_default_key_provider() -> KeyProvider:
    return _default_provider


def set_default_key_provider(provider: KeyProvider) -> None:
    global _default_provider
    _default_provider = provider
