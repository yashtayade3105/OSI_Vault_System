"""
KMS Key Management Provider interface and implementations for OSIVault fields.
"""

import os
import base64
import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class BaseKMSProvider(ABC):
    """
    Abstract Base Class for Key Management System (KMS) providers.
    """

    @abstractmethod
    def get_master_key(self, key_id: str | None = None) -> bytes:
        """Return 32-byte raw master key for field encryption."""
        pass


class LocalKeyringProvider(BaseKMSProvider):
    """
    Local environment keyring provider for development and testing.
    Reads master key from OSIVAULT_FIELD_KEY environment variable.
    """

    def __init__(self, fallback_key: bytes | str | None = None):
        self.fallback_key = fallback_key

    def get_master_key(self, key_id: str | None = None) -> bytes:
        env_key = os.environ.get("OSIVAULT_FIELD_KEY")
        if env_key:
            return self._format_key(env_key)

        if self.fallback_key:
            return self._format_key(self.fallback_key)

        # Fail closed in production, fallback in dev with warning
        if os.environ.get("ENVIRONMENT", "development").lower() in ("production", "prod"):
            raise ValueError("OSIVAULT_FIELD_KEY environment variable is missing in production environment!")

        logger.warning("OSIVAULT_FIELD_KEY is unconfigured. Using dev/test deterministic fallback key.")
        return b"osivault-dev-local-master-key-32b!"[:32]

    def _format_key(self, key: bytes | str) -> bytes:
        if isinstance(key, bytes):
            if len(key) == 32:
                return key
            return key.ljust(32, b"\0")[:32]
        if isinstance(key, str):
            # Try base64
            try:
                decoded = base64.b64decode(key)
                if len(decoded) == 32:
                    return decoded
            except Exception:
                pass
            raw = key.encode("utf-8")
            return raw.ljust(32, b"\0")[:32]
        raise TypeError(f"Invalid key type: {type(key)}")


class AWSKMSProvider(BaseKMSProvider):
    """
    AWS KMS provider for production envelope encryption.
    """

    def __init__(self, aws_region: str | None = None, default_key_id: str | None = None):
        self.aws_region = aws_region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self.default_key_id = default_key_id or os.environ.get("AWS_KMS_KEY_ID")

    def get_master_key(self, key_id: str | None = None) -> bytes:
        target_key_id = key_id or self.default_key_id
        if not target_key_id:
            raise ValueError("AWS KMS key_id must be provided or set via AWS_KMS_KEY_ID")

        try:
            import boto3
            client = boto3.client("kms", region_name=self.aws_region)
            response = client.generate_data_key(
                KeyId=target_key_id,
                KeySpec="AES_256"
            )
            return response["Plaintext"]
        except ImportError:
            raise RuntimeError("boto3 package is required to use AWSKMSProvider")
        except Exception as e:
            raise RuntimeError(f"AWS KMS DataKey generation failed: {str(e)}") from e
