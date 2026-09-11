"""
Cryptographic operations, canonical JSON serialization, and envelope verification for osivault.audit.
"""

import hmac
import hashlib
import json
from datetime import datetime, timezone

ALLOWED_MAC_ALGORITHMS = {"HMAC-SHA-256"}
ALLOWED_HASH_ALGORITHMS = {"SHA-256"}
FORMAT_VERSION = 1


class AuditError(Exception):
    """Base exception for all osivault.audit errors."""
    pass


class ImmutabilityError(AuditError):
    """Raised when an illegal modification or deletion of an audit record is attempted."""
    pass


class ConfigurationError(AuditError):
    """Raised when required cryptographic keys or key providers are missing or misconfigured."""
    pass


class AllowlistError(AuditError):
    """Raised when an unallowed cryptographic algorithm or envelope version is encountered."""
    pass


def validate_envelope(envelope: dict) -> None:
    """
    Validate that the envelope header contains an allowed MAC algorithm.
    Must refuse any unallowed algorithm before performing cryptographic calculations.
    """
    if not isinstance(envelope, dict):
        raise AllowlistError("Envelope must be a dictionary or valid JSON object")

    mac_alg = envelope.get("mac_alg")
    if mac_alg not in ALLOWED_MAC_ALGORITHMS:
        raise AllowlistError(f"Envelope algorithm '{mac_alg}' not in allowlist {list(ALLOWED_MAC_ALGORITHMS)}")

    fmt_ver = envelope.get("fmt_ver")
    if fmt_ver != FORMAT_VERSION:
        raise AllowlistError(f"Envelope format version '{fmt_ver}' not supported. Expected {FORMAT_VERSION}")


def canonical_json(data: dict) -> bytes:
    """
    Produce canonical JSON representation with sorted keys, compact separators, and UTF-8 encoding.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def format_iso_timestamp(dt: datetime) -> str:
    """
    Format a datetime object as ISO 8601 UTC with microsecond precision.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def build_checksum_payload(
    envelope: dict,
    previous_hash: str,
    timestamp_str: str,
    actor: str,
    tenant: str,
    resource_type: str,
    resource_id: str,
    action: str,
    old_values: dict,
    new_values: dict,
) -> dict:
    """
    Build canonical payload dictionary containing every authenticated field.
    """
    return {
        "action": str(action),
        "actor": str(actor),
        "envelope": envelope,
        "new_values": new_values if new_values is not None else {},
        "old_values": old_values if old_values is not None else {},
        "previous_hash": str(previous_hash or ""),
        "resource_id": str(resource_id),
        "resource_type": str(resource_type),
        "tenant": str(tenant),
        "timestamp": str(timestamp_str),
    }


def compute_hmac_sha256(key_bytes: bytes, payload_bytes: bytes) -> str:
    """
    Compute HMAC-SHA-256 signature over payload bytes.
    """
    if isinstance(key_bytes, str):
        key_bytes = key_bytes.encode("utf-8")
    return hmac.new(key_bytes, payload_bytes, hashlib.sha256).hexdigest()
