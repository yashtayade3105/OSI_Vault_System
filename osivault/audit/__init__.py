"""
osivault.audit: Keyed, chained, tamper-evident audit records.
"""

def __getattr__(name):
    if name in {"append", "verify_entry", "verify_chain", "rotate_key", "checkpoint", "AuditVerificationReport"}:
        from osivault.audit import operations
        return getattr(operations, name)
    if name in {"AuditError", "ImmutabilityError", "ConfigurationError", "AllowlistError"}:
        from osivault.audit import crypto
        return getattr(crypto, name)
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


__all__ = [
    "append",
    "verify_entry",
    "verify_chain",
    "rotate_key",
    "checkpoint",
    "AuditVerificationReport",
    "AuditError",
    "ImmutabilityError",
    "ConfigurationError",
    "AllowlistError",
]
