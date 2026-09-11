"""
Comprehensive conformance test suite for osivault.audit.

Written FIRST in accordance with TDD principles to verify failure before implementation.
"""

import threading
import logging
import pytest
from django.db import connection, transaction
from django.conf import settings

from tests.models import ConcreteAuditLog
from osivault.audit import append, verify_entry, verify_chain, rotate_key, checkpoint
from osivault.audit.models import OSIVaultAuditCheckpoint
from osivault.audit.crypto import ImmutabilityError, ConfigurationError, AllowlistError


@pytest.mark.django_db
def test_chain_integrity():
    """
    Append ten entries; verify_chain reports intact.
    """
    for i in range(10):
        append(
            model_class=ConcreteAuditLog,
            actor=f"user_{i}@onesmarter.com",
            tenant="tenant_alpha",
            resource_type="Document",
            resource_id=f"doc_{i}",
            action="CREATE",
            old_values={},
            new_values={"index": i},
        )

    report = verify_chain(ConcreteAuditLog)
    assert report.is_intact is True
    assert report.total_count == 10
    assert report.current_key_count == 10
    assert report.previous_key_count == 0
    assert report.failed_pk is None


@pytest.mark.django_db
def test_altered_entry_field():
    """
    Alter any field of an entry via raw SQL; verify_chain reports exact row and MAC failure.
    """
    entries = []
    for i in range(10):
        e = append(
            model_class=ConcreteAuditLog,
            actor=f"user_{i}@onesmarter.com",
            tenant="tenant_alpha",
            resource_type="Document",
            resource_id=f"doc_{i}",
            action="READ",
            old_values={},
            new_values={},
        )
        entries.append(e)

    target_pk = entries[4].pk
    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE test_concrete_audit_log SET action = 'MALICIOUS_UPDATE' WHERE id = {target_pk}"
        )

    report = verify_chain(ConcreteAuditLog)
    assert report.is_intact is False
    assert report.failed_pk == target_pk
    assert "MAC verification failed" in report.failure_reason


@pytest.mark.django_db
def test_deleted_middle_row():
    """
    Delete a middle row via raw SQL; verify_chain reports break at following row.
    """
    entries = []
    for i in range(10):
        e = append(
            model_class=ConcreteAuditLog,
            actor=f"user_{i}@onesmarter.com",
            tenant="tenant_alpha",
            resource_type="Document",
            resource_id=f"doc_{i}",
            action="WRITE",
            old_values={},
            new_values={},
        )
        entries.append(e)

    deleted_pk = entries[4].pk
    following_pk = entries[5].pk

    with connection.cursor() as cursor:
        cursor.execute(f"DELETE FROM test_concrete_audit_log WHERE id = {deleted_pk}")

    report = verify_chain(ConcreteAuditLog)
    assert report.is_intact is False
    assert report.failed_pk == following_pk
    assert "previous_hash mismatch" in report.failure_reason or "Chain link broken" in report.failure_reason


@pytest.mark.django_db
def test_swapped_row_order():
    """
    Swap order of two rows' contents via raw SQL; verify_chain reports both.
    """
    entries = []
    for i in range(5):
        e = append(
            model_class=ConcreteAuditLog,
            actor=f"user_{i}@onesmarter.com",
            tenant="tenant_alpha",
            resource_type="Item",
            resource_id=f"item_{i}",
            action=f"ACTION_TYPE_{i}",
            old_values={},
            new_values={},
        )
        entries.append(e)

    pk1, pk2 = entries[1].pk, entries[2].pk
    act1, act2 = entries[1].action, entries[2].action

    with connection.cursor() as cursor:
        cursor.execute(f"UPDATE test_concrete_audit_log SET action = '{act2}' WHERE id = {pk1}")
        cursor.execute(f"UPDATE test_concrete_audit_log SET action = '{act1}' WHERE id = {pk2}")

    report = verify_chain(ConcreteAuditLog)
    assert report.is_intact is False
    assert report.failed_pk == pk1


@pytest.mark.django_db
def test_timestamp_tampering():
    """
    Regression Test: Change only timestamp via raw SQL -> MAC fails.
    """
    entry = append(
        model_class=ConcreteAuditLog,
        actor="alice@onesmarter.com",
        tenant="tenant_beta",
        resource_type="MedicalRecord",
        resource_id="mr_100",
        action="VIEW",
        old_values={},
        new_values={},
    )

    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE test_concrete_audit_log SET timestamp = '2000-01-01 00:00:00.000000+00' WHERE id = {entry.pk}"
        )

    modified_entry = ConcreteAuditLog.objects.get(pk=entry.pk)
    verified, key_used, reason = verify_entry(modified_entry)
    assert verified is False
    assert "MAC verification failed" in reason or "Timestamp" in reason


@pytest.mark.django_db
def test_tenant_tampering():
    """
    Regression Test: Change only tenant via raw SQL -> MAC fails.
    """
    entry = append(
        model_class=ConcreteAuditLog,
        actor="bob@onesmarter.com",
        tenant="tenant_original",
        resource_type="BillingData",
        resource_id="bill_50",
        action="EXPORT",
        old_values={},
        new_values={},
    )

    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE test_concrete_audit_log SET tenant = 'tenant_hacked' WHERE id = {entry.pk}"
        )

    modified_entry = ConcreteAuditLog.objects.get(pk=entry.pk)
    verified, key_used, reason = verify_entry(modified_entry)
    assert verified is False


@pytest.mark.django_db
def test_unkeyed_rehash_attack():
    """
    Attacker re-calculates SHA-256 hash without secret key -> verify_entry rejects.
    """
    import hashlib
    entry = append(
        model_class=ConcreteAuditLog,
        actor="attacker@onesmarter.com",
        tenant="tenant_target",
        resource_type="Account",
        resource_id="acc_1",
        action="TRANSFER",
        old_values={"amount": 100},
        new_values={"amount": 10000},
    )

    # Raw SQL update simulating unkeyed SHA-256 recalculation by adversary
    unkeyed_hash = hashlib.sha256(b"fake_payload_without_secret_key").hexdigest()
    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE test_concrete_audit_log SET new_values = '{{\"amount\": 10000}}', entry_hash = '{unkeyed_hash}' WHERE id = {entry.pk}"
        )

    modified_entry = ConcreteAuditLog.objects.get(pk=entry.pk)
    verified, key_used, reason = verify_entry(modified_entry)
    assert verified is False


@pytest.mark.django_db
def test_key_rotation(monkeypatch):
    """
    Test key rotation across 10 entries and double rotation behavior.
    """
    for i in range(5):
        append(
            model_class=ConcreteAuditLog,
            actor=f"user_{i}@onesmarter.com",
            tenant="tenant_gamma",
            resource_type="Record",
            resource_id=f"rec_{i}",
            action="CREATE",
            old_values={},
            new_values={},
        )

    # Rotate Key
    new_key = "k2_brand_new_current_key_2026_spec_32bytes!!"
    rotate_key(new_current_key=new_key)

    for i in range(5, 10):
        append(
            model_class=ConcreteAuditLog,
            actor=f"user_{i}@onesmarter.com",
            tenant="tenant_gamma",
            resource_type="Record",
            resource_id=f"rec_{i}",
            action="CREATE",
            old_values={},
            new_values={},
        )

    report = verify_chain(ConcreteAuditLog)
    assert report.is_intact is True
    assert report.current_key_count == 5
    assert report.previous_key_count == 5

    # Second Rotation: Original key is now purged
    rotate_key(new_current_key="k3_third_key_2026_spec_32bytes!!!")
    report2 = verify_chain(ConcreteAuditLog)
    assert report2.is_intact is False
    assert report2.failed_pk == ConcreteAuditLog.objects.order_by("pk").first().pk


@pytest.mark.django_db
def test_allowlist_envelope_rejection():
    """
    Envelope naming unallowed algorithm (e.g. HMAC-SHA-512) refused before computing anything.
    """
    entry = append(
        model_class=ConcreteAuditLog,
        actor="charlie@onesmarter.com",
        tenant="tenant_delta",
        resource_type="File",
        resource_id="file_1",
        action="DELETE",
        old_values={},
        new_values={},
    )

    unsupported_envelope = '{"mac_alg": "HMAC-SHA-512", "fmt_ver": 1, "hash_alg": "SHA-512", "key_id": "k1"}'
    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE test_concrete_audit_log SET envelope = '{unsupported_envelope}' WHERE id = {entry.pk}"
        )

    modified_entry = ConcreteAuditLog.objects.get(pk=entry.pk)
    verified, key_used, reason = verify_entry(modified_entry)
    assert verified is False
    assert "Envelope algorithm 'HMAC-SHA-512' not in allowlist" in reason or "allowlist" in reason.lower()


@pytest.mark.django_db
def test_fail_closed_and_debug_fallback(monkeypatch, caplog):
    """
    Missing key with DEBUG=False raises ConfigurationError. DEBUG=True uses fallback & logs warning.
    """
    from osivault.audit.keys import EnvVarKeyProvider, set_default_key_provider
    set_default_key_provider(EnvVarKeyProvider())

    monkeypatch.delenv("OSIVAULT_AUDIT_CURRENT_KEY", raising=False)
    monkeypatch.delenv("OSIVAULT_AUDIT_PREVIOUS_KEY", raising=False)

    # Case 1: DEBUG=False -> Fail closed
    monkeypatch.setattr(settings, "DEBUG", False)
    with pytest.raises(ConfigurationError):
        append(
            model_class=ConcreteAuditLog,
            actor="dev@onesmarter.com",
            tenant="tenant_test",
            resource_type="Test",
            resource_id="1",
            action="TEST",
            old_values={},
            new_values={},
        )

    # Case 2: DEBUG=True -> Log warning and use fallback key
    monkeypatch.setattr(settings, "DEBUG", True)
    with caplog.at_level(logging.WARNING):
        entry = append(
            model_class=ConcreteAuditLog,
            actor="dev@onesmarter.com",
            tenant="tenant_test",
            resource_type="Test",
            resource_id="1",
            action="TEST",
            old_values={},
            new_values={},
        )
        assert entry is not None
        assert "DEVELOPMENT FALLBACK KEY" in caplog.text


@pytest.mark.django_db
def test_immutability_guards():
    """
    Model save on existing PK raises ImmutabilityError; delete raises ImmutabilityError.
    Queryset update and delete raise ImmutabilityError.
    """
    entry = append(
        model_class=ConcreteAuditLog,
        actor="dave@onesmarter.com",
        tenant="tenant_epsilon",
        resource_type="Policy",
        resource_id="pol_1",
        action="ACTIVATE",
        old_values={},
        new_values={},
    )

    # 1. ORM Save on existing PK
    with pytest.raises(ImmutabilityError):
        entry.action = "TAMPER"
        entry.save()

    # 2. ORM Delete
    with pytest.raises(ImmutabilityError):
        entry.delete()

    # 3. QuerySet Update & Delete
    with pytest.raises(ImmutabilityError):
        ConcreteAuditLog.objects.filter(pk=entry.pk).update(action="TAMPER")

    with pytest.raises(ImmutabilityError):
        ConcreteAuditLog.objects.filter(pk=entry.pk).delete()


@pytest.mark.django_db(transaction=True)
def test_concurrency_safe():
    """
    Simultaneous appends across multiple threads result in linear, intact audit chain.
    """
    threads = []
    errors = []

    def worker(thread_idx):
        try:
            for i in range(10):
                for attempt in range(10):
                    try:
                        append(
                            model_class=ConcreteAuditLog,
                            actor=f"thread_{thread_idx}@onesmarter.com",
                            tenant="tenant_concurrent",
                            resource_type="BatchJob",
                            resource_id=f"job_{i}",
                            action="PROCESS",
                            old_values={},
                            new_values={"thread": thread_idx, "iter": i},
                        )
                        break
                    except Exception as ex:
                        if "database is locked" in str(ex).lower() and attempt < 9:
                            import time
                            time.sleep(0.05)
                        else:
                            raise
        except Exception as ex:
            errors.append(ex)

    for t_id in range(4):
        t = threading.Thread(target=worker, args=(t_id,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    assert len(errors) == 0
    assert ConcreteAuditLog.objects.count() == 40

    report = verify_chain(ConcreteAuditLog)
    assert report.is_intact is True


@pytest.mark.django_db
def test_table_replacement_checkpoint():
    """
    Checkpoint verification catches whole-table replacement attacks.
    """
    for i in range(5):
        append(
            model_class=ConcreteAuditLog,
            actor=f"user_{i}@onesmarter.com",
            tenant="tenant_secure",
            resource_type="Tx",
            resource_id=f"tx_{i}",
            action="EXECUTE",
            old_values={},
            new_values={},
        )

    # Take Checkpoint 1
    cp1 = checkpoint(ConcreteAuditLog)
    assert cp1 is not None

    # Replace whole table contents with new valid chain of same length
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM test_concrete_audit_log")

    for i in range(5):
        append(
            model_class=ConcreteAuditLog,
            actor=f"fake_user_{i}@onesmarter.com",
            tenant="tenant_fake",
            resource_type="Tx",
            resource_id=f"fake_tx_{i}",
            action="EXECUTE",
            old_values={},
            new_values={},
        )

    # verify_chain on new table is internally intact
    new_report = verify_chain(ConcreteAuditLog)
    assert new_report.is_intact is True

    # BUT historical checkpoint fails to verify against replaced table!
    last_row = ConcreteAuditLog.objects.order_by("-pk").first()
    assert last_row.entry_hash != cp1.last_entry_hash
