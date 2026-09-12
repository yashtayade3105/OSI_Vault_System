"""
Pytest configuration and shared fixtures for OSIVault test suite.
"""

import os
import django

# Set DJANGO_SETTINGS_MODULE and setup Django before importing models
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")
django.setup()

from django.core.management import call_command
from django.db import connection
import pytest

TEST_CURRENT_KEY = "k1_super_secret_current_key_2026_audit_spec_32bytes!"
TEST_PREVIOUS_KEY = "k0_super_secret_previous_key_2026_audit_spec_32bytes!"


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """
    Ensure in-memory SQLite tables are created for all models in INSTALLED_APPS.
    """
    call_command("migrate", run_syncdb=True, verbosity=0)


@pytest.fixture(autouse=True)
def setup_audit_keys(monkeypatch):
    """
    Configure standard test keys in environment variables for key provider tests.
    """
    monkeypatch.setenv("OSIVAULT_AUDIT_CURRENT_KEY", TEST_CURRENT_KEY)
    monkeypatch.setenv("OSIVAULT_AUDIT_PREVIOUS_KEY", TEST_PREVIOUS_KEY)


@pytest.fixture(autouse=True)
def flush_test_db():
    """
    Flush test database between individual test runs using raw SQL.
    """
    yield
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM test_concrete_audit_log;")
        cursor.execute("DELETE FROM osivault_audit_checkpoint;")
        try:
            cursor.execute("DELETE FROM test_patient_record;")
        except Exception:
            pass
