"""
Concrete models for OSIVault test suite.
"""

from django.db import models
from osivault.audit.models import OSIVaultAuditLog
from osivault.fields import EncryptedTextField, EncryptedJSONField


class ConcreteAuditLog(OSIVaultAuditLog):
    """
    Concrete implementation of OSIVaultAuditLog used by the conformance test suite.
    """
    class Meta:
        app_label = "tests"
        db_table = "test_concrete_audit_log"


class PatientRecord(models.Model):
    """
    Test model for verifying EncryptedTextField and EncryptedJSONField.
    """
    patient_name = models.CharField(max_length=255)
    ssn = EncryptedTextField(null=True, blank=True)
    ssn_search = models.CharField(max_length=64, db_index=True, null=True, blank=True)
    medical_history = EncryptedJSONField(null=True, blank=True)

    class Meta:
        app_label = "tests"
        db_table = "test_patient_record"
