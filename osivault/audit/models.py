"""
Abstract Django Audit Log model and Checkpoint model with strict ORM immutability guards.
"""

from django.db import models
from osivault.audit.crypto import ImmutabilityError


class OSIVaultAuditQuerySet(models.QuerySet):
    """QuerySet subclass that prohibits bulk update and delete operations."""

    def update(self, *args, **kwargs):
        raise ImmutabilityError("OSIVault audit log queryset update is strictly prohibited.")

    def delete(self, *args, **kwargs):
        raise ImmutabilityError("OSIVault audit log queryset delete is strictly prohibited.")


class OSIVaultAuditManager(models.Manager):
    """Manager returning OSIVaultAuditQuerySet."""

    def get_queryset(self):
        return OSIVaultAuditQuerySet(self.model, using=self._db)


class OSIVaultAuditLog(models.Model):
    """
    Abstract Django audit log model.
    Consuming applications subclass this model to add tenant foreign keys or app-specific columns.
    """

    timestamp = models.DateTimeField(db_index=True)
    actor = models.CharField(max_length=255)
    tenant = models.CharField(max_length=255)
    resource_type = models.CharField(max_length=255)
    resource_id = models.CharField(max_length=255)
    action = models.CharField(max_length=255)
    old_values = models.JSONField(default=dict, blank=True)
    new_values = models.JSONField(default=dict, blank=True)
    previous_hash = models.CharField(max_length=128, blank=True)
    entry_hash = models.CharField(max_length=128)
    envelope = models.JSONField()

    objects = OSIVaultAuditManager()

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        """
        Immutability guard: Refuses updates to an existing primary key.
        Only allows insertion when pk is None or force_insert is True.
        """
        if self.pk is not None and not kwargs.get("force_insert", False):
            raise ImmutabilityError("OSIVault audit entries are immutable and cannot be updated.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """
        Immutability guard: Always refuses deletion.
        """
        raise ImmutabilityError("OSIVault audit entries are immutable and cannot be deleted.")


class OSIVaultAuditCheckpoint(models.Model):
    """
    Table storing signed periodic checkpoints to catch whole-table replacement attacks.
    """

    last_entry_hash = models.CharField(max_length=128)
    row_count = models.IntegerField()
    envelope = models.JSONField()
    timestamp = models.DateTimeField(db_index=True)
    checkpoint_hash = models.CharField(max_length=128)

    class Meta:
        db_table = "osivault_audit_checkpoint"



