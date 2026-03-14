"""
workflow.py — High-level orchestration of the Export & Delete workflow.

The PIIWorkflow class is the single façade for calling code (e.g. an API
handler or CLI).  It wires together ExportService, DeleteService, and
AuditLogger and exposes clean, documented public methods.

Typical usage
-------------
    db = InMemoryDatabase()
    seed_test_data(db, user_id="usr_001")

    wf = PIIWorkflow(db)

    # Export
    export_req = wf.export_user_data("usr_001")

    # Delete
    del_req  = wf.request_deletion("usr_001")
    del_req  = wf.confirm_deletion(del_req.request_id, del_req.confirmation_token)
    del_req  = wf.execute_deletion(del_req.request_id)

    # Audit
    chain_ok = wf.verify_audit_chain()
    trail    = wf.get_user_audit_trail("usr_001")
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from audit_logger import AuditLogger
from delete_service import DeleteService
from export_service import ExportService
from models import (
    DeletionRequest,
    ExportRequest,
    InMemoryDatabase,
)


class PIIWorkflow:
    """
    Unified façade for the GDPR PII Export & Delete workflow.

    Parameters
    ----------
    db          : InMemoryDatabase (or compatible repository).
    output_dir  : Where to write export ZIP files.
                  None = in-memory only (useful for tests / serverless).
    service_name: Label used in audit entries.
    """

    def __init__(
        self,
        db: InMemoryDatabase,
        output_dir: Optional[str] = None,
        service_name: str = "pii-workflow",
    ) -> None:
        self._db     = db
        self._audit  = AuditLogger(db, service_name)
        self._export = ExportService(db, self._audit, output_dir)
        self._delete = DeleteService(db, self._audit)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_user_data(
        self,
        user_id: str,
        requested_by: str = "user",
        ip_address: Optional[str] = None,
    ) -> ExportRequest:
        """
        Generate and return a complete export package for the given user.

        The returned ExportRequest contains:
          • package_path — where the ZIP was written (or virtual path)
          • package_hash — SHA-256 of the ZIP (for integrity verification)

        Raises ExportError on failure.
        """
        return self._export.request_export(
            user_id=user_id,
            requested_by=requested_by,
            ip_address=ip_address,
        )

    def get_export_bytes(self, request_id: str) -> Optional[bytes]:
        """Retrieve the raw ZIP bytes for a completed export (in-memory mode)."""
        return self._export.get_package_bytes(request_id)

    # ------------------------------------------------------------------
    # Deletion — step by step
    # ------------------------------------------------------------------

    def request_deletion(
        self,
        user_id: str,
        requested_by: str = "user",
        reason: str = "user_request",
        grace_period_days: int = 30,
        ip_address: Optional[str] = None,
    ) -> DeletionRequest:
        """
        Step 1 — Initiate a deletion request and receive a confirmation token.

        In a real system the token would be sent to the user's verified email
        address, never returned directly from the API.
        """
        return self._delete.request_deletion(
            user_id=user_id,
            requested_by=requested_by,
            reason=reason,
            grace_period_days=grace_period_days,
            ip_address=ip_address,
        )

    def confirm_deletion(
        self,
        request_id: str,
        token: str,
        actor: str = "user",
        ip_address: Optional[str] = None,
    ) -> DeletionRequest:
        """
        Step 2 — Validate the confirmation token and mark the request as
        CONFIRMED.  Raises InvalidTokenError if the token is wrong/expired.
        """
        return self._delete.confirm_deletion(
            request_id=request_id,
            token=token,
            actor=actor,
            ip_address=ip_address,
        )

    def execute_deletion(self, request_id: str) -> DeletionRequest:
        """
        Step 3 — Permanently purge all PII for the user.

        Must be called after confirm_deletion().
        Typically scheduled after the grace period expires.
        """
        return self._delete.execute_deletion(request_id)

    def cancel_deletion(
        self,
        request_id: str,
        actor: str,
        reason: str = "user_changed_mind",
    ) -> DeletionRequest:
        """Cancel a PENDING deletion request."""
        return self._delete.cancel_deletion(request_id, actor, reason)

    def get_deletion_status(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Return a public-safe status dict for a deletion request."""
        return self._delete.get_status(request_id)

    # ------------------------------------------------------------------
    # Combined export-then-delete (convenience)
    # ------------------------------------------------------------------

    def export_then_request_deletion(
        self,
        user_id: str,
        actor: str = "user",
        reason: str = "user_request",
        ip_address: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Convenience: export the user's data then immediately create a
        deletion request.  Returns both results in a single dict.

        This mirrors the GDPR "right to be forgotten" UX where a user
        downloads their data before requesting account closure.
        """
        export_req = self.export_user_data(user_id, actor, ip_address)
        del_req    = self.request_deletion(user_id, actor, reason, ip_address=ip_address)
        return {
            "export": export_req.to_dict(),
            "deletion": del_req.to_dict(),
        }

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    def verify_audit_chain(self) -> Dict[str, Any]:
        """
        Verify the integrity of the full audit chain.

        Returns a report dict with keys:
          valid (bool), total_entries (int), details (str).
        """
        return self._audit.verify_chain()

    def get_user_audit_trail(self, user_id: str) -> List[Dict[str, Any]]:
        """Return all audit entries touching a given user (as dicts)."""
        return self._audit.get_user_trail(user_id)

    def get_audit_summary(self) -> Dict[str, Any]:
        """Return aggregate stats for the audit log."""
        return self._audit.summary_stats()

    def export_full_audit_log(self) -> str:
        """Serialise the full audit log as a JSON string."""
        return self._audit.export_full_log()

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    def user_data_exists(self, user_id: str) -> Dict[str, bool]:
        """Return which data tables still hold data for a user."""
        return {
            "profile":     self._db.get_profile(user_id) is not None,
            "payments":    len(self._db.get_payments_for_user(user_id)) > 0,
            "activities":  len(self._db.get_activities_for_user(user_id)) > 0,
            "credentials": self._db.get_credential(user_id) is not None,
        }

    def pretty_print_summary(self, user_id: str) -> None:
        """Print a formatted summary of the current state for a user."""
        exists = self.user_data_exists(user_id)
        audit  = self.get_user_audit_trail(user_id)
        chain  = self.verify_audit_chain()

        print(f"\n{'='*60}")
        print(f"  PII Workflow Summary — User: {user_id}")
        print(f"{'='*60}")
        print("\n  Data presence:")
        for table, present in exists.items():
            status = "✓ present" if present else "✗ deleted"
            print(f"    {table:<16} {status}")
        print(f"\n  Audit trail entries for user : {len(audit)}")
        print(f"  Audit chain integrity        : {'✓ valid' if chain['valid'] else '✗ BROKEN'}")
        print(f"  Total audit entries (all)    : {chain['total_entries']}")
        if audit:
            print("\n  Recent events:")
            for e in audit[-5:]:
                print(f"    [{e['timestamp']}] {e['action']}")
        print(f"{'='*60}\n")
