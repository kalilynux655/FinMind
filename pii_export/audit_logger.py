"""
audit_logger.py — Immutable, tamper-evident audit trail.

Design:
  • Append-only log stored in the InMemoryDatabase (swap for a write-once
    store / WORM log in production).
  • Each entry is SHA-256 chained: entry_hash = SHA256(payload + prev_hash).
  • verify_chain() validates the entire log has not been altered.
  • Structured JSON export for SIEM / compliance tools.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models import AuditAction, AuditLogEntry, InMemoryDatabase

logger = logging.getLogger(__name__)


class ChainIntegrityError(Exception):
    """Raised when the audit chain hash verification fails."""


class AuditLogger:
    """
    Thread-safe (append) audit logger with hash-chaining.

    Parameters
    ----------
    db : InMemoryDatabase
        Shared database reference used to persist entries.
    service_name : str
        Identifies the component writing entries (e.g. 'export-service').
    """

    GENESIS_HASH = "0" * 64  # sentinel previous hash for the first entry

    def __init__(self, db: InMemoryDatabase, service_name: str = "pii-workflow") -> None:
        self._db = db
        self._service = service_name

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _last_hash(self) -> str:
        """Return the hash of the most recently appended entry."""
        if not self._db.audit_log:
            return self.GENESIS_HASH
        return self._db.audit_log[-1].entry_hash

    def _build_entry(
        self,
        action: AuditAction,
        actor: str,
        user_id: str,
        request_id: str,
        details: Dict[str, Any],
        ip_address: Optional[str],
    ) -> AuditLogEntry:
        entry = AuditLogEntry(
            action=action,
            actor=actor,
            user_id=user_id,
            request_id=request_id,
            details=details,
            ip_address=ip_address,
            prev_hash=self._last_hash(),
        )
        entry.seal()
        return entry

    # ------------------------------------------------------------------
    # Public logging methods
    # ------------------------------------------------------------------

    def log(
        self,
        action: AuditAction,
        actor: str,
        user_id: str,
        request_id: str = "",
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> AuditLogEntry:
        """
        Append a new audit entry to the chain.

        Parameters
        ----------
        action      : The event type.
        actor       : Who performed the action ("user:<id>", "system", "admin:<id>").
        user_id     : The data subject (whose PII is affected).
        request_id  : Optional export / deletion request ID.
        details     : Arbitrary structured detail payload.
        ip_address  : Client IP, if available.

        Returns the sealed AuditLogEntry.
        """
        entry = self._build_entry(
            action=action,
            actor=actor,
            user_id=user_id,
            request_id=request_id,
            details=details or {},
            ip_address=ip_address,
        )
        self._db.append_audit(entry)
        logger.info(
            "[AUDIT] %s | actor=%s | user=%s | req=%s | hash=%s…",
            action.value, actor, user_id, request_id, entry.entry_hash[:12],
        )
        return entry

    # -- Convenience wrappers for common events -------------------------

    def log_export_requested(self, actor: str, user_id: str, request_id: str,
                              ip: Optional[str] = None) -> AuditLogEntry:
        return self.log(AuditAction.EXPORT_REQUESTED, actor, user_id,
                        request_id, {"event": "User data export requested"}, ip)

    def log_export_started(self, user_id: str, request_id: str,
                            tables: List[str]) -> AuditLogEntry:
        return self.log(AuditAction.EXPORT_STARTED, "system", user_id,
                        request_id, {"tables_included": tables})

    def log_export_completed(self, user_id: str, request_id: str,
                              package_path: str, package_hash: str,
                              record_counts: Dict[str, int]) -> AuditLogEntry:
        return self.log(AuditAction.EXPORT_COMPLETED, "system", user_id,
                        request_id, {
                            "package_path": package_path,
                            "package_sha256": package_hash,
                            "record_counts": record_counts,
                        })

    def log_export_failed(self, user_id: str, request_id: str,
                           error: str) -> AuditLogEntry:
        return self.log(AuditAction.EXPORT_FAILED, "system", user_id,
                        request_id, {"error": error})

    def log_delete_requested(self, actor: str, user_id: str, request_id: str,
                              reason: str, ip: Optional[str] = None) -> AuditLogEntry:
        return self.log(AuditAction.DELETE_REQUESTED, actor, user_id,
                        request_id, {"reason": reason}, ip)

    def log_delete_token_issued(self, user_id: str, request_id: str,
                                 token_preview: str,
                                 expires_at: str) -> AuditLogEntry:
        return self.log(AuditAction.DELETE_TOKEN_ISSUED, "system", user_id,
                        request_id, {
                            "token_preview": token_preview,  # first 8 chars only
                            "expires_at": expires_at,
                        })

    def log_delete_confirmed(self, actor: str, user_id: str,
                              request_id: str,
                              ip: Optional[str] = None) -> AuditLogEntry:
        return self.log(AuditAction.DELETE_CONFIRMED, actor, user_id,
                        request_id, {"event": "Deletion confirmed by actor"}, ip)

    def log_delete_started(self, user_id: str, request_id: str,
                            tables: List[str]) -> AuditLogEntry:
        return self.log(AuditAction.DELETE_STARTED, "system", user_id,
                        request_id, {"tables_targeted": tables})

    def log_delete_completed(self, user_id: str, request_id: str,
                              deleted: int, anonymised: int) -> AuditLogEntry:
        return self.log(AuditAction.DELETE_COMPLETED, "system", user_id,
                        request_id, {
                            "records_deleted": deleted,
                            "records_anonymised": anonymised,
                        })

    def log_delete_failed(self, user_id: str, request_id: str,
                           error: str) -> AuditLogEntry:
        return self.log(AuditAction.DELETE_FAILED, "system", user_id,
                        request_id, {"error": error})

    def log_delete_cancelled(self, actor: str, user_id: str,
                              request_id: str, reason: str) -> AuditLogEntry:
        return self.log(AuditAction.DELETE_CANCELLED, actor, user_id,
                        request_id, {"reason": reason})

    def log_field_redacted(self, user_id: str, request_id: str,
                            table: str, field: str) -> AuditLogEntry:
        return self.log(AuditAction.PII_FIELD_REDACTED, "system", user_id,
                        request_id, {"table": table, "field": field})

    def log_field_deleted(self, user_id: str, request_id: str,
                           table: str, field: str) -> AuditLogEntry:
        return self.log(AuditAction.PII_FIELD_DELETED, "system", user_id,
                        request_id, {"table": table, "field": field})

    def log_record_anonymised(self, user_id: str, request_id: str,
                               table: str, record_id: str) -> AuditLogEntry:
        return self.log(AuditAction.RECORD_ANONYMISED, "system", user_id,
                        request_id, {"table": table, "record_id": record_id})

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_chain(self) -> Dict[str, Any]:
        """
        Verify the integrity of the entire audit chain.

        Returns a report dict with:
          - valid (bool)
          - total_entries (int)
          - first_broken_index (int | None)
          - details (str)
        """
        entries = self._db.audit_log
        if not entries:
            return {"valid": True, "total_entries": 0,
                    "first_broken_index": None, "details": "Empty log."}

        prev_hash = self.GENESIS_HASH

        for idx, entry in enumerate(entries):
            # Re-compute what the hash should be
            expected_hash = entry.compute_hash()

            if entry.entry_hash != expected_hash:
                return {
                    "valid": False,
                    "total_entries": len(entries),
                    "first_broken_index": idx,
                    "details": (
                        f"Entry {idx} ({entry.entry_id}) hash mismatch. "
                        f"Stored: {entry.entry_hash[:16]}… "
                        f"Expected: {expected_hash[:16]}…"
                    ),
                }

            if entry.prev_hash != prev_hash:
                return {
                    "valid": False,
                    "total_entries": len(entries),
                    "first_broken_index": idx,
                    "details": (
                        f"Entry {idx} ({entry.entry_id}) prev_hash broken. "
                        f"Stored: {entry.prev_hash[:16]}… "
                        f"Expected: {prev_hash[:16]}…"
                    ),
                }

            prev_hash = entry.entry_hash

        return {
            "valid": True,
            "total_entries": len(entries),
            "first_broken_index": None,
            "details": f"All {len(entries)} entries verified successfully.",
        }

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def get_user_trail(self, user_id: str) -> List[Dict[str, Any]]:
        """Return all audit entries for a specific user as serialisable dicts."""
        return [e.to_dict() for e in self._db.get_audit_for_user(user_id)]

    def export_full_log(self) -> str:
        """Serialise the entire audit log to a JSON string."""
        return json.dumps(
            [e.to_dict() for e in self._db.audit_log],
            indent=2,
            default=str,
        )

    def summary_stats(self) -> Dict[str, Any]:
        """Return high-level stats about the audit log."""
        entries = self._db.audit_log
        action_counts: Dict[str, int] = {}
        user_counts:   Dict[str, int] = {}

        for e in entries:
            action_counts[e.action.value] = action_counts.get(e.action.value, 0) + 1
            user_counts[e.user_id] = user_counts.get(e.user_id, 0) + 1

        return {
            "total_entries":  len(entries),
            "action_counts":  action_counts,
            "unique_users":   len(user_counts),
            "user_event_counts": user_counts,
        }
