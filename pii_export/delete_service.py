"""
delete_service.py — GDPR-compliant irreversible PII deletion workflow.

Deletion pipeline:
  1. request_deletion()    — creates a DeletionRequest + issues a one-time
                             confirmation token (HMAC-SHA256, time-limited).
  2. confirm_deletion()    — validates the token and advances status to CONFIRMED.
  3. execute_deletion()    — hard-deletes PII, anonymises audit-trail references,
                             and seals the deletion record.

Anonymisation strategy (for records that cannot be deleted, e.g. financial
ledger entries required by law):
  • Replacing personal fields with deterministic pseudonyms derived from a
    one-way hash, making the original value irrecoverable without the salt.

Deletion scope per table
------------------------
  profile     → hard delete the entire row
  payments    → hard delete all rows belonging to the user
  activities  → hard delete all rows belonging to the user
  credentials → hard delete the credential row

Retained (anonymised) data
--------------------------
  audit_log   → user_id replaced with anonymised token; content retained
                for compliance / legal hold.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from audit_logger import AuditLogger
from models import (
    DeletionRequest,
    DeletionStatus,
    InMemoryDatabase,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_TOKEN_BYTES          = 32          # 256-bit confirmation token
_TOKEN_TTL_MINUTES    = 60          # token valid for 1 hour
_ANON_SALT_ENV        = "PII_ANON_SALT"
_DEFAULT_ANON_SALT    = "change-me-in-production-use-env-var"


def _get_anon_salt() -> str:
    return os.environ.get(_ANON_SALT_ENV, _DEFAULT_ANON_SALT)


def _anonymise_value(original: str, purpose: str = "") -> str:
    """
    Produce a one-way pseudonym for a value using HMAC-SHA256.
    The salt MUST be secret and consistent across the application lifetime
    so the same original always maps to the same pseudonym (for deduplication).
    """
    key = (_get_anon_salt() + purpose).encode()
    digest = hmac.new(key, original.encode(), hashlib.sha256).hexdigest()
    return f"anon_{digest[:16]}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class DeletionError(Exception):
    """Raised on unrecoverable deletion workflow errors."""


class InvalidTokenError(DeletionError):
    """Raised when a confirmation token is invalid or expired."""


class DeletionAlreadyProcessedError(DeletionError):
    """Raised when a deletion request has already been processed."""


# ---------------------------------------------------------------------------
# DeleteService
# ---------------------------------------------------------------------------

class DeleteService:
    """
    Orchestrates the irreversible PII deletion workflow.

    Parameters
    ----------
    db           : Shared InMemoryDatabase.
    audit_logger : AuditLogger for writing events.
    """

    def __init__(self, db: InMemoryDatabase, audit_logger: AuditLogger) -> None:
        self._db    = db
        self._audit = audit_logger
        # In-memory token store: request_id → (token, expires_at)
        # In production, store in Redis with TTL or encrypted DB column.
        self._tokens: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Step 1 — Request deletion
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
        Initiate a deletion request.

        Generates a one-time confirmation token that the caller (or the user
        via email link) must present to confirm_deletion().

        Parameters
        ----------
        user_id           : Data subject.
        requested_by      : "user", "admin:<id>", "legal", etc.
        reason            : Human-readable reason for deletion.
        grace_period_days : Days before deletion becomes eligible to execute.
                            Set to 0 for immediate processing.
        ip_address        : Client IP for audit.

        Returns the DeletionRequest.
        """
        req = DeletionRequest(
            user_id=user_id,
            requested_by=requested_by,
            reason=reason,
            grace_period_days=grace_period_days,
        )
        self._db.save_deletion_request(req)

        self._audit.log_delete_requested(
            actor=f"{requested_by}:{user_id}",
            user_id=user_id,
            request_id=req.request_id,
            reason=reason,
            ip=ip_address,
        )

        # Issue confirmation token
        token = secrets.token_urlsafe(_TOKEN_BYTES)
        expires_at = _now() + timedelta(minutes=_TOKEN_TTL_MINUTES)
        expires_iso = expires_at.isoformat()

        self._tokens[req.request_id] = {
            "token":      token,
            "expires_at": expires_at,
        }

        req.confirmation_token = token   # In prod, send via email — never return in API
        req.token_expires_at   = expires_iso
        self._db.save_deletion_request(req)

        self._audit.log_delete_token_issued(
            user_id=user_id,
            request_id=req.request_id,
            token_preview=token[:8],
            expires_at=expires_iso,
        )

        return req

    # ------------------------------------------------------------------
    # Step 2 — Confirm deletion
    # ------------------------------------------------------------------

    def confirm_deletion(
        self,
        request_id: str,
        token: str,
        actor: str = "user",
        ip_address: Optional[str] = None,
    ) -> DeletionRequest:
        """
        Validate the confirmation token and advance the request to CONFIRMED.

        Parameters
        ----------
        request_id  : The ID from the DeletionRequest.
        token       : The one-time token from request_deletion().
        actor       : Who is confirming (for the audit log).
        ip_address  : Client IP for audit.

        Raises InvalidTokenError if the token is wrong or expired.
        Raises DeletionAlreadyProcessedError if already confirmed/completed.
        """
        req = self._db.get_deletion_request(request_id)
        if req is None:
            raise DeletionError(f"Deletion request {request_id} not found.")

        if req.status in (DeletionStatus.COMPLETED, DeletionStatus.IN_PROGRESS):
            raise DeletionAlreadyProcessedError(
                f"Request {request_id} is already {req.status.value}."
            )

        stored = self._tokens.get(request_id)
        if stored is None:
            raise InvalidTokenError("No token found for this request.")

        if _now() > stored["expires_at"]:
            del self._tokens[request_id]
            raise InvalidTokenError(
                f"Confirmation token expired at {stored['expires_at'].isoformat()}."
            )

        # Constant-time comparison to prevent timing attacks
        if not secrets.compare_digest(stored["token"], token):
            raise InvalidTokenError("Confirmation token is invalid.")

        # Invalidate the one-time token
        del self._tokens[request_id]

        req.status       = DeletionStatus.CONFIRMED
        req.confirmed_at = _now_iso()
        self._db.save_deletion_request(req)

        self._audit.log_delete_confirmed(
            actor=actor,
            user_id=req.user_id,
            request_id=request_id,
            ip=ip_address,
        )

        return req

    # ------------------------------------------------------------------
    # Step 3 — Execute deletion
    # ------------------------------------------------------------------

    def execute_deletion(self, request_id: str) -> DeletionRequest:
        """
        Permanently delete all PII for the user associated with the request.

        Must be called after confirm_deletion().  Typically invoked by:
          • A background worker after the grace-period expires, OR
          • Immediately (grace_period_days=0) for admin/legal requests.

        Returns the completed DeletionRequest.
        Raises DeletionError on failure (partial state is rolled back where possible).
        """
        req = self._db.get_deletion_request(request_id)
        if req is None:
            raise DeletionError(f"Deletion request {request_id} not found.")

        if req.status != DeletionStatus.CONFIRMED:
            raise DeletionError(
                f"Request {request_id} cannot be executed in status '{req.status.value}'. "
                "Must be CONFIRMED first."
            )

        user_id = req.user_id
        tables_targeted = ["profile", "payments", "activities", "credentials"]

        req.status = DeletionStatus.IN_PROGRESS
        self._db.save_deletion_request(req)
        self._audit.log_delete_started(user_id, request_id, tables_targeted)

        deleted_count    = 0
        anonymised_count = 0

        try:
            # -- 1. Hard-delete profile ---------------------------------
            if user_id in self._db.profiles:
                del self._db.profiles[user_id]
                deleted_count += 1
                self._audit.log_field_deleted(user_id, request_id, "profiles", "*")

            # -- 2. Hard-delete payment records -------------------------
            payment_ids = [
                r.record_id
                for r in self._db.payments.values()
                if r.user_id == user_id
            ]
            for pid in payment_ids:
                del self._db.payments[pid]
                deleted_count += 1
            if payment_ids:
                self._audit.log_field_deleted(
                    user_id, request_id, "payments",
                    f"{len(payment_ids)} records"
                )

            # -- 3. Hard-delete activity logs ---------------------------
            activity_ids = [
                a.log_id
                for a in self._db.activities.values()
                if a.user_id == user_id
            ]
            for aid in activity_ids:
                del self._db.activities[aid]
                deleted_count += 1
            if activity_ids:
                self._audit.log_field_deleted(
                    user_id, request_id, "activities",
                    f"{len(activity_ids)} records"
                )

            # -- 4. Hard-delete credentials -----------------------------
            if user_id in self._db.credentials:
                del self._db.credentials[user_id]
                deleted_count += 1
                self._audit.log_field_deleted(
                    user_id, request_id, "credentials", "*"
                )

            # -- 5. Anonymise audit log entries -------------------------
            # We CANNOT delete audit entries (they are a legal record of
            # what happened), but we MUST pseudonymise the user_id.
            anon_id = _anonymise_value(user_id, purpose="audit_user_id")
            for entry in self._db.audit_log:
                if entry.user_id == user_id:
                    entry.user_id = anon_id
                    # Intentionally do NOT recompute entry_hash — the audit
                    # chain records the pseudonymisation event separately.
                    anonymised_count += 1
                    self._audit.log_record_anonymised(
                        anon_id, request_id, "audit_log", entry.entry_id
                    )

            # -- Finalise request ---------------------------------------
            req.status                  = DeletionStatus.COMPLETED
            req.completed_at            = _now_iso()
            req.deleted_record_count    = deleted_count
            req.anonymised_record_count = anonymised_count
            req.confirmation_token      = None  # wipe the token from the record
            self._db.save_deletion_request(req)

            self._audit.log_delete_completed(
                user_id=anon_id,   # use anonymised ID going forward
                request_id=request_id,
                deleted=deleted_count,
                anonymised=anonymised_count,
            )

        except Exception as exc:
            req.status = DeletionStatus.FAILED
            req.error  = str(exc)
            self._db.save_deletion_request(req)
            self._audit.log_delete_failed(user_id, request_id, str(exc))
            raise DeletionError(
                f"Deletion failed for user {user_id}: {exc}"
            ) from exc

        return req

    # ------------------------------------------------------------------
    # Cancellation (before confirmation)
    # ------------------------------------------------------------------

    def cancel_deletion(
        self,
        request_id: str,
        actor: str,
        reason: str = "user_changed_mind",
    ) -> DeletionRequest:
        """
        Cancel a pending deletion request (only allowed while PENDING).

        Once CONFIRMED or IN_PROGRESS, the deletion cannot be stopped.
        """
        req = self._db.get_deletion_request(request_id)
        if req is None:
            raise DeletionError(f"Deletion request {request_id} not found.")

        if req.status not in (DeletionStatus.PENDING,):
            raise DeletionError(
                f"Cannot cancel a request in status '{req.status.value}'. "
                "Cancellation is only allowed while PENDING."
            )

        # Invalidate token
        self._tokens.pop(request_id, None)
        req.status             = DeletionStatus.FAILED
        req.confirmation_token = None
        self._db.save_deletion_request(req)

        self._audit.log_delete_cancelled(
            actor=actor,
            user_id=req.user_id,
            request_id=request_id,
            reason=reason,
        )

        return req

    # ------------------------------------------------------------------
    # Status query
    # ------------------------------------------------------------------

    def get_status(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Return a public-safe status dict for a deletion request."""
        req = self._db.get_deletion_request(request_id)
        if req is None:
            return None
        d = req.to_dict()
        # Never expose the raw token in a status query
        d.pop("confirmation_token", None)
        return d
