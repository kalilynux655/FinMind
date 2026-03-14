"""
export_service.py — GDPR-compliant PII export package generator.

Package structure (ZIP):
  export_<request_id>/
    MANIFEST.json          — metadata, record counts, SHA-256 checksums
    README.txt             — human-readable explanation
    data/
      profile.json         — UserProfile record
      payments.json        — PaymentRecord list
      activities.json      — ActivityLog list (truncated to last 1 000)
      credentials.json     — Credentials (secrets redacted)
    audit/
      audit_trail.json     — all audit events concerning this user
    pii_report/
      pii_classification.json  — PII field classification for each table
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from audit_logger import AuditLogger
from models import (
    ExportRequest,
    ExportStatus,
    InMemoryDatabase,
)
from pii_detector import PIIDetector


# Maximum activity log rows included in an export
_MAX_ACTIVITY_ROWS = 1_000

_README_TEMPLATE = """\
Your Personal Data Export
=========================
Request ID : {request_id}
User ID    : {user_id}
Requested  : {requested_at}
Generated  : {generated_at}

This archive contains all personal data held about you in our systems,
in compliance with GDPR Article 20 (Right to Data Portability).

Files
-----
data/profile.json         — Your account and contact information
data/payments.json        — Payment and billing records
data/activities.json      — Activity and usage logs (last {max_activities} entries)
data/credentials.json     — Authentication metadata (secrets are REDACTED)
audit/audit_trail.json    — Log of all privacy-related actions on your account
pii_report/               — Internal PII classification (for transparency)

MANIFEST.json             — File inventory with SHA-256 hashes

How to use this data
--------------------
All files are UTF-8 encoded JSON. You may import them into any compatible
service using the GDPR portability format.

Questions? Contact privacy@example.com
"""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _to_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, indent=2, default=str, ensure_ascii=False).encode("utf-8")


class ExportService:
    """
    Generates a structured, self-verifying ZIP export package for a user.

    Parameters
    ----------
    db            : Shared InMemoryDatabase instance.
    audit_logger  : AuditLogger for writing events.
    output_dir    : Directory (or memory) where the ZIP is 'written'.
                    Use None for in-memory only (returns bytes).
    """

    def __init__(
        self,
        db: InMemoryDatabase,
        audit_logger: AuditLogger,
        output_dir: Optional[str] = None,
    ) -> None:
        self._db = db
        self._audit = audit_logger
        self._output_dir = output_dir
        self._detector = PIIDetector()

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def request_export(
        self,
        user_id: str,
        requested_by: str = "user",
        ip_address: Optional[str] = None,
    ) -> ExportRequest:
        """
        Create and immediately fulfil an export request.

        Returns the completed ExportRequest (with package_path / package_hash).
        Raises ExportError on failure.
        """
        req = ExportRequest(
            user_id=user_id,
            requested_by=requested_by,
        )
        self._db.save_export_request(req)
        self._audit.log_export_requested(
            actor=f"{requested_by}:{user_id}",
            user_id=user_id,
            request_id=req.request_id,
            ip=ip_address,
        )

        try:
            req.status = ExportStatus.IN_PROGRESS
            self._db.save_export_request(req)

            package_bytes, manifest = self._build_package(req)
            package_hash = _sha256_bytes(package_bytes)

            # Persist or store in-memory
            package_path = self._persist_package(req.request_id, package_bytes)

            req.status       = ExportStatus.COMPLETED
            req.package_path = package_path
            req.package_hash = package_hash
            req.completed_at = _now_iso()
            self._db.save_export_request(req)

            self._audit.log_export_completed(
                user_id=user_id,
                request_id=req.request_id,
                package_path=package_path,
                package_hash=package_hash,
                record_counts=manifest["record_counts"],
            )

        except Exception as exc:
            req.status = ExportStatus.FAILED
            req.error  = str(exc)
            self._db.save_export_request(req)
            self._audit.log_export_failed(user_id, req.request_id, str(exc))
            raise ExportError(f"Export failed for user {user_id}: {exc}") from exc

        return req

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_package(
        self, req: ExportRequest,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Build the ZIP bytes and return (zip_bytes, manifest_dict)."""
        user_id = req.user_id
        buf = io.BytesIO()
        file_hashes: Dict[str, str] = {}
        record_counts: Dict[str, int] = {}

        tables_included = []

        with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:

            def _add(arc_path: str, data: bytes) -> None:
                zf.writestr(arc_path, data)
                file_hashes[arc_path] = _sha256_bytes(data)

            base = f"export_{req.request_id}"

            # ---- data/profile.json ------------------------------------
            profile = self._db.get_profile(user_id)
            if profile:
                profile_data = profile.to_dict()
                _add(f"{base}/data/profile.json", _to_json_bytes(profile_data))
                record_counts["profile"] = 1
                tables_included.append("profile")
            else:
                _add(f"{base}/data/profile.json", _to_json_bytes([]))
                record_counts["profile"] = 0

            # ---- data/payments.json -----------------------------------
            payments = self._db.get_payments_for_user(user_id)
            payments_data = [p.to_dict() for p in payments]
            _add(f"{base}/data/payments.json", _to_json_bytes(payments_data))
            record_counts["payments"] = len(payments_data)
            if payments_data:
                tables_included.append("payments")

            # ---- data/activities.json (capped) ------------------------
            activities = self._db.get_activities_for_user(user_id)
            activities_data = [a.to_dict() for a in activities[-_MAX_ACTIVITY_ROWS:]]
            _add(f"{base}/data/activities.json", _to_json_bytes(activities_data))
            record_counts["activities"] = len(activities_data)
            if activities_data:
                tables_included.append("activities")

            # ---- data/credentials.json (secrets redacted) -------------
            cred = self._db.get_credential(user_id)
            if cred:
                cred_data = cred.to_dict()   # secrets already masked in model
                _add(f"{base}/data/credentials.json", _to_json_bytes(cred_data))
                record_counts["credentials"] = 1
                tables_included.append("credentials")
            else:
                _add(f"{base}/data/credentials.json", _to_json_bytes({}))
                record_counts["credentials"] = 0

            # ---- audit/audit_trail.json --------------------------------
            user_audit = self._audit.get_user_trail(user_id)
            _add(f"{base}/audit/audit_trail.json", _to_json_bytes(user_audit))
            record_counts["audit_events"] = len(user_audit)

            # ---- pii_report/ -------------------------------------------
            pii_reports = self._build_pii_reports(
                user_id, profile, payments, activities, cred
            )
            _add(
                f"{base}/pii_report/pii_classification.json",
                _to_json_bytes(pii_reports),
            )

            # ---- README.txt -------------------------------------------
            readme = _README_TEMPLATE.format(
                request_id=req.request_id,
                user_id=user_id,
                requested_at=req.requested_at,
                generated_at=_now_iso(),
                max_activities=_MAX_ACTIVITY_ROWS,
            )
            _add(f"{base}/README.txt", readme.encode("utf-8"))

            # ---- MANIFEST.json ----------------------------------------
            manifest: Dict[str, Any] = {
                "schema_version": "1.0",
                "request_id":     req.request_id,
                "user_id":        user_id,
                "generated_at":   _now_iso(),
                "record_counts":  record_counts,
                "tables_included": tables_included,
                "files":          file_hashes,
            }
            _add(f"{base}/MANIFEST.json", _to_json_bytes(manifest))

        self._audit.log_export_started(user_id, req.request_id, tables_included)

        return buf.getvalue(), manifest

    def _build_pii_reports(
        self,
        user_id: str,
        profile: Any,
        payments: List[Any],
        activities: List[Any],
        cred: Any,
    ) -> Dict[str, Any]:
        """Run PII detection across all data tables and return aggregated report."""
        reports: Dict[str, Any] = {}

        if profile:
            r = self._detector.scan(profile.to_dict(), "UserProfile")
            reports["profile"] = r.to_dict()

        if payments:
            payment_reports = self._detector.scan_multiple(
                [p.to_dict() for p in payments], "PaymentRecord"
            )
            reports["payments"] = [r.to_dict() for r in payment_reports]

        if activities:
            activity_reports = self._detector.scan_multiple(
                [a.to_dict() for a in activities[:10]], "ActivityLog"  # sample
            )
            reports["activities_sample"] = [r.to_dict() for r in activity_reports]

        if cred:
            r = self._detector.scan(cred.to_dict(), "UserCredential")
            reports["credentials"] = r.to_dict()

        return reports

    def _persist_package(self, request_id: str, package_bytes: bytes) -> str:
        """
        'Persist' the package.

        In production: upload to encrypted S3 bucket / Azure Blob with a
        pre-signed URL valid for 24 h.  Here we return a logical path string.
        """
        if self._output_dir:
            import os
            os.makedirs(self._output_dir, exist_ok=True)
            path = os.path.join(self._output_dir, f"export_{request_id}.zip")
            with open(path, "wb") as fh:
                fh.write(package_bytes)
            return path
        # In-memory mode — return a virtual path
        return f"memory://exports/export_{request_id}.zip"

    def get_package_bytes(self, request_id: str) -> Optional[bytes]:
        """
        Retrieve the raw ZIP bytes for a completed export (in-memory mode).
        In production, this would generate a signed download URL.
        """
        req = self._db.export_requests.get(request_id)
        if not req or req.status != ExportStatus.COMPLETED:
            return None
        # Re-build (idempotent) for in-memory mode
        try:
            package_bytes, _ = self._build_package(req)
            return package_bytes
        except Exception:
            return None


class ExportError(Exception):
    """Raised when export package generation fails."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
