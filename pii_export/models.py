"""
models.py — Core data models for the PII Export & Delete Workflow.

Defines User, associated PII data tables, and AuditLogEntry using
pure Python dataclasses (no external ORM dependency required).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class DataCategory(str, Enum):
    """GDPR Article 4 — categories of personal data."""
    IDENTITY        = "identity"          # name, DOB, national ID
    CONTACT         = "contact"           # email, phone, address
    FINANCIAL       = "financial"         # card numbers, IBAN, transactions
    BEHAVIOURAL     = "behavioural"       # activity logs, preferences
    SENSITIVE       = "sensitive"         # health, biometric, political views
    CREDENTIALS     = "credentials"       # hashed passwords, tokens
    TECHNICAL       = "technical"         # IP addresses, device IDs, cookies


class DeletionStatus(str, Enum):
    PENDING     = "pending"
    CONFIRMED   = "confirmed"
    IN_PROGRESS = "in_progress"
    COMPLETED   = "completed"
    FAILED      = "failed"


class ExportStatus(str, Enum):
    REQUESTED   = "requested"
    IN_PROGRESS = "in_progress"
    COMPLETED   = "completed"
    FAILED      = "failed"


class AuditAction(str, Enum):
    EXPORT_REQUESTED    = "EXPORT_REQUESTED"
    EXPORT_STARTED      = "EXPORT_STARTED"
    EXPORT_COMPLETED    = "EXPORT_COMPLETED"
    EXPORT_FAILED       = "EXPORT_FAILED"
    DELETE_REQUESTED    = "DELETE_REQUESTED"
    DELETE_TOKEN_ISSUED = "DELETE_TOKEN_ISSUED"
    DELETE_CONFIRMED    = "DELETE_CONFIRMED"
    DELETE_STARTED      = "DELETE_STARTED"
    DELETE_COMPLETED    = "DELETE_COMPLETED"
    DELETE_FAILED       = "DELETE_FAILED"
    DELETE_CANCELLED    = "DELETE_CANCELLED"
    PII_FIELD_REDACTED  = "PII_FIELD_REDACTED"
    PII_FIELD_DELETED   = "PII_FIELD_DELETED"
    RECORD_ANONYMISED   = "RECORD_ANONYMISED"


# ---------------------------------------------------------------------------
# PII Data Records (simulate various data stores)
# ---------------------------------------------------------------------------

@dataclass
class UserProfile:
    """Core identity & contact data."""
    user_id:      str
    full_name:    str
    email:        str
    phone:        Optional[str]       = None
    date_of_birth: Optional[str]      = None   # ISO-8601
    national_id:  Optional[str]       = None
    address:      Optional[Dict[str, str]] = None  # street/city/postcode/country
    created_at:   str = field(default_factory=lambda: _now_iso())
    updated_at:   str = field(default_factory=lambda: _now_iso())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PaymentRecord:
    """Financial / payment data."""
    record_id:      str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id:        str = ""
    card_last4:     str = ""
    card_brand:     str = ""
    billing_name:   str = ""
    billing_address: Optional[Dict[str, str]] = None
    transaction_ids: List[str] = field(default_factory=list)
    created_at:     str = field(default_factory=lambda: _now_iso())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ActivityLog:
    """Behavioural / usage data."""
    log_id:      str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id:     str = ""
    ip_address:  str = ""
    user_agent:  str = ""
    action:      str = ""
    resource:    str = ""
    timestamp:   str = field(default_factory=lambda: _now_iso())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UserCredential:
    """Credential / authentication data."""
    user_id:         str
    password_hash:   str
    salt:            str
    mfa_secret:      Optional[str]   = None
    recovery_codes:  List[str]       = field(default_factory=list)
    last_login:      Optional[str]   = None
    created_at:      str = field(default_factory=lambda: _now_iso())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Never expose raw secrets in exports — mask them
        d["password_hash"] = "[REDACTED]"
        d["salt"]          = "[REDACTED]"
        d["mfa_secret"]    = "[REDACTED]" if d["mfa_secret"] else None
        d["recovery_codes"] = ["[REDACTED]"] * len(d["recovery_codes"])
        return d


# ---------------------------------------------------------------------------
# Workflow state models
# ---------------------------------------------------------------------------

@dataclass
class ExportRequest:
    request_id:  str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id:     str = ""
    requested_at: str = field(default_factory=lambda: _now_iso())
    status:      ExportStatus = ExportStatus.REQUESTED
    package_path: Optional[str] = None
    package_hash: Optional[str] = None   # SHA-256 of the ZIP
    completed_at: Optional[str] = None
    error:        Optional[str] = None
    requested_by: str = ""               # "user" | "admin" | "legal"

    def to_dict(self) -> Dict[str, Any]:
        return {k: (v.value if isinstance(v, Enum) else v)
                for k, v in asdict(self).items()}


@dataclass
class DeletionRequest:
    request_id:     str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id:        str = ""
    requested_at:   str = field(default_factory=lambda: _now_iso())
    status:         DeletionStatus = DeletionStatus.PENDING
    confirmation_token: Optional[str] = None
    token_expires_at:   Optional[str] = None
    confirmed_at:       Optional[str] = None
    completed_at:       Optional[str] = None
    deleted_record_count: int = 0
    anonymised_record_count: int = 0
    error:          Optional[str] = None
    requested_by:   str = ""
    reason:         str = ""  # "user_request" | "legal_hold" | "admin"
    grace_period_days: int = 30

    def to_dict(self) -> Dict[str, Any]:
        return {k: (v.value if isinstance(v, Enum) else v)
                for k, v in asdict(self).items()}


# ---------------------------------------------------------------------------
# Audit log entry (append-only, chained)
# ---------------------------------------------------------------------------

@dataclass
class AuditLogEntry:
    """
    Immutable audit log entry with SHA-256 chaining for tamper evidence.

    Each entry hashes its own content + the previous entry's hash to form
    a verifiable chain (similar to a blockchain / CT log).
    """
    entry_id:     str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:    str = field(default_factory=lambda: _now_iso())
    action:       AuditAction = AuditAction.EXPORT_REQUESTED
    actor:        str = ""          # who triggered the action
    user_id:      str = ""          # subject whose data is affected
    request_id:   str = ""          # export or deletion request ID
    details:      Dict[str, Any] = field(default_factory=dict)
    ip_address:   Optional[str] = None
    prev_hash:    str = ""          # hash of previous entry in chain
    entry_hash:   str = ""          # computed hash of *this* entry

    # ------------------------------------------------------------------
    def compute_hash(self) -> str:
        """
        Compute the SHA-256 hash of this entry's canonical payload.
        Called after all fields are set (including prev_hash).
        """
        payload = {
            "entry_id":   self.entry_id,
            "timestamp":  self.timestamp,
            "action":     self.action.value,
            "actor":      self.actor,
            "user_id":    self.user_id,
            "request_id": self.request_id,
            "details":    self.details,
            "ip_address": self.ip_address,
            "prev_hash":  self.prev_hash,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def seal(self) -> "AuditLogEntry":
        """Finalise the entry by computing and storing its own hash."""
        self.entry_hash = self.compute_hash()
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {k: (v.value if isinstance(v, Enum) else v)
                for k, v in asdict(self).items()}


# ---------------------------------------------------------------------------
# In-memory "database" (acts as a thin repository layer)
# ---------------------------------------------------------------------------

class InMemoryDatabase:
    """
    Simulated multi-table database.
    In production, replace each dict with the corresponding ORM/SQL table.
    """

    def __init__(self) -> None:
        self.profiles:     Dict[str, UserProfile]     = {}
        self.payments:     Dict[str, PaymentRecord]   = {}  # key = record_id
        self.activities:   Dict[str, ActivityLog]     = {}  # key = log_id
        self.credentials:  Dict[str, UserCredential]  = {}  # key = user_id
        self.export_requests:   Dict[str, ExportRequest]   = {}
        self.deletion_requests: Dict[str, DeletionRequest] = {}
        self.audit_log:    List[AuditLogEntry]         = []

    # -- profiles ----------------------------------------------------------
    def add_profile(self, profile: UserProfile) -> None:
        self.profiles[profile.user_id] = profile

    def get_profile(self, user_id: str) -> Optional[UserProfile]:
        return self.profiles.get(user_id)

    # -- payments ----------------------------------------------------------
    def add_payment(self, record: PaymentRecord) -> None:
        self.payments[record.record_id] = record

    def get_payments_for_user(self, user_id: str) -> List[PaymentRecord]:
        return [r for r in self.payments.values() if r.user_id == user_id]

    # -- activities --------------------------------------------------------
    def add_activity(self, log: ActivityLog) -> None:
        self.activities[log.log_id] = log

    def get_activities_for_user(self, user_id: str) -> List[ActivityLog]:
        return [a for a in self.activities.values() if a.user_id == user_id]

    # -- credentials -------------------------------------------------------
    def add_credential(self, cred: UserCredential) -> None:
        self.credentials[cred.user_id] = cred

    def get_credential(self, user_id: str) -> Optional[UserCredential]:
        return self.credentials.get(user_id)

    # -- requests ----------------------------------------------------------
    def save_export_request(self, req: ExportRequest) -> None:
        self.export_requests[req.request_id] = req

    def save_deletion_request(self, req: DeletionRequest) -> None:
        self.deletion_requests[req.request_id] = req

    def get_deletion_request(self, request_id: str) -> Optional[DeletionRequest]:
        return self.deletion_requests.get(request_id)

    # -- audit -------------------------------------------------------------
    def append_audit(self, entry: AuditLogEntry) -> None:
        self.audit_log.append(entry)

    def get_audit_for_user(self, user_id: str) -> List[AuditLogEntry]:
        return [e for e in self.audit_log if e.user_id == user_id]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
