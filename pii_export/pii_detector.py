"""
pii_detector.py — PII field classification engine.

Identifies and classifies PII fields within arbitrary dicts using:
  1. Known field-name patterns (fast lookup).
  2. Regex-based value scanning for common PII formats.
  3. Confidence scoring so callers can apply risk-appropriate handling.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from models import DataCategory


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    LOW      = "low"       # pseudonymised / indirectly identifying
    MEDIUM   = "medium"    # directly identifying but not sensitive
    HIGH     = "high"      # sensitive / financial / credentials
    CRITICAL = "critical"  # e.g. SSN, full card PAN, biometric


# ---------------------------------------------------------------------------
# Detection result
# ---------------------------------------------------------------------------

@dataclass
class PIIField:
    """Describes a single detected PII field."""
    field_path:  str               # dot-notation path, e.g. "address.postcode"
    category:    DataCategory
    risk_level:  RiskLevel
    confidence:  float             # 0.0 – 1.0
    match_reason: str              # human-readable explanation
    sample_value: Optional[str] = None  # redacted preview (first 4 chars + ***)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field_path":   self.field_path,
            "category":     self.category.value,
            "risk_level":   self.risk_level.value,
            "confidence":   self.confidence,
            "match_reason": self.match_reason,
            "sample_value": self.sample_value,
        }


@dataclass
class PIIReport:
    """Aggregated report for a complete record."""
    record_type:   str
    total_fields:  int
    pii_fields:    List[PIIField]
    overall_risk:  RiskLevel

    @property
    def pii_field_count(self) -> int:
        return len(self.pii_fields)

    @property
    def has_critical(self) -> bool:
        return any(f.risk_level == RiskLevel.CRITICAL for f in self.pii_fields)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type":    self.record_type,
            "total_fields":   self.total_fields,
            "pii_field_count": self.pii_field_count,
            "overall_risk":   self.overall_risk.value,
            "pii_fields":     [f.to_dict() for f in self.pii_fields],
        }


# ---------------------------------------------------------------------------
# Known field-name → (category, risk) mapping
# ---------------------------------------------------------------------------

_FIELD_NAME_MAP: List[Tuple[re.Pattern, DataCategory, RiskLevel, str]] = [
    # Identity
    (re.compile(r"\b(full_?name|first_?name|last_?name|surname|given_?name|display_?name)\b", re.I),
     DataCategory.IDENTITY, RiskLevel.MEDIUM, "name field"),
    (re.compile(r"\b(dob|date_of_birth|birth_?date|birthday)\b", re.I),
     DataCategory.IDENTITY, RiskLevel.HIGH, "date of birth field"),
    (re.compile(r"\b(national_?id|ssn|social_?security|passport|tax_?id|nin|nino)\b", re.I),
     DataCategory.IDENTITY, RiskLevel.CRITICAL, "government ID field"),
    (re.compile(r"\b(gender|sex|ethnicity|race|religion|political_?view|sexual_?orientation)\b", re.I),
     DataCategory.SENSITIVE, RiskLevel.CRITICAL, "sensitive attribute field"),

    # Contact
    (re.compile(r"\b(email|e_?mail|email_?address)\b", re.I),
     DataCategory.CONTACT, RiskLevel.MEDIUM, "email field"),
    (re.compile(r"\b(phone|telephone|mobile|cell|fax|tel)\b", re.I),
     DataCategory.CONTACT, RiskLevel.MEDIUM, "phone field"),
    (re.compile(r"\b(address|street|city|postcode|zip_?code|postal_?code|country)\b", re.I),
     DataCategory.CONTACT, RiskLevel.MEDIUM, "address field"),

    # Financial
    (re.compile(r"\b(card_?number|pan|credit_?card|debit_?card|card_?no)\b", re.I),
     DataCategory.FINANCIAL, RiskLevel.CRITICAL, "payment card field"),
    (re.compile(r"\b(card_?last4|last_?4|last_?four)\b", re.I),
     DataCategory.FINANCIAL, RiskLevel.MEDIUM, "partial card field"),
    (re.compile(r"\b(iban|bic|sort_?code|account_?number|routing_?number|bank_?account)\b", re.I),
     DataCategory.FINANCIAL, RiskLevel.HIGH, "bank account field"),
    (re.compile(r"\b(billing_?name|billing_?address)\b", re.I),
     DataCategory.FINANCIAL, RiskLevel.MEDIUM, "billing detail field"),

    # Credentials
    (re.compile(r"\b(password|passwd|pwd|secret|api_?key|token|auth_?token|refresh_?token|mfa_?secret|recovery_?code)\b", re.I),
     DataCategory.CREDENTIALS, RiskLevel.CRITICAL, "credential field"),
    (re.compile(r"\b(password_?hash|hashed_?pw|salt)\b", re.I),
     DataCategory.CREDENTIALS, RiskLevel.HIGH, "hashed credential field"),

    # Technical
    (re.compile(r"\b(ip_?address|ipv4|ipv6|ip)\b", re.I),
     DataCategory.TECHNICAL, RiskLevel.LOW, "IP address field"),
    (re.compile(r"\b(user_?agent|device_?id|fingerprint|cookie|session_?id)\b", re.I),
     DataCategory.TECHNICAL, RiskLevel.LOW, "device/session field"),

    # Behavioural
    (re.compile(r"\b(preference|setting|behaviour|activity|event|click|view)\b", re.I),
     DataCategory.BEHAVIOURAL, RiskLevel.LOW, "behavioural field"),
]


# ---------------------------------------------------------------------------
# Regex value scanners
# ---------------------------------------------------------------------------

_VALUE_PATTERNS: List[Tuple[re.Pattern, DataCategory, RiskLevel, str]] = [
    (re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$"),
     DataCategory.CONTACT, RiskLevel.MEDIUM, "email value pattern"),
    (re.compile(r"^\+?[\d\s\-().]{7,20}$"),
     DataCategory.CONTACT, RiskLevel.MEDIUM, "phone number value pattern"),
    (re.compile(r"^\d{3}-\d{2}-\d{4}$"),
     DataCategory.IDENTITY, RiskLevel.CRITICAL, "SSN value pattern"),
    (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"),
     DataCategory.FINANCIAL, RiskLevel.CRITICAL, "payment card PAN value pattern"),
    (re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b"),
     DataCategory.FINANCIAL, RiskLevel.HIGH, "IBAN value pattern"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
     DataCategory.TECHNICAL, RiskLevel.LOW, "IPv4 value pattern"),
    (re.compile(r"^\d{4}-\d{2}-\d{2}$"),
     DataCategory.IDENTITY, RiskLevel.MEDIUM, "date value pattern"),
]

# Risk ordering for aggregation
_RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


def _redact_sample(value: Any) -> Optional[str]:
    """Return a safely redacted preview: first 2 chars + ***."""
    if value is None:
        return None
    s = str(value)
    if len(s) <= 2:
        return "***"
    return s[:2] + "***"


def _detect_field(
    field_path: str,
    value: Any,
) -> Optional[PIIField]:
    """
    Detect whether a single (path, value) pair contains PII.
    Returns the highest-confidence PIIField, or None.
    """
    leaf = field_path.split(".")[-1]
    best: Optional[PIIField] = None

    # 1. Field-name matching
    for pattern, category, risk, reason in _FIELD_NAME_MAP:
        if pattern.search(leaf):
            candidate = PIIField(
                field_path=field_path,
                category=category,
                risk_level=risk,
                confidence=0.9,
                match_reason=f"field name matched: {reason}",
                sample_value=_redact_sample(value),
            )
            if best is None or _RISK_ORDER[risk] > _RISK_ORDER[best.risk_level]:
                best = candidate

    # 2. Value-pattern matching (only on string-like scalars)
    if isinstance(value, (str, int, float)) and value not in (None, "", 0):
        str_value = str(value)
        for pattern, category, risk, reason in _VALUE_PATTERNS:
            if pattern.search(str_value):
                candidate = PIIField(
                    field_path=field_path,
                    category=category,
                    risk_level=risk,
                    confidence=0.75,
                    match_reason=f"value matched: {reason}",
                    sample_value=_redact_sample(value),
                )
                if best is None or _RISK_ORDER[risk] > _RISK_ORDER[best.risk_level]:
                    best = candidate

    return best


def _flatten_dict(
    obj: Any,
    prefix: str = "",
    sep: str = ".",
) -> List[Tuple[str, Any]]:
    """Recursively flatten a nested dict/list into (dot-path, value) pairs."""
    items: List[Tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            new_key = f"{prefix}{sep}{k}" if prefix else k
            items.extend(_flatten_dict(v, new_key, sep))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            new_key = f"{prefix}[{i}]"
            items.extend(_flatten_dict(v, new_key, sep))
    else:
        items.append((prefix, obj))
    return items


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class PIIDetector:
    """
    Scans arbitrary record dicts and returns a structured PIIReport.

    Usage::

        detector = PIIDetector()
        report = detector.scan(record_dict, record_type="UserProfile")
    """

    def scan(self, record: Dict[str, Any], record_type: str = "unknown") -> PIIReport:
        """Scan a single record dict and return a full PIIReport."""
        flat_fields = _flatten_dict(record)
        total = len(flat_fields)
        detected: List[PIIField] = []
        seen_paths: set = set()

        for path, value in flat_fields:
            if path in seen_paths:
                continue
            result = _detect_field(path, value)
            if result:
                detected.append(result)
                seen_paths.add(path)

        # Compute overall risk as the max risk across all detected fields
        if not detected:
            overall_risk = RiskLevel.LOW
        else:
            overall_risk = max(detected, key=lambda f: _RISK_ORDER[f.risk_level]).risk_level

        return PIIReport(
            record_type=record_type,
            total_fields=total,
            pii_fields=detected,
            overall_risk=overall_risk,
        )

    def scan_multiple(
        self,
        records: List[Dict[str, Any]],
        record_type: str = "unknown",
    ) -> List[PIIReport]:
        """Scan a list of records and return a report per record."""
        return [self.scan(r, record_type) for r in records]

    def classify_fields(
        self,
        record: Dict[str, Any],
    ) -> Dict[str, PIIField]:
        """Return a flat mapping of {field_path: PIIField} for PII fields."""
        report = self.scan(record)
        return {f.field_path: f for f in report.pii_fields}
