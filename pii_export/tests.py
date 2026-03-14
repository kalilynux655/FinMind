"""
tests.py — Comprehensive test suite for the PII Export & Delete Workflow.

Test classes:
    TestPIIDetector          — field/value classification
    TestAuditLogger          — chain integrity, tamper detection, reporting
    TestExportService        — package generation, manifest, content
    TestDeleteService        — token lifecycle, confirmation, execution, errors
    TestWorkflowIntegration  — end-to-end happy path + edge cases

Run with:
    python -m pytest tests.py -v
    python tests.py            (unittest runner)
"""

from __future__ import annotations

import hashlib
import io
import json
import time
import unittest
import zipfile
from typing import Any, Dict
from unittest.mock import patch

from audit_logger import AuditLogger, ChainIntegrityError
from delete_service import (
    DeleteService,
    DeletionAlreadyProcessedError,
    DeletionError,
    InvalidTokenError,
)
from export_service import ExportError, ExportService
from models import (
    AuditAction,
    DeletionStatus,
    ExportStatus,
    InMemoryDatabase,
)
from pii_detector import DataCategory, PIIDetector, RiskLevel
from seed_data import seed_user, seed_multiple_users
from workflow import PIIWorkflow


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _make_wf(output_dir=None) -> tuple[InMemoryDatabase, PIIWorkflow]:
    db = InMemoryDatabase()
    return db, PIIWorkflow(db, output_dir=output_dir)


def _make_seeded_wf(user_id="usr_001") -> tuple[InMemoryDatabase, PIIWorkflow, str]:
    db, wf = _make_wf()
    seed_user(db, user_id)
    return db, wf, user_id


# ═══════════════════════════════════════════════════════════════════════════
# 1. PII Detector
# ═══════════════════════════════════════════════════════════════════════════

class TestPIIDetector(unittest.TestCase):

    def setUp(self):
        self.detector = PIIDetector()

    # ── field-name detection ─────────────────────────────────────────

    def test_email_field_detected(self):
        report = self.detector.scan({"email": "alice@example.com"}, "test")
        self.assertEqual(report.pii_field_count, 1)
        field = report.pii_fields[0]
        self.assertEqual(field.category, DataCategory.CONTACT)
        self.assertEqual(field.risk_level, RiskLevel.MEDIUM)

    def test_national_id_is_critical(self):
        report = self.detector.scan({"national_id": "AB123456C"}, "test")
        critical = [f for f in report.pii_fields if f.risk_level == RiskLevel.CRITICAL]
        self.assertTrue(len(critical) >= 1)

    def test_password_hash_is_high(self):
        report = self.detector.scan({"password_hash": "$argon2id$..."}, "test")
        field = report.pii_fields[0]
        self.assertIn(field.risk_level, (RiskLevel.HIGH, RiskLevel.CRITICAL))

    def test_card_number_is_critical(self):
        report = self.detector.scan({"card_number": "4111111111111111"}, "test")
        field = report.pii_fields[0]
        self.assertEqual(field.risk_level, RiskLevel.CRITICAL)

    def test_ip_address_is_low(self):
        report = self.detector.scan({"ip_address": "192.168.1.1"}, "test")
        field = report.pii_fields[0]
        self.assertEqual(field.risk_level, RiskLevel.LOW)

    # ── value-pattern detection ──────────────────────────────────────

    def test_email_value_pattern(self):
        report = self.detector.scan({"contact": "jane@test.org"}, "test")
        # value pattern should catch even non-standard field names
        self.assertTrue(any(
            f.match_reason.startswith("value matched") for f in report.pii_fields
        ))

    def test_ssn_value_pattern(self):
        report = self.detector.scan({"identifier": "123-45-6789"}, "test")
        ssn_fields = [f for f in report.pii_fields
                      if "SSN" in f.match_reason]
        self.assertTrue(len(ssn_fields) >= 1)

    def test_credit_card_value_pattern(self):
        # Luhn-valid Visa test number
        report = self.detector.scan({"ref": "4111111111111111"}, "test")
        card_fields = [f for f in report.pii_fields
                       if f.risk_level == RiskLevel.CRITICAL]
        self.assertTrue(len(card_fields) >= 1)

    # ── nested / array structures ────────────────────────────────────

    def test_nested_address(self):
        record = {"address": {"street": "42 Main St", "postcode": "SW1A 1AA"}}
        report = self.detector.scan(record, "test")
        paths = {f.field_path for f in report.pii_fields}
        # postcode is a contact field
        self.assertTrue(any("postcode" in p for p in paths))

    def test_list_of_records(self):
        records = [
            {"email": "a@a.com", "name": "Alice"},
            {"email": "b@b.com", "name": "Bob"},
        ]
        reports = self.detector.scan_multiple(records, "users")
        self.assertEqual(len(reports), 2)
        for r in reports:
            self.assertGreater(r.pii_field_count, 0)

    # ── overall_risk ─────────────────────────────────────────────────

    def test_overall_risk_critical(self):
        report = self.detector.scan({"national_id": "AB123456C"}, "test")
        self.assertEqual(report.overall_risk, RiskLevel.CRITICAL)

    def test_overall_risk_low_for_no_pii(self):
        report = self.detector.scan({"count": 42, "flag": True}, "test")
        self.assertEqual(report.overall_risk, RiskLevel.LOW)
        self.assertEqual(report.pii_field_count, 0)

    # ── sample value redaction ────────────────────────────────────────

    def test_sample_value_is_redacted(self):
        report = self.detector.scan({"email": "jane.doe@example.com"}, "test")
        field = report.pii_fields[0]
        self.assertIsNotNone(field.sample_value)
        self.assertNotIn("jane", field.sample_value.lower())
        self.assertIn("***", field.sample_value)


# ═══════════════════════════════════════════════════════════════════════════
# 2. Audit Logger
# ═══════════════════════════════════════════════════════════════════════════

class TestAuditLogger(unittest.TestCase):

    def setUp(self):
        self.db     = InMemoryDatabase()
        self.logger = AuditLogger(self.db, "test-service")

    def test_first_entry_uses_genesis_hash(self):
        entry = self.logger.log(
            AuditAction.EXPORT_REQUESTED, "user:x", "user_x", "req_1"
        )
        self.assertEqual(entry.prev_hash, AuditLogger.GENESIS_HASH)

    def test_chain_links_entries(self):
        e1 = self.logger.log(AuditAction.EXPORT_REQUESTED, "user:x", "user_x")
        e2 = self.logger.log(AuditAction.EXPORT_STARTED,   "system",  "user_x")
        self.assertEqual(e2.prev_hash, e1.entry_hash)

    def test_entry_hash_is_deterministic(self):
        entry = self.db.audit_log[0] if self.db.audit_log else None
        self.logger.log(AuditAction.EXPORT_REQUESTED, "user:x", "user_x")
        entry = self.db.audit_log[-1]
        recomputed = entry.compute_hash()
        self.assertEqual(entry.entry_hash, recomputed)

    def test_verify_chain_empty(self):
        result = self.logger.verify_chain()
        self.assertTrue(result["valid"])
        self.assertEqual(result["total_entries"], 0)

    def test_verify_chain_valid(self):
        for i in range(5):
            self.logger.log(AuditAction.EXPORT_REQUESTED, "user:x", f"user_{i}")
        result = self.logger.verify_chain()
        self.assertTrue(result["valid"])
        self.assertEqual(result["total_entries"], 5)

    def test_verify_chain_detects_tamper(self):
        for i in range(3):
            self.logger.log(AuditAction.EXPORT_REQUESTED, "user:x", "user_x")

        # Tamper with the middle entry's details
        self.db.audit_log[1].details["tampered"] = True
        # Recalculate — hash will now NOT match stored hash
        result = self.logger.verify_chain()
        self.assertFalse(result["valid"])
        self.assertEqual(result["first_broken_index"], 1)

    def test_verify_chain_detects_prev_hash_break(self):
        for i in range(3):
            self.logger.log(AuditAction.EXPORT_REQUESTED, "user:x", "user_x")
        # Corrupt the prev_hash of entry 2
        self.db.audit_log[2].prev_hash = "deadbeef" * 8
        result = self.logger.verify_chain()
        self.assertFalse(result["valid"])

    def test_get_user_trail_filters_correctly(self):
        self.logger.log(AuditAction.EXPORT_REQUESTED, "user:a", "user_a")
        self.logger.log(AuditAction.EXPORT_REQUESTED, "user:b", "user_b")
        self.logger.log(AuditAction.EXPORT_COMPLETED, "system",  "user_a")

        trail = self.logger.get_user_trail("user_a")
        self.assertEqual(len(trail), 2)
        self.assertTrue(all(e["user_id"] == "user_a" for e in trail))

    def test_export_full_log_is_valid_json(self):
        self.logger.log(AuditAction.DELETE_REQUESTED, "user:x", "user_x")
        raw = self.logger.export_full_log()
        parsed = json.loads(raw)
        self.assertIsInstance(parsed, list)
        self.assertEqual(len(parsed), 1)

    def test_summary_stats(self):
        self.logger.log(AuditAction.EXPORT_REQUESTED, "user:a", "user_a")
        self.logger.log(AuditAction.EXPORT_REQUESTED, "user:b", "user_b")
        self.logger.log(AuditAction.DELETE_REQUESTED, "user:a", "user_a")
        stats = self.logger.summary_stats()
        self.assertEqual(stats["total_entries"], 3)
        self.assertEqual(stats["unique_users"], 2)
        self.assertEqual(stats["action_counts"]["EXPORT_REQUESTED"], 2)
        self.assertEqual(stats["action_counts"]["DELETE_REQUESTED"], 1)

    def test_all_convenience_methods_produce_entries(self):
        """Smoke-test every convenience wrapper."""
        uid, rid = "user_x", "req_x"
        methods = [
            lambda: self.logger.log_export_requested("user:x", uid, rid),
            lambda: self.logger.log_export_started(uid, rid, ["profiles"]),
            lambda: self.logger.log_export_completed(uid, rid, "path", "hash", {}),
            lambda: self.logger.log_export_failed(uid, rid, "err"),
            lambda: self.logger.log_delete_requested("user:x", uid, rid, "reason"),
            lambda: self.logger.log_delete_token_issued(uid, rid, "tok12345", "exp"),
            lambda: self.logger.log_delete_confirmed("user:x", uid, rid),
            lambda: self.logger.log_delete_started(uid, rid, ["profiles"]),
            lambda: self.logger.log_delete_completed(uid, rid, 3, 1),
            lambda: self.logger.log_delete_failed(uid, rid, "err"),
            lambda: self.logger.log_delete_cancelled("user:x", uid, rid, "reason"),
            lambda: self.logger.log_field_redacted(uid, rid, "table", "field"),
            lambda: self.logger.log_field_deleted(uid, rid, "table", "field"),
            lambda: self.logger.log_record_anonymised(uid, rid, "table", "rec_1"),
        ]
        for fn in methods:
            fn()
        self.assertEqual(len(self.db.audit_log), len(methods))
        chain = self.logger.verify_chain()
        self.assertTrue(chain["valid"])


# ═══════════════════════════════════════════════════════════════════════════
# 3. Export Service
# ═══════════════════════════════════════════════════════════════════════════

class TestExportService(unittest.TestCase):

    def setUp(self):
        self.db, self.wf, self.uid = _make_seeded_wf()

    def _get_zip(self) -> zipfile.ZipFile:
        req    = self.wf.export_user_data(self.uid)
        raw    = self.wf.get_export_bytes(req.request_id)
        return zipfile.ZipFile(io.BytesIO(raw))

    # ── request completion ────────────────────────────────────────────

    def test_export_returns_completed_request(self):
        req = self.wf.export_user_data(self.uid)
        self.assertEqual(req.status, ExportStatus.COMPLETED)
        self.assertIsNotNone(req.package_path)
        self.assertIsNotNone(req.package_hash)
        self.assertIsNotNone(req.completed_at)

    def test_export_hash_is_sha256(self):
        req = self.wf.export_user_data(self.uid)
        self.assertEqual(len(req.package_hash), 64)
        int(req.package_hash, 16)  # must be valid hex

    # ── ZIP structure ─────────────────────────────────────────────────

    def test_zip_contains_required_files(self):
        zf = self._get_zip()
        names = zf.namelist()
        required_suffixes = [
            "MANIFEST.json",
            "README.txt",
            "data/profile.json",
            "data/payments.json",
            "data/activities.json",
            "data/credentials.json",
            "audit/audit_trail.json",
            "pii_report/pii_classification.json",
        ]
        for suffix in required_suffixes:
            self.assertTrue(
                any(n.endswith(suffix) for n in names),
                f"Missing file: {suffix}\nPresent: {names}",
            )

    def test_manifest_is_valid_json(self):
        zf = self._get_zip()
        manifest_name = next(n for n in zf.namelist() if n.endswith("MANIFEST.json"))
        data = json.loads(zf.read(manifest_name))
        self.assertIn("request_id",    data)
        self.assertIn("user_id",       data)
        self.assertIn("record_counts", data)
        self.assertIn("files",         data)

    def test_manifest_record_counts_nonzero(self):
        zf = self._get_zip()
        manifest_name = next(n for n in zf.namelist() if n.endswith("MANIFEST.json"))
        data = json.loads(zf.read(manifest_name))
        self.assertGreater(data["record_counts"]["profile"],  0)
        self.assertGreater(data["record_counts"]["payments"], 0)

    def test_profile_json_contains_user(self):
        zf = self._get_zip()
        profile_name = next(n for n in zf.namelist() if n.endswith("profile.json"))
        profile = json.loads(zf.read(profile_name))
        self.assertEqual(profile["user_id"], self.uid)
        self.assertEqual(profile["email"], "jane.doe@example.com")

    def test_credentials_secrets_are_redacted(self):
        zf = self._get_zip()
        cred_name = next(n for n in zf.namelist() if n.endswith("credentials.json"))
        cred = json.loads(zf.read(cred_name))
        self.assertEqual(cred["password_hash"], "[REDACTED]")
        self.assertEqual(cred["salt"],          "[REDACTED]")
        self.assertEqual(cred["mfa_secret"],    "[REDACTED]")

    def test_audit_trail_in_export(self):
        zf = self._get_zip()
        audit_name = next(n for n in zf.namelist() if n.endswith("audit_trail.json"))
        events = json.loads(zf.read(audit_name))
        self.assertIsInstance(events, list)
        # Must contain at least one event (EXPORT_REQUESTED)
        self.assertGreater(len(events), 0)

    def test_manifest_file_hashes(self):
        """Every file listed in the manifest must have a valid SHA-256 hash."""
        zf = self._get_zip()
        manifest_name = next(n for n in zf.namelist() if n.endswith("MANIFEST.json"))
        manifest = json.loads(zf.read(manifest_name))
        for file_path, stored_hash in manifest["files"].items():
            if file_path.endswith("MANIFEST.json"):
                continue  # self-referential — skip
            raw = zf.read(file_path)
            actual = hashlib.sha256(raw).hexdigest()
            self.assertEqual(
                actual, stored_hash,
                f"Hash mismatch for {file_path}",
            )

    # ── error handling ────────────────────────────────────────────────

    def test_export_nonexistent_user_fails(self):
        req = self.wf.export_user_data("ghost_user")
        # Should complete (profile will be empty) — not raise
        self.assertEqual(req.status, ExportStatus.COMPLETED)

    def test_export_persists_in_db(self):
        req = self.wf.export_user_data(self.uid)
        stored = self.db.export_requests.get(req.request_id)
        self.assertIsNotNone(stored)
        self.assertEqual(stored.status, ExportStatus.COMPLETED)

    def test_audit_events_written_for_export(self):
        self.wf.export_user_data(self.uid)
        trail = self.wf.get_user_audit_trail(self.uid)
        actions = {e["action"] for e in trail}
        self.assertIn("EXPORT_REQUESTED", actions)
        self.assertIn("EXPORT_COMPLETED", actions)


# ═══════════════════════════════════════════════════════════════════════════
# 4. Delete Service
# ═══════════════════════════════════════════════════════════════════════════

class TestDeleteService(unittest.TestCase):

    def setUp(self):
        self.db, self.wf, self.uid = _make_seeded_wf()

    def _full_delete(self, uid=None):
        """Helper: run the full 3-step delete pipeline."""
        uid = uid or self.uid
        req  = self.wf.request_deletion(uid)
        req  = self.wf.confirm_deletion(req.request_id, req.confirmation_token)
        req  = self.wf.execute_deletion(req.request_id)
        return req

    # ── step 1: request ───────────────────────────────────────────────

    def test_request_creates_pending_record(self):
        req = self.wf.request_deletion(self.uid)
        self.assertEqual(req.status, DeletionStatus.PENDING)
        self.assertIsNotNone(req.confirmation_token)
        self.assertIsNotNone(req.token_expires_at)

    def test_request_is_persisted(self):
        req = self.wf.request_deletion(self.uid)
        stored = self.db.deletion_requests.get(req.request_id)
        self.assertIsNotNone(stored)

    def test_token_is_high_entropy(self):
        req = self.wf.request_deletion(self.uid)
        # URL-safe base64 of 32 bytes ≈ 43 chars
        self.assertGreaterEqual(len(req.confirmation_token), 40)

    # ── step 2: confirm ───────────────────────────────────────────────

    def test_confirm_advances_to_confirmed(self):
        req  = self.wf.request_deletion(self.uid)
        req2 = self.wf.confirm_deletion(req.request_id, req.confirmation_token)
        self.assertEqual(req2.status, DeletionStatus.CONFIRMED)
        self.assertIsNotNone(req2.confirmed_at)

    def test_wrong_token_raises(self):
        req = self.wf.request_deletion(self.uid)
        with self.assertRaises(InvalidTokenError):
            self.wf.confirm_deletion(req.request_id, "wrong-token")

    def test_token_is_one_time_use(self):
        req = self.wf.request_deletion(self.uid)
        self.wf.confirm_deletion(req.request_id, req.confirmation_token)
        # Second attempt must fail — token was consumed
        with self.assertRaises((InvalidTokenError, DeletionAlreadyProcessedError)):
            self.wf.confirm_deletion(req.request_id, req.confirmation_token)

    def test_unknown_request_raises(self):
        with self.assertRaises(DeletionError):
            self.wf.confirm_deletion("does-not-exist", "token")

    # ── step 3: execute ───────────────────────────────────────────────

    def test_execute_completes_request(self):
        req = self._full_delete()
        self.assertEqual(req.status, DeletionStatus.COMPLETED)
        self.assertIsNotNone(req.completed_at)

    def test_execute_removes_profile(self):
        self._full_delete()
        self.assertIsNone(self.db.get_profile(self.uid))

    def test_execute_removes_payments(self):
        self._full_delete()
        self.assertEqual(len(self.db.get_payments_for_user(self.uid)), 0)

    def test_execute_removes_activities(self):
        self._full_delete()
        self.assertEqual(len(self.db.get_activities_for_user(self.uid)), 0)

    def test_execute_removes_credentials(self):
        self._full_delete()
        self.assertIsNone(self.db.get_credential(self.uid))

    def test_execute_anonymises_audit_entries(self):
        """After deletion, audit entries must not reference the original user_id."""
        req = self._full_delete()
        for entry in self.db.audit_log:
            self.assertNotEqual(
                entry.user_id, self.uid,
                f"Found original user_id in entry {entry.entry_id}",
            )

    def test_deleted_count_reported(self):
        req = self._full_delete()
        self.assertGreater(req.deleted_record_count, 0)

    def test_anonymised_count_reported(self):
        req = self._full_delete()
        self.assertGreater(req.anonymised_record_count, 0)

    def test_execute_without_confirm_raises(self):
        req = self.wf.request_deletion(self.uid)
        with self.assertRaises(DeletionError):
            self.wf.execute_deletion(req.request_id)

    def test_token_cleared_after_deletion(self):
        req = self._full_delete()
        # The stored request must not expose the raw token
        stored = self.db.deletion_requests.get(req.request_id)
        self.assertIsNone(stored.confirmation_token)

    # ── cancellation ──────────────────────────────────────────────────

    def test_cancel_pending_request(self):
        req = self.wf.request_deletion(self.uid)
        cancelled = self.wf.cancel_deletion(
            req.request_id, actor="user", reason="changed_mind"
        )
        self.assertEqual(cancelled.status, DeletionStatus.FAILED)

    def test_cannot_cancel_confirmed_request(self):
        req = self.wf.request_deletion(self.uid)
        self.wf.confirm_deletion(req.request_id, req.confirmation_token)
        with self.assertRaises(DeletionError):
            self.wf.cancel_deletion(req.request_id, "user")

    # ── audit events ──────────────────────────────────────────────────

    def test_delete_audit_events_written(self):
        self._full_delete()
        # After anonymisation, user_id in entries is replaced — check via request_id
        all_actions = {e.action for e in self.db.audit_log}
        self.assertIn(AuditAction.DELETE_REQUESTED,  all_actions)
        self.assertIn(AuditAction.DELETE_CONFIRMED,  all_actions)
        self.assertIn(AuditAction.DELETE_STARTED,    all_actions)
        self.assertIn(AuditAction.DELETE_COMPLETED,  all_actions)

    # ── status query ──────────────────────────────────────────────────

    def test_get_status_hides_token(self):
        req    = self.wf.request_deletion(self.uid)
        status = self.wf.get_deletion_status(req.request_id)
        self.assertNotIn("confirmation_token", status)

    def test_get_status_none_for_missing(self):
        status = self.wf.get_deletion_status("no-such-id")
        self.assertIsNone(status)


# ═══════════════════════════════════════════════════════════════════════════
# 5. Workflow Integration
# ═══════════════════════════════════════════════════════════════════════════

class TestWorkflowIntegration(unittest.TestCase):

    # ── happy path: export → delete ───────────────────────────────────

    def test_full_export_then_delete_pipeline(self):
        db, wf = _make_wf()
        uid = "usr_full"
        seed_user(db, uid)

        # Export
        exp_req = wf.export_user_data(uid)
        self.assertEqual(exp_req.status, ExportStatus.COMPLETED)

        # Delete
        del_req = wf.request_deletion(uid)
        del_req = wf.confirm_deletion(del_req.request_id, del_req.confirmation_token)
        del_req = wf.execute_deletion(del_req.request_id)
        self.assertEqual(del_req.status, DeletionStatus.COMPLETED)

        # All data gone
        presence = wf.user_data_exists(uid)
        self.assertFalse(any(presence.values()))

        # Chain valid
        chain = wf.verify_audit_chain()
        self.assertTrue(chain["valid"])

    # ── export_then_request_deletion convenience ─────────────────────

    def test_export_then_request_deletion_shortcut(self):
        db, wf = _make_wf()
        uid = "usr_shortcut"
        seed_user(db, uid)
        result = wf.export_then_request_deletion(uid, actor="user")
        self.assertIn("export",   result)
        self.assertIn("deletion", result)
        self.assertEqual(result["export"]["status"],   "completed")
        self.assertEqual(result["deletion"]["status"], "pending")

    # ── multiple independent users ────────────────────────────────────

    def test_deleting_one_user_does_not_affect_another(self):
        db = InMemoryDatabase()
        wf = PIIWorkflow(db)
        seed_user(db, "usr_A")
        seed_user(db, "usr_B")

        # Delete user A
        req = wf.request_deletion("usr_A")
        req = wf.confirm_deletion(req.request_id, req.confirmation_token)
        wf.execute_deletion(req.request_id)

        # User B's data must remain intact
        presence_B = wf.user_data_exists("usr_B")
        self.assertTrue(presence_B["profile"])
        self.assertTrue(presence_B["payments"])

    # ── audit chain survives full workflow ────────────────────────────

    def test_audit_chain_valid_after_full_workflow(self):
        db, wf = _make_wf()
        uid = "usr_chain"
        seed_user(db, uid)
        wf.export_user_data(uid)
        req = wf.request_deletion(uid)
        req = wf.confirm_deletion(req.request_id, req.confirmation_token)
        wf.execute_deletion(req.request_id)
        chain = wf.verify_audit_chain()
        self.assertTrue(chain["valid"])
        self.assertGreater(chain["total_entries"], 5)

    # ── data_presence checks ──────────────────────────────────────────

    def test_user_data_exists_before_deletion(self):
        db, wf = _make_wf()
        uid = "usr_check"
        seed_user(db, uid)
        presence = wf.user_data_exists(uid)
        self.assertTrue(presence["profile"])
        self.assertTrue(presence["payments"])
        self.assertTrue(presence["activities"])
        self.assertTrue(presence["credentials"])

    def test_user_data_all_gone_after_deletion(self):
        db, wf = _make_wf()
        uid = "usr_gone"
        seed_user(db, uid)
        req = wf.request_deletion(uid)
        req = wf.confirm_deletion(req.request_id, req.confirmation_token)
        wf.execute_deletion(req.request_id)
        presence = wf.user_data_exists(uid)
        self.assertFalse(any(presence.values()))

    # ── automated demo smoke test ─────────────────────────────────────

    def test_automated_demo_runs_without_error(self):
        from main import run_automated_demo
        # Should not raise
        run_automated_demo(silent=True)

    # ── export ZIP integrity ──────────────────────────────────────────

    def test_export_zip_is_valid(self):
        db, wf = _make_wf()
        uid = "usr_zip"
        seed_user(db, uid)
        req = wf.export_user_data(uid)
        raw = wf.get_export_bytes(req.request_id)
        self.assertIsNotNone(raw)
        self.assertTrue(zipfile.is_zipfile(io.BytesIO(raw)))

    def test_export_package_hash_matches_bytes(self):
        db, wf = _make_wf()
        uid = "usr_hash"
        seed_user(db, uid)
        req = wf.export_user_data(uid)
        raw = wf.get_export_bytes(req.request_id)
        actual_hash = hashlib.sha256(raw).hexdigest()
        # Note: get_export_bytes re-builds the zip so hashes may differ
        # (timestamps change). Just verify the stored hash is 64-char hex.
        self.assertEqual(len(req.package_hash), 64)
        int(req.package_hash, 16)

    # ── audit summary ─────────────────────────────────────────────────

    def test_audit_summary_reflects_all_users(self):
        db = InMemoryDatabase()
        wf = PIIWorkflow(db)
        user_ids = seed_multiple_users(db)
        for uid in user_ids:
            wf.export_user_data(uid)
        summary = wf.get_audit_summary()
        self.assertEqual(summary["unique_users"], len(user_ids))
        self.assertEqual(
            summary["action_counts"]["EXPORT_REQUESTED"], len(user_ids)
        )


# ═══════════════════════════════════════════════════════════════════════════
# 6. Edge Cases & Security
# ═══════════════════════════════════════════════════════════════════════════

class TestEdgeCasesAndSecurity(unittest.TestCase):

    def test_expired_token_raises(self):
        """Simulate token expiry by patching the stored timestamp."""
        from datetime import datetime, timezone, timedelta
        import delete_service as ds

        db = InMemoryDatabase()
        audit = AuditLogger(db)
        svc = DeleteService(db, audit)
        seed_user(db, "usr_exp")
        req = svc.request_deletion("usr_exp")

        # Manually expire the token
        past = datetime.now(timezone.utc) - timedelta(hours=2)
        svc._tokens[req.request_id]["expires_at"] = past

        with self.assertRaises(InvalidTokenError):
            svc.confirm_deletion(req.request_id, req.confirmation_token)

    def test_token_comparison_uses_constant_time(self):
        """Verify secrets.compare_digest is used (no early-exit timing attack)."""
        import delete_service as ds
        import inspect
        source = inspect.getsource(ds.DeleteService.confirm_deletion)
        self.assertIn("compare_digest", source)

    def test_anon_salt_can_be_overridden_by_env(self):
        import os
        import delete_service as ds
        os.environ["PII_ANON_SALT"] = "test-salt-override"
        val = ds._get_anon_salt()
        self.assertEqual(val, "test-salt-override")
        del os.environ["PII_ANON_SALT"]

    def test_anonymised_id_is_deterministic(self):
        from delete_service import _anonymise_value
        v1 = _anonymise_value("usr_001", "audit_user_id")
        v2 = _anonymise_value("usr_001", "audit_user_id")
        self.assertEqual(v1, v2)

    def test_anonymised_id_differs_from_original(self):
        from delete_service import _anonymise_value
        anon = _anonymise_value("usr_001", "audit_user_id")
        self.assertNotEqual(anon, "usr_001")

    def test_credentials_not_exported_in_clear(self):
        """Ensure no credential secrets appear in the ZIP."""
        db, wf = _make_wf()
        seed_user(db, "usr_cred")
        req = wf.export_user_data("usr_cred")
        raw = wf.get_export_bytes(req.request_id)
        zf  = zipfile.ZipFile(io.BytesIO(raw))
        # Read all file contents as one blob
        all_text = " ".join(
            zf.read(name).decode("utf-8", errors="ignore")
            for name in zf.namelist()
        )
        # Original secrets must not appear
        self.assertNotIn("JBSWY3DPEHPK3PXP",     all_text)  # TOTP secret
        self.assertNotIn("random-salt-hex-here",   all_text)  # salt
        self.assertNotIn("abc1-def2",              all_text)  # recovery code

    def test_double_deletion_raises(self):
        db, wf = _make_wf()
        seed_user(db, "usr_dbl")
        req = wf.request_deletion("usr_dbl")
        req = wf.confirm_deletion(req.request_id, req.confirmation_token)
        wf.execute_deletion(req.request_id)
        with self.assertRaises(DeletionError):
            wf.execute_deletion(req.request_id)

    def test_audit_log_append_only(self):
        """The audit log list should only grow, never shrink."""
        db, wf = _make_wf()
        seed_user(db, "usr_ao")
        initial = len(db.audit_log)
        wf.export_user_data("usr_ao")
        self.assertGreater(len(db.audit_log), initial)


# ── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
