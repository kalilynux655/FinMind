"""
main.py — Interactive CLI demonstration of the PII Export & Delete Workflow.

Run:
    python main.py

Menu options:
    1  Export user data
    2  Request deletion
    3  Confirm deletion
    4  Execute deletion
    5  Cancel deletion
    6  Verify audit chain
    7  View audit trail (user)
    8  View full audit summary
    9  Check data presence
    0  Quit
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
from typing import Optional

from models import InMemoryDatabase
from seed_data import seed_user, seed_multiple_users
from workflow import PIIWorkflow


# ── Colour helpers (graceful degradation on Windows/non-TTY) ───────────────

def _c(code: str, text: str) -> str:
    if sys.stdout.isatty() and os.name != "nt":
        return f"\033[{code}m{text}\033[0m"
    return text

GREEN  = lambda t: _c("32", t)
YELLOW = lambda t: _c("33", t)
RED    = lambda t: _c("31", t)
CYAN   = lambda t: _c("36", t)
BOLD   = lambda t: _c("1",  t)


# ── Pretty-print helpers ────────────────────────────────────────────────────

def _pp(obj: object) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _banner() -> None:
    print(CYAN("""
╔══════════════════════════════════════════════════════╗
║     GDPR PII Export & Delete Workflow  (demo)        ║
╚══════════════════════════════════════════════════════╝
"""))


def _menu() -> None:
    print(BOLD("\n── Menu ─────────────────────────────────────────────"))
    options = [
        ("1", "Export user data"),
        ("2", "Request deletion"),
        ("3", "Confirm deletion (enter token)"),
        ("4", "Execute deletion"),
        ("5", "Cancel deletion"),
        ("6", "Verify audit chain integrity"),
        ("7", "View audit trail for a user"),
        ("8", "View audit summary (all users)"),
        ("9", "Check data presence for a user"),
        ("0", "Quit"),
    ]
    for key, label in options:
        print(f"  {YELLOW(key)}  {label}")
    print()


# ── CLI handler ─────────────────────────────────────────────────────────────

class CLI:
    def __init__(self) -> None:
        self.db  = InMemoryDatabase()
        self.wf  = PIIWorkflow(self.db, output_dir=None)   # in-memory mode
        # Track most-recent deletion request per user for convenience
        self._last_del_req: dict = {}

        # Pre-seed three users
        user_ids = seed_multiple_users(self.db)
        print(GREEN(f"\n✓ Seeded {len(user_ids)} test users: {', '.join(user_ids)}"))

    # ----------------------------------------------------------------
    def _prompt_user_id(self) -> str:
        uid = input("  Enter user_id (e.g. usr_001): ").strip()
        return uid or "usr_001"

    # ----------------------------------------------------------------
    def run(self) -> None:
        _banner()
        while True:
            _menu()
            choice = input(BOLD("Select option: ")).strip()

            if choice == "1":
                self._export()
            elif choice == "2":
                self._request_delete()
            elif choice == "3":
                self._confirm_delete()
            elif choice == "4":
                self._execute_delete()
            elif choice == "5":
                self._cancel_delete()
            elif choice == "6":
                self._verify_chain()
            elif choice == "7":
                self._user_trail()
            elif choice == "8":
                self._audit_summary()
            elif choice == "9":
                self._data_presence()
            elif choice == "0":
                print(GREEN("\nGoodbye!\n"))
                break
            else:
                print(RED("Unknown option — try again."))

    # ── Option handlers ──────────────────────────────────────────────

    def _export(self) -> None:
        uid = self._prompt_user_id()
        try:
            req = self.wf.export_user_data(uid, requested_by="user",
                                            ip_address="127.0.0.1")
            print(GREEN(f"\n✓ Export complete!"))
            print(f"  Request ID   : {req.request_id}")
            print(f"  Status       : {req.status.value}")
            print(f"  Package path : {req.package_path}")
            print(f"  SHA-256      : {req.package_hash}")
            print(f"  Completed at : {req.completed_at}")
        except Exception as e:
            print(RED(f"\n✗ Export failed: {e}"))

    def _request_delete(self) -> None:
        uid = self._prompt_user_id()
        reason = input("  Reason [user_request]: ").strip() or "user_request"
        grace  = input("  Grace period days [0 for immediate]: ").strip()
        grace  = int(grace) if grace.isdigit() else 0
        try:
            req = self.wf.request_deletion(uid, reason=reason,
                                            grace_period_days=grace,
                                            ip_address="127.0.0.1")
            self._last_del_req[uid] = req
            print(GREEN(f"\n✓ Deletion request created!"))
            print(f"  Request ID : {req.request_id}")
            print(f"  Status     : {req.status.value}")
            print(f"  Expires at : {req.token_expires_at}")
            print(YELLOW(f"\n  ⚠  Confirmation token (in prod, sent via email):"))
            print(f"  {req.confirmation_token}")
        except Exception as e:
            print(RED(f"\n✗ Failed: {e}"))

    def _confirm_delete(self) -> None:
        uid = self._prompt_user_id()
        saved = self._last_del_req.get(uid)
        if saved:
            req_id  = saved.request_id
            default_token = saved.confirmation_token
            print(f"  (auto-filled request_id: {req_id})")
        else:
            req_id        = input("  Request ID   : ").strip()
            default_token = ""

        token = input(
            f"  Token [{default_token[:20]}…]: "
        ).strip() or default_token

        try:
            req = self.wf.confirm_deletion(req_id, token, actor=f"user:{uid}",
                                            ip_address="127.0.0.1")
            print(GREEN(f"\n✓ Deletion confirmed!"))
            print(f"  Status       : {req.status.value}")
            print(f"  Confirmed at : {req.confirmed_at}")
        except Exception as e:
            print(RED(f"\n✗ Confirmation failed: {e}"))

    def _execute_delete(self) -> None:
        uid = self._prompt_user_id()
        saved = self._last_del_req.get(uid)
        if saved:
            req_id = saved.request_id
            print(f"  (auto-filled request_id: {req_id})")
        else:
            req_id = input("  Request ID: ").strip()

        confirm = input(
            RED("  This is IRREVERSIBLE. Type 'DELETE' to proceed: ")
        ).strip()
        if confirm != "DELETE":
            print(YELLOW("  Aborted."))
            return

        try:
            req = self.wf.execute_deletion(req_id)
            print(GREEN(f"\n✓ Deletion executed!"))
            print(f"  Status       : {req.status.value}")
            print(f"  Completed at : {req.completed_at}")
            print(f"  Records deleted    : {req.deleted_record_count}")
            print(f"  Records anonymised : {req.anonymised_record_count}")
        except Exception as e:
            print(RED(f"\n✗ Deletion failed: {e}"))

    def _cancel_delete(self) -> None:
        uid = self._prompt_user_id()
        saved = self._last_del_req.get(uid)
        if saved:
            req_id = saved.request_id
        else:
            req_id = input("  Request ID: ").strip()
        try:
            req = self.wf.cancel_deletion(req_id, actor=f"user:{uid}",
                                           reason="user_changed_mind")
            print(GREEN(f"\n✓ Deletion request cancelled."))
            print(f"  Status: {req.status.value}")
        except Exception as e:
            print(RED(f"\n✗ Cancel failed: {e}"))

    def _verify_chain(self) -> None:
        result = self.wf.verify_audit_chain()
        icon   = GREEN("✓") if result["valid"] else RED("✗")
        print(f"\n  Audit chain: {icon} {result['details']}")
        print(f"  Total entries: {result['total_entries']}")

    def _user_trail(self) -> None:
        uid   = self._prompt_user_id()
        trail = self.wf.get_user_audit_trail(uid)
        if not trail:
            print(YELLOW(f"\n  No audit entries found for '{uid}'."))
            return
        print(f"\n  {len(trail)} entries for {uid}:\n")
        for e in trail:
            print(f"  [{e['timestamp']}]  {BOLD(e['action'])}")
            print(f"    actor={e['actor']}  req={e['request_id'] or '-'}")
            if e.get("details"):
                detail_str = json.dumps(e["details"], separators=(",", ":"))
                print(f"    {textwrap.shorten(detail_str, 80)}")

    def _audit_summary(self) -> None:
        summary = self.wf.get_audit_summary()
        print(f"\n  Total log entries : {summary['total_entries']}")
        print(f"  Unique users      : {summary['unique_users']}")
        print("\n  Action breakdown:")
        for action, count in sorted(summary["action_counts"].items()):
            print(f"    {action:<35} {count}")

    def _data_presence(self) -> None:
        uid    = self._prompt_user_id()
        exists = self.wf.user_data_exists(uid)
        print(f"\n  Data presence for '{uid}':")
        for table, present in exists.items():
            icon = GREEN("✓") if present else RED("✗")
            print(f"    {icon}  {table}")


# ── Entry point ─────────────────────────────────────────────────────────────

def run_automated_demo(silent: bool = False) -> None:
    """
    Run a non-interactive demo that exercises the full workflow end-to-end.
    Used in tests and as a smoke-test entry point.
    """

    def log(msg: str) -> None:
        if not silent:
            print(msg)

    log("\n" + "="*60)
    log("  AUTOMATED DEMO — Full PII Export & Delete Workflow")
    log("="*60)

    db  = InMemoryDatabase()
    wf  = PIIWorkflow(db, output_dir=None)
    uid = "usr_demo"
    seed_user(db, uid)

    # ── 1. Export ────────────────────────────────────────────────────
    log("\n[1] Exporting user data …")
    export_req = wf.export_user_data(uid, requested_by="user", ip_address="10.0.0.1")
    log(f"    ✓ Export complete  | hash={export_req.package_hash[:16]}…")

    # ── 2. Request deletion ──────────────────────────────────────────
    log("\n[2] Requesting deletion …")
    del_req = wf.request_deletion(uid, reason="user_request", grace_period_days=0)
    log(f"    ✓ Request created  | id={del_req.request_id[:8]}…")
    token = del_req.confirmation_token

    # ── 3. Confirm deletion ──────────────────────────────────────────
    log("\n[3] Confirming deletion …")
    del_req = wf.confirm_deletion(del_req.request_id, token, actor=f"user:{uid}")
    log(f"    ✓ Confirmed        | status={del_req.status.value}")

    # ── 4. Execute deletion ──────────────────────────────────────────
    log("\n[4] Executing deletion …")
    del_req = wf.execute_deletion(del_req.request_id)
    log(f"    ✓ Deletion done    | deleted={del_req.deleted_record_count}"
        f"  anonymised={del_req.anonymised_record_count}")

    # ── 5. Verify data is gone ───────────────────────────────────────
    log("\n[5] Verifying data was purged …")
    presence = wf.user_data_exists(uid)
    all_gone = not any(presence.values())
    log(f"    ✓ All PII removed  | presence={presence}")
    assert all_gone, f"Expected all PII gone, got: {presence}"

    # ── 6. Verify audit chain ────────────────────────────────────────
    log("\n[6] Verifying audit chain integrity …")
    chain = wf.verify_audit_chain()
    log(f"    ✓ Chain valid      | entries={chain['total_entries']}")
    assert chain["valid"], f"Audit chain broken: {chain['details']}"

    # ── 7. Audit summary ─────────────────────────────────────────────
    log("\n[7] Audit summary:")
    summary = wf.get_audit_summary()
    for action, count in sorted(summary["action_counts"].items()):
        log(f"    {action:<35} {count}")

    log("\n" + "="*60)
    log("  DEMO COMPLETE — all assertions passed ✓")
    log("="*60 + "\n")


if __name__ == "__main__":
    if "--demo" in sys.argv:
        run_automated_demo()
    else:
        CLI().run()
