"""
seed_data.py — Helper to populate an InMemoryDatabase with realistic test data.

Used by main.py and tests.py.
"""

from __future__ import annotations

import uuid
from models import (
    ActivityLog,
    InMemoryDatabase,
    PaymentRecord,
    UserCredential,
    UserProfile,
)


def seed_user(db: InMemoryDatabase, user_id: str = "usr_001") -> None:
    """Seed a complete user profile + related PII data for demonstration."""

    # -- Profile ----------------------------------------------------------
    db.add_profile(UserProfile(
        user_id=user_id,
        full_name="Jane Doe",
        email="jane.doe@example.com",
        phone="+44 7700 900123",
        date_of_birth="1990-03-15",
        national_id="AB123456C",
        address={
            "street":   "42 Acacia Avenue",
            "city":     "London",
            "postcode": "SW1A 1AA",
            "country":  "GB",
        },
    ))

    # -- Credentials ------------------------------------------------------
    db.add_credential(UserCredential(
        user_id=user_id,
        password_hash="$argon2id$v=19$m=65536,t=3,p=4$...",
        salt="random-salt-hex-here",
        mfa_secret="JBSWY3DPEHPK3PXP",  # TOTP secret
        recovery_codes=["abc1-def2", "ghi3-jkl4", "mno5-pqr6"],
        last_login="2024-06-01T09:00:00+00:00",
    ))

    # -- Payments ---------------------------------------------------------
    for i, (brand, last4) in enumerate([("Visa", "4242"), ("Mastercard", "5555")], 1):
        db.add_payment(PaymentRecord(
            record_id=f"pay_{user_id}_{i:03d}",
            user_id=user_id,
            card_last4=last4,
            card_brand=brand,
            billing_name="Jane Doe",
            billing_address={
                "street":   "42 Acacia Avenue",
                "city":     "London",
                "postcode": "SW1A 1AA",
                "country":  "GB",
            },
            transaction_ids=[f"txn_{uuid.uuid4().hex[:8]}" for _ in range(3)],
        ))

    # -- Activity logs ----------------------------------------------------
    actions = [
        ("login",        "/auth/login"),
        ("view_profile", "/account/profile"),
        ("update_email", "/account/settings"),
        ("download",     "/account/export"),
        ("logout",       "/auth/logout"),
    ]
    for i, (action, resource) in enumerate(actions):
        db.add_activity(ActivityLog(
            log_id=f"log_{user_id}_{i:03d}",
            user_id=user_id,
            ip_address=f"192.168.1.{10 + i}",
            user_agent="Mozilla/5.0 (compatible; demo)",
            action=action,
            resource=resource,
        ))


def seed_multiple_users(db: InMemoryDatabase) -> list[str]:
    """Seed three different users and return their IDs."""
    user_ids = ["usr_001", "usr_002", "usr_003"]
    for uid in user_ids:
        seed_user(db, uid)
    return user_ids
