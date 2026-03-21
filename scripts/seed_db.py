#!/usr/bin/env python3
"""
scripts/seed_db.py
──────────────────
Seeds the database with an initial admin user.
Run once after applying the schema:

    cd backend
    python ../scripts/seed_db.py

    # Or with a custom password:
    ADMIN_PASSWORD=MyS3cretPwd python ../scripts/seed_db.py
"""
import os
import sys
import uuid

# Allow running from repo root or backend/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from passlib.context import CryptContext
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

DATABASE_URL = os.environ["DATABASE_URL"].replace("postgresql+asyncpg://", "postgresql://")
ADMIN_EMAIL  = os.environ.get("ADMIN_EMAIL",    "admin@memoryscope.local")
ADMIN_NAME   = os.environ.get("ADMIN_NAME",     "Administrator")
ADMIN_PASS   = os.environ.get("ADMIN_PASSWORD", "changeme123!")

pwd = CryptContext(schemes=["bcrypt"]).hash(ADMIN_PASS)
engine = create_engine(DATABASE_URL)

with engine.begin() as conn:
    existing = conn.execute(
        text("SELECT id FROM users WHERE email = :email"),
        {"email": ADMIN_EMAIL},
    ).fetchone()

    if existing:
        conn.execute(
            text("UPDATE users SET password_hash = :hash WHERE email = :email"),
            {"hash": pwd, "email": ADMIN_EMAIL},
        )
        print(f"✓ Updated password for existing user: {ADMIN_EMAIL}")
    else:
        conn.execute(
            text("""
                INSERT INTO users (id, email, display_name, password_hash, role)
                VALUES (:id, :email, :name, :hash, 'admin')
            """),
            {
                "id":    str(uuid.uuid4()),
                "email": ADMIN_EMAIL,
                "name":  ADMIN_NAME,
                "hash":  pwd,
            },
        )
        print(f"✓ Created admin user: {ADMIN_EMAIL}")

print(f"  Password: {ADMIN_PASS}")
print("\nLogin at http://localhost:3000")
engine.dispose()
