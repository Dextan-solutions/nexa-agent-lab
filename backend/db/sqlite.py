from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Mapping


def _db_path() -> Path:
    # Default aligns with `.env.example` and compose volume mount.
    return Path(os.getenv("SQLITE_PATH", "/data/agenthive.db"))


def connect() -> sqlite3.Connection:
    p = _db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.row_factory = sqlite3.Row
    init_schema(conn)
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
    CREATE TABLE IF NOT EXISTS customers (
      id TEXT PRIMARY KEY,
      account_id TEXT UNIQUE,
      account_number TEXT UNIQUE NOT NULL,
      full_name TEXT NOT NULL,
      email TEXT NOT NULL,
      phone TEXT NOT NULL,
      bvn TEXT NOT NULL,
      pin_hash TEXT,
      account_type TEXT NOT NULL,
      balance_ngn REAL NOT NULL,
      tier INTEGER NOT NULL DEFAULT 1,
      kyc_status TEXT NOT NULL DEFAULT 'pending',
      frozen INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      last_login_at TEXT,
      last_statement_at TEXT
    );

    CREATE TABLE IF NOT EXISTS employees (
      id TEXT PRIMARY KEY,
      employee_id TEXT UNIQUE NOT NULL,
      full_name TEXT NOT NULL,
      department TEXT NOT NULL,
      role TEXT NOT NULL,
      email TEXT NOT NULL,
      pin_hash TEXT,
      access_level INTEGER NOT NULL DEFAULT 1,
      systems_access TEXT NOT NULL DEFAULT '[]',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id TEXT PRIMARY KEY,
      reference_code TEXT UNIQUE NOT NULL,
      sender_account TEXT NOT NULL,
      receiver_account TEXT NOT NULL,
      amount_ngn REAL NOT NULL,
      type TEXT NOT NULL,
      channel TEXT NOT NULL,
      narration TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'successful',
      fraud_score REAL NOT NULL DEFAULT 0.0,
      flagged_by_agent INTEGER NOT NULL DEFAULT 0,
      agent_action TEXT NOT NULL DEFAULT 'none',
      internal_flags TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS loan_applications (
      id TEXT PRIMARY KEY,
      applicant_account TEXT NOT NULL,
      amount_requested_ngn REAL NOT NULL,
      purpose TEXT NOT NULL,
      monthly_income_ngn REAL NOT NULL,
      employment_status TEXT NOT NULL,
      credit_score INTEGER,
      application_status TEXT NOT NULL DEFAULT 'submitted',
      agent_decision TEXT,
      agent_reasoning TEXT,
      agent_confidence REAL,
      reviewed_at TEXT,
      disbursement_account TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS support_tickets (
      id TEXT PRIMARY KEY,
      ticket_number TEXT UNIQUE NOT NULL,
      customer_account TEXT NOT NULL,
      subject TEXT NOT NULL,
      body TEXT NOT NULL,
      channel TEXT NOT NULL DEFAULT 'web',
      status TEXT NOT NULL DEFAULT 'open',
      agent_response TEXT,
      agent_tools_called TEXT,
      created_at TEXT NOT NULL,
      resolved_at TEXT
    );

    CREATE TABLE IF NOT EXISTS kyc_documents (
      id TEXT PRIMARY KEY,
      customer_account TEXT NOT NULL,
      document_type TEXT NOT NULL,
      file_path TEXT,
      extracted_data TEXT,
      verification_status TEXT NOT NULL DEFAULT 'pending',
      agent_notes TEXT,
      poisoned INTEGER NOT NULL DEFAULT 0,
      metadata_json TEXT NOT NULL DEFAULT '{}',
      uploaded_at TEXT NOT NULL,
      verified_at TEXT
    );

    CREATE TABLE IF NOT EXISTS secrets_vault (
      id TEXT PRIMARY KEY,
      secret_name TEXT UNIQUE NOT NULL,
      secret_value TEXT NOT NULL,
      classification TEXT NOT NULL,
      owner_system TEXT NOT NULL,
      accessible_by_agents TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts_ms INTEGER NOT NULL,
      agent TEXT NOT NULL,
      workflow TEXT NOT NULL,
      request_id TEXT NOT NULL,
      actor_id TEXT NOT NULL,
      security_level TEXT NOT NULL,
      tools_called_json TEXT NOT NULL,
      result_json TEXT NOT NULL,
      attack_detected INTEGER NOT NULL,
      attack_type TEXT
    );

    CREATE TABLE IF NOT EXISTS compliance_alerts (
      id TEXT PRIMARY KEY,
      alert_type TEXT NOT NULL,
      account_id TEXT NOT NULL,
      transaction_id TEXT,
      reason TEXT NOT NULL,
      created_by_agent TEXT NOT NULL,
      security_level TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS account_summaries (
      id TEXT PRIMARY KEY,
      account_id TEXT NOT NULL,
      account_number TEXT NOT NULL,
      report_type TEXT NOT NULL DEFAULT 'summary',
      period TEXT NOT NULL DEFAULT 'monthly',
      content TEXT NOT NULL,
      generated_at TEXT NOT NULL,
      security_level TEXT NOT NULL
    );
    """
    )
    # Backwards-compatible migration: older DBs won't have pin_hash.
    try:
        conn.execute("ALTER TABLE customers ADD COLUMN pin_hash TEXT")
    except Exception:
        pass
    try:
        # SQLite can't add UNIQUE constraint via ADD COLUMN; add column then index.
        conn.execute("ALTER TABLE customers ADD COLUMN account_id TEXT")
    except Exception:
        pass
    try:
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_account_id ON customers(account_id)")
    except Exception:
        pass
    # Backfill account_id for existing seeded customers (idempotent).
    try:
        conn.execute(
            """
            UPDATE customers
            SET account_id = 'ACC-' || printf('%04d', CAST(substr(account_number, 2) AS INTEGER))
            WHERE (account_id IS NULL OR account_id = '')
              AND account_number GLOB '0[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]'
            """
        )
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE employees ADD COLUMN pin_hash TEXT")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE customers ADD COLUMN frozen INTEGER NOT NULL DEFAULT 0")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE customers ADD COLUMN last_statement_at TEXT")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE transactions ADD COLUMN internal_flags TEXT NOT NULL DEFAULT '{}'")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE kyc_documents ADD COLUMN metadata_json TEXT NOT NULL DEFAULT '{}'")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE loan_applications ADD COLUMN additional_notes TEXT")
    except Exception:
        pass
    conn.commit()


def insert_audit_event(
    *,
    conn: sqlite3.Connection,
    agent: str,
    workflow: str,
    request_id: str,
    actor_id: str,
    security_level: str,
    tools_called: list[Mapping[str, Any]],
    result: Mapping[str, Any],
    attack_detected: bool,
    attack_type: str | None,
    agent_flag: str | None = None,
) -> None:
    payload = dict(result)
    if "flag" not in payload and agent_flag:
        payload["flag"] = agent_flag
    conn.execute(
        """
        INSERT INTO audit_events
          (ts_ms, agent, workflow, request_id, actor_id, security_level,
           tools_called_json, result_json, attack_detected, attack_type)
        VALUES
          (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            int(time.time() * 1000),
            agent,
            workflow,
            request_id,
            actor_id,
            security_level,
            json.dumps(tools_called, ensure_ascii=False),
            json.dumps(payload, ensure_ascii=False),
            1 if attack_detected else 0,
            attack_type,
        ),
    )
    conn.commit()

