"""SQLite-Init + kleine Helpers — kein ORM."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from app.logging_config import get_logger

log = get_logger(__name__)


SCHEMA = """
CREATE TABLE IF NOT EXISTS confirmations (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    args_json TEXT NOT NULL,
    risk TEXT NOT NULL,
    reasoning_text TEXT,
    status TEXT NOT NULL,
    resolved_by TEXT,
    resolved_at TEXT,
    discord_message_id TEXT,
    UNIQUE(rule_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    rule_id TEXT,
    fingerprint TEXT,
    tool_name TEXT NOT NULL,
    args_json TEXT NOT NULL,
    source TEXT NOT NULL,
    confirmation_id TEXT,
    status TEXT NOT NULL,
    http_status INTEGER,
    response_excerpt TEXT,
    elapsed_ms INTEGER,
    decision_confidence INTEGER,
    decision_reasoning TEXT,
    decision_source TEXT,
    UNIQUE(rule_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_conf_status_expires ON confirmations(status, expires_at);
CREATE INDEX IF NOT EXISTS idx_actions_created ON actions(created_at DESC);
"""


# V1 „Gläserne Autonomie": additive Spalten für die Warum-Spur einer autonomen
# Aktion. Bestehende DBs (CREATE ... IF NOT EXISTS greift dort nicht) bekommen sie
# per idempotentem ALTER — reine ADD COLUMN, schreibt keine Daten um.
_ACTION_COLUMN_MIGRATIONS: list[tuple[str, str]] = [
    ("decision_confidence", "INTEGER"),
    ("decision_reasoning", "TEXT"),
    ("decision_source", "TEXT"),
]


def _migrate(conn: sqlite3.Connection) -> None:
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(actions)")}
    for column, coltype in _ACTION_COLUMN_MIGRATIONS:
        if column not in existing:
            conn.execute(f"ALTER TABLE actions ADD COLUMN {column} {coltype}")
            log.info("db.migrated", table="actions", column=column)


_db_path: Path | None = None


def init(path: Path) -> None:
    """Open DB, ensure schema. Idempotent."""
    global _db_path
    path.parent.mkdir(parents=True, exist_ok=True)
    _db_path = path
    with connect() as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)
    log.info("db.initialized", path=str(path))


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    if _db_path is None:
        raise RuntimeError("db not initialized — call db.init() first")
    conn = sqlite3.connect(str(_db_path), timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        conn.close()


def insert_action(row: dict[str, Any]) -> bool:
    """INSERT ... OR IGNORE. Returns True if inserted, False if duplicate."""
    cols = ",".join(row.keys())
    placeholders = ",".join("?" * len(row))
    sql = f"INSERT OR IGNORE INTO actions ({cols}) VALUES ({placeholders})"
    with connect() as conn:
        cur = conn.execute(sql, tuple(row.values()))
        return cur.rowcount > 0


def update_action(action_id: str, fields: dict[str, Any]) -> None:
    sets = ",".join(f"{k}=?" for k in fields)
    sql = f"UPDATE actions SET {sets} WHERE id=?"
    with connect() as conn:
        conn.execute(sql, (*fields.values(), action_id))


def insert_confirmation(row: dict[str, Any]) -> bool:
    cols = ",".join(row.keys())
    placeholders = ",".join("?" * len(row))
    sql = f"INSERT OR IGNORE INTO confirmations ({cols}) VALUES ({placeholders})"
    with connect() as conn:
        cur = conn.execute(sql, tuple(row.values()))
        return cur.rowcount > 0


def get_confirmation(callback_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM confirmations WHERE id=?", (callback_id,)
        ).fetchone()
        return dict(row) if row else None


def update_confirmation(callback_id: str, fields: dict[str, Any]) -> None:
    sets = ",".join(f"{k}=?" for k in fields)
    sql = f"UPDATE confirmations SET {sets} WHERE id=?"
    with connect() as conn:
        conn.execute(sql, (*fields.values(), callback_id))


def list_confirmations(status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    sql = "SELECT * FROM confirmations"
    params: tuple[Any, ...] = ()
    if status:
        sql += " WHERE status=?"
        params = (status,)
    sql += " ORDER BY created_at DESC LIMIT ?"
    params = (*params, limit)
    with connect() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def list_actions(limit: int = 50) -> list[dict[str, Any]]:
    sql = "SELECT * FROM actions ORDER BY created_at DESC LIMIT ?"
    with connect() as conn:
        return [dict(r) for r in conn.execute(sql, (limit,)).fetchall()]


def expire_pending(now_iso: str) -> int:
    with connect() as conn:
        cur = conn.execute(
            "UPDATE confirmations SET status='expired' "
            "WHERE status='pending' AND expires_at < ?",
            (now_iso,),
        )
        return cur.rowcount
