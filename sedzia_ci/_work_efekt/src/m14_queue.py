#!/usr/bin/env python3
"""Durable M14 wake-up queue. Delivery is at-least-once; effects remain in uczenie.py."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Optional

from m14_common import canonical, safe_id, sha256_json, utc_now

SCHEMA = "m14.queue/1"


class QueueConflict(RuntimeError):
    pass


class Queue:
    def __init__(self, state_dir: Path):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.db = self.state_dir / "queue.sqlite3"
        self.con = sqlite3.connect(self.db, timeout=10, isolation_level=None)
        self.con.row_factory = sqlite3.Row
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("PRAGMA synchronous=FULL")
        self.con.executescript("""
        CREATE TABLE IF NOT EXISTS events(
          event_id TEXT PRIMARY KEY,
          payload_sha256 TEXT NOT NULL,
          payload_json TEXT NOT NULL,
          state TEXT NOT NULL,
          queued_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          attempt_id TEXT,
          result_json TEXT
        );
        CREATE INDEX IF NOT EXISTS events_state ON events(state, queued_at);
        """)

    def close(self):
        self.con.close()

    def enqueue(self, event_id: str, payload: dict) -> dict:
        event_id = safe_id(event_id, "event_id")
        if not isinstance(payload, dict):
            raise ValueError("payload must be object")
        digest = sha256_json(payload)
        now = utc_now()
        self.con.execute("BEGIN IMMEDIATE")
        try:
            old = self.con.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
            if old:
                if old["payload_sha256"] != digest:
                    raise QueueConflict(f"same event_id with different payload: {event_id}")
                self.con.execute("COMMIT")
                return dict(old)
            self.con.execute(
                "INSERT INTO events VALUES(?,?,?,?,?,?,NULL,NULL)",
                (event_id, digest, canonical(payload).decode(), "PENDING", now, now),
            )
            self.con.execute("COMMIT")
        except Exception:
            self.con.execute("ROLLBACK")
            raise
        return self.get(event_id)

    def get(self, event_id: str) -> Optional[dict]:
        row = self.con.execute("SELECT * FROM events WHERE event_id=?", (event_id,)).fetchone()
        return dict(row) if row else None

    def claim(self, attempt_id: str) -> Optional[dict]:
        safe_id(attempt_id, "attempt_id")
        self.con.execute("BEGIN IMMEDIATE")
        try:
            row = self.con.execute(
                "SELECT * FROM events WHERE state IN ('PENDING','WAITING_FOR_PLAN') ORDER BY queued_at,event_id LIMIT 1"
            ).fetchone()
            if not row:
                self.con.execute("COMMIT")
                return None
            now = utc_now()
            changed = self.con.execute(
                "UPDATE events SET state='CLAIMED',attempt_id=?,updated_at=? WHERE event_id=? AND state IN ('PENDING','WAITING_FOR_PLAN')",
                (attempt_id, now, row["event_id"]),
            ).rowcount
            if changed != 1:
                self.con.execute("ROLLBACK")
                return None
            self.con.execute("COMMIT")
            return self.get(row["event_id"])
        except Exception:
            self.con.execute("ROLLBACK")
            raise

    def finish(self, event_id: str, attempt_id: str, state: str, result: dict) -> dict:
        if state not in {"DONE", "BLOCKED", "FAILED", "WAITING_FOR_PLAN"}:
            raise ValueError("invalid final state")
        now = utc_now()
        self.con.execute("BEGIN IMMEDIATE")
        try:
            changed = self.con.execute(
                "UPDATE events SET state=?,result_json=?,updated_at=? WHERE event_id=? AND state='CLAIMED' AND attempt_id=?",
                (state, canonical(result).decode(), now, event_id, attempt_id),
            ).rowcount
            if changed != 1:
                raise QueueConflict("claim lost or changed")
            self.con.execute("COMMIT")
        except Exception:
            self.con.execute("ROLLBACK")
            raise
        return self.get(event_id)

    def release(self, event_id: str, attempt_id: str) -> dict:
        """Return an unexecuted claim to PENDING when a stop arrives."""
        now = utc_now()
        self.con.execute("BEGIN IMMEDIATE")
        try:
            changed = self.con.execute(
                "UPDATE events SET state='PENDING',attempt_id=NULL,updated_at=? WHERE event_id=? AND state='CLAIMED' AND attempt_id=?",
                (now, event_id, attempt_id),
            ).rowcount
            if changed != 1:
                raise QueueConflict("claim lost or changed")
            self.con.execute("COMMIT")
        except Exception:
            self.con.execute("ROLLBACK")
            raise
        return self.get(event_id)

    def counts(self) -> dict:
        return {r[0]: r[1] for r in self.con.execute("SELECT state,count(*) FROM events GROUP BY state")}
