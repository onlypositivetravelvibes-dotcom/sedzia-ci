#!/usr/bin/env python3
"""Fail-open Stop hook: hash stable identifiers and enqueue only; never runs a model/cycle."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

MAX_INPUT = 65536
OFF = {"0", "off", "nie", "false", "no", "wyl", "stop"}


def _root() -> Path:
    configured = os.environ.get("CLAUDE_PROJECT_DIR")
    if configured:
        return Path(configured).resolve()
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "products/quorum-brain").is_dir():
            return parent
    return here.parents[2]


def main() -> int:
    try:
        root = _root()
        runtime = root / "products/quorum-brain/runtime"
        sys.path.insert(0, str(runtime))
        from m14_queue import Queue
        marker = root / "products/quorum-brain/feniks/state/HAKI_WYLACZONE"
        if marker.exists() or marker.is_symlink() or os.environ.get("BRAUN_HOOK", "").strip().lower() in OFF:
            return 0
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            return 0
        incoming = json.loads(raw or b"{}")
        if incoming.get("hook_event_name", "Stop") != "Stop":
            return 0
        turn = incoming.get("turn_id") or incoming.get("prompt_id")
        if not isinstance(turn, str) or not turn or len(turn) > 256:
            return 0
        session = incoming.get("session_id", "")
        if not isinstance(session, str) or len(session) > 1024:
            return 0
        turn_sha = hashlib.sha256(turn.encode()).hexdigest()
        event_id = "stop-" + turn_sha
        payload = {
            "schema": "m14.wakeup/1",
            "hook_event_name": "Stop",
            "turn_sha256": turn_sha,
            "session_sha256": hashlib.sha256(session.encode()).hexdigest(),
        }
        q = Queue(root / "products/quorum-brain/runtime_state/m14")
        try:
            q.enqueue(event_id, payload)
        finally:
            q.close()
    except Exception:
        # Wake-up is neither authority nor a receipt. Hook failure must not lock the captain out.
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
