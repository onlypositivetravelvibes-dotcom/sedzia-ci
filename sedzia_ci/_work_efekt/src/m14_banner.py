#!/usr/bin/env python3
"""Honest projection of M14 state. It never infers GREEN from missing data."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from m14_queue import Queue


def banner(root: Path, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    state = root / "products/quorum-brain/runtime_state/m14"
    q = Queue(state)
    try:
        counts = q.counts()
    finally:
        q.close()
    cycles = root / "products/quorum-brain/runtime_state/cykle/solver-gen/cycles.json"
    rows, status = [], "UNKNOWN"
    try:
        data = json.loads(cycles.read_text(encoding="utf-8"))
        rows = list((data.get("cycles") or {}).values())
        status = "READY"
    except Exception:
        pass
    kept = sorted((r for r in rows if r.get("state") == "KEPT"), key=lambda r: r.get("seq", 0))
    last = kept[-1] if kept else None
    worker = state / "last_worker.json"
    age = None
    if worker.exists():
        age = max(0, now - worker.stat().st_mtime)
    return {
        "schema": "m14.banner/1",
        "state": status,
        "effect_status": "UNPROVEN",
        "cycles": len(rows),
        "last_kept": ({"cycle_id": last.get("cycle_id"), "seq": last.get("seq"), "scope": (last.get("proposal") or {}).get("scope")} if last else None),
        "queue": counts,
        "last_worker_age_s": age,
        "reason": "R1 has no protected independent host verifier; missing/corrupt data remains UNKNOWN",
    }


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--root", required=True); args = ap.parse_args()
    print(json.dumps(banner(Path(args.root).resolve()), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
