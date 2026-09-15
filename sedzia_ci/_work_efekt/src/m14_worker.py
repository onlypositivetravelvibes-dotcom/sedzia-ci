#!/usr/bin/env python3
"""M14 R1 worker: resume existing uczenie cycles, then call samonaprawa_cykl.cykl narrowly."""
from __future__ import annotations

import argparse
import importlib
import json
import os
from pathlib import Path
import sys
import uuid

from m14_common import HEX64_RE, atomic_json, safe_id, sha256_file, under, utc_now
from m14_queue import Queue
from m14_trust import verify_effect_bundle

PLAN_SCHEMA = "m14.cycle_plan/1"
COST_STOP = "products/quorum-brain/hle/biegi/STOP_BIEGI"
HOME_STOP = "products/quorum-brain/feniks/state/HAKI_WYLACZONE"
OFF = {"0", "off", "nie", "false", "no", "wyl", "stop"}


class StopRequested(RuntimeError):
    pass


def stopped(root: Path) -> bool:
    return (
        (root / HOME_STOP).exists() or (root / HOME_STOP).is_symlink()
        or (root / COST_STOP).exists() or (root / COST_STOP).is_symlink()
        or os.environ.get("BRAUN_HOOK", "").strip().lower() in OFF
    )


def validate_plan(plan: dict, event_id: str, root: Path) -> dict:
    if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
        raise ValueError("BAD_PLAN_SCHEMA")
    if plan.get("source_event_id") != event_id:
        raise ValueError("SOURCE_EVENT_MISMATCH")
    for key in ("cycle_id", "g0", "g1", "owner_record_id", "candidate_domain"):
        safe_id(plan.get(key), key)
    if plan["g0"] == plan["g1"]:
        raise ValueError("R0_EQUALS_R1")
    if plan.get("domain") != "GEN":
        raise ValueError("UNSUPPORTED_DOMAIN")
    if not isinstance(plan.get("witnesses"), list) or not plan["witnesses"]:
        raise ValueError("WITNESSES_MISSING")
    if not isinstance(plan.get("sample_ids"), list) or not plan["sample_ids"]:
        raise ValueError("SAMPLES_MISSING")
    if len(set(map(str, plan["sample_ids"]))) != len(plan["sample_ids"]):
        raise ValueError("DUPLICATE_SAMPLES")
    if not HEX64_RE.fullmatch(str(plan.get("plan_sha256", ""))):
        raise ValueError("BAD_PLAN_SHA256")
    if not HEX64_RE.fullmatch(str(plan.get("effect_subject_sha256", ""))):
        raise ValueError("BAD_EFFECT_SUBJECT")
    effect_ids = plan.get("effect_statement_ids")
    if not isinstance(effect_ids, list) or len(effect_ids) != 2 or len(set(effect_ids)) != 2:
        raise ValueError("TWO_EFFECT_STATEMENTS_REQUIRED")
    for statement_id in effect_ids:
        safe_id(statement_id, "effect_statement_id")
    if plan.get("activation_mode") != "PREPARE_ONLY" or plan.get("rollback_after_test") is not True:
        raise ValueError("PREPARE_ONLY_REQUIRED")
    for key in ("r0_path", "r1_path"):
        p = under(root, root / str(plan.get(key, "")))
        allowed = root / "products/quorum-brain/runtime/solvers"
        under(allowed, p)
        if not p.is_file():
            raise ValueError("ARTIFACT_MISSING:" + key)
    expected = plan.get("artifact_sha256") or {}
    if expected.get("r0") != sha256_file(root / plan["r0_path"]) or expected.get("r1") != sha256_file(root / plan["r1_path"]):
        raise ValueError("ARTIFACT_HASH_MISMATCH")
    if plan.get("grant_ref") != f"owner:{plan['owner_record_id']}:{plan['g1']}":
        raise ValueError("CURRENT_GRANT_BINDING_REQUIRED")
    return plan


def load_host(root: Path):
    runtime = root / "products/quorum-brain/runtime"
    sys.path.insert(0, str(runtime))
    modules = {name: importlib.import_module(name) for name in ("uczenie", "uczenie_porty", "publikacja", "budzet", "samonaprawa_cykl")}
    if modules["samonaprawa_cykl"].cykl.__name__ != "cykl":
        raise RuntimeError("EXISTING_CYCLE_CALLER_MISSING")
    return modules


class PrepareOnlyPorts:
    """Deny activation-shaped port calls while forwarding diagnostic operations."""
    BLOCKED = {"aktywuj", "activate", "activation", "promote", "publish", "opublikuj"}

    def __init__(self, wrapped):
        object.__setattr__(self, "_wrapped", wrapped)

    def __getattr__(self, name):
        lowered = name.lower()
        if lowered in self.BLOCKED or any(token in lowered for token in ("aktyw", "activat", "promot")):
            def blocked(*_args, **_kwargs):
                raise PermissionError("PREPARE_ONLY: activation port blocked")
            return blocked
        return getattr(self._wrapped, name)

    def __setattr__(self, name, value):
        setattr(self._wrapped, name, value)


def resume_then_call(root: Path, plan: dict, modules=None, trust_result: dict | None = None) -> dict:
    if stopped(root):
        raise StopRequested("STOP_BIEGI_OR_HOME_STOP")
    event_id = plan["source_event_id"]
    plan = validate_plan(plan, event_id, root)
    if not isinstance(trust_result, dict) or trust_result.get("status") != "EFFECT_VERIFIED":
        raise PermissionError("DIAGNOSTIC_ONLY: protected independent effect verifier missing")
    if plan.get("candidate_domain") in set(trust_result.get("domains") or []):
        raise PermissionError("DIAGNOSTIC_ONLY: candidate domain cannot verify its own effect")
    m = modules or load_host(root)
    SC, U, UP, PUB, B = (m[k] for k in ("samonaprawa_cykl", "uczenie", "uczenie_porty", "publikacja", "budzet"))
    registry = PUB.RejestrLokalny()
    ports = PrepareOnlyPorts(UP.PortyLokalne(view=SC.VIEW, scope=SC.SCOPE, rejestr=registry))
    budget = B.Budzet(B.BAZA)
    ctx = U.otworz(SC.STAN, ports)
    resumed = []
    for cycle_id in sorted(ctx.get("cycles", {})):
        row = U.wznow(ctx, cycle_id)
        resumed.append({"cycle_id": cycle_id, "state": row.get("state")})
    if stopped(root):
        raise StopRequested("STOP_BIEGI_OR_HOME_STOP")
    result = SC.cykl(
        plan["cycle_id"], ports, ctx, budget, plan["g0"], plan["g1"],
        plan["owner_record_id"], plan["witnesses"], plan["plan_sha256"],
        list(plan["sample_ids"]), bool(plan.get("rollback_after_test", False)),
    )
    return {"state": result.get("state", "UNKNOWN"), "cycle_id": plan["cycle_id"], "resumed": resumed, "result": result}


def process_one(
    root: Path,
    queue: Queue,
    attempt_id: str,
    modules=None,
    trust_result=None,
    attest_dir: Path | None = None,
    environ=None,
    now: str | None = None,
) -> dict | None:
    if stopped(root):
        return None
    row = queue.claim(attempt_id)
    if not row:
        return None
    event_id = row["event_id"]
    plan_path = root / "products/quorum-brain/runtime_state/m14/plans" / f"{event_id}.json"
    if not plan_path.is_file():
        return queue.finish(event_id, attempt_id, "WAITING_FOR_PLAN", {"status": "DIAGNOSTIC_ONLY", "reason": "PLAN_MISSING"})
    if stopped(root):
        queue.release(event_id, attempt_id)
        return None
    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        plan = validate_plan(plan, event_id, root)
        # Production derives trust from two signed envelopes and owner-session
        # public keys. The optional object exists only for isolated test doubles;
        # no plan field can set it.
        if trust_result is None:
            trust_result = verify_effect_bundle(
                attest_dir or (root / "od_astry/KANAL/attest"),
                plan["effect_statement_ids"],
                plan["candidate_domain"],
                plan["cycle_id"],
                plan["effect_subject_sha256"],
                now or utc_now(),
                environ=environ,
            )
        result = resume_then_call(root, plan, modules=modules, trust_result=trust_result)
        final = "DONE" if result["state"] in {"KEPT", "ROLLED_BACK", "NO_DEMONSTRATED_GAIN"} else "BLOCKED"
    except StopRequested:
        queue.release(event_id, attempt_id)
        return None
    except PermissionError as exc:
        result, final = {"status": "DIAGNOSTIC_ONLY", "reason": str(exc)}, "BLOCKED"
    except Exception as exc:
        result, final = {"status": "FAILED", "reason": f"{type(exc).__name__}: {str(exc)[:200]}"}, "FAILED"
    return queue.finish(event_id, attempt_id, final, result)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--max-events", type=int, default=100)
    ap.add_argument("--attest-dir", type=Path)
    args = ap.parse_args()
    root = Path(args.root).resolve()
    state = root / "products/quorum-brain/runtime_state/m14"
    if stopped(root):
        print(json.dumps({"status": "STOPPED_BY_STOP_BIEGI_OR_HOME"}))
        return 0
    attempt = "worker-" + uuid.uuid4().hex
    q = Queue(state)
    results = []
    try:
        for _ in range(max(0, min(args.max_events, 1000))):
            row = process_one(root, q, attempt, attest_dir=args.attest_dir)
            if row is None:
                break
            results.append({"event_id": row["event_id"], "state": row["state"]})
    finally:
        counts = q.counts()
        q.close()
    report = {"schema": "m14.worker_run/1", "utc": utc_now(), "attempt_id": attempt, "results": results, "counts": counts}
    atomic_json(state / "last_worker.json", report)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 1 if any(r["state"] == "FAILED" for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
