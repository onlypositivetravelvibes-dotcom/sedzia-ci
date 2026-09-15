#!/usr/bin/env python3
"""Reproduce M14 E24 GEN BEFORE from the immutable input bundle."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent
BYTES = ROOT / "bajty"
OUT = ROOT / "out"


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha_file(path: Path) -> str:
    return sha_bytes(path.read_bytes())


def write_new(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False).encode("utf-8") + b"\n"
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


R0_SHA256 = "0b36f708ce4f23264cee0f6a56663a6b75603acc33da473e2658b89e6b88749f"


def main() -> int:
    issued_at = os.environ.get("ISSUED_AT", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    issued = datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ")
    phase = os.environ.get("PHASE", "AFTER")
    if phase not in {"BEFORE", "AFTER", "SHADOW"}:
        raise ValueError("BAD_PHASE")
    statement_id = os.environ.get("STATEMENT_ID", "m14-e24-gen-" + phase.lower() + "-astra-1")
    issuer_ref = os.environ.get("ISSUER_REF", "1a835d13240da459")
    lineage_ref = os.environ.get("LINEAGE_REF", "astra-e24-independent-reproduction-1")
    if not all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}", value) for value in (statement_id, issuer_ref, lineage_ref)):
        raise ValueError("BAD_STATEMENT_IDENTITY")
    manifest = json.loads((ROOT / "E24_MANIFEST.json").read_text(encoding="utf-8"))
    seed_text = (ROOT / "HOLDOUT_SEED_GEN_v2.txt").read_text(encoding="utf-8").strip()
    if sha_bytes(seed_text.encode()) != manifest["holdout_seed_sha256"]:
        raise ValueError("HOLDOUT_SEED_SHA256_MISMATCH")
    seed = int(seed_text)

    local_files = {
        "solver": Path(os.environ.get("SOLVER_PATH", str(BYTES / "gen_sekwencje.py"))),
        "scorer": BYTES / "zdolnosci.py",
        "gold_oracle": BYTES / "wzorzec_zdolnosci.py",
        "generator": BYTES / "fixtures_zdolnosci.py",
        "common": BYTES / "common.py",
        "measure_port": BYTES / "zdolnosci_pomiar.py",
    }
    file_hashes = {name: sha_file(path) for name, path in local_files.items()}
    for name, actual in file_hashes.items():
        expected = R0_SHA256 if name == "solver" and phase == "BEFORE" else manifest["code"][name]["sha256"]
        if actual != expected:
            raise ValueError("CODE_SHA256_MISMATCH:" + name)
    if sha_bytes(canonical(manifest["tasks"])) != manifest["sample_manifest_sha256"]:
        raise ValueError("SAMPLE_MANIFEST_SHA256_MISMATCH")

    sys.path.insert(0, str(BYTES))
    import fixtures_zdolnosci as fixtures
    import zdolnosci as evaluator

    generated = [case for case in fixtures.generate(seed) if case["domain"] == "GEN"]
    if len(generated) != manifest["n"]:
        raise ValueError("GENERATED_TASK_COUNT_MISMATCH")
    generated_by_id = {case["task_id"]: case for case in generated}
    if len(generated_by_id) != len(generated):
        raise ValueError("DUPLICATE_GENERATED_TASK_ID")

    manifest_by_id = {row["task_id"]: row for row in manifest["tasks"]}
    if set(generated_by_id) != set(manifest_by_id):
        raise ValueError("TASK_ID_SET_MISMATCH")
    split_for_family = {0: "DEV", 1: "DEV", 2: "DEV", 3: "SHADOW", 4: "SHADOW", 5: "FINAL"}
    for task_id, case in generated_by_id.items():
        expected = manifest_by_id[task_id]
        family_number = int(case["family_id"].split("-")[-1])
        if case["input_sha256"] != expected["input_sha256"]:
            raise ValueError("INPUT_SHA256_MISMATCH:" + task_id)
        if case["family_id"] != expected["family_id"] or split_for_family[family_number] != expected["split"]:
            raise ValueError("TASK_CLASSIFICATION_MISMATCH:" + task_id)

    child = (
        "import json,sys; sys.path.insert(0,'.'); "
        "from gen_sekwencje import solve; "
        "print(json.dumps(solve(json.load(sys.stdin)),sort_keys=True,separators=(',',':')))"
    )
    answers = []
    verdicts = []
    with tempfile.TemporaryDirectory(prefix="m14-e24-solver-") as directory:
        work = Path(directory)
        shutil.copyfile(local_files["solver"], work / "gen_sekwencje.py")
        safe_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONIOENCODING": "utf-8"}
        for row in manifest["tasks"]:
            case = generated_by_id[row["task_id"]]
            before = resource.getrusage(resource.RUSAGE_CHILDREN)
            started = time.monotonic_ns()
            done = subprocess.run(
                [sys.executable, "-I", "-c", child],
                input=json.dumps(case["input"], ensure_ascii=False),
                text=True,
                capture_output=True,
                cwd=work,
                env=safe_env,
                timeout=10,
                check=False,
            )
            elapsed_ns = time.monotonic_ns() - started
            after = resource.getrusage(resource.RUSAGE_CHILDREN)
            cpu_us = max(0, round(((after.ru_utime + after.ru_stime) - (before.ru_utime + before.ru_stime)) * 1_000_000))
            if done.returncode != 0:
                raise RuntimeError("SOLVER_FAILED:" + row["task_id"] + ":" + done.stderr[:160])
            raw = done.stdout.strip()
            verdict = evaluator.evaluate(case, raw)
            answers.append({
                "task_id": row["task_id"],
                "split": row["split"],
                "input_sha256": row["input_sha256"],
                "raw_answer": raw,
                "raw_answer_sha256": sha_bytes(raw.encode()),
                "solver_cpu_us": cpu_us,
                "wall_us": round(elapsed_ns / 1000),
            })
            verdicts.append({"task_id": row["task_id"], "split": row["split"], **verdict})

    passed = sum(row["status"] == "PASS" for row in verdicts)
    raw_evidence = {
        "schema": "braun.m14.e24_before_raw/1",
        "source_commit": "bd71e091c6ba09bdecd1df07a0ea0bce44adf546",
        "cycle_id": "M14-E24-GEN-1",
        "phase": phase,
        "domain": "GEN",
        "manifest_sha256": sha_file(ROOT / "E24_MANIFEST.json"),
        "sample_manifest_sha256": manifest["sample_manifest_sha256"],
        "holdout_seed_sha256": manifest["holdout_seed_sha256"],
        "code_sha256": file_hashes,
        "isolation": {
            "solver_process": "python -I child; only reviewed solver file copied into child cwd",
            "environment": "allowlist PATH and PYTHONIOENCODING only",
            "gold_and_evaluator": "parent process only",
            "residual": "same OS user and filesystem; seed disclosed to evaluator and accessible in source bundle",
        },
        "answers": answers,
        "verdicts": verdicts,
        "result": {"passed": passed, "n": len(verdicts), "value": passed / len(verdicts)},
        "cost": {"unit": "cpu_us", "observed_solver_total": sum(row["solver_cpu_us"] for row in answers)},
        "activation_eligible": False,
    }
    raw_path = OUT / "E24_BEFORE_RAW.json"
    write_new(raw_path, raw_evidence)
    raw_sha = sha_file(raw_path)
    subject_sha = sha_bytes(canonical({
        "cycle_id": raw_evidence["cycle_id"],
        "domain": "GEN",
        "candidate_sha256": file_hashes["solver"],
        "sample_manifest_sha256": manifest["sample_manifest_sha256"],
    }))
    statement = {
        "schema": "braun.m14.statement/1",
        "statement_id": statement_id,
        "predicate_kind": "MEASUREMENT",
        "subject_sha256": subject_sha,
        "cycle_id": raw_evidence["cycle_id"],
        "operation_id": "M14-E24-WEJSCIE-1",
        "source_event_id": "github-comment-5676764233",
        "raw_evidence_sha256": raw_sha,
        "candidate_sha256": file_hashes["solver"],
        "evaluator_sha256": file_hashes["scorer"],
        "protocol_sha256": sha_bytes(manifest["code"]["protocol"].encode()),
        "sample_manifest_sha256": manifest["sample_manifest_sha256"],
        "issuer_ref": issuer_ref,
        "lineage_ref": lineage_ref,
        "issued_at": issued_at,
        "expires_at": (issued + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "phase": phase,
        "value": passed / len(verdicts),
        "unit": "accuracy",
        "direction": "higher",
        "n": len(verdicts),
        "sample_ids": sorted(generated_by_id),
        "cost": raw_evidence["cost"]["observed_solver_total"],
        "cost_unit": "cpu_us",
        "missingness": "NONE" if passed == len(verdicts) else "NONPASS_PRESENT",
        "activation_eligible": False,
    }
    write_new(OUT / "E24_BEFORE_MEASUREMENT_BODY_UNSIGNED.json", statement)
    summary = {
        "schema": "braun.m14.e24_before_summary/1",
        "status": "MEASURED_UNSIGNED",
        "passed": passed,
        "n": len(verdicts),
        "value": passed / len(verdicts),
        "raw_evidence_sha256": raw_sha,
        "statement_body_sha256": sha_bytes(canonical(statement)),
        "signature": "NOT_RUN_PRIVATE_KEY_UNAVAILABLE_IN_RUNTIME",
        "raw_evidence_persistence": "LOCAL_TRANSIENT_NOT_PUBLISHED_TO_AVOID_HOLDOUT_ANSWER_LEAKAGE",
        "after": "NOT_RUN",
        "effect": "NOT_RUN",
        "grant": "NOT_ISSUED",
        "full_m14_green": False,
        "m15_gate": "BLOCKED",
    }
    write_new(OUT / "SUMMARY.json", summary)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0  # A valid measurement may have accuracy below 1; execution success is separate.


if __name__ == "__main__":
    raise SystemExit(main())
