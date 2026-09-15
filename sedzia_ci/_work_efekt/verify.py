#!/usr/bin/env python3
"""Reproducible M14 R9 verification. Evidence is preflighted and create-only."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

PACKAGE = Path(__file__).resolve().parent
MUTANTS = [
    ('r9_runner_domain', 'RUN_EFFECT.py', "require(before['domain'] == after['domain'], 'RUNNER_DOMAIN_MISMATCH')", "require(True, 'RUNNER_DOMAIN_MISMATCH')"),
    ('r9_subject', 'RUN_EFFECT.py', "require(subject == plan.get('effect_subject_sha256'), 'EFFECT_SUBJECT_MISMATCH')", "require(True, 'EFFECT_SUBJECT_MISMATCH')"),
    ('r9_plan_hash', 'RUN_EFFECT.py', "require(digest == plan.get('plan_sha256'), 'PLAN_HASH_MISMATCH')", "require(True, 'PLAN_HASH_MISMATCH')"),
    ('r9_signature', 'RUN_EFFECT.py', "require(result.get('status') == 'VERIFIED', 'MEASUREMENT_' + result.get('reason', 'UNVERIFIED'))", "require(True, 'MEASUREMENT_' + result.get('reason', 'UNVERIFIED'))"),
    ('r9_r0r1', 'RUN_EFFECT.py', "require(a['candidate_sha256'] == R0_SHA256 and b['candidate_sha256'] == R1_SHA256, 'R0_R1_BINDING_MISMATCH')", "require(True, 'R0_R1_BINDING_MISMATCH')"),
    ('r9_issuer', 'RUN_EFFECT.py', "require(entry.get('domain') == domain, 'EFFECT_ISSUER_DOMAIN_MISMATCH')", "require(True, 'EFFECT_ISSUER_DOMAIN_MISMATCH')"),
    ('r9_prepare', 'RUN_EFFECT.py', "require(plan.get('activation_mode') == 'PREPARE_ONLY' and plan.get('rollback_after_test') is True, 'PREPARE_ONLY_REQUIRED')", "require(True, 'PREPARE_ONLY_REQUIRED')"),

    ("r8_ci_slot_removed", "src/m14_trust.py", '("BRAUN_ASTRA_CI_PUBKEY", "astra-ci", "astra-ci-run-"),', '("BRAUN_UNUSED_CI_PUBKEY", "unused-ci", "unused-ci-run-"),'),
    ("r8_published_key_alias_allowed", "src/m14_trust.py", 'if keyid in published_domains and published_domains[keyid] != domain:', "if False:"),
    ("candidate_as_judge", "src/m14_attestation.py", "if candidate_domain in domains:", "if False:"),
    ("scorer_mismatch_ignored", "src/m14_attestation.py", "if any(a.get(k) != b.get(k) for k in keys):", "if False:"),
    ("unsigned_is_enough", "src/m14_attestation.py", "if verifier is None:", "if False:"),
    ("reuse_after", "src/m14_attestation.py", "if a.get(\"statement_id\") == b.get(\"statement_id\") or a.get(\"raw_evidence_sha256\") == b.get(\"raw_evidence_sha256\"):", "if False:"),
    ("queue_last_write_wins", "src/m14_queue.py", "if old[\"payload_sha256\"] != digest:", "if False:"),
    ("trust_gate_removed", "src/m14_worker.py", "if not isinstance(trust_result, dict) or trust_result.get(\"status\") != \"EFFECT_VERIFIED\":", "if False:"),
    ("resume_skipped", "src/m14_worker.py", "for cycle_id in sorted(ctx.get(\"cycles\", {})):", "for cycle_id in []:"),
    ("unproven_banner_green", "src/m14_banner.py", '"effect_status": "UNPROVEN",', '"effect_status": "EFFECT_VERIFIED",'),
    ("stop_biegi_ignored", "src/m14_worker.py", "or (root / COST_STOP).exists() or (root / COST_STOP).is_symlink()", "or False"),
    ("installer_lock_removed", "installer.py", "with install_lock(root):\n        plan = inspect(root)", "with contextlib.nullcontext():\n        plan = inspect(root)"),
    ("evidence_overwrite", "verify.py", "mode=" + '\"x\"', "mode=" + '\"w\"'),
    ("installer_orphan_ignored", "installer.py", 'holds.append("NEW_TARGET_EXISTS:" + path)', 'changes[path] = content'),
    ("installer_commit_skipped", "installer.py", "os.replace(_staged_path(root, staged[path], path), root / path)", "pass"),
    ("evidence_preflight_removed", "verify.py", "evidence_target = " + "preflight_evidence(args.evidence)", "evidence_target = args.evidence"),
    ("record_path_escape_allowed", "installer.py", 'if relative.is_absolute() or ".." in relative.parts:', "if False:"),
    ("record_stage_parent_unchecked", "installer.py", "if path.parent != target.parent or not path.name.startswith(expected_prefix):", "if False:"),
    ("r4_git_policy_accepted", "src/m14_trust.py", 'if policy.get("source") != POLICY_SOURCE:', "if False:"),
    ("r6_astra_anchor_removed", "src/m14_trust.py", 'if not ({"astra", "astra-ci"} & domains) or not ({"brat", "sedzia-ci"} & domains):', "if False:"),
    ("r4_signature_bypassed", "src/m14_trust.py", "Ed25519PublicKey.from_public_bytes(raw).verify(signature, message)\n            return True", "return True"),
    ("r4_filename_id_unbound", "src/m14_trust.py", 'if body.get("statement_id") != statement_id:', "if False:"),
    ("r4_effect_plan_unbound", "src/m14_trust.py", 'if body.get("cycle_id") != cycle_id or body.get("subject_sha256") != subject_sha256:', "if False:"),
    ("r4_self_reported_trust_used", "src/m14_worker.py", "if trust_result is None:", "if False:"),
    ("r4_prepare_only_removed", "src/m14_worker.py", 'if plan.get("activation_mode") != "PREPARE_ONLY" or plan.get("rollback_after_test") is not True:', "if False:"),
    ("r4_activation_port_open", "src/m14_worker.py", 'if lowered in self.BLOCKED or any(token in lowered for token in ("aktyw", "activat", "promot")):', "if False:"),
    ("r5_owner_key_not_normalized", "src/m14_trust.py", "normalized = value.strip().lower()", "normalized = value"),
    ("r5_bad_owner_key_accepted", "src/m14_trust.py", "if not HEX64_RE.fullmatch(normalized):", "if False:"),
    ("r6_sedzia_slot_removed", "src/m14_trust.py", '("BRAUN_SEDZIA_CI_PUBKEY", "sedzia-ci", "sedzia-ci-run-"),', '("BRAUN_UNUSED_PUBKEY", "unused", None),'),
    ("r6_lineage_policy_removed", "src/m14_attestation.py", "if lineage_prefix is not None and (", "if False and ("),
    ("r7_astra_effect_witness_removed", "src/m14_trust.py", 'if assessed.get("status") == "EFFECT_VERIFIED" and not ({"astra", "astra-ci"} & set(assessed.get("domains", []))):', "if False:"),
]


def run_tests(package: Path):
    started = time.monotonic()
    proc = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"], cwd=package, capture_output=True, text=True, timeout=120)
    return {"returncode": proc.returncode, "seconds": round(time.monotonic() - started, 3), "stdout": proc.stdout, "stderr": proc.stderr}


def mutate(package: Path, path: str, before: str, after: str):
    target = package / path; text = target.read_text()
    if text.count(before) != 1: raise RuntimeError("mutation anchor mismatch: " + path)
    target.write_text(text.replace(before, after))


def manifest(package: Path):
    excluded = {"MANIFEST_SHA256.json"}
    return {str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(package.rglob("*")) if p.is_file() and "__pycache__" not in p.parts and p.name not in excluded and not p.name.endswith(".pyc")}


def write_evidence(target: Path, report: dict) -> None:
    target = Path(target).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open(mode="x", encoding="utf-8") as handle:
        handle.write(json.dumps(report, sort_keys=True, indent=2) + "\n")


def preflight_evidence(target: Path) -> Path:
    target = Path(target).resolve()
    if target.exists() or target.is_symlink():
        raise FileExistsError(target)
    return target


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--evidence", type=Path, metavar="NEW_PATH"); args = ap.parse_args()
    evidence_target = None
    if args.evidence:
        try:
            evidence_target = preflight_evidence(args.evidence)
        except FileExistsError:
            print(json.dumps({"status": "HOLD", "reason": "EVIDENCE_EXISTS", "path": str(args.evidence.resolve())}, sort_keys=True))
            return 2
    baseline = run_tests(PACKAGE)
    mutant_results = []
    if baseline["returncode"] == 0:
        for name, path, before, after in MUTANTS:
            with tempfile.TemporaryDirectory(prefix="m14-mutant-") as d:
                copy = Path(d) / "package"; shutil.copytree(PACKAGE, copy, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "evidence"))
                mutate(copy, path, before, after); result = run_tests(copy)
                mutant_results.append({"name": name, "killed": result["returncode"] != 0, "returncode": result["returncode"]})
    report = {
        "schema": "m14.r9.local_results/1", "baseline_returncode": baseline["returncode"],
        "tests_discovered": baseline["stderr"].count(" ... ok"), "seconds": baseline["seconds"],
        "mutants": mutant_results, "mutants_killed": sum(x["killed"] for x in mutant_results),
        "mutants_total": len(MUTANTS), "host_tests": "NOT_RUN", "module_all_green": False,
        "stdout_sha256": hashlib.sha256(baseline["stdout"].encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256(baseline["stderr"].encode()).hexdigest(),
    }
    if evidence_target:
        try:
            write_evidence(evidence_target, report)
        except FileExistsError:
            print(json.dumps({"status": "HOLD", "reason": "EVIDENCE_EXISTS", "path": str(evidence_target)}, sort_keys=True))
            return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if baseline["returncode"] == 0 and report["mutants_killed"] == report["mutants_total"] else 1


if __name__ == "__main__": raise SystemExit(main())
