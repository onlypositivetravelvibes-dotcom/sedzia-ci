from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PACKAGE = Path(__file__).resolve().parents[1]
SRC = PACKAGE / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(PACKAGE))

from m14_attestation import PAYLOAD_TYPE, assess_effect, comparable, pae, validate_holdout, verify
from m14_common import canonical, sha256_file
from m14_queue import Queue, QueueConflict
from m14_trust import POLICY_SOURCE, ed25519_verifier_from_policy, trust_policy_from_env, verify_effect_bundle
import m14_worker
from sign_statement import build_envelope


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)

    def tearDown(self): self.tmp.cleanup()

    def test_enqueue_deduplicates_identical(self):
        q = Queue(self.root); a = q.enqueue("event-1", {"x": 1}); b = q.enqueue("event-1", {"x": 1})
        self.assertEqual(a["payload_sha256"], b["payload_sha256"]); self.assertEqual(q.counts(), {"PENDING": 1}); q.close()

    def test_same_id_changed_payload_conflicts(self):
        q = Queue(self.root); q.enqueue("event-1", {"x": 1})
        with self.assertRaises(QueueConflict): q.enqueue("event-1", {"x": 2})
        q.close()

    def test_claim_is_single_owner_and_finish_is_cas(self):
        q1 = Queue(self.root); q2 = Queue(self.root); q1.enqueue("event-1", {"x": 1})
        self.assertIsNotNone(q1.claim("a1")); self.assertIsNone(q2.claim("a2"))
        with self.assertRaises(QueueConflict): q2.finish("event-1", "a2", "DONE", {})
        self.assertEqual(q1.finish("event-1", "a1", "DONE", {"ok": True})["state"], "DONE")
        q1.close(); q2.close()

    def test_release_returns_unexecuted_claim_to_pending(self):
        q = Queue(self.root); q.enqueue("event-1", {"x": 1}); q.claim("a1")
        self.assertEqual(q.release("event-1", "a1")["state"], "PENDING")
        self.assertIsNotNone(q.claim("a2")); q.close()

    def test_hook_queues_hashes_only_and_is_idempotent(self):
        env = dict(os.environ, CLAUDE_PROJECT_DIR=str(self.root), PYTHONPATH=str(SRC))
        body = json.dumps({"hook_event_name": "Stop", "turn_id": "secret-turn", "session_id": "secret-session"})
        for _ in range(2):
            r = subprocess.run([sys.executable, str(SRC / "m14_hak.py")], input=body, text=True, env=env, capture_output=True, timeout=2)
            self.assertEqual(r.returncode, 0)
        q = Queue(self.root / "products/quorum-brain/runtime_state/m14")
        row = q.con.execute("select * from events").fetchone(); self.assertIsNotNone(row)
        stored = row["payload_json"]; self.assertNotIn("secret-turn", stored); self.assertNotIn("secret-session", stored)
        self.assertEqual(q.counts(), {"PENDING": 1}); q.close()

    def test_hook_missing_turn_and_home_stop_do_nothing(self):
        env = dict(os.environ, CLAUDE_PROJECT_DIR=str(self.root), PYTHONPATH=str(SRC))
        r = subprocess.run([sys.executable, str(SRC / "m14_hak.py")], input='{"hook_event_name":"Stop"}', text=True, env=env, timeout=2)
        self.assertEqual(r.returncode, 0)
        marker = self.root / "products/quorum-brain/feniks/state/HAKI_WYLACZONE"; marker.parent.mkdir(parents=True); marker.touch()
        r = subprocess.run([sys.executable, str(SRC / "m14_hak.py")], input='{"hook_event_name":"Stop","turn_id":"x"}', text=True, env=env, timeout=2)
        self.assertEqual(r.returncode, 0); self.assertFalse((self.root / "products/quorum-brain/runtime_state/m14/queue.sqlite3").exists())


def statement(kind="EFFECT", **updates):
    z = "0" * 64
    body = {
        "schema": "braun.m14.statement/1", "statement_id": "s1", "predicate_kind": kind,
        "subject_sha256": z, "cycle_id": "c1", "operation_id": "o1", "source_event_id": "e1",
        "raw_evidence_sha256": "1" * 64, "candidate_sha256": "2" * 64,
        "evaluator_sha256": "3" * 64, "protocol_sha256": "4" * 64,
        "sample_manifest_sha256": "5" * 64, "issuer_ref": "k1", "lineage_ref": "lineage-a",
        "issued_at": "2026-09-15T00:00:00Z", "expires_at": "2026-09-16T00:00:00Z",
    }
    if kind == "MEASUREMENT":
        body.update(phase="BEFORE", value=0.5, unit="accuracy", direction="higher", n=2, sample_ids=["a", "b"], cost=2, missingness=[])
    body.update(updates)
    raw = (json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
           if any(isinstance(v, float) and not __import__("math").isfinite(v) for v in body.values()) else canonical(body))
    return {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(raw).decode(), "signatures": [{"keyid": "k1", "sig": base64.b64encode(b"valid").decode()}]}


class AttestationTests(unittest.TestCase):
    policy = {"keys": {"k1": {"domain": "judge-a", "predicates": ["EFFECT", "MEASUREMENT"], "revoked": False}}}
    good_verifier = staticmethod(lambda keyid, message, sig: keyid == "k1" and message.startswith(b"DSSEv1 ") and sig == b"valid")

    def test_valid_signature_positive_control(self):
        result = verify(statement(), self.policy, "2026-09-15T01:00:00Z", self.good_verifier)
        self.assertEqual(result["status"], "VERIFIED")

    def test_no_protected_verifier_is_unproven(self):
        self.assertEqual(verify(statement(), self.policy, "2026-09-15T01:00:00Z")["status"], "UNPROVEN")

    def test_invalid_signature_wrong_type_and_forged_key(self):
        self.assertEqual(verify(statement(), self.policy, "2026-09-15T01:00:00Z", lambda *_: False)["reason"], "INVALID_SIGNATURE")
        e = statement(); e["payloadType"] = "text/plain"
        self.assertEqual(verify(e, self.policy, "2026-09-15T01:00:00Z", self.good_verifier)["reason"], "WRONG_PAYLOAD_TYPE")
        e = statement(); e["signatures"][0]["keyid"] = "forged"
        self.assertEqual(verify(e, self.policy, "2026-09-15T01:00:00Z", self.good_verifier)["reason"], "SIGNER_UNKNOWN")

    def test_revoked_and_expired(self):
        p = {"keys": {"k1": {"domain": "judge-a", "predicates": ["EFFECT"], "revoked": True}}}
        self.assertEqual(verify(statement(), p, "2026-09-15T01:00:00Z", self.good_verifier)["reason"], "SIGNER_REVOKED")
        self.assertEqual(verify(statement(), self.policy, "2027-01-01T00:00:00Z", self.good_verifier)["reason"], "STATEMENT_EXPIRED")
        self.assertEqual(verify(statement(issued_at="2026-09-15T02:00:00Z"), self.policy, "2026-09-15T01:00:00Z", self.good_verifier)["reason"], "STATEMENT_FROM_FUTURE")

    def test_noncanonical_nan_bool_and_sample_errors_rejected(self):
        for update in ({"value": True}, {"value": "ACCEPT"}, {"value": float("inf")}, {"n": 2, "sample_ids": ["a", "a"]}, {"cost": -1}):
            with self.subTest(update=update):
                e = statement("MEASUREMENT", **update)
                self.assertEqual(verify(e, self.policy, "2026-09-15T01:00:00Z", self.good_verifier)["status"], "REJECTED")

    def test_candidate_domain_is_not_independent(self):
        a = {"status": "VERIFIED", "predicate_kind": "EFFECT", "domain": "candidate", "lineage": "a", "statement_id": "s-a", "body": {"subject_sha256": "0"*64, "cycle_id": "c"}}
        b = {"status": "VERIFIED", "predicate_kind": "EFFECT", "domain": "judge", "lineage": "b", "statement_id": "s-b", "body": {"subject_sha256": "0"*64, "cycle_id": "c"}}
        self.assertEqual(assess_effect([a, b], "candidate")["status"], "UNPROVEN")

    def test_two_independent_domains_required(self):
        a = {"status": "VERIFIED", "predicate_kind": "EFFECT", "domain": "a", "lineage": "x", "body": {"subject_sha256": "0"*64, "cycle_id": "c"}}
        a["statement_id"] = "s-a"
        b = {"status": "VERIFIED", "predicate_kind": "EFFECT", "domain": "b", "lineage": "y", "statement_id": "s-b", "body": {"subject_sha256": "0"*64, "cycle_id": "c"}}
        self.assertEqual(assess_effect([a, b], "candidate")["status"], "EFFECT_VERIFIED")
        b["lineage"] = "x"; self.assertEqual(assess_effect([a, b], "candidate")["status"], "UNPROVEN")

    def test_before_after_must_be_distinct_and_comparable(self):
        before = verify(statement("MEASUREMENT"), self.policy, "2026-09-15T01:00:00Z", self.good_verifier)
        reused = verify(statement("MEASUREMENT", phase="AFTER", statement_id="s2"), self.policy, "2026-09-15T01:00:00Z", self.good_verifier)
        self.assertEqual(comparable(before, reused)["reason"], "REUSED_EXECUTION")
        after_e = statement("MEASUREMENT", phase="AFTER", statement_id="s2", raw_evidence_sha256="9"*64, value=0.75)
        after = verify(after_e, self.policy, "2026-09-15T01:00:00Z", self.good_verifier)
        self.assertEqual(comparable(before, after), {"status": "COMPARABLE", "delta": 0.25})
        changed = verify(statement("MEASUREMENT", phase="AFTER", statement_id="s3", raw_evidence_sha256="8"*64, evaluator_sha256="f"*64), self.policy, "2026-09-15T01:00:00Z", self.good_verifier)
        self.assertEqual(comparable(before, changed)["status"], "MEASUREMENT_PENDING")

    def test_holdout_is_cluster_disjoint(self):
        good = {"groups": {
            "DEV": [{"cluster_id": "t0", "sample_ids": ["d0", "d1"]}],
            "SHADOW": [{"cluster_id": "t3", "sample_ids": ["s0"]}],
            "FINAL": [{"cluster_id": "t5", "sample_ids": ["f0"]}],
        }}
        self.assertEqual(validate_holdout(good)["status"], "SEALED")
        bad = json.loads(json.dumps(good)); bad["groups"]["FINAL"][0]["cluster_id"] = "t3"
        self.assertEqual(validate_holdout(bad)["reason"], "CLUSTER_OVERLAP")
        bad = json.loads(json.dumps(good)); bad["groups"]["FINAL"][0]["sample_ids"] = ["s0"]
        self.assertEqual(validate_holdout(bad)["reason"], "SAMPLE_OVERLAP")


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        solvers = self.root / "products/quorum-brain/runtime/solvers"; solvers.mkdir(parents=True)
        (solvers / "r0.py").write_text("x=0\n"); (solvers / "r1.py").write_text("x=1\n")
        self.plan = {
            "schema": "m14.cycle_plan/1", "source_event_id": "event-1", "cycle_id": "cycle-1", "domain": "GEN",
            "g0": "G-r0", "g1": "G-r1", "owner_record_id": "R-now", "grant_ref": "owner:R-now:G-r1",
            "r0_path": "products/quorum-brain/runtime/solvers/r0.py", "r1_path": "products/quorum-brain/runtime/solvers/r1.py",
            "artifact_sha256": {"r0": sha256_file(solvers / "r0.py"), "r1": sha256_file(solvers / "r1.py")},
            "plan_sha256": "a"*64, "sample_ids": ["GEN-template-3-v0"],
            "witnesses": [{"event_id": "inc-1", "ref": "ticket:1", "task": "GEN-template-0-v0"}],
            "candidate_domain": "candidate", "effect_subject_sha256": "6"*64,
            "effect_statement_ids": ["effect-astra", "effect-brat"],
            "activation_mode": "PREPARE_ONLY", "rollback_after_test": True,
        }
        self.calls = []

    def tearDown(self): self.tmp.cleanup()

    def modules(self):
        calls = self.calls
        class Registry: pass
        class Ports:
            def __init__(self, **kw): calls.append(("ports", kw))
        class Budget:
            def __init__(self, path): calls.append(("budget", path))
        U = types.SimpleNamespace(
            otworz=lambda state, ports: {"cycles": {"old-b": {}, "old-a": {}}},
            wznow=lambda ctx, cid: calls.append(("resume", cid)) or {"state": "TESTED"},
        )
        SC = types.SimpleNamespace(
            VIEW="solver-gen", SCOPE="solvers/gen_sekwencje.py", STAN=str(self.root / "cycles"),
            cykl=lambda *args: calls.append(("cycle", args[4], args[5])) or {"state": "NO_DEMONSTRATED_GAIN"},
        )
        return {"samonaprawa_cykl": SC, "uczenie": U, "uczenie_porty": types.SimpleNamespace(PortyLokalne=Ports), "publikacja": types.SimpleNamespace(RejestrLokalny=Registry), "budzet": types.SimpleNamespace(Budzet=Budget, BAZA=str(self.root/"budget.sqlite"))}

    def test_resume_precedes_exact_existing_cycle_call(self):
        result = m14_worker.resume_then_call(self.root, self.plan, self.modules(), {"status": "EFFECT_VERIFIED", "domains": ["judge-a", "judge-b"]})
        self.assertEqual(result["state"], "NO_DEMONSTRATED_GAIN")
        order = [x[0] for x in self.calls]; self.assertLess(order.index("resume"), order.index("cycle"))
        self.assertEqual([x[1] for x in self.calls if x[0] == "resume"], ["old-a", "old-b"])
        cycle = [x for x in self.calls if x[0] == "cycle"][0]; self.assertEqual(cycle[1:], ("G-r0", "G-r1"))

    def test_diagnostic_only_blocks_call(self):
        with self.assertRaises(PermissionError): m14_worker.resume_then_call(self.root, self.plan, self.modules())
        self.assertFalse(any(x[0] == "cycle" for x in self.calls))

    def test_stale_or_missing_grant_rejected(self):
        self.plan["grant_ref"] = "owner:old:G-r1"
        with self.assertRaisesRegex(ValueError, "GRANT"): m14_worker.resume_then_call(self.root, self.plan, self.modules(), {"status": "EFFECT_VERIFIED", "domains": ["a", "b"]})

    def test_artifact_escape_and_hash_drift_rejected(self):
        self.plan["r1_path"] = "../../etc/passwd"
        with self.assertRaises(ValueError): m14_worker.resume_then_call(self.root, self.plan, self.modules(), {"status": "EFFECT_VERIFIED", "domains": ["a", "b"]})
        self.plan["r1_path"] = "products/quorum-brain/runtime/solvers/r1.py"; self.plan["artifact_sha256"]["r1"] = "0"*64
        with self.assertRaisesRegex(ValueError, "HASH"): m14_worker.resume_then_call(self.root, self.plan, self.modules(), {"status": "EFFECT_VERIFIED", "domains": ["a", "b"]})

    def test_self_reported_trust_and_candidate_judge_are_refused(self):
        self.plan["trust_status"] = "EFFECT_VERIFIED"
        with self.assertRaises(PermissionError): m14_worker.resume_then_call(self.root, self.plan, self.modules())
        with self.assertRaisesRegex(PermissionError, "candidate domain"):
            m14_worker.resume_then_call(self.root, self.plan, self.modules(), {"status": "EFFECT_VERIFIED", "domains": ["candidate", "judge"]})

    def test_worker_waits_without_plan_and_does_not_call(self):
        q = Queue(self.root / "products/quorum-brain/runtime_state/m14"); q.enqueue("event-1", {"x": 1})
        row = m14_worker.process_one(self.root, q, "attempt-1", modules=self.modules())
        self.assertEqual(row["state"], "WAITING_FOR_PLAN"); self.assertFalse(any(x[0] == "cycle" for x in self.calls)); q.close()

    def test_waiting_event_runs_when_plan_arrives(self):
        state = self.root / "products/quorum-brain/runtime_state/m14"; q = Queue(state); q.enqueue("event-1", {"x": 1})
        self.assertEqual(m14_worker.process_one(self.root, q, "attempt-1", modules=self.modules())["state"], "WAITING_FOR_PLAN")
        plans = state / "plans"; plans.mkdir(); (plans / "event-1.json").write_text(json.dumps(self.plan))
        row = m14_worker.process_one(self.root, q, "attempt-2", modules=self.modules(), trust_result={"status": "EFFECT_VERIFIED", "domains": ["judge-a", "judge-b"]})
        self.assertEqual(row["state"], "DONE"); self.assertTrue(any(x[0] == "cycle" for x in self.calls)); q.close()

    def test_stop_biegi_prevents_claim_and_cycle(self):
        state = self.root / "products/quorum-brain/runtime_state/m14"; q = Queue(state); q.enqueue("event-1", {"x": 1})
        stop = self.root / m14_worker.COST_STOP; stop.parent.mkdir(parents=True); stop.touch()
        self.assertIsNone(m14_worker.process_one(self.root, q, "attempt-1", modules=self.modules(), trust_result={"status": "EFFECT_VERIFIED", "domains": ["a", "b"]}))
        self.assertEqual(q.get("event-1")["state"], "PENDING"); self.assertFalse(any(x[0] == "cycle" for x in self.calls)); q.close()

    def test_process_one_derives_real_two_signature_trust(self):
        state = self.root / "products/quorum-brain/runtime_state/m14"; q = Queue(state); q.enqueue("event-1", {"x": 1})
        plans = state / "plans"; plans.mkdir(); (plans / "event-1.json").write_text(json.dumps(self.plan))
        attest = self.root / "attest"; attest.mkdir()
        a, a_hex, a_id = key_material(); b, b_hex, b_id = key_material()
        (attest / "effect-astra.dsse.json").write_text(json.dumps(signed_effect(a, a_id, "effect-astra", "astra-lineage")))
        (attest / "effect-brat.dsse.json").write_text(json.dumps(signed_effect(b, b_id, "effect-brat", "brat-lineage")))
        row = m14_worker.process_one(
            self.root, q, "attempt-real", modules=self.modules(), attest_dir=attest,
            environ={"BRAUN_ASTRA_PUBKEY": a_hex, "BRAUN_BRAT_PUBKEY": b_hex}, now="2026-09-15T01:00:00Z",
        )
        self.assertEqual(row["state"], "DONE"); self.assertTrue(any(x[0] == "cycle" for x in self.calls)); q.close()

    def test_prepare_only_plan_fields_are_mandatory(self):
        self.plan["activation_mode"] = "ACTIVATE"
        with self.assertRaisesRegex(ValueError, "PREPARE_ONLY"):
            m14_worker.validate_plan(self.plan, "event-1", self.root)


def key_material():
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return private, raw.hex(), hashlib.sha256(raw).hexdigest()[:16]


def signed_effect(private, keyid, statement_id, lineage, cycle_id="cycle-1", subject="6"*64):
    body = statement(
        statement_id=statement_id, issuer_ref=keyid, lineage_ref=lineage,
        cycle_id=cycle_id, subject_sha256=subject,
    )
    payload = json.loads(base64.b64decode(body["payload"]))
    return build_envelope(payload, private)


class R4ProtectedVerifierTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.astra, self.astra_hex, self.astra_id = key_material()
        self.brat, self.brat_hex, self.brat_id = key_material()
        self.env = {"BRAUN_ASTRA_PUBKEY": self.astra_hex, "BRAUN_BRAT_PUBKEY": self.brat_hex}
        (self.root / "effect-astra.dsse.json").write_text(json.dumps(signed_effect(self.astra, self.astra_id, "effect-astra", "astra-lineage")))
        (self.root / "effect-brat.dsse.json").write_text(json.dumps(signed_effect(self.brat, self.brat_id, "effect-brat", "brat-lineage")))

    def tearDown(self): self.tmp.cleanup()

    def bundle(self, **updates):
        args = dict(attest_dir=self.root, statement_ids=["effect-astra", "effect-brat"], candidate_domain="candidate", cycle_id="cycle-1", subject_sha256="6"*64, now="2026-09-15T01:00:00Z", environ=self.env)
        args.update(updates)
        return verify_effect_bundle(**args)

    def test_owner_env_is_the_only_trust_source(self):
        self.assertEqual(trust_policy_from_env({})["status"], "DIAGNOSTIC_ONLY")
        one = trust_policy_from_env({"BRAUN_ASTRA_PUBKEY": self.astra_hex})
        self.assertEqual(one["reason"], "INDEPENDENT_EFFECT_DOMAINS_MISSING")
        policy = trust_policy_from_env(self.env)
        self.assertEqual(policy["status"], "READY"); self.assertEqual(policy["source"], POLICY_SOURCE)
        fake = dict(policy, source="GIT_FILE")
        self.assertIsNone(ed25519_verifier_from_policy(fake))
        (self.root / "TRUST_ASTRA_PUBKEY.txt").write_text(self.astra_hex)
        self.assertEqual(self.bundle(environ={})["status"], "UNPROVEN")

    def test_owner_env_key_normalization_is_explicit_and_safe(self):
        decorated = {
            "BRAUN_ASTRA_PUBKEY": "  " + self.astra_hex.upper() + "\n",
            "BRAUN_BRAT_PUBKEY": "\t" + self.brat_hex.upper() + "  ",
        }
        policy = trust_policy_from_env(decorated)
        self.assertEqual(policy["status"], "READY")
        self.assertEqual(policy["keys"][self.astra_id]["public_key_hex"], self.astra_hex)
        self.assertEqual(policy["keys"][self.brat_id]["public_key_hex"], self.brat_hex)
        self.assertEqual(self.bundle(environ=decorated)["status"], "EFFECT_VERIFIED")

    def test_malformed_present_owner_env_key_has_named_reason(self):
        malformed = dict(self.env, BRAUN_ASTRA_PUBKEY="not-a-key\n")
        policy = trust_policy_from_env(malformed)
        self.assertEqual(policy["status"], "DIAGNOSTIC_ONLY")
        self.assertEqual(policy["reason"], "KEY_FORMAT:BRAUN_ASTRA_PUBKEY")
        result = self.bundle(environ=malformed)
        self.assertEqual(result["status"], "UNPROVEN")
        self.assertEqual(result["reason"], "KEY_FORMAT:BRAUN_ASTRA_PUBKEY")

    def test_normalization_does_not_create_a_second_domain(self):
        duplicate = {
            "BRAUN_ASTRA_PUBKEY": self.astra_hex,
            "BRAUN_BRAT_PUBKEY": " " + self.astra_hex.upper() + "\n",
        }
        policy = trust_policy_from_env(duplicate)
        self.assertEqual(policy["status"], "DIAGNOSTIC_ONLY")
        self.assertEqual(policy["reason"], "INDEPENDENT_EFFECT_DOMAINS_MISSING")

    def test_two_real_signatures_are_required_and_bound(self):
        result = self.bundle()
        self.assertEqual(result["status"], "EFFECT_VERIFIED")
        self.assertEqual(result["domains"], ["astra", "brat"])
        bad = json.loads((self.root / "effect-astra.dsse.json").read_text())
        raw = bytearray(base64.b64decode(bad["payload"])); raw[-2] ^= 1
        bad["payload"] = base64.b64encode(raw).decode()
        (self.root / "effect-astra.dsse.json").write_text(json.dumps(bad))
        self.assertNotEqual(self.bundle()["status"], "EFFECT_VERIFIED")

    def test_wrong_signature_over_valid_payload_is_rejected(self):
        bad = json.loads((self.root / "effect-astra.dsse.json").read_text())
        bad["signatures"][0]["sig"] = base64.b64encode(b"\0" * 64).decode()
        (self.root / "effect-astra.dsse.json").write_text(json.dumps(bad))
        self.assertEqual(self.bundle()["reason"], "INVALID_SIGNATURE")

    def test_statement_id_is_bound_to_filename(self):
        envelope = json.loads((self.root / "effect-astra.dsse.json").read_text())
        body = json.loads(base64.b64decode(envelope["payload"])); body["statement_id"] = "different-id"
        (self.root / "effect-astra.dsse.json").write_text(json.dumps(build_envelope(body, self.astra)))
        self.assertEqual(self.bundle()["reason"], "STATEMENT_ID_PATH_MISMATCH")

    def test_candidate_mismatch_expiry_revocation_and_escape_fail(self):
        self.assertEqual(self.bundle(candidate_domain="astra")["reason"], "CANDIDATE_DOMAIN_IS_JUDGE")
        self.assertEqual(self.bundle(cycle_id="other")["reason"], "EFFECT_WITNESS_PLAN_MISMATCH")
        self.assertEqual(self.bundle(now="2027-01-01T00:00:00Z")["reason"], "STATEMENT_EXPIRED")
        policy = trust_policy_from_env(self.env); policy["keys"][self.astra_id]["revoked"] = True
        result = verify(json.loads((self.root / "effect-astra.dsse.json").read_text()), policy, "2026-09-15T01:00:00Z", ed25519_verifier_from_policy(policy))
        self.assertEqual(result["reason"], "SIGNER_REVOKED")
        self.assertEqual(self.bundle(statement_ids=["../escape", "effect-brat"])["status"], "REJECTED")

    def test_issuer_must_match_signing_key(self):
        with self.assertRaisesRegex(ValueError, "ISSUER_KEYID_MISMATCH"):
            signed_effect(self.astra, self.brat_id, "bad-issuer", "astra-lineage")
        envelope = statement(issuer_ref="other")
        result = verify(envelope, AttestationTests.policy, "2026-09-15T01:00:00Z", AttestationTests.good_verifier)
        self.assertEqual(result["reason"], "ISSUER_KEYID_MISMATCH")

    def test_prepare_only_proxy_blocks_activation(self):
        calls = []
        wrapped = types.SimpleNamespace(aktywuj=lambda: calls.append("activated"), read=lambda: "ok")
        ports = m14_worker.PrepareOnlyPorts(wrapped)
        self.assertEqual(ports.read(), "ok")
        with self.assertRaisesRegex(PermissionError, "PREPARE_ONLY"):
            ports.aktywuj()
        self.assertEqual(calls, [])

    def test_private_key_is_not_packaged(self):
        names = [str(p.relative_to(PACKAGE)).lower() for p in PACKAGE.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
        self.assertFalse(any(name.endswith((".pem", ".key")) or "private_key" in name for name in names))
        trust = (PACKAGE / "TRUST_ASTRA_PUBKEY.txt").read_text()
        self.assertIn("ef73047d2382297d2c435ab9b7f4137ef901447ac807246a791e10765c2dedd0", trust)
        self.assertNotIn("BEGIN PRIVATE KEY", trust)

    def test_r6_sedzia_ci_is_an_explicit_third_domain(self):
        ci, ci_hex, ci_id = key_material()
        env = {
            "BRAUN_ASTRA_PUBKEY": self.astra_hex,
            "BRAUN_SEDZIA_CI_PUBKEY": "  " + ci_hex.upper() + "\n",
        }
        policy = trust_policy_from_env(env)
        self.assertEqual(policy["status"], "READY")
        self.assertEqual(policy["keys"][ci_id]["domain"], "sedzia-ci")
        self.assertEqual(policy["keys"][ci_id]["lineage_prefix"], "sedzia-ci-run-")
        (self.root / "effect-ci.dsse.json").write_text(json.dumps(
            signed_effect(ci, ci_id, "effect-ci", "sedzia-ci-run-123")
        ))
        result = self.bundle(
            statement_ids=["effect-astra", "effect-ci"], environ=env
        )
        self.assertEqual(result["status"], "EFFECT_VERIFIED")
        self.assertEqual(result["domains"], ["astra", "sedzia-ci"])

    def test_r6_astra_anchor_and_second_domain_are_required(self):
        _, ci_hex, _ = key_material()
        self.assertEqual(
            trust_policy_from_env({"BRAUN_SEDZIA_CI_PUBKEY": ci_hex})["status"],
            "DIAGNOSTIC_ONLY",
        )
        self.assertEqual(
            trust_policy_from_env({
                "BRAUN_BRAT_PUBKEY": self.brat_hex,
                "BRAUN_SEDZIA_CI_PUBKEY": ci_hex,
            })["reason"],
            "INDEPENDENT_EFFECT_DOMAINS_MISSING",
        )
        all_three = dict(self.env, BRAUN_SEDZIA_CI_PUBKEY=ci_hex)
        self.assertEqual(trust_policy_from_env(all_three)["status"], "READY")

    def test_r7_effect_bundle_requires_astra_witness_even_with_three_keys(self):
        ci, ci_hex, ci_id = key_material()
        all_three = dict(self.env, BRAUN_SEDZIA_CI_PUBKEY=ci_hex)
        (self.root / "effect-ci.dsse.json").write_text(json.dumps(
            signed_effect(ci, ci_id, "effect-ci", "sedzia-ci-run-456")
        ))
        result = self.bundle(
            statement_ids=["effect-brat", "effect-ci"], environ=all_three
        )
        self.assertEqual(result, {
            "status": "UNPROVEN",
            "reason": "ASTRA_EFFECT_WITNESS_MISSING",
        })
        self.assertEqual(self.bundle(environ=all_three)["status"], "EFFECT_VERIFIED")
        self.assertEqual(
            self.bundle(statement_ids=["effect-astra", "effect-ci"], environ=all_three)["status"],
            "EFFECT_VERIFIED",
        )

    def test_r6_third_key_format_duplicate_and_lineage_fail_closed(self):
        ci, ci_hex, ci_id = key_material()
        malformed = dict(self.env, BRAUN_SEDZIA_CI_PUBKEY="bad")
        self.assertEqual(
            trust_policy_from_env(malformed)["reason"],
            "KEY_FORMAT:BRAUN_SEDZIA_CI_PUBKEY",
        )
        duplicate = dict(self.env, BRAUN_SEDZIA_CI_PUBKEY=self.brat_hex)
        self.assertEqual(
            trust_policy_from_env(duplicate)["reason"],
            "INDEPENDENT_EFFECT_DOMAINS_MISSING",
        )
        env = {
            "BRAUN_ASTRA_PUBKEY": self.astra_hex,
            "BRAUN_SEDZIA_CI_PUBKEY": ci_hex,
        }
        (self.root / "effect-ci-bad.dsse.json").write_text(json.dumps(
            signed_effect(ci, ci_id, "effect-ci-bad", "brat-lineage")
        ))
        result = self.bundle(
            statement_ids=["effect-astra", "effect-ci-bad"], environ=env
        )
        self.assertEqual(result["reason"], "LINEAGE_POLICY_MISMATCH")

    def test_r6b_published_sedzia_key_has_exact_id_and_explicit_domain(self):
        published = "08e9d619b2751985b6b72ded6caaedf7a8579c9ce6be3545102b172f18f58655"
        keyid = hashlib.sha256(bytes.fromhex(published)).hexdigest()[:16]
        self.assertEqual(keyid, "fc5df253a482079e")
        policy = trust_policy_from_env({
            "BRAUN_ASTRA_PUBKEY": self.astra_hex,
            "BRAUN_SEDZIA_CI_PUBKEY": published,
        })
        self.assertEqual(policy["status"], "READY")
        self.assertEqual(policy["keys"][keyid]["domain"], "sedzia-ci")
        self.assertEqual(policy["keys"][keyid]["lineage_prefix"], "sedzia-ci-run-")
        self.assertEqual(policy["keys"][keyid]["variable"], "BRAUN_SEDZIA_CI_PUBKEY")


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name) / "host"; self.pkg = Path(self.tmp.name) / "pkg"
        self.root.mkdir(); shutil.copytree(SRC, self.pkg / "src")
        self.launcher = m13_line = 'krok "m13-worker"        120 "$KORZEN"  python3 products/quorum-brain/runtime/m13_worker.py --root "$KORZEN"\n'
        self.launcher += '\n' + 'krok_mierzacy "przyrzady-p1p8"    450 "$KORZEN"  python3 braun_boot/przyrzady.py --full\n'
        settings = {"permissions": {"allow": ["x"]}, "hooks": {"Stop": [{"matcher": "*", "hooks": [{"type": "command", "timeout": 1, "command": str(i)}]} for i in range(6)]}}
        files = {"braun_boot/start_tlo.sh": self.launcher.encode(), ".claude/settings.json": json.dumps(settings, separators=(",", ":")).encode(), "protected.txt": b"unchanged"}
        for p, data in files.items(): (self.root / p).parent.mkdir(parents=True, exist_ok=True); (self.root / p).write_bytes(data)
        contract = {"host_pins": {p: hashlib.sha256(data).hexdigest() for p, data in files.items()}}
        (self.pkg / "KONTRAKT_R1.json").write_text(json.dumps(contract))
        self.spec = importlib.util.spec_from_file_location("installer_tested", PACKAGE / "installer.py"); self.inst = importlib.util.module_from_spec(self.spec); self.spec.loader.exec_module(self.inst); self.old = self.inst.PACKAGE; self.inst.PACKAGE = self.pkg

    def tearDown(self): self.inst.PACKAGE = self.old; self.tmp.cleanup()

    def test_check_apply_and_rollback_preserve_existing_bytes(self):
        before_settings = (self.root / ".claude/settings.json").read_bytes()
        launcher = self.root / "braun_boot/start_tlo.sh"; launcher.chmod(0o755)
        self.assertEqual(self.inst.inspect(self.root)["state"], "READY")
        with self.assertRaisesRegex(ValueError, "HOUSE_STOP"): self.inst.apply(self.root)
        marker = self.root / self.inst.MARKER; marker.parent.mkdir(parents=True); marker.touch()
        self.assertEqual(self.inst.apply(self.root)["state"], "APPLIED")
        self.assertEqual(launcher.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.inst.inspect(self.root)["state"], "INSTALLED")
        after = json.loads((self.root / ".claude/settings.json").read_text()); self.assertEqual(len(after["hooks"]["Stop"]), 7); self.assertEqual(after["permissions"], {"allow": ["x"]})
        self.assertEqual(self.inst.rollback(self.root)["state"], "ROLLED_BACK")
        self.assertEqual(launcher.stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.root / ".claude/settings.json").read_bytes(), before_settings); self.assertEqual((self.root / "protected.txt").read_bytes(), b"unchanged")
        self.assertEqual(self.inst.rollback(self.root), {"state": "ALREADY_ROLLED_BACK", "changed": False})

    def test_drift_blocks_apply_and_foreign_post_edit_blocks_rollback(self):
        (self.root / "protected.txt").write_bytes(b"foreign")
        self.assertEqual(self.inst.inspect(self.root)["state"], "HOLD")
        (self.root / "protected.txt").write_bytes(b"unchanged")
        marker = self.root / self.inst.MARKER; marker.parent.mkdir(parents=True); marker.touch(); self.inst.apply(self.root)
        target = self.root / "products/quorum-brain/runtime/m14_banner.py"; target.write_text(target.read_text() + "# foreign\n")
        with self.assertRaisesRegex(ValueError, "ROLLBACK_DRIFT"): self.inst.rollback(self.root)

    def test_rollback_without_record_is_idempotent_noop(self):
        marker = self.root / self.inst.MARKER; marker.parent.mkdir(parents=True); marker.touch()
        self.assertEqual(self.inst.rollback(self.root), {"state": "NOTHING_INSTALLED", "changed": False})

    def test_parallel_apply_has_one_writer(self):
        marker = self.root / self.inst.MARKER; marker.parent.mkdir(parents=True); marker.touch()
        results, errors, gate = [], [], threading.Barrier(2)
        def run():
            try:
                gate.wait(); results.append(self.inst.apply(self.root)["state"])
            except Exception as exc:
                errors.append(str(exc))
        threads = [threading.Thread(target=run) for _ in range(2)]
        for thread in threads: thread.start()
        for thread in threads: thread.join(5)
        self.assertFalse(errors); self.assertCountEqual(results, ["APPLIED", "INSTALL_ALREADY_RECORDED"])

    def test_unrecorded_new_target_is_visible_hold(self):
        path, content = next(iter(self.inst.targets().items()))
        target = self.root / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(content)
        result = self.inst.inspect(self.root)
        self.assertEqual(result["state"], "HOLD")
        self.assertIn("NEW_TARGET_EXISTS:" + path, result["holds"])

    def test_interrupted_commit_is_tracked_and_rollback_cleans_targets_and_stages(self):
        marker = self.root / self.inst.MARKER; marker.parent.mkdir(parents=True); marker.touch()
        real_replace = self.inst.os.replace; stage_replaces = 0
        def interrupt(source, target):
            nonlocal stage_replaces
            if ".m14-stage-" in str(source):
                stage_replaces += 1
                if stage_replaces == 2:
                    raise RuntimeError("SIMULATED_SIGKILL_WINDOW")
            return real_replace(source, target)
        with mock.patch.object(self.inst.os, "replace", side_effect=interrupt):
            with self.assertRaisesRegex(RuntimeError, "SIMULATED_SIGKILL_WINDOW"):
                self.inst.apply(self.root)
        result = self.inst.inspect(self.root)
        self.assertEqual(result["state"], "HOLD"); self.assertIn("INSTALL_INCOMPLETE", result["holds"])
        self.assertEqual(self.inst.rollback(self.root)["state"], "ROLLED_BACK")
        self.assertEqual((self.root / "braun_boot/start_tlo.sh").read_text(), self.launcher)
        for path in self.inst.targets():
            self.assertFalse((self.root / path).exists())
            self.assertEqual(list((self.root / path).parent.glob("." + Path(path).name + ".m14-stage-*")), [])

    def test_r2_install_record_remains_readable_and_rollbackable(self):
        marker = self.root / self.inst.MARKER; marker.parent.mkdir(parents=True); marker.touch()
        self.inst.apply(self.root)
        state = self.root / self.inst.STATE / "install.json"; record = json.loads(state.read_text())
        record["schema"] = "m14.install/1"; record.pop("staged"); record.pop("transaction_id"); record.pop("phase")
        state.write_text(json.dumps(record))
        self.assertEqual(self.inst.inspect(self.root)["state"], "INSTALLED")
        self.assertEqual(self.inst.rollback(self.root)["state"], "ROLLED_BACK")

    def test_recorded_r7_upgrades_to_r8_and_rolls_back_to_r7(self):
        marker = self.root / self.inst.MARKER; marker.parent.mkdir(parents=True); marker.touch()
        self.inst.apply(self.root)
        state = self.root / self.inst.STATE / "install.json"
        r7_record = json.loads(state.read_text())
        r7_record["package_generation"] = "M14-R7"
        r7_record.pop("parent_record", None)
        state.write_text(json.dumps(r7_record))
        hook_before = (self.root / ".claude/settings.json").read_bytes()
        launcher_before = (self.root / "braun_boot/start_tlo.sh").read_bytes()
        source = self.pkg / "src/m14_trust.py"; source.write_text(source.read_text() + "\n# R7 mandatory Astra witness\n")
        self.assertEqual(self.inst.inspect(self.root)["state"], "READY_UPGRADE")
        self.assertEqual(self.inst.apply(self.root)["state"], "APPLIED")
        upgraded = json.loads(state.read_text())
        self.assertEqual(upgraded["schema"], "m14.install/3")
        self.assertEqual(upgraded["package_generation"], "M14-R8")
        self.assertEqual(upgraded["parent_record"], r7_record)
        self.assertEqual((self.root / ".claude/settings.json").read_bytes(), hook_before)
        self.assertEqual((self.root / "braun_boot/start_tlo.sh").read_bytes(), launcher_before)
        self.assertEqual(self.inst.rollback(self.root)["state"], "ROLLED_BACK_TO_PARENT")
        self.assertEqual(json.loads(state.read_text()), r7_record)
        self.assertEqual(self.inst.rollback(self.root), {"state": "ALREADY_ROLLED_BACK", "changed": False})

    def test_tampered_stage_path_cannot_escape_root(self):
        marker = self.root / self.inst.MARKER; marker.parent.mkdir(parents=True); marker.touch()
        self.inst.apply(self.root)
        state = self.root / self.inst.STATE / "install.json"; record = json.loads(state.read_text())
        first = next(iter(record["staged"])); original = record["staged"][first]
        record["staged"][first] = str(self.root / original)
        state.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "INSTALL_RECORD_CORRUPT"):
            self.inst.rollback(self.root)
        record["staged"][first] = "foreign/" + Path(original).name
        state.write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, "INSTALL_RECORD_CORRUPT"):
            self.inst.rollback(self.root)
        self.assertEqual((self.root / "protected.txt").read_bytes(), b"unchanged")


class EvidenceTests(unittest.TestCase):
    def test_evidence_requires_explicit_new_path_and_never_overwrites(self):
        spec = importlib.util.spec_from_file_location("m14_verify_tested", PACKAGE / "verify.py")
        tested = importlib.util.module_from_spec(spec); spec.loader.exec_module(tested)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "run.json"
            tested.write_evidence(path, {"run": 1})
            before = path.read_bytes()
            with self.assertRaises(FileExistsError): tested.write_evidence(path, {"run": 2})
            self.assertEqual(path.read_bytes(), before)

    def test_existing_evidence_refuses_before_test_run(self):
        spec = importlib.util.spec_from_file_location("m14_verify_preflight", PACKAGE / "verify.py")
        tested = importlib.util.module_from_spec(spec); spec.loader.exec_module(tested)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "exists.json"; path.write_text("protected\n")
            old = sys.argv; sys.argv = ["verify.py", "--evidence", str(path)]
            try:
                with mock.patch.object(tested, "run_tests", side_effect=AssertionError("tests must not run")):
                    self.assertEqual(tested.main(), 2)
            finally:
                sys.argv = old
            self.assertEqual(path.read_text(), "protected\n")


class StaticPolicyTests(unittest.TestCase):
    def test_no_historical_owner_helper_or_main_called(self):
        text = (SRC / "m14_worker.py").read_text()
        self.assertNotIn("dokument_wlasciciela(", text); self.assertNotIn(".main(", text)
        self.assertIn("SC.cykl(", text)

    def test_hook_has_no_model_or_cycle_import(self):
        text = (SRC / "m14_hak.py").read_text()
        self.assertNotIn("samonaprawa", text); self.assertNotIn("uczenie", text); self.assertNotIn("subprocess", text)

    def test_contract_keeps_module_green_false(self):
        c = json.loads((PACKAGE / "KONTRAKT_R1.json").read_text())
        self.assertTrue(c["green"]["r1_local_green_is_not_module_green"]); self.assertEqual(c["trust"]["status"], "HOLD_DIAGNOSTIC_ONLY")

    def test_banner_never_infers_green_from_corrupt_cycle_state(self):
        from m14_banner import banner
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); p = root / "products/quorum-brain/runtime_state/cykle/solver-gen/cycles.json"; p.parent.mkdir(parents=True); p.write_text("broken")
            result = banner(root)
            self.assertEqual(result["state"], "UNKNOWN"); self.assertEqual(result["effect_status"], "UNPROVEN")

    def test_external_two_domain_effect_example(self):
        example = json.loads((PACKAGE / "EFFECT_TWO_DOMAINS_EXAMPLE.json").read_text())
        result = assess_effect(example["verified_attestations"], example["candidate_domain"])
        self.assertEqual(result, example["expected"])


if __name__ == "__main__": unittest.main()
