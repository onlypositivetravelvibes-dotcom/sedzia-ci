#!/usr/bin/env python3
"""Owner-env trust roots and strict DSSE loading for M14 R8."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping

from m14_attestation import assess_effect, verify
from m14_common import HEX64_RE, safe_id, sha256_bytes, under

POLICY_SCHEMA = "braun.m14.owner_env_policy/1"
POLICY_SOURCE = "OWNER_SESSION_ENV"
KEY_SPECS = (
    ("BRAUN_ASTRA_PUBKEY", "astra", None),
    ("BRAUN_ASTRA_CI_PUBKEY", "astra-ci", "astra-ci-run-"),
    ("BRAUN_BRAT_PUBKEY", "brat", None),
    ("BRAUN_SEDZIA_CI_PUBKEY", "sedzia-ci", "sedzia-ci-run-"),
)
PREDICATES = ["BLOB_FACT", "MEASUREMENT", "EFFECT"]
MAX_ENVELOPE_BYTES = 1024 * 1024


def _entry(variable: str, domain: str, lineage_prefix: str | None, value: str) -> tuple[str, dict]:
    if not isinstance(value, str):
        raise ValueError("KEY_FORMAT:" + variable)
    normalized = value.strip().lower()
    if not HEX64_RE.fullmatch(normalized):
        raise ValueError("KEY_FORMAT:" + variable)
    raw = bytes.fromhex(normalized)
    keyid = sha256_bytes(raw)[:16]
    published_domains = {"1f536afc558e71dd": "astra-ci", "fc5df253a482079e": "sedzia-ci"}
    if keyid in published_domains and published_domains[keyid] != domain:
        raise ValueError("KEY_DOMAIN_MISMATCH:" + variable)
    return keyid, {
        "domain": domain,
        "lineage_prefix": lineage_prefix,
        "predicates": list(PREDICATES),
        "public_key_hex": normalized,
        "revoked": False,
        "source": POLICY_SOURCE,
        "variable": variable,
    }


def trust_policy_from_env(environ: Mapping[str, str] | None = None) -> dict:
    """Require Astra plus at least one independent owner-admitted judge."""
    env = os.environ if environ is None else environ
    keys, missing = {}, []
    try:
        for variable, domain, lineage_prefix in KEY_SPECS:
            value = env.get(variable)
            if not value:
                missing.append(variable)
                continue
            keyid, entry = _entry(variable, domain, lineage_prefix, value)
            if keyid in keys:
                return {"schema": POLICY_SCHEMA, "source": POLICY_SOURCE, "status": "DIAGNOSTIC_ONLY", "reason": "INDEPENDENT_EFFECT_DOMAINS_MISSING", "keys": {}}
            keys[keyid] = entry
    except ValueError as exc:
        return {"schema": POLICY_SCHEMA, "source": POLICY_SOURCE, "status": "DIAGNOSTIC_ONLY", "reason": str(exc), "keys": {}}
    domains = {entry["domain"] for entry in keys.values()}
    if not ({"astra", "astra-ci"} & domains) or not ({"brat", "sedzia-ci"} & domains):
        return {
            "schema": POLICY_SCHEMA,
            "source": POLICY_SOURCE,
            "status": "DIAGNOSTIC_ONLY",
            "reason": "INDEPENDENT_EFFECT_DOMAINS_MISSING",
            "missing": missing,
            "keys": keys,
        }
    return {"schema": POLICY_SCHEMA, "source": POLICY_SOURCE, "status": "READY", "keys": keys}


def ed25519_verifier_from_policy(policy: dict):
    """Return a verifier only for keys whose provenance is the owner env."""
    if policy.get("source") != POLICY_SOURCE:
        return None
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception:
        return None

    def check(keyid: str, message: bytes, signature: bytes) -> bool:
        entry = (policy.get("keys") or {}).get(keyid)
        if not entry or entry.get("source") != POLICY_SOURCE or entry.get("revoked"):
            return False
        try:
            raw = bytes.fromhex(entry["public_key_hex"])
            Ed25519PublicKey.from_public_bytes(raw).verify(signature, message)
            return True
        except Exception:
            return False

    return check


def _load_envelope(attest_dir: Path, statement_id: str) -> dict:
    safe_id(statement_id, "statement_id")
    root = attest_dir.resolve()
    path = under(root, root / (statement_id + ".dsse.json"))
    if path.parent != root or not path.is_file() or path.is_symlink():
        raise ValueError("ATTESTATION_FILE_MISSING_OR_UNSAFE:" + statement_id)
    if path.stat().st_size > MAX_ENVELOPE_BYTES:
        raise ValueError("ATTESTATION_FILE_TOO_LARGE:" + statement_id)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError("ATTESTATION_JSON_INVALID:" + statement_id) from exc
    return value


def verify_effect_bundle(
    attest_dir: Path,
    statement_ids: list[str],
    candidate_domain: str,
    cycle_id: str,
    subject_sha256: str,
    now: str,
    environ: Mapping[str, str] | None = None,
) -> dict:
    """Load exactly two ID-bound envelopes and derive, never accept, trust status."""
    if not isinstance(statement_ids, list) or len(statement_ids) != 2 or len(set(statement_ids)) != 2:
        return {"status": "UNPROVEN", "reason": "INDEPENDENT_EFFECT_DOMAINS_MISSING"}
    if not HEX64_RE.fullmatch(str(subject_sha256)):
        return {"status": "REJECTED", "reason": "BAD_EFFECT_SUBJECT"}
    policy = trust_policy_from_env(environ)
    if policy.get("status") != "READY":
        return {"status": "UNPROVEN", "reason": policy.get("reason", "PROTECTED_VERIFIER_UNAVAILABLE"), "policy_status": policy.get("status")}
    verifier = ed25519_verifier_from_policy(policy)
    if verifier is None:
        return {"status": "UNPROVEN", "reason": "PROTECTED_VERIFIER_UNAVAILABLE"}
    checked = []
    for statement_id in statement_ids:
        try:
            envelope = _load_envelope(Path(attest_dir), statement_id)
        except ValueError as exc:
            return {"status": "REJECTED", "reason": str(exc)}
        result = verify(envelope, policy, now, verifier)
        if result.get("status") != "VERIFIED":
            return {"status": result.get("status", "REJECTED"), "reason": result.get("reason", "ATTESTATION_NOT_VERIFIED"), "statement_id": statement_id}
        body = result["body"]
        if body.get("statement_id") != statement_id:
            return {"status": "REJECTED", "reason": "STATEMENT_ID_PATH_MISMATCH", "statement_id": statement_id}
        if body.get("cycle_id") != cycle_id or body.get("subject_sha256") != subject_sha256:
            return {"status": "REJECTED", "reason": "EFFECT_WITNESS_PLAN_MISMATCH", "statement_id": statement_id}
        checked.append(result)
    assessed = assess_effect(checked, candidate_domain)
    if assessed.get("status") == "EFFECT_VERIFIED" and not ({"astra", "astra-ci"} & set(assessed.get("domains", []))):
        return {"status": "UNPROVEN", "reason": "ASTRA_EFFECT_WITNESS_MISSING"}
    if assessed.get("status") == "EFFECT_VERIFIED" and not ({"brat", "sedzia-ci"} & set(assessed.get("domains", []))):
        return {"status": "UNPROVEN", "reason": "INDEPENDENT_EFFECT_DOMAINS_MISSING"}
    if assessed.get("status") == "EFFECT_VERIFIED":
        assessed = dict(assessed, statement_ids=list(statement_ids), policy_source=POLICY_SOURCE)
    return assessed
