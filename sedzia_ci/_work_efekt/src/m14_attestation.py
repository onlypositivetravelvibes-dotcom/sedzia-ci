#!/usr/bin/env python3
"""Strict DSSE parsing and trust-boundary assessment; verification is injected by protected policy."""
from __future__ import annotations

import base64
import json
import re
from typing import Callable, Optional

from m14_common import HEX64_RE, canonical, finite_number, sha256_bytes

PAYLOAD_TYPE = "application/vnd.braun.m14.statement.v1+json"
PREDICATES = {"EFFECT", "MEASUREMENT", "BLOB_FACT"}
UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def pae(payload_type: str, payload: bytes) -> bytes:
    pt = payload_type.encode()
    return b"DSSEv1 " + str(len(pt)).encode() + b" " + pt + b" " + str(len(payload)).encode() + b" " + payload


def _decode(envelope: dict) -> tuple[bytes, dict]:
    if not isinstance(envelope, dict) or envelope.get("payloadType") != PAYLOAD_TYPE:
        raise ValueError("WRONG_PAYLOAD_TYPE")
    try:
        raw = base64.b64decode(envelope["payload"], validate=True)
        body = json.loads(raw)
    except Exception as exc:
        raise ValueError("MALFORMED_PAYLOAD") from exc
    if canonical(body) != raw:
        raise ValueError("NONCANONICAL_PAYLOAD")
    required = {
        "schema", "statement_id", "predicate_kind", "subject_sha256", "cycle_id",
        "operation_id", "source_event_id", "raw_evidence_sha256", "candidate_sha256",
        "evaluator_sha256", "protocol_sha256", "sample_manifest_sha256", "issuer_ref",
        "lineage_ref", "issued_at", "expires_at",
    }
    if set(body) < required or body.get("schema") != "braun.m14.statement/1":
        raise ValueError("MISSING_FIELDS")
    if body["predicate_kind"] not in PREDICATES:
        raise ValueError("BAD_PREDICATE")
    for key in ("subject_sha256", "raw_evidence_sha256", "candidate_sha256", "evaluator_sha256", "protocol_sha256", "sample_manifest_sha256"):
        if not isinstance(body.get(key), str) or not HEX64_RE.fullmatch(body[key]):
            raise ValueError("BAD_SHA256:" + key)
    if body["predicate_kind"] == "MEASUREMENT":
        for key in ("phase", "value", "unit", "direction", "n", "sample_ids", "cost", "missingness"):
            if key not in body:
                raise ValueError("MISSING_MEASUREMENT_FIELD:" + key)
        if body["phase"] not in {"BEFORE", "SHADOW", "AFTER"} or not finite_number(body["value"]):
            raise ValueError("BAD_MEASUREMENT")
        if not isinstance(body["n"], int) or isinstance(body["n"], bool) or body["n"] < 1:
            raise ValueError("BAD_N")
        if len(body["sample_ids"]) != body["n"] or len(set(body["sample_ids"])) != body["n"]:
            raise ValueError("BAD_SAMPLES")
        if not finite_number(body["cost"]) or body["cost"] < 0:
            raise ValueError("BAD_COST")
    return raw, body


def verify(envelope: dict, trust_policy: dict, now: str, verifier: Optional[Callable[[str, bytes, bytes], bool]] = None) -> dict:
    try:
        raw, body = _decode(envelope)
    except ValueError as exc:
        return {"status": "REJECTED", "reason": str(exc)}
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        return {"status": "REJECTED", "reason": "EXACTLY_ONE_SIGNATURE_REQUIRED"}
    sig = signatures[0]
    keyid = sig.get("keyid") if isinstance(sig, dict) else None
    entry = (trust_policy.get("keys") or {}).get(keyid)
    if not entry:
        return {"status": "UNKNOWN", "reason": "SIGNER_UNKNOWN"}
    if body.get("issuer_ref") != keyid:
        return {"status": "REJECTED", "reason": "ISSUER_KEYID_MISMATCH"}
    if entry.get("revoked"):
        return {"status": "REJECTED", "reason": "SIGNER_REVOKED"}
    if body["predicate_kind"] not in set(entry.get("predicates") or []):
        return {"status": "REJECTED", "reason": "PREDICATE_NOT_ALLOWED"}
    lineage_prefix = entry.get("lineage_prefix")
    if lineage_prefix is not None and (
        not isinstance(body.get("lineage_ref"), str)
        or not body["lineage_ref"].startswith(lineage_prefix)
        or len(body["lineage_ref"]) == len(lineage_prefix)
    ):
        return {"status": "REJECTED", "reason": "LINEAGE_POLICY_MISMATCH"}
    if not UTC_RE.fullmatch(str(now)) or not UTC_RE.fullmatch(str(body["issued_at"])) or not UTC_RE.fullmatch(str(body["expires_at"])):
        return {"status": "REJECTED", "reason": "BAD_TIMESTAMP"}
    if str(body["issued_at"]) > now:
        return {"status": "REJECTED", "reason": "STATEMENT_FROM_FUTURE"}
    if now >= str(body["expires_at"]):
        return {"status": "REJECTED", "reason": "STATEMENT_EXPIRED"}
    if verifier is None:
        return {"status": "UNPROVEN", "reason": "PROTECTED_VERIFIER_UNAVAILABLE"}
    try:
        signature = base64.b64decode(sig.get("sig", ""), validate=True)
        ok = verifier(keyid, pae(PAYLOAD_TYPE, raw), signature)
    except Exception:
        ok = False
    if not ok:
        return {"status": "REJECTED", "reason": "INVALID_SIGNATURE"}
    return {
        "status": "VERIFIED",
        "predicate_kind": body["predicate_kind"],
        "domain": entry.get("domain"),
        "lineage": body["lineage_ref"],
        "statement_id": body["statement_id"],
        "payload_sha256": sha256_bytes(raw),
        "body": body,
    }


def assess_effect(attestations: list[dict], candidate_domain: str) -> dict:
    verified = [a for a in attestations if a.get("status") == "VERIFIED" and a.get("predicate_kind") == "EFFECT"]
    domains = {a.get("domain") for a in verified}
    lineages = {a.get("lineage") for a in verified}
    statement_ids = {a.get("statement_id") for a in verified}
    if candidate_domain in domains:
        return {"status": "UNPROVEN", "reason": "CANDIDATE_DOMAIN_IS_JUDGE"}
    if None in domains or len(domains) < 2 or None in lineages or len(lineages) < 2:
        return {"status": "UNPROVEN", "reason": "INDEPENDENT_EFFECT_DOMAINS_MISSING"}
    if None in statement_ids or len(statement_ids) != len(verified):
        return {"status": "UNPROVEN", "reason": "DUPLICATE_EFFECT_STATEMENT"}
    subjects = {a["body"].get("subject_sha256") for a in verified}
    cycles = {a["body"].get("cycle_id") for a in verified}
    if len(subjects) != 1 or len(cycles) != 1:
        return {"status": "REJECTED", "reason": "EFFECT_WITNESSES_DISAGREE"}
    return {"status": "EFFECT_VERIFIED", "domains": sorted(domains), "lineages": sorted(lineages)}


def comparable(before: dict, after: dict) -> dict:
    if before.get("status") != "VERIFIED" or after.get("status") != "VERIFIED":
        return {"status": "MEASUREMENT_PENDING", "reason": "UNVERIFIED_MEASUREMENT"}
    a, b = before["body"], after["body"]
    if a.get("phase") != "BEFORE" or b.get("phase") != "AFTER":
        return {"status": "MEASUREMENT_PENDING", "reason": "PHASE_MISMATCH"}
    keys = ("evaluator_sha256", "protocol_sha256", "sample_manifest_sha256", "unit", "direction")
    if any(a.get(k) != b.get(k) for k in keys):
        return {"status": "MEASUREMENT_PENDING", "reason": "MEASUREMENT_CONTRACT_CHANGED"}
    if a.get("statement_id") == b.get("statement_id") or a.get("raw_evidence_sha256") == b.get("raw_evidence_sha256"):
        return {"status": "MEASUREMENT_PENDING", "reason": "REUSED_EXECUTION"}
    return {"status": "COMPARABLE", "delta": float(b["value"]) - float(a["value"])}


def validate_holdout(manifest: dict) -> dict:
    """Validate separation by independent cluster, never by report count."""
    groups = manifest.get("groups") if isinstance(manifest, dict) else None
    if not isinstance(groups, dict) or set(groups) != {"DEV", "SHADOW", "FINAL"}:
        return {"status": "CONTAMINATED", "reason": "GROUPS_MISSING"}
    seen_samples, seen_clusters = set(), set()
    for group in ("DEV", "SHADOW", "FINAL"):
        rows = groups[group]
        if not isinstance(rows, list) or not rows:
            return {"status": "CONTAMINATED", "reason": "EMPTY_GROUP:" + group}
        for row in rows:
            cluster = row.get("cluster_id") if isinstance(row, dict) else None
            samples = row.get("sample_ids") if isinstance(row, dict) else None
            if not cluster or cluster in seen_clusters:
                return {"status": "CONTAMINATED", "reason": "CLUSTER_OVERLAP"}
            if not isinstance(samples, list) or not samples or len(set(samples)) != len(samples):
                return {"status": "CONTAMINATED", "reason": "DUPLICATE_OR_EMPTY_SAMPLES"}
            if seen_samples & set(samples):
                return {"status": "CONTAMINATED", "reason": "SAMPLE_OVERLAP"}
            seen_clusters.add(cluster); seen_samples.update(samples)
    return {"status": "SEALED", "independent_clusters": len(seen_clusters), "samples": len(seen_samples)}
