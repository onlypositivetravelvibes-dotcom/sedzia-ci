#!/usr/bin/env python3
"""Build an unsigned E24 EFFECT from two authenticated measurements and a plan."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
from datetime import datetime, timedelta, timezone

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'src'))
from m14_common import canonical, sha256_bytes, safe_id
from m14_trust import trust_policy_from_env, ed25519_verifier_from_policy
from m14_attestation import verify, comparable
from RUN_BEFORE import write_new, R0_SHA256

R1_SHA256 = 'b43a0aa0bc26f64b298baf6d240dc944a211f3416edf44aa4565ecc6bd1b0038'
E24_SHA256 = 'b8d068d37f6c9033cd24cf530c5c78b9f42f3a4e499c1d655237c90016127c7c'
EVALUATOR_SHA256 = '37329b673095fc36f5abf5be0eaf3f67966533c28a7e8a6c22f91a26aaa91e5d'
PROTOCOL_SHA256 = '5085572cd3d82cdd834a0d066a2573a1473c6edf9351253685cd484eb6bbab03'
SAMPLES = sorted(f'GEN-template-{f}-v{v}' for f in range(6) for v in range(4))


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def build_effect(before_raw: bytes, after_raw: bytes, plan: dict, env: dict, now: str):
    policy = trust_policy_from_env(env)
    require(policy.get('status') == 'READY', 'TRUST_POLICY_NOT_READY')
    verifier = ed25519_verifier_from_policy(policy)
    require(verifier is not None, 'PROTECTED_VERIFIER_UNAVAILABLE')
    checked = []
    for raw in (before_raw, after_raw):
        require(len(raw) <= 1024 * 1024, 'ENVELOPE_TOO_LARGE')
        result = verify(json.loads(raw), policy, now, verifier)
        require(result.get('status') == 'VERIFIED', 'MEASUREMENT_' + result.get('reason', 'UNVERIFIED'))
        require(result.get('predicate_kind') == 'MEASUREMENT', 'NOT_MEASUREMENT')
        checked.append(result)
    before, after = checked
    require(before['domain'] == after['domain'], 'RUNNER_DOMAIN_MISMATCH')
    domain = before['domain']
    require(domain in {'astra-ci', 'sedzia-ci'}, 'UNSUPPORTED_RUNNER')
    a, b = before['body'], after['body']
    require(a['cycle_id'] == b['cycle_id'], 'MEASUREMENT_CYCLE_MISMATCH')
    require(before['lineage'] != after['lineage'], 'REUSED_MEASUREMENT_RUN')
    comparison = comparable(before, after)
    require(comparison.get('status') == 'COMPARABLE', comparison.get('reason', 'NOT_COMPARABLE'))
    require(a['candidate_sha256'] == R0_SHA256 and b['candidate_sha256'] == R1_SHA256, 'R0_R1_BINDING_MISMATCH')
    for body in (a, b):
        require(body['sample_manifest_sha256'] == E24_SHA256, 'E24_MANIFEST_MISMATCH')
        require(body['evaluator_sha256'] == EVALUATOR_SHA256 and body['protocol_sha256'] == PROTOCOL_SHA256, 'E24_SCORER_PROTOCOL_MISMATCH')
        require(body['unit'] == 'accuracy' and body['direction'] == 'higher', 'UNIT_DIRECTION_MISMATCH')
        require(body['n'] == 24 and sorted(body['sample_ids']) == SAMPLES, 'E24_SAMPLES_MISMATCH')
        require(0 <= body['value'] <= 1, 'ACCURACY_RANGE')
    require(isinstance(plan, dict) and plan.get('schema') == 'm14.cycle_plan/1', 'BAD_PLAN_SCHEMA')
    digest = sha256_bytes(canonical({k: v for k, v in plan.items() if k != 'plan_sha256'}))
    require(digest == plan.get('plan_sha256'), 'PLAN_HASH_MISMATCH')
    require(plan.get('activation_mode') == 'PREPARE_ONLY' and plan.get('rollback_after_test') is True, 'PREPARE_ONLY_REQUIRED')
    require(plan.get('domain') == 'GEN' and plan.get('candidate_domain') not in {'astra','astra-ci','brat','sedzia-ci'}, 'BAD_CANDIDATE_DOMAIN')
    for key in ('cycle_id', 'source_event_id', 'g0', 'g1', 'owner_record_id', 'candidate_domain'):
        safe_id(plan.get(key), key)
    require(plan['g0'] != plan['g1'], 'R0_EQUALS_R1')
    require(plan.get('grant_ref') == f"owner:{plan['owner_record_id']}:{plan['g1']}", 'PLAN_OWNER_BINDING_MISMATCH')
    require(plan.get('artifact_sha256') == {'r0': R0_SHA256, 'r1': R1_SHA256}, 'PLAN_ARTIFACT_MISMATCH')
    require(sorted(plan.get('sample_ids', [])) == SAMPLES, 'PLAN_SAMPLES_MISMATCH')
    subject = sha256_bytes(canonical({'cycle_id': plan['cycle_id'], 'domain': 'GEN', 'candidate_sha256': R1_SHA256, 'sample_manifest_sha256': E24_SHA256}))
    require(subject == plan.get('effect_subject_sha256'), 'EFFECT_SUBJECT_MISMATCH')
    sid, issuer, lineage = (env.get(k) for k in ('STATEMENT_ID', 'ISSUER_REF', 'LINEAGE_REF'))
    safe_id(sid, 'statement_id'); safe_id(issuer, 'issuer_ref'); safe_id(lineage, 'lineage_ref')
    ids = plan.get('effect_statement_ids')
    require(isinstance(ids, list) and len(ids) == 2 and len(set(ids)) == 2 and sid in ids, 'EFFECT_ID_NOT_IN_PLAN')
    entry = policy['keys'].get(issuer, {})
    require(entry.get('domain') == domain, 'EFFECT_ISSUER_DOMAIN_MISMATCH')
    require(lineage.startswith(domain + '-run-') and len(lineage) > len(domain + '-run-'), 'LINEAGE_POLICY_MISMATCH')
    require(lineage not in {before['lineage'], after['lineage']}, 'REUSED_EFFECT_RUN')
    issued_text = env.get('ISSUED_AT', now)
    issued = datetime.strptime(issued_text, '%Y-%m-%dT%H:%M:%SZ')
    require(issued_text == issued.strftime('%Y-%m-%dT%H:%M:%SZ') and issued_text <= now, 'BAD_ISSUED_AT')
    require(issued_text >= max(a['issued_at'], b['issued_at']), 'EFFECT_BEFORE_MEASUREMENTS')
    expires = min((issued + timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%SZ'), a['expires_at'], b['expires_at'])
    require(expires > now, 'EFFECT_EXPIRED')
    refs = {'before': sha256_bytes(before_raw), 'after': sha256_bytes(after_raw)}
    operation_id = plan.get('operation_id', plan['cycle_id'])
    safe_id(operation_id, 'operation_id')
    body = {
        'schema': 'braun.m14.statement/1', 'predicate_kind': 'EFFECT',
        'statement_id': sid, 'issuer_ref': issuer, 'lineage_ref': lineage,
        'issued_at': issued_text, 'expires_at': expires, 'subject_sha256': subject,
        'cycle_id': plan['cycle_id'], 'source_event_id': plan['source_event_id'], 'operation_id': operation_id,
        'raw_evidence_sha256': sha256_bytes(canonical(refs)), 'candidate_sha256': R1_SHA256,
        'evaluator_sha256': EVALUATOR_SHA256, 'protocol_sha256': PROTOCOL_SHA256,
        'sample_manifest_sha256': E24_SHA256, 'value': comparison['delta'], 'unit': 'accuracy',
        'direction': 'higher', 'n': 24, 'sample_ids': SAMPLES,
        'cost': a['cost'] + b['cost'], 'cost_scope': 'reported measurement costs; effect generation not metered',
        'missingness': {'before': a['missingness'], 'after': b['missingness']},
        'evidence_envelopes': refs, 'measurement_cycle_id': a['cycle_id'],
        'plan_sha256': digest, 'activation_eligible': False,
        'effect_scope': 'signed E24 accuracy delta, not activation success',
        'trust_residual': 'shared repository administration; same EFFECT code for both CI signers',
    }
    canonical(body)
    return body, refs, checked


def main():
    require(os.environ.get('MODE', 'EFFECT') == 'EFFECT', 'BAD_MODE')
    env = dict(os.environ)
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    before_raw = Path(env['BEFORE_ENVELOPE']).read_bytes()
    after_raw = Path(env['AFTER_ENVELOPE']).read_bytes()
    plan = json.loads(Path(env['PLAN_PATH']).read_text())
    body, refs, _ = build_effect(before_raw, after_raw, plan, env, now)
    out = ROOT / 'out'
    targets = ['EFFECT_BEFORE.dsse.json','EFFECT_AFTER.dsse.json','EFFECT_EVIDENCE.json','EFFECT_BODY_UNSIGNED.json']
    require(not any((out / name).exists() or (out / name).is_symlink() for name in targets), 'EVIDENCE_EXISTS')
    out.mkdir(exist_ok=True)
    # Preserve exact original envelope bytes, not reserialized JSON.
    for name, raw in [('EFFECT_BEFORE.dsse.json', before_raw), ('EFFECT_AFTER.dsse.json', after_raw)]:
        with (out / name).open('xb') as f:
            f.write(raw); f.flush(); os.fsync(f.fileno())
    write_new(out / 'EFFECT_EVIDENCE.json', refs)
    write_new(out / 'EFFECT_BODY_UNSIGNED.json', body)  # Completion marker written last.
    print(json.dumps({'status':'EFFECT_BODY_UNSIGNED','domain':body['lineage_ref'].split('-run-')[0], 'delta':body['value'],'subject_sha256':body['subject_sha256'],'activation_eligible':False},sort_keys=True))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
