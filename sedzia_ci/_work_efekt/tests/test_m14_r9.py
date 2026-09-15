import unittest, json, base64, copy, tempfile, shutil, os, subprocess, sys
from pathlib import Path
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from m14_common import canonical,sha256_bytes
from sign_statement import build_envelope
from RUN_EFFECT import build_effect
from m14_trust import verify_effect_bundle

ROOT=Path(__file__).resolve().parents[1]
PUB={'astra-ci':'bca808603e88881236290198950b0bc68efa44a98ed852c2ae4a568a10714fd2','sedzia-ci':'08e9d619b2751985b6b72ded6caaedf7a8579c9ce6be3545102b172f18f58655'}
ENV={'BRAUN_ASTRA_CI_PUBKEY':PUB['astra-ci'],'BRAUN_SEDZIA_CI_PUBKEY':PUB['sedzia-ci']}
class R9Tests(unittest.TestCase):
 def setUp(self):
  self.plan=json.loads((ROOT/'inputs/PLAN_CYKLU_M14-E24-GEN-1.json').read_text())
  self.before=(ROOT/'inputs/ci-astra-r0.dsse.json').read_bytes();self.after=(ROOT/'inputs/ci-astra-r1b.dsse.json').read_bytes()
  self.now='2026-09-15T16:00:00Z'
  self.env=dict(ENV,STATEMENT_ID='effect-astra-ci-1',ISSUER_REF='1f536afc558e71dd',LINEAGE_REF='astra-ci-run-999999',ISSUED_AT=self.now)
 def build(self,b=None,a=None,p=None,e=None):return build_effect(self.before if b is None else b,self.after if a is None else a,self.plan if p is None else p,self.env if e is None else e,self.now)
 def rehash(self,p):p['plan_sha256']=sha256_bytes(canonical({k:v for k,v in p.items() if k!='plan_sha256'}));return p
 def test_two_live_pairs(self):
  body,refs,checked=self.build();self.assertAlmostEqual(body['value'],1/3);self.assertEqual(body['subject_sha256'],self.plan['effect_subject_sha256']);self.assertFalse(body['activation_eligible'])
  self.assertEqual(body['operation_id'],self.plan['cycle_id'])
  self.assertEqual(body['raw_evidence_sha256'],sha256_bytes(canonical(refs)))
  e=dict(self.env,STATEMENT_ID='effect-sedzia-ci-1',ISSUER_REF='fc5df253a482079e',LINEAGE_REF='sedzia-ci-run-999999')
  b=(ROOT/'inputs/ci-before-r0.dsse.json').read_bytes();a=(ROOT/'inputs/ci-after-r1.dsse.json').read_bytes()
  other,_,_=self.build(b,a,e=e);self.assertAlmostEqual(other['value'],1/3);self.assertEqual(other['subject_sha256'],body['subject_sha256'])
 def test_swapped_and_cross_domain(self):
  with self.assertRaisesRegex(ValueError,'PHASE_MISMATCH'):self.build(self.after,self.before)
  with self.assertRaisesRegex(ValueError,'RUNNER_DOMAIN_MISMATCH'):self.build(a=(ROOT/'inputs/ci-after-r1.dsse.json').read_bytes())
 def test_signature_and_reuse(self):
  x=json.loads(self.after);s=bytearray(base64.b64decode(x['signatures'][0]['sig']));s[0]^=1;x['signatures'][0]['sig']=base64.b64encode(s).decode()
  with self.assertRaisesRegex(ValueError,'INVALID_SIGNATURE'):self.build(a=json.dumps(x).encode())
  with self.assertRaises(ValueError):self.build(a=self.before)
 def test_plan_subject_hash_and_activation(self):
  p=copy.deepcopy(self.plan);p['effect_subject_sha256']='0'*64
  with self.assertRaisesRegex(ValueError,'PLAN_HASH_MISMATCH'):self.build(p=p)
  with self.assertRaisesRegex(ValueError,'EFFECT_SUBJECT_MISMATCH'):self.build(p=self.rehash(p))
  p=copy.deepcopy(self.plan);p['activation_mode']='ACTIVATE'
  with self.assertRaisesRegex(ValueError,'PREPARE_ONLY_REQUIRED'):self.build(p=self.rehash(p))
 def test_output_identity(self):
  with self.assertRaisesRegex(ValueError,'EFFECT_ISSUER_DOMAIN_MISMATCH'):self.build(e=dict(self.env,ISSUER_REF='fc5df253a482079e'))
  with self.assertRaisesRegex(ValueError,'LINEAGE_POLICY_MISMATCH'):self.build(e=dict(self.env,LINEAGE_REF='sedzia-ci-run-999999'))
  with self.assertRaisesRegex(ValueError,'EFFECT_ID_NOT_IN_PLAN'):self.build(e=dict(self.env,STATEMENT_ID='other'))
 def test_signed_semantic_attacks(self):
  key=Ed25519PrivateKey.generate();pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex();kid=sha256_bytes(bytes.fromhex(pub))[:16]
  e=dict(self.env,BRAUN_ASTRA_CI_PUBKEY=pub,ISSUER_REF=kid)
  def body(raw):return json.loads(base64.b64decode(json.loads(raw)['payload']))
  a,b=body(self.before),body(self.after);a['issuer_ref']=b['issuer_ref']=kid
  def signed(x):return canonical(build_envelope(x,key))
  for field,value,reason in [('candidate_sha256','0'*64,'R0_R1_BINDING_MISMATCH'),('sample_manifest_sha256','0'*64,'MEASUREMENT_CONTRACT_CHANGED'),('cycle_id','wrong','MEASUREMENT_CYCLE_MISMATCH'),('unit','fraction','MEASUREMENT_CONTRACT_CHANGED'),('raw_evidence_sha256',a['raw_evidence_sha256'],'REUSED_EXECUTION')]:
   bad=dict(b,**{field:value})
   with self.subTest(field=field),self.assertRaisesRegex(ValueError,reason):self.build(signed(a),signed(bad),e=e)
 def test_generated_effects_pass_existing_bundle(self):
  with tempfile.TemporaryDirectory() as d:
   env={};ids=[]
   for domain,slot,files in [('astra-ci','BRAUN_ASTRA_CI_PUBKEY',('ci-astra-r0','ci-astra-r1b')),('sedzia-ci','BRAUN_SEDZIA_CI_PUBKEY',('ci-before-r0','ci-after-r1'))]:
    e=dict(self.env,STATEMENT_ID='effect-'+domain+'-1',ISSUER_REF=sha256_bytes(bytes.fromhex(PUB[domain]))[:16],LINEAGE_REF=domain+'-run-999999')
    body,_,_=self.build(*[(ROOT/('inputs/'+x+'.dsse.json')).read_bytes() for x in files],e=e)
    key=Ed25519PrivateKey.generate();pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex();env[slot]=pub;body['issuer_ref']=sha256_bytes(bytes.fromhex(pub))[:16]
    sid=body['statement_id'];ids.append(sid);Path(d,sid+'.dsse.json').write_bytes(canonical(build_envelope(body,key)))
   r=verify_effect_bundle(Path(d),ids,'candidate-gen',self.plan['cycle_id'],self.plan['effect_subject_sha256'],self.now,env)
   self.assertEqual(r['status'],'EFFECT_VERIFIED')
 def test_cli_preserves_evidence_and_refuses_overwrite(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);shutil.copytree(ROOT/'src',p/'src');shutil.copyfile(ROOT/'RUN_EFFECT.py',p/'RUN_EFFECT.py');shutil.copyfile(ROOT/'RUN_BEFORE.py',p/'RUN_BEFORE.py')
   env=dict(os.environ,**self.env,MODE='EFFECT',BEFORE_ENVELOPE=str(ROOT/'inputs/ci-astra-r0.dsse.json'),AFTER_ENVELOPE=str(ROOT/'inputs/ci-astra-r1b.dsse.json'),PLAN_PATH=str(ROOT/'inputs/PLAN_CYKLU_M14-E24-GEN-1.json'))
   env['ISSUED_AT']=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
   proc=subprocess.run([sys.executable,str(p/'RUN_EFFECT.py')],env=env,capture_output=True,text=True);self.assertEqual(proc.returncode,0,proc.stderr)
   self.assertEqual((p/'out/EFFECT_BEFORE.dsse.json').read_bytes(),self.before)
   raw=(p/'out/EFFECT_BODY_UNSIGNED.json').read_bytes()
   proc=subprocess.run([sys.executable,str(p/'RUN_EFFECT.py')],env=env,capture_output=True,text=True);self.assertNotEqual(proc.returncode,0);self.assertIn('EVIDENCE_EXISTS',proc.stderr);self.assertEqual((p/'out/EFFECT_BODY_UNSIGNED.json').read_bytes(),raw)
