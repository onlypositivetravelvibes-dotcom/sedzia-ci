import unittest
import tempfile
import json
from pathlib import Path
import test_m14_r1 as h
from m14_trust import trust_policy_from_env, verify_effect_bundle

class R8Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.a,self.ah,self.ai=h.key_material()
        self.c,self.ch,self.ci=h.key_material()
        self.s,self.sh,self.si=h.key_material()
        self.env={'BRAUN_ASTRA_PUBKEY':self.ah,'BRAUN_ASTRA_CI_PUBKEY':self.ch,'BRAUN_SEDZIA_CI_PUBKEY':self.sh}
        for key,kid,sid,lineage in [(self.a,self.ai,'a','astra-run-1'),(self.c,self.ci,'c','astra-ci-run-1'),(self.c,self.ci,'c2','astra-ci-run-2'),(self.s,self.si,'s','sedzia-ci-run-2')]:
            (self.root/(sid+'.dsse.json')).write_text(json.dumps(h.signed_effect(key,kid,sid,lineage)))
    def tearDown(self): self.tmp.cleanup()
    def bundle(self, ids, env=None):
        return verify_effect_bundle(self.root,ids,'candidate','cycle-1','6'*64,'2026-09-15T01:00:00Z',self.env if env is None else env)
    def test_ci_pair_without_local_astra(self):
        env={k:v for k,v in self.env.items() if k!='BRAUN_ASTRA_PUBKEY'}
        self.assertEqual(trust_policy_from_env(env)['status'],'READY')
        r=self.bundle(['c','s'],env)
        self.assertEqual(r['status'],'EFFECT_VERIFIED')
        self.assertEqual(r['domains'],['astra-ci','sedzia-ci'])
    def test_same_ci_and_astra_family_are_not_two_judges(self):
        self.assertEqual(self.bundle(['c','c2'])['status'],'UNPROVEN')
        self.assertEqual(self.bundle(['c','c'])['status'],'UNPROVEN')
        self.assertEqual(self.bundle(['a','c'])['status'],'UNPROVEN')
    def test_bad_lineage_and_swapped_slots(self):
        (self.root/'c.dsse.json').write_text(json.dumps(h.signed_effect(self.c,self.ci,'c','sedzia-ci-run-1')))
        self.assertEqual(self.bundle(['c','s'])['reason'],'LINEAGE_POLICY_MISMATCH')
        env=dict(self.env,BRAUN_ASTRA_CI_PUBKEY=self.sh,BRAUN_SEDZIA_CI_PUBKEY=self.ch)
        self.assertEqual(self.bundle(['c','s'],env)['status'],'REJECTED')
    def test_published_astra_ci_cannot_be_relabelled(self):
        pub='bca808603e88881236290198950b0bc68efa44a98ed852c2ae4a568a10714fd2'
        for slot in ['BRAUN_SEDZIA_CI_PUBKEY','BRAUN_BRAT_PUBKEY','BRAUN_ASTRA_PUBKEY']:
            r=trust_policy_from_env(dict(self.env,**{slot:pub}))
            self.assertEqual(r['status'],'DIAGNOSTIC_ONLY')
            self.assertEqual(r['reason'],'KEY_DOMAIN_MISMATCH:'+slot)
        r=trust_policy_from_env(dict(self.env,BRAUN_ASTRA_CI_PUBKEY=pub))
        self.assertEqual(r['keys']['1f536afc558e71dd']['domain'],'astra-ci')
    def test_duplicate_keys_rejected(self):
        r=trust_policy_from_env(dict(self.env,BRAUN_ASTRA_CI_PUBKEY=self.sh))
        self.assertEqual(r['status'],'DIAGNOSTIC_ONLY')
