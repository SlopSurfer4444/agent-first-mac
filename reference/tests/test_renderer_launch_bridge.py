"""Schema4 helper delivery requires exact settled launch ancestry."""
import contextlib,importlib.machinery,importlib.util
from pathlib import Path
from unittest.mock import patch
import unittest
import test_wine_installed_policy as base
w=base.w
class Proof:
 def __init__(self,before,after):self.before_lifecycle=before;self.installed_lifecycle=after;self.calls=0;self.valid=True
 def revalidate(self):
  self.calls+=1
  if not self.valid:raise w.Blocked('fixture_proof_drift')
class Tests(unittest.TestCase):
 def setUp(self):
  self.f=base.Fixture();self.addCleanup(self.f.close)
  self.f.plan();self.f.tx().run('after');self.f.next_generation()
  self.before=self.f.root.read('ds3/ds3-runtime')[0];self.after=self.f.root.read('payload/ds3-runtime')[0]
  self.f.put('ds3/ds3-runtime',self.after,0o700)
  p=w.decode(self.f.root.read('ds3/receipt.json')[0]);p['lifecycleSha256']=w.digest(self.after);self.f.put('ds3/receipt.json',w.encode(p))
  self.proof=Proof(self.before,self.after)
 def plan(self,proof=None):
  return w.build(self.f.root,base.legacy.COMMIT,self.f.pins[w.PE32],self.f.pins[w.PE],self.f.policy_sha,runtime_sha256=self.f.pins,installed_policy_source=True,predecessor_lifecycle=self.before,launch_proof=proof)
 def test_exact_schema4_launch_proof_allows_metadata_successor(self):
  result=self.plan(self.proof);self.f.plan_sha=result['planSha256'];self.f.tx().run('after');self.f.verified()
  self.assertGreater(self.proof.calls,0);self.assertFalse(self.f.tx().run('after')['changed'])
 def test_missing_stale_or_mismatched_proof_refused_before_plan(self):
  with self.assertRaisesRegex(w.Blocked,'predecessor_scope'):self.plan()
  for field in ('before_lifecycle','installed_lifecycle'):
   proof=Proof(self.before,self.after);setattr(proof,field,b'unknown')
   with self.assertRaisesRegex(w.Blocked,'launch_binding'):self.plan(proof)
  self.proof.valid=False
  with self.assertRaisesRegex(w.Blocked,'proof_drift'):self.plan(self.proof)
  self.assertFalse(self.f.root.exists('state/transaction'))
 def test_settled_adapter_proof_checked_before_and_after(self):
  path=Path(__file__).resolve().parents[1]/'bin/games-runtime-update';l=importlib.machinery.SourceFileLoader('renderer_delivery_bridge_test',str(path));m=importlib.util.module_from_spec(importlib.util.spec_from_loader(l.name,l));l.exec_module(m)
  @contextlib.contextmanager
  def bridge(root,commit,phase):
   self.assertEqual(phase,'settled');yield self.proof
  d={'schema':3,'overlayPolicySha256':self.f.policy_sha};p=w.decode(self.f.root.read('payload/policy.json')[0])
  with patch.object(m,'launch_bridge',bridge):result=m.build_delivery(w,self.f.root,base.legacy.COMMIT,d,p,publish=False)
  self.assertIn('planSha256',result);self.assertGreaterEqual(self.proof.calls,3)
if __name__=='__main__':unittest.main()
