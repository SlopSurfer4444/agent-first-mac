"""Current-source exact-head rollback; actual schema7 journals in synthetic HOME."""
import copy,json,unittest
from contextlib import ExitStack
from unittest.mock import patch
import test_ds3_winemac_successor as wm
m=wm.m
class RollbackHead(unittest.TestCase):
 @classmethod
 def setUpClass(cls):wm.WinemacSuccessor.setUpClass()
 def setUp(self):
  self.fixture=wm.WinemacSuccessor('run');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups);self.f=self.fixture.f
  m.renderer_run(self.f.tx,'after');self.first=self.f.commit;self.first_policy=copy.deepcopy(self.f.policy)
  self.fixture.prepare('8',b'second winemac experiment');m.renderer_run(self.f.tx,'after');self.second=self.f.commit
  self.policies={self.first:self.first_policy,self.second:copy.deepcopy(self.f.policy)};self.current='a'*40;self.guard_calls=0
  stack=ExitStack();self.addCleanup(stack.close)
  def source(commit,action):
   self.assertEqual(commit,self.current);self.assertEqual(action,'renderer-rollback')
   def guard():self.guard_calls+=1
   return guard
  def git(argv):
   if 'merge-base' in argv:self.assertIn(argv[-2],self.policies);self.assertEqual(argv[-1],self.current);return b''
   self.assertIn('show',argv);return m.json_bytes(self.policies[argv[-1].split(':')[0]])
  stack.enter_context(patch.object(m,'source_gate',side_effect=source));stack.enter_context(patch.object(m,'run',side_effect=git))
  for name in ('window_repair_pending_guard','inactive','verify_installed','verify_borderless'):stack.enter_context(patch.object(m,name))
 def snapshots(self):return {p:p.read_bytes() for p in m.renderer_targets(self.f.policy).values()}
 def test_two_heads_current_source_retains_graphics(self):
  fixed={p:p.read_bytes() for k,p in m.renderer_targets(self.f.policy).items() if k not in ('nativeWinemac','manifest','receipt','borderlessReceipt')}
  self.assertTrue(m.renderer_rollback_head(self.current,self.second)['changed']);self.assertEqual(m.renderer_fields(m.load(m.ROOT/'manifest.json'))['transactionCommit'],self.first)
  self.assertTrue(m.renderer_rollback_head(self.current,self.first)['changed']);self.assertTrue(self.guard_calls>2)
  for p,raw in fixed.items():self.assertEqual(p.read_bytes(),raw)
 def test_wrong_head_rejected_before_writes(self):
  before=self.snapshots()
  with self.assertRaisesRegex(RuntimeError,'renderer_rollback_head'):m.renderer_rollback_head(self.current,self.first)
  self.assertEqual(before,self.snapshots())
 def test_historical_policy_tamper_rejected(self):
  before=self.snapshots();self.policies[self.second]['candidateFiles']['winemac.so']='f'*64
  with self.assertRaisesRegex(RuntimeError,'historical_policy'):m.renderer_rollback_head(self.current,self.second)
  self.assertEqual(before,self.snapshots())
 def test_target_drift_retained(self):
  p=m.renderer_targets(self.f.policy)['nativeWinemac'];p.write_bytes(b'foreign');before=self.snapshots()
  with self.assertRaises(RuntimeError):m.renderer_rollback_head(self.current,self.second)
  self.assertEqual(before,self.snapshots())
 def test_interrupted_before_direction_resumes_same_command(self):
  fired=[]
  def stop(label):
   if label=='published:manifest' and not fired:fired.append(True);raise SystemExit(77)
  with patch.object(m,'renderer_checkpoint',side_effect=stop):
   with self.assertRaises(SystemExit):m.renderer_rollback_head(self.current,self.second)
  self.assertTrue(fired);self.assertTrue(m.renderer_rollback_head(self.current,self.second)['changed']);self.assertEqual(m.renderer_fields(m.load(m.ROOT/'manifest.json'))['transactionCommit'],self.first)
 def test_guard_failure_retains_targets(self):
  before=self.snapshots()
  def guard():raise RuntimeError('source drift')
  with patch.object(m,'source_gate',return_value=guard):
   with self.assertRaisesRegex(RuntimeError,'source drift'):m.renderer_rollback_head(self.current,self.second)
  self.assertEqual(before,self.snapshots())
 def test_completed_rollback_cannot_redo_or_rollback_nonhead(self):
  m.renderer_rollback_head(self.current,self.second);before=self.snapshots()
  with self.assertRaisesRegex(RuntimeError,'renderer_rollback_head'):m.renderer_rollback_head(self.current,self.second)
  self.assertEqual(before,self.snapshots())
 def test_forward_interruption_is_not_rollback_recovery(self):
  path=self.f.tx/'record.json';record=json.loads(path.read_bytes());record.update(phase='running',direction='after',intent=None);path.write_bytes(m.json_bytes(record));before=self.snapshots()
  with self.assertRaisesRegex(RuntimeError,'renderer_rollback_head'):m.renderer_rollback_head(self.current,self.second)
  self.assertEqual(before,self.snapshots())
 def test_nonancestor_source_rejected_before_writes(self):
  before=self.snapshots()
  with patch.object(m,'run',side_effect=RuntimeError('not ancestor')):
   with self.assertRaisesRegex(RuntimeError,'not ancestor'):m.renderer_rollback_head(self.current,self.second)
  self.assertEqual(before,self.snapshots())
 def test_record_policy_change_after_binding_rejected(self):
  before=self.snapshots();original=m.renderer_run
  def drift_then_run(*args,**kwargs):
   path=self.f.tx/'record.json';record=json.loads(path.read_bytes());record['policy']['diagnosticCapable']=not record['policy']['diagnosticCapable'];path.write_bytes(m.json_bytes(record));kwargs['guard']()
   return original(*args,**kwargs)
  with patch.object(m,'renderer_run',side_effect=drift_then_run):
   with self.assertRaisesRegex(RuntimeError,'renderer_rollback_record_drift'):m.renderer_rollback_head(self.current,self.second)
  self.assertEqual(before,self.snapshots())
