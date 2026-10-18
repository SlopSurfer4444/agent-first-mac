"""Real fixed nine+two transactions integrated on a synthetic home; no live CLI."""
import contextlib,importlib.machinery,json,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import test_game_native_admission_transaction as fixture
from lib import game_native_admission_capability as cap
from lib import game_native_admission_transaction as tx
from lib import game_native_admission_bridge as b
ROOT=Path(__file__).resolve().parents[1]
m=importlib.machinery.SourceFileLoader('native_update_integration',str(ROOT/'bin/game-native-admission-update')).load_module()

class Integration(unittest.TestCase):
 def setUp(self):
  f=fixture.Transactions('run');f.setUp();self.addCleanup(f.doCleanups);self.f=f;self.commit=f.commit
  self.intent={'preserveServerSha256':'c'*64,'preserveRuntimeHashes':{'engine/lib/wine/x86_64-unix/ntdll.so':'d'*64},'nativeRoute':{'image':r'C:\Program Files (x86)\Steam\steamapps\common\DARK SOULS III\Game\DarkSoulsIII.exe','machine':0x8664,'bundleIdentifier':'local.exact','targetSha256':'e'*64,'bundleFiles':{'Contents/MacOS/wine':{'sha256':'a'*64},'Contents/Info.plist':{'sha256':'b'*64}}}}
  self.source=f.home/'control';self.sources={'admission.helper':'bin/game-launch-admission','hub.launcher':'bin/games-play','cs2.launcher':'bin/cs2-play','ds3.lifecycle':'bin/ds3-runtime'}
  for key,rel in self.sources.items():f.fixture.put(self.source/rel,f.after[key][0],f.after[key][1])
  for rel in m.RECOVERY_SOURCE:f.fixture.put(self.source/rel,(ROOT/rel).read_bytes())
  for module,key,value in [(m,'HOME',f.home),(m,'STATE',f.home/'AIDev/state'),(m,'DS3',f.root),(m,'CONTROL',self.source),(tx,'HOME',f.home),(cap,'HOME',f.home)]:
   p=patch.object(module,key,value);p.start();self.addCleanup(p.stop)
  after=cap.derive(self.intent);self.report=dict(f.reviewed,policySha256=b.sha(self.enc(self.intent)),capabilityBeforeSha256={'approval':None,'routes':None},approvalCandidateSha256=b.sha(after['approval']),routeCandidateSha256=b.sha(after['routes']))
  self.pin=b.sha(self.enc(self.report));self.assets_calls=[];self.local=lambda:True
  self.assets=SimpleNamespace(publish=lambda *args:self.assets_calls.append('publish'),verify_assets=lambda *args:self.assets_calls.append('verify'))
  planner=SimpleNamespace(enc=self.enc,SOURCES=self.sources,prepare=lambda commit:(self.report,f.before,f.after,f.policy,None,None))
  p=patch.object(m,'planner',return_value=planner);p.start();self.addCleanup(p.stop)
 def enc(self,value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
 def run_operation(self,operation):return m._publish(operation,self.commit,self.pin,self.f.home/'payload',self.intent,self.local,self.assets,tx)
 def side(self,side):
  self.assertEqual(self.f.images(),self.f.after if side=='after' else self.f.before)
  c=cap.Transaction(self.commit,self.intent,lambda:True);r,images=c.read();self.assertEqual(r['direction'],side);self.assertEqual({key:cap.optional(path) for key,path in c.targets.items()},images[side])
 def test_one_operation_apply_noop_rollback_return_and_no_launch(self):
  self.assertTrue(self.run_operation('apply')['changed']);self.side('after');self.assertFalse(self.run_operation('apply')['changed'])
  self.assertTrue(self.run_operation('rollback')['changed']);self.side('before');self.assertFalse(self.run_operation('rollback')['changed'])
  result=self.run_operation('return');self.assertTrue(result['changed']);self.assertFalse(result['launchPerformed']);self.assertFalse(result['installedAcceptanceClaimed']);self.side('after')
 def test_core_global_preparation_before_proof_recovers(self):
  original=tx.prepare;fired=[]
  def prepare(*args,**kwargs):
   def checkpoint(label):
    if label=='prepared:global' and not fired:fired.append(True);raise SystemExit(91)
   return original(*args,**dict(kwargs,checkpoint=checkpoint))
  with patch.object(tx,'prepare',side_effect=prepare),self.assertRaises(SystemExit):self.run_operation('apply')
  self.assertEqual(self.f.images(),self.f.before)
  with self.assertRaisesRegex(RuntimeError,'recovery_required'):self.run_operation('plan')
  self.assertFalse(self.f.proof.exists());self.run_operation('recover');self.side('after')
 def test_legacy_capability_preparation_without_record_recovers(self):
  c=cap.Transaction(self.commit,self.intent,lambda:True)
  c.directory.mkdir(mode=0o700)
  self.f.fixture.put(c.directory/'approval.after',c.after['approval'][:11])
  self.run_operation('recover');self.side('after')
  self.assertFalse(self.run_operation('apply')['changed'])
 def test_recovery_source_allows_current_engine_not_changed_policy(self):
  import subprocess,tempfile
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory)
   def git(*args):return subprocess.check_output(['git','-c','core.hooksPath=/dev/null','-c','commit.gpgsign=false','-C',str(root),*args],stderr=subprocess.DEVNULL,timeout=15).decode().strip()
   git('init','-q');git('config','user.email','fixture@example.invalid');git('config','user.name','Fixture')
   path=root/m.RECOVERY_SOURCE[0];path.parent.mkdir();path.write_text('engine')
   git('add',m.RECOVERY_SOURCE[0]);git('commit','-qm','engine');original=git('rev-parse','HEAD')
   (root/'note').write_text('unrelated');git('add','note');git('commit','-qm','note');current=git('rev-parse','HEAD')
   with patch.object(m,'CONTROL',root),patch.object(m,'HERE',root):
    self.assertEqual(m.recovery_source('recover',original),current)
    path.write_text('different engine');git('add',m.RECOVERY_SOURCE[0]);git('commit','-qm','engine changed')
    self.assertEqual(m.recovery_source('recover',original),git('rev-parse','HEAD'))
    policy=root/m.POLICY;policy.parent.mkdir();policy.write_text('changed policy');git('add',m.POLICY);git('commit','-qm','policy changed')
    with self.assertRaisesRegex(RuntimeError,'command_failed'):m.recovery_source('recover',original)
 def test_connected_guard_admits_once_then_rechecks_exact_source_bytes(self):
  from lib import game_operation_readiness as ready
  @contextlib.contextmanager
  def locks():yield lambda:True
  def publish(operation,commit,expected,payload,intent,local,*components):
   for _ in range(4):self.assertTrue(local())
   (self.source/m.POLICY).write_bytes(b'changed')
   with self.assertRaisesRegex(RuntimeError,'native_policy_changed'):local()
   return {'checked':True}
  with patch.object(m,'source_check',return_value=self.intent) as source,patch.object(m,'locks',locks),patch.object(m,'inactive',return_value=True),patch.object(m,'_publish',side_effect=publish),patch.object(ready,'bound',return_value=lambda:True),patch.object(ready,'ready',return_value={'scopedCandidateReady':True}):
   self.assertEqual(m.operate('apply',self.commit,self.pin),{'checked':True})
   self.assertEqual(source.call_count,1)
 def test_nine_file_publication_interruption_recovers_before_capability(self):
  original=tx.prepare;fired=[]
  def prepare(*args,**kwargs):
   def checkpoint(label):
    if label=='published:ds3.receipt:after' and not fired:fired.append(True);raise SystemExit(92)
   return original(*args,**dict(kwargs,checkpoint=checkpoint))
  with patch.object(tx,'prepare',side_effect=prepare),self.assertRaises(SystemExit):self.run_operation('apply')
  self.assertTrue(all(cap.optional(path) is None for path in cap.layout()[2].values()));self.run_operation('recover');self.side('after')
 def test_capability_publication_interruption_recovers_then_rollback(self):
  original=cap.Transaction;fired=[]
  class Fault(original):
   def __init__(obj,*args,**kwargs):
    def event(label):
     if label=='published:approval' and not fired:fired.append(True);raise SystemExit(93)
    super().__init__(*args,**dict(kwargs,event=event))
  with patch.object(cap,'Transaction',Fault),self.assertRaises(SystemExit):self.run_operation('apply')
  self.assertEqual(self.f.images(),self.f.after);self.run_operation('recover');self.side('after')
  fired.clear()
  with patch.object(cap,'Transaction',Fault),self.assertRaises(SystemExit):self.run_operation('rollback')
  self.run_operation('recover');self.side('before')
 def test_return_gap_after_core_complete_keeps_armed_forward_direction(self):
  self.run_operation('apply');self.run_operation('rollback');original=cap.Transaction.run
  def run(obj,direction,recover=False):
   if direction=='after':raise SystemExit(94)
   return original(obj,direction,recover)
  with patch.object(cap.Transaction,'run',run),self.assertRaises(SystemExit):self.run_operation('return')
  self.assertEqual(self.f.images(),self.f.after);self.run_operation('recover');self.side('after')
 def test_external_activity_between_publications_blocks_next_write(self):
  original=tx.prepare;active=[]
  def local():
   if active:raise RuntimeError('ds3_prefix_active')
   return True
  self.local=local
  def prepare(*args,**kwargs):
   def checkpoint(label):
    if label=='published:admission.helper:after':active.append(True)
   return original(*args,**dict(kwargs,checkpoint=checkpoint))
  with patch.object(tx,'prepare',side_effect=prepare),self.assertRaisesRegex(RuntimeError,'prefix_active'):self.run_operation('apply')
  for key,raw in self.f.images().items():self.assertEqual(raw,self.f.after[key] if key=='admission.helper' else self.f.before[key])
  self.assertTrue(all(cap.optional(path) is None for path in cap.layout()[2].values()));active.clear();self.run_operation('recover');self.side('after')
 def test_changed_source_policy_or_target_refuses(self):
  self.run_operation('apply');self.intent['preserveServerSha256']='f'*64
  with self.assertRaisesRegex(RuntimeError,'source_policy_changed'):self.run_operation('rollback')
 def test_real_operate_local_guard_rechecks_prefix_activity(self):
  from lib import game_operation_readiness as ready
  active=[];probes=[]
  @contextlib.contextmanager
  def locks():yield lambda:True
  def inactive(intent,verify_runtime=True):
   probes.append(verify_runtime)
   if active:raise RuntimeError('ds3_prefix_active')
   return True
  def publish(operation,commit,expected,payload,intent,local,*components):
   local();active.append(True);local();self.fail('active prefix passed the real mutation guard')
  with patch.object(m,'source_check',return_value=self.intent),patch.object(m,'locks',locks),patch.object(m,'inactive',side_effect=inactive),patch.object(m,'_publish',side_effect=publish),patch.object(ready,'bound',return_value=lambda:True),patch.object(ready,'ready',return_value={'scopedCandidateReady':True}):
   with self.assertRaisesRegex(RuntimeError,'prefix_active'):m.operate('apply',self.commit,self.pin)
  self.assertGreaterEqual(probes.count(False),2)
 def test_noncanonical_execution_refused_before_readiness(self):
  with self.assertRaisesRegex(RuntimeError,'canonical_source_required'):m.operate('apply',self.commit,self.pin)
 def test_existing_generation_successor_roundtrip_keeps_route_and_history(self):
  self.run_operation('apply');f=self.f
  first_commit,first_pin=self.commit,self.pin
  import subprocess,types,lib
  old='46e3a690096b6f89f2ca09a23e8c9e668fb6bbc0:'
  legacy_bridge=types.ModuleType('legacy_native_bridge')
  raw=subprocess.check_output(['git','-C',str(ROOT),'show',old+'lib/game_native_admission_bridge.py'])
  exec(compile(raw,'accepted46e3_bridge','exec'),legacy_bridge.__dict__)
  legacy_tx=types.ModuleType('legacy_native_transaction')
  raw=subprocess.check_output(['git','-C',str(ROOT),'show',old+'lib/game_native_admission_transaction.py'])
  with patch.object(lib,'game_native_admission_bridge',legacy_bridge):
   exec(compile(raw,'accepted46e3_transaction','exec'),legacy_tx.__dict__)
  history={p:p.read_bytes() for d in (f.state,f.proof) for p in d.iterdir() if p.is_file()}
  old_cap={key:cap.optional(path) for key,path in cap.layout()[2].items()}
  f.before=dict(f.after);previous=b.decode(f.before['ds3.manifest'][0])['launchAdmissionOverride']
  self.commit='2'*40
  f.policy=dict(f.policy,schema=2,previousAdmission=previous,
      previousLifecycleSha256=b.sha(f.before['ds3.lifecycle'][0]),sourceManifestSha256=b.sha(f.before['ds3.manifest'][0]),
      lifecycleSha256=b.sha(b'successor lifecycle'),admissionSha256=b.sha(b'successor helper'))
  f.after={'admission.helper':(b'successor helper',0o600),'hub.launcher':(b'successor hub',0o755),
           'cs2.launcher':(b'successor cs2',0o755)}
  ds=b.derive({key:f.before['ds3.'+key][0] for key in b.TARGETS},f.policy,self.commit,b'successor lifecycle')
  f.after.update({'ds3.'+key:(raw,b.MODES[key]) for key,raw in ds.items()})
  hub=b.decode(f.before['hub.receipt'][0]);hub.update(launcherSha256=b.sha(f.after['hub.launcher'][0]),launchAdmissionSha256=f.policy['admissionSha256'],launchReliabilityCommit=self.commit)
  cs2=b.decode(f.before['cs2.receipt'][0]);cs2.update(launcherSha256=b.sha(f.after['cs2.launcher'][0]),launcherCommit=self.commit)
  f.after.update({'hub.receipt':(self.enc(hub),0o600),'cs2.receipt':(self.enc(cs2),0o600)})
  self.intent=dict(self.intent,companionGeneration=2)
  self.report=dict(self.report,provisionalCommit=self.commit,policySha256=b.sha(self.enc(self.intent)),
      ds3BridgePolicySha256=b.sha(b.json_bytes(f.policy)),capabilityBeforeSha256={key:b.sha(raw) for key,raw in old_cap.items()},
      targets={key:{'beforeSha256':b.sha(f.before[key][0]),'afterSha256':b.sha(f.after[key][0]),'mode':tx.MODES[key]} for key in tx.KEYS})
  self.pin=b.sha(self.enc(self.report))
  for key,rel in self.sources.items():f.fixture.put(self.source/rel,*f.after[key])
  self.assertTrue(self.run_operation('apply')['changed']);self.side('after')
  with self.assertRaisesRegex(RuntimeError,'third_state'):
   legacy_tx.load(first_commit,first_pin,guard=lambda:True,_test_home=f.home)
  self.assertFalse(self.run_operation('apply')['changed'])
  self.assertEqual(b.verify(f.root,b.decode(f.after['ds3.manifest'][0])),f.policy['lifecycleSha256'])
  self.assertTrue(self.run_operation('rollback')['changed']);self.side('before')
  self.assertEqual(old_cap,{key:cap.optional(path) for key,path in cap.layout()[2].items()})
  self.assertEqual(history,{p:p.read_bytes() for p in history})
  # Run the ACTUAL first-generation verifier against the rollback result.
  # It cannot parse schema2 policy records, so those use the distinct prefix.
  self.assertEqual(legacy_bridge.verify(f.root,b.decode(f.before['ds3.manifest'][0])),previous['lifecycleSha256'])
  self.assertTrue(legacy_tx.load(first_commit,first_pin,guard=lambda:True,_test_home=f.home).side('after'))
  self.assertTrue(self.run_operation('return')['changed']);self.side('after')

if __name__=='__main__':unittest.main()
