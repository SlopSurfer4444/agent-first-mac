import copy
import importlib.machinery
import json
import os
from pathlib import Path
import tempfile
import shutil
from unittest.mock import patch
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/'bin/ds3-runtime'
m=importlib.machinery.SourceFileLoader('ds3_renderer_test',str(SCRIPT)).load_module()

class Renderer(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='ds3-renderer-',dir=str(SCRIPT.parents[2]));self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
  self.oldglobals={k:getattr(m,k) for k in ('ROOT','PREFIX','renderer_checkpoint')};m.ROOT=self.root;m.PREFIX=self.root/'profiles/ds3'
  self.commit='1'*40;self.old=b'old renderer';self.new=b'new renderer';self.oldsha=m.digest_bytes(self.old);self.newsha=m.digest_bytes(self.new)
  self.source=b'corresponding source';provenance=m.json_bytes({'d3d11Sha256':self.newsha,'sourceArchiveSha256':m.digest_bytes(self.source),'nativeBridgeModified':False,'diagnosticCapable':True})
  self.files={'d3d11.dll':self.new,'source.tar.gz':self.source,'provenance.json':provenance}
  self.policy={'schema':1,'id':'ds3-renderer-update','owner':'control-ds3-marshal-fix','previousRendererSha256':self.oldsha,'candidateFiles':{k:m.digest_bytes(v) for k,v in self.files.items()},'diagnosticCapable':True}
  manifest={'schema':4,'sourceCriticalHashes':{m.RENDERER_REL:self.oldsha},'candidateSha256':'a'*64,'donorSha256':'b'*64}
  before={'runtime':self.old,'prefix':self.old,'manifest':m.json_bytes(manifest),'borderless':m.json_bytes({'nativeBinding':{'d3d11Sha256':self.oldsha,'winemetalSha256':'a'*64,'donorSha256':'b'*64}}),'borderlessReceipt':m.json_bytes({'keep':'borderless'}),'receipt':m.json_bytes({'keep':'owner','sourceRuntimeTreeSha256':'c'*64})}
  self.modes={k:0o755 if k=='runtime' else 0o644 if k=='prefix' else 0o600 for k in before}
  for name,path in m.renderer_targets().items():path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);path.write_bytes(before[name]);path.chmod(self.modes[name])
  native=self.root/'runtime/native-preserved';native.write_bytes(b'native');native.chmod(0o600)
  save=m.PREFIX/'save.dat';save.write_bytes(b'save');save.chmod(0o600)
  self.rows=m.renderer_rows();self.after=m.renderer_after(before,self.modes,self.files,self.policy,self.commit,self.rows);self.before=before
  self.tx=m.renderer_transaction(self.commit);self.tx.mkdir(mode=0o700);(self.tx/'source').mkdir(mode=0o700)
  for name,data in self.files.items():p=self.tx/'source'/name;p.write_bytes(data);p.chmod(0o600)
  for side,images in [('before',before),('after',self.after)]:
   for name,data in images.items():p=self.tx/(name+'.'+side);p.write_bytes(data);p.chmod(0o600)
  self.record={'schema':1,'commit':self.commit,'policy':self.policy,'images':{n:{'before':m.digest_bytes(before[n]),'after':m.digest_bytes(self.after[n]),'mode':self.modes[n]} for n in before},'treeRows':self.rows,'phase':'prepared','direction':'after','intent':None}
  p=self.tx/'record.json';p.write_bytes(m.json_bytes(self.record));p.chmod(0o600)
 def tearDown(self):
  for k,v in self.oldglobals.items():setattr(m,k,v)
  self.tmp.cleanup()
 def assert_images(self,images):
  for n,p in m.renderer_targets().items():self.assertEqual(p.read_bytes(),images[n]);self.assertEqual(p.stat().st_mode&0o777,self.modes[n])
 def test_apply_noop_rollback_return_preserves_native_save(self):
  self.assertTrue(m.renderer_run(self.tx,'after'));self.assert_images(self.after)
  self.assertFalse(m.renderer_run(self.tx,'after'));m.renderer_verify_binding(json.loads(self.after['manifest']))
  self.assertTrue(m.renderer_run(self.tx,'before'));self.assert_images(self.before)
  self.assertFalse(m.renderer_run(self.tx,'before'));self.assertTrue(m.renderer_run(self.tx,'after'))
  self.assertEqual((self.root/'runtime/native-preserved').read_bytes(),b'native');self.assertEqual((m.PREFIX/'save.dat').read_bytes(),b'save')
 def test_each_published_image_interruption_recovers(self):
  for name in m.renderer_targets():
   with self.subTest(name=name):
    fired=[]
    def fault(label):
     if label=='published:'+name and not fired:fired.append(True);raise SystemExit(77)
    m.renderer_checkpoint=fault
    with self.assertRaises(SystemExit):m.renderer_run(self.tx,'after')
    m.renderer_checkpoint=lambda label:None;m.renderer_run(self.tx,'after',recover=True);self.assert_images(self.after)
    m.renderer_run(self.tx,'before')
 def test_third_state_and_other_runtime_refused_before_mutation(self):
  p=m.renderer_targets()['prefix'];p.write_bytes(b'foreign')
  with self.assertRaisesRegex(RuntimeError,'target_drift'):m.renderer_run(self.tx,'after')
  self.assertEqual(m.renderer_targets()['runtime'].read_bytes(),self.old);p.write_bytes(self.old)
  (self.root/'runtime/native-preserved').write_bytes(b'changed')
  with self.assertRaisesRegex(RuntimeError,'other_runtime'):m.renderer_run(self.tx,'after')
 def test_race_after_preflight_not_adopted(self):
  def fault(label):
   if label=='intent:runtime':m.renderer_targets()['runtime'].write_bytes(b'foreign')
  m.renderer_checkpoint=fault
  with self.assertRaisesRegex(RuntimeError,'target_changed'):m.renderer_run(self.tx,'after')
  self.assertEqual(m.renderer_targets()['runtime'].read_bytes(),b'foreign')
 def test_hard_exit_each_staging_cut_recovers(self):
  for cut in range(1,21):
   with self.subTest(cut=cut):
    pid=os.fork()
    if pid==0:
     count=[0]
     def die(label):
      if label=='replace:staged':
       count[0]+=1
       if count[0]==cut:os._exit(77)
     m.renderer_checkpoint=die;m.renderer_run(self.tx,'after');os._exit(78)
    _,status=os.waitpid(pid,0);self.assertEqual(os.WEXITSTATUS(status),77)
    self.assertTrue(list(self.root.glob('.ds3-renderer-write-*')))
    m.renderer_run(self.tx,'after',recover=True);self.assert_images(self.after)
    self.assertFalse(list(self.root.glob('.ds3-renderer-write-*')))
    m.renderer_run(self.tx,'before')
 def test_record_backup_mode_and_prefix_tamper(self):
  r=copy.deepcopy(self.record);r['schema']=True;(self.tx/'record.json').write_bytes(m.json_bytes(r))
  with self.assertRaisesRegex(RuntimeError,'schema'):m.renderer_read(self.tx)
  (self.tx/'record.json').write_bytes(m.json_bytes(self.record));m.renderer_run(self.tx,'after')
  m.renderer_targets()['prefix'].chmod(0o600)
  with self.assertRaisesRegex(RuntimeError,'prefix_drift'):m.renderer_verify_binding(json.loads(self.after['manifest']))
 def test_fifo_target_refused_without_blocking(self):
  target=m.renderer_targets()['runtime'];target.unlink();os.mkfifo(target,0o600)
  with self.assertRaisesRegex(RuntimeError,'target_mode'):m.renderer_replace(target,self.new,0o755,self.oldsha)
 def test_actual_operation_prepare_apply_noop_rollback(self):
  shutil.rmtree(self.tx);candidate=self.root/'candidate';candidate.mkdir(mode=0o700)
  for name,data in self.files.items():p=candidate/name;p.write_bytes(data);p.chmod(0o600)
  with patch.object(m,'source_gate'),patch.object(m,'window_repair_pending_guard'),patch.object(m,'inactive'),patch.object(m,'renderer_policy',return_value=self.policy),patch.object(m,'verify_installed',return_value=(json.loads(self.before['manifest']),json.loads(self.before['receipt']))),patch.object(m,'verify_borderless'):
   self.assertTrue(m.renderer_operation(self.commit,'upgrade',candidate)['changed']);self.assert_images(self.after)
   self.assertFalse(m.renderer_operation(self.commit,'upgrade',candidate)['changed'])
   self.assertTrue(m.renderer_operation(self.commit,'rollback')['changed']);self.assert_images(self.before)
   self.assertTrue(m.renderer_operation(self.commit,'return')['changed']);self.assert_images(self.after)
 def test_trace_session_protocol_and_normal_environment_off(self):
  (self.root/'logs').mkdir(mode=0o700)
  base=json.loads(self.after['manifest']);path=m.renderer_trace_session(base,{'windowWidth':1920,'windowHeight':1080})
  self.assertRegex(path.name,r'^dxmt-trace-session-[0-9a-f]{32}$')
  self.assertEqual(path.stat().st_mode&0o777,0o700)
  marker=path/'.cs2trace-session';self.assertEqual(marker.read_bytes(),b'CS2TRACE_SESSION_V1\n');self.assertEqual(marker.stat().st_mode&0o777,0o600)
  self.assertFalse(json.loads((path/'capture.json').read_bytes())['armed'])
  with patch.dict(os.environ,{'DXMT_CS2_TRACE_DIR':'untrusted inherited path'}):self.assertNotIn('DXMT_CS2_TRACE_DIR',m.wine_env(self.root/'runtime',m.PREFIX))
 def test_legacy_and_override_effective_hash(self):
  old=json.loads(self.before['manifest']);self.assertEqual(m.renderer_hash(old),self.oldsha)
  new=json.loads(self.after['manifest']);self.assertEqual(m.renderer_hash(new),self.newsha);self.assertEqual(new['sourceCriticalHashes'],old['sourceCriticalHashes'])
 def test_second_generation_operation_uses_override_and_preserves_ancestry(self):
  m.renderer_run(self.tx,'after');previous_manifest=m.renderer_targets()['manifest'].read_bytes()
  files={'d3d11.dll':b'second renderer with native borderless','source.tar.gz':b'second source'}
  files['provenance.json']=m.json_bytes({'d3d11Sha256':m.digest_bytes(files['d3d11.dll']),'sourceArchiveSha256':m.digest_bytes(files['source.tar.gz']),'nativeBridgeModified':False,'diagnosticCapable':True,'nativeBorderlessCapable':True,'traceProtocolVersion':2})
  policy=dict(self.policy,schema=2,previousRendererSha256=self.newsha,candidateFiles={k:m.digest_bytes(v) for k,v in files.items()},nativeBorderlessCapable=True,traceProtocolVersion=2)
  candidate=self.root/'candidate-next';candidate.mkdir(mode=0o700)
  for name,data in files.items():p=candidate/name;p.write_bytes(data);p.chmod(0o600)
  commit='2'*40
  def installed():return tuple(json.loads(m.renderer_targets()[key].read_bytes()) for key in ('manifest','receipt'))
  with patch.object(m,'source_gate'),patch.object(m,'window_repair_pending_guard'),patch.object(m,'inactive'),patch.object(m,'renderer_policy',return_value=policy),patch.object(m,'verify_installed',side_effect=installed),patch.object(m,'verify_borderless'):
   self.assertTrue(m.renderer_operation(commit,'upgrade',candidate)['changed'])
   current=installed()[0];self.assertEqual(current['sourceCriticalHashes'],json.loads(self.before['manifest'])['sourceCriticalHashes']);self.assertTrue(m.renderer_fields(current)['nativeBorderlessCapable']);m.renderer_verify_binding(current)
   (self.root/'logs').mkdir(mode=0o700);capture=m.renderer_trace_session(current,{'windowWidth':1920,'windowHeight':1080})
   self.assertEqual((capture/'.cs2trace-session').read_bytes(),b'CS2TRACE_SESSION_V2\n');self.assertEqual(json.loads((capture/'capture.json').read_bytes())['traceProtocolVersion'],2)
   self.assertFalse(m.renderer_operation(commit,'upgrade',candidate)['changed'])
   self.assertTrue(m.renderer_operation(commit,'rollback')['changed']);self.assertEqual(m.renderer_targets()['manifest'].read_bytes(),previous_manifest);m.renderer_verify_binding(installed()[0])
   self.assertTrue(m.renderer_operation(commit,'return')['changed']);m.renderer_verify_binding(installed()[0])
  self.assertEqual((self.root/'runtime/native-preserved').read_bytes(),b'native');self.assertEqual((m.PREFIX/'save.dat').read_bytes(),b'save')
 def test_native_borderless_capability_requires_policy_and_provenance(self):
  candidate=self.root/'candidate-capability';candidate.mkdir(mode=0o700)
  for name,data in self.files.items():p=candidate/name;p.write_bytes(data);p.chmod(0o600)
  policy=dict(self.policy,schema=2,nativeBorderlessCapable=True,traceProtocolVersion=2)
  with self.assertRaisesRegex(RuntimeError,'borderless_provenance'):m.renderer_candidate(candidate,policy)
  for value in (None,1,'true'):
   with self.assertRaisesRegex(RuntimeError,'policy_schema'):m.renderer_policy_validate(dict(policy,nativeBorderlessCapable=value))
  with self.assertRaisesRegex(RuntimeError,'policy_schema'):m.renderer_policy_validate(dict(self.policy,nativeBorderlessCapable=True,traceProtocolVersion=2))
  for value in (None,True,1,3,'2'):
   with self.assertRaisesRegex(RuntimeError,'policy_schema'):m.renderer_policy_validate(dict(policy,traceProtocolVersion=value))
  overridden=json.loads(self.after['manifest']);overridden['rendererOverride']['nativeBorderlessCapable']=1
  with self.assertRaisesRegex(RuntimeError,'override_schema'):m.renderer_fields(overridden)
 def test_trace_protocol_provenance_is_bound(self):
  candidate=self.root/'candidate-trace-protocol';candidate.mkdir(mode=0o700);files=dict(self.files)
  value=json.loads(files['provenance.json']);value['nativeBorderlessCapable']=True;value['traceProtocolVersion']=1;files['provenance.json']=m.json_bytes(value)
  for name,data in files.items():p=candidate/name;p.write_bytes(data);p.chmod(0o600)
  policy=dict(self.policy,schema=2,nativeBorderlessCapable=True,traceProtocolVersion=2,candidateFiles={k:m.digest_bytes(v) for k,v in files.items()})
  with self.assertRaisesRegex(RuntimeError,'renderer_trace_protocol_provenance'):m.renderer_candidate(candidate,policy)
if __name__=='__main__':unittest.main()
