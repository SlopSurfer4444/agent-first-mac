"""Exact renderer successor composition into retained launch/overlay archival."""
import importlib.machinery
from pathlib import Path
import unittest
from test_game_archive_schema4 import Schema4Archive,u,w,a,COMMIT
from unittest.mock import patch
m=importlib.machinery.SourceFileLoader('archive_renderer_fixture',str(Path(__file__).resolve().parents[1]/'bin/ds3-runtime')).load_module()
class RendererArchive(Schema4Archive):
 def intermediate_overlay(self,f,policy):
  (f.path/'ds3/runtime'/m.RENDERER_REL).chmod(0o755)
  h=w.tree_hash(w.tree_rows(f.root,'ds3/runtime'))
  for rel,key in (('ds3/receipt.json','runtimeTreeSha256'),('ds3/borderless/receipt.json','baseRuntimeTreeSha256')):
   value=w.decode(f.root.read(rel)[0]);value[key]=h;f.put(rel,w.encode(value))
  return policy
 def setUp(self):
  self.bridgepatch=patch.object(a,'renderer_archive_view',lambda root,commit,old:u.renderer_successor(root,commit,old));self.bridgepatch.start();self.addCleanup(self.bridgepatch.stop)
  super().setUp();m.ROOT=self.mapping['ds3'];m.PREFIX=m.ROOT/'profiles/ds3'
  old=self.path('ds3/runtime/'+m.RENDERER_REL).read_bytes();self.put('ds3/profiles/ds3/'+m.RENDERER_PREFIX,old,0o644)
  files={'d3d11.dll':b'reviewed replacement renderer','source.tar.gz':b'corresponding source'}
  files['provenance.json']=w.encode({'d3d11Sha256':w.digest(files['d3d11.dll']),'sourceArchiveSha256':w.digest(files['source.tar.gz']),'nativeBridgeModified':False,'diagnosticCapable':True})
  self.rpolicy={'schema':1,'id':'ds3-renderer-update','owner':'control-ds3-marshal-fix','previousRendererSha256':w.digest(old),'candidateFiles':{k:w.digest(v) for k,v in files.items()},'diagnosticCapable':True}
  self.launch_history['manifests/ds3-renderer-update.json']=m.json_bytes(self.rpolicy)
  self.put('source/manifests/ds3-renderer-update.json',m.json_bytes(self.rpolicy))
  self.rt=m.renderer_transaction(COMMIT);self.rt.mkdir(mode=0o700);(self.rt/'source').mkdir(mode=0o700)
  before={k:p.read_bytes() for k,p in m.renderer_targets().items()};modes={k:p.stat().st_mode&0o777 for k,p in m.renderer_targets().items()};rows=m.renderer_rows()
  after=m.renderer_after(before,modes,files,self.rpolicy,COMMIT,rows)
  for name,data in files.items():p=self.rt/'source'/name;p.write_bytes(data);p.chmod(0o600)
  for side,images in (('before',before),('after',after)):
   for name,data in images.items():p=self.rt/(name+'.'+side);p.write_bytes(data);p.chmod(0o600)
  self.record={'schema':1,'commit':COMMIT,'policy':self.rpolicy,'images':{n:{'before':w.digest(before[n]),'after':w.digest(after[n]),'mode':modes[n]} for n in before},'treeRows':rows,'phase':'prepared','direction':'after','intent':None}
  self.write_record();m.renderer_run(self.rt,'after');self.record=m.load(self.rt/'record.json')
  self.definition['previousFiles']={key:self.image(rel) for key,rel in u.TARGETS.items()};self.definition['guards']={rel:self.image(rel) for rel in u.GUARDS};self.put('source/'+u.POLICY,u.encode(self.definition))
 def write_record(self):p=self.rt/'record.json';p.write_bytes(m.json_bytes(self.record));p.chmod(0o600)
 def second_renderer(self):
  self.second_generation();revision=self.archive_old_commit
  before={k:p.read_bytes() for k,p in m.renderer_targets().items()};modes={k:p.stat().st_mode&0o777 for k,p in m.renderer_targets().items()}
  files={'d3d11.dll':b'second reviewed replacement renderer','source.tar.gz':b'second corresponding source'}
  files['provenance.json']=w.encode({'d3d11Sha256':w.digest(files['d3d11.dll']),'sourceArchiveSha256':w.digest(files['source.tar.gz']),'nativeBridgeModified':False,'diagnosticCapable':True,'nativeBorderlessCapable':True,'traceProtocolVersion':2})
  self.rpolicy=dict(self.rpolicy,schema=2,previousRendererSha256=m.renderer_hash(w.decode(before['manifest'])),candidateFiles={k:w.digest(v) for k,v in files.items()},nativeBorderlessCapable=True,traceProtocolVersion=2)
  self.second_history['manifests/ds3-renderer-update.json']=m.json_bytes(self.rpolicy)
  self.rt=m.renderer_transaction(revision);self.rt.mkdir(mode=0o700);(self.rt/'source').mkdir(mode=0o700)
  rows=m.renderer_rows();after=m.renderer_after(before,modes,files,self.rpolicy,revision,rows)
  for name,data in files.items():p=self.rt/'source'/name;p.write_bytes(data);p.chmod(0o600)
  for side,images in (('before',before),('after',after)):
   for name,data in images.items():p=self.rt/(name+'.'+side);p.write_bytes(data);p.chmod(0o600)
  self.record={'schema':1,'commit':revision,'policy':self.rpolicy,'images':{n:{'before':w.digest(before[n]),'after':w.digest(after[n]),'mode':modes[n]} for n in before},'treeRows':rows,'phase':'prepared','direction':'after','intent':None}
  self.write_record();m.renderer_run(self.rt,'after');self.record=m.load(self.rt/'record.json')
  self.definition['previousFiles']={key:self.image(rel) for key,rel in u.TARGETS.items()};self.definition['guards']={rel:self.image(rel) for rel in u.GUARDS};self.put('source/'+u.POLICY,u.encode(self.definition))
 def test_renderer_carried_baseline_archives_without_unwind(self):
  self.second_generation();before=self.renderer_images();self.assertTrue(self.archive()['changed'])
  self.assertTrue(a.operate('archive-applied',self.successor_commit,self.new_overlay_pin,self.archive_old_commit)['changed']);self.assertEqual(self.renderer_images(),before)
 def test_renderer_second_generation_archives_launch_and_overlay(self):
  self.second_renderer();before=self.renderer_images();self.assertTrue(self.archive()['changed'])
  self.assertTrue(a.operate('archive-applied',self.successor_commit,self.new_overlay_pin,self.archive_old_commit)['changed']);self.assertEqual(self.renderer_images(),before)
 def renderer_images(self):return {key:(path.read_bytes(),path.stat().st_mode&0o777) for key,path in m.renderer_targets().items()}
 def test_renderer_baseline_foreign_prefix_rejected(self):
  self.second_generation();self.path('ds3/profiles/ds3/'+m.RENDERER_PREFIX).write_bytes(b'foreign');self.refused()
 def test_renderer_baseline_gate_race_rejected(self):
  self.second_generation();self.archive();seen=[];fired=[];original=a.local_gate
  def view(root,commit,old):result=u.renderer_successor(root,commit,old);seen.append(True);return result
  def gate(*args,**kwargs):
   result=original(*args,**kwargs)
   if seen and not fired:self.path('ds3/profiles/ds3/'+m.RENDERER_PREFIX).write_bytes(b'gate-race');fired.append(True)
   return result
  with patch.object(a,'renderer_archive_view',view),patch.object(a,'local_gate',gate):
   with self.assertRaisesRegex(RuntimeError,'renderer_baseline_pair_drift'):a.operate('archive-applied',self.successor_commit,self.new_overlay_pin,self.archive_old_commit)
  self.assertTrue(fired);self.assertTrue((self.mapping['state']/a.NAMESPACE/'transaction').is_dir())
 def test_renderer_second_generation_foreign_pair_rejected(self):
  self.second_renderer();self.path('ds3/profiles/ds3/'+m.RENDERER_PREFIX).write_bytes(b'foreign');self.refused()
 def test_renderer_second_generation_backup_rejected(self):
  self.second_renderer();p=self.rt/'receipt.before';p.write_bytes(w.encode({'foreign':True}));self.record['images']['receipt']['before']=w.digest(p.read_bytes());self.write_record();self.refused()
 def test_renderer_second_generation_capability_provenance_rejected(self):
  self.second_renderer();p=self.rt/'source/provenance.json';value=w.decode(p.read_bytes());value['nativeBorderlessCapable']=False;raw=w.encode(value);p.write_bytes(raw)
  self.record['policy']['candidateFiles']['provenance.json']=w.digest(raw);self.second_history['manifests/ds3-renderer-update.json']=m.json_bytes(self.record['policy']);self.write_record()
  with self.assertRaisesRegex(RuntimeError,'renderer_successor_borderless_provenance'):self.archive()
  self.assertTrue((self.mapping['state']/u.NAMESPACE/'transaction').is_dir())
 def test_renderer_second_generation_trace_protocol_provenance_rejected(self):
  self.second_renderer();p=self.rt/'source/provenance.json';value=w.decode(p.read_bytes());value['traceProtocolVersion']=1;raw=w.encode(value);p.write_bytes(raw)
  self.record['policy']['candidateFiles']['provenance.json']=w.digest(raw);self.second_history['manifests/ds3-renderer-update.json']=m.json_bytes(self.record['policy']);self.write_record()
  with self.assertRaisesRegex(RuntimeError,'renderer_successor_trace_protocol_provenance'):self.archive()
  self.assertTrue((self.mapping['state']/u.NAMESPACE/'transaction').is_dir())
 def test_renderer_second_generation_malformed_prior_override_rejected(self):
  self.second_renderer();p=self.rt/'manifest.before';value=w.decode(p.read_bytes());value['rendererOverride']['diagnosticCapable']=1;raw=m.json_bytes(value);p.write_bytes(raw);self.record['images']['manifest']['before']=w.digest(raw);self.write_record()
  with self.assertRaisesRegex(RuntimeError,'renderer_successor_prior_override'):self.archive()
  self.assertTrue((self.mapping['state']/u.NAMESPACE/'transaction').is_dir())
 def test_renderer_second_generation_prior_not_in_baseline_rejected(self):
  self.second_renderer();p=self.rt/'manifest.before';value=w.decode(p.read_bytes());value['rendererOverride']['transactionCommit']=self.successor_commit;raw=m.json_bytes(value);p.write_bytes(raw);self.record['images']['manifest']['before']=w.digest(raw);self.write_record();self.refused()
 def test_renderer_successor_archives_launch(self):self.assertTrue(self.archive()['changed'])
 def test_renderer_then_overlay_archive(self):
  self.assertTrue(self.archive()['changed'])
  self.assertTrue(a.operate('archive-applied',self.successor_commit,self.new_overlay_pin,COMMIT)['changed'])
 def test_renderer_overlay_gate_race_refused(self):
  self.archive();seen=[];fired=[];original=a.local_gate
  def view(root,commit,old):
   result=u.renderer_successor(root,commit,old);seen.append(True);return result
  def gate(*args,**kwargs):
   result=original(*args,**kwargs)
   if seen and not fired:self.path('ds3/profiles/ds3/'+m.RENDERER_PREFIX).write_bytes(b'gate-race');fired.append(True)
   return result
  with patch.object(a,'renderer_archive_view',view),patch.object(a,'local_gate',gate):
   with self.assertRaisesRegex(RuntimeError,'renderer_successor_endpoint'):a.operate('archive-applied',self.successor_commit,self.new_overlay_pin,COMMIT)
  self.assertTrue(fired);self.assertTrue((self.mapping['state']/a.NAMESPACE/'transaction').is_dir())
 def test_renderer_other_pending_refused(self):
  directory=m.ROOT/('.renderer-'+'f'*40);directory.mkdir(mode=0o700)
  p=directory/'record.json';p.write_bytes(m.json_bytes(dict(self.record,phase='running')));p.chmod(0o600);self.refused()
 def test_renderer_dangling_stage_refused(self):
  (m.ROOT/'.ds3-renderer-stage-interrupted').mkdir(mode=0o700);self.refused()
 def test_renderer_backup_mode_refused(self):
  (self.rt/'manifest.before').chmod(0o644);self.refused()
 def test_renderer_pending_rejected(self):self.record['phase']='running';self.write_record();self.refused()
 def test_renderer_foreign_endpoint_rejected(self):self.path('ds3/profiles/ds3/'+m.RENDERER_PREFIX).write_bytes(b'foreign');self.refused()
 def test_renderer_historical_policy_mismatch_rejected(self):self.launch_history['manifests/ds3-renderer-update.json']=w.encode(dict(self.rpolicy,diagnosticCapable=False));self.refused()
 def test_renderer_backup_rebound_rejected(self):
  p=self.rt/'receipt.before';p.write_bytes(w.encode({'foreign':True}));self.record['images']['receipt']['before']=w.digest(p.read_bytes());self.write_record();self.refused()
 def test_renderer_unrelated_runtime_drift_rejected(self):self.path('ds3/runtime/engine/bin/wineserver').write_bytes(b'foreign');self.refused()
 def test_renderer_extra_inventory_rejected(self):p=self.rt/'extra';p.write_bytes(b'extra');p.chmod(0o600);self.refused()
 def test_renderer_race_before_archive_rejected(self):
  def event(label):
   if label=='before-archive':self.path('ds3/profiles/ds3/'+m.RENDERER_PREFIX).write_bytes(b'raced')
  with self.assertRaisesRegex(RuntimeError,'renderer_successor_endpoint'):u.operate('archive-settled',self.successor_commit,self.pin,old_commit=COMMIT,event=event)
  self.assertTrue((self.mapping['state']/u.NAMESPACE/'transaction').is_dir())
def load_tests(loader,tests,pattern):return unittest.TestSuite(RendererArchive(n) for n in loader.getTestCaseNames(RendererArchive) if n.startswith('test_renderer_'))
