"""Offline native renderer set, preserving the legacy six-target route."""
import json
import shutil
import unittest
from unittest.mock import patch
import test_ds3_renderer as legacy
m=legacy.m

class NativeRenderer(unittest.TestCase):
 def setUp(self):
  self.base=legacy.Renderer('run');self.base.setUp();self.addCleanup(self.base.tearDown)
  self.root=self.base.root;self.commit=self.base.commit;self.tx=self.base.tx;shutil.rmtree(self.tx);self.tx=m.renderer_transaction(self.commit,native=True)
  self.files=dict(self.base.files);self.before=dict(self.base.before);self.modes=dict(self.base.modes)
  manifest=json.loads(self.before['manifest']);manifest['runtimeOverrides']={};self.before['manifest']=m.json_bytes(manifest)
  previous={}
  for key,(rel,name) in m.RENDERER_NATIVE.items():
   old=('old '+name).encode();self.files[name]=('new '+name).encode();previous[rel]=m.digest_bytes(old)
   self.before[key]=old;self.modes[key]=m.RENDERER_NATIVE_MODES[key]
  self.before['lifecycle']=b'old helper';self.files['ds3-runtime']=b'new helper';self.modes['lifecycle']=0o700
  self.policy=dict(self.base.policy,schema=3,nativeBorderlessCapable=True,traceProtocolVersion=2,previousNativeRuntimeHashes=previous,nativeIdentityHashes={rel:m.digest_bytes(('identity '+rel).encode()) for rel in m.RENDERER_PE_IDENTITIES})
  for name,path in m.renderer_targets(self.policy).items():
   path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);path.write_bytes(self.before[name]);path.chmod(self.modes[name])
  for rel in m.RENDERER_PE_IDENTITIES:
   path=self.root/'runtime'/rel;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);path.write_bytes(('identity '+rel).encode());path.chmod(0o755)
  self.files['provenance.json']=m.json_bytes(dict(d3d11Sha256=m.digest_bytes(self.files['d3d11.dll']),sourceArchiveSha256=m.digest_bytes(self.files['source.tar.gz']),nativeBridgeModified=True,diagnosticCapable=True,nativeBorderlessCapable=True,traceProtocolVersion=2,nativeRuntimeHashes={rel:m.digest_bytes(self.files[name]) for rel,name in m.RENDERER_NATIVE.values()},nativeIdentityHashes=self.policy['nativeIdentityHashes'],lifecycleSha256=m.digest_bytes(self.files['ds3-runtime'])))
  self.policy['candidateFiles']={name:m.digest_bytes(data) for name,data in self.files.items()}
  self.rows=m.renderer_rows();self.after=m.renderer_after(self.before,self.modes,self.files,self.policy,self.commit,self.rows)
  self.make_transaction()
 def make_transaction(self):
  self.tx.mkdir(mode=0o700);(self.tx/'source').mkdir(mode=0o700)
  for name,data in self.files.items():path=self.tx/'source'/name;path.write_bytes(data);path.chmod(0o600)
  for side,images in (('before',self.before),('after',self.after)):
   for name,data in images.items():path=self.tx/(name+'.'+side);path.write_bytes(data);path.chmod(0o600)
  record=dict(schema=1,commit=self.commit,policy=self.policy,images={n:dict(before=m.digest_bytes(self.before[n]),after=m.digest_bytes(self.after[n]),mode=self.modes[n]) for n in self.before},treeRows=self.rows,phase='prepared',direction='after',intent=None)
  (self.tx/'record.json').write_bytes(m.json_bytes(record));(self.tx/'record.json').chmod(0o600)
 def assert_images(self,images):
  for name,path in m.renderer_targets(self.policy).items():self.assertEqual(path.read_bytes(),images[name])
 def test_coherent_set_apply_noop_rollback_return(self):
  self.assertEqual(len(m.renderer_targets(self.policy)),10)
  m.renderer_run(self.tx,'after');self.assert_images(self.after);self.assertFalse(m.renderer_run(self.tx,'after'))
  installed=json.loads(self.after['manifest']);m.renderer_verify_binding(installed)
  self.assertEqual(m.renderer_overlay_lifecycle(installed),m.digest_bytes(b'old helper'))
  effective=m.installed_critical_hashes(installed)
  for rel,name in m.RENDERER_NATIVE.values():self.assertEqual(effective[rel],m.digest_bytes(self.files[name]))
  self.assertEqual(installed['candidateSha256'],'a'*64)
  self.assertEqual(json.loads(self.after['borderless'])['nativeBinding']['winemetalSha256'],m.digest_bytes(self.files['winemetal.so']))
  m.renderer_run(self.tx,'before');self.assert_images(self.before);self.assertFalse(m.renderer_run(self.tx,'before'))
  # The restored pre-wave helper must ignore the separately named native record.
  import importlib.machinery, subprocess, tempfile
  from pathlib import Path
  source=subprocess.check_output(['git','show','d7940ae798c6258bc8dfc9b9359dbe0c443bac1a:bin/ds3-runtime'],cwd=str(Path(__file__).resolve().parents[1]))
  with tempfile.NamedTemporaryFile(suffix='.py') as helper:
   helper.write(source);helper.flush();old=importlib.machinery.SourceFileLoader('pre_wave_native_helper',helper.name).load_module();old.ROOT=self.root;old.PREFIX=m.PREFIX
   old.renderer_pending_guard();old.renderer_verify_binding(json.loads(self.before['manifest']))
  m.renderer_run(self.tx,'after');self.assert_images(self.after)
  self.assertEqual((m.PREFIX/'save.dat').read_bytes(),b'save')
 def test_every_publication_interruption_recovers_whole_set(self):
  for name in m.renderer_targets(self.policy):
   fired=[]
   def fault(label):
    if label=='published:'+name and not fired:fired.append(True);raise SystemExit(77)
   m.renderer_checkpoint=fault
   with self.assertRaises(SystemExit):m.renderer_run(self.tx,'after')
   m.renderer_checkpoint=lambda _:None;m.renderer_run(self.tx,'after',recover=True);self.assert_images(self.after);m.renderer_run(self.tx,'before')
 def test_native_and_pe_third_state_refused_before_mutation(self):
  for rel in [*self.policy['previousNativeRuntimeHashes'],*m.RENDERER_PE_IDENTITIES]:
   path=self.root/'runtime'/rel;before=path.read_bytes();path.write_bytes(b'foreign')
   with self.assertRaisesRegex(RuntimeError,'runtime_drift'):m.renderer_run(self.tx,'after')
   self.assertEqual((self.root/'ds3-runtime').read_bytes(),b'old helper');path.write_bytes(before)
 def test_legacy_successor_cannot_drop_native_bindings(self):
  m.renderer_run(self.tx,'after')
  six={key:path.read_bytes() for key,path in m.renderer_targets().items()}
  policy=dict(self.base.policy,previousRendererSha256=self.base.newsha)
  with self.assertRaisesRegex(RuntimeError,'native_scope_downgrade'):m.renderer_after(six,self.base.modes,self.base.files,policy,'2'*40,m.renderer_rows())
 def test_actual_native_operation_prepares_applies_noop_and_recovers(self):
  candidate=self.root/'candidate';shutil.copytree(self.tx/'source',candidate);shutil.rmtree(self.tx)
  control=self.root/'control';(control/'bin').mkdir(parents=True,mode=0o700);(control/'bin/ds3-runtime').write_bytes(self.files['ds3-runtime'])
  def installed(*,operational=False):
   self.assertIs(operational,False)
   return tuple(json.loads((self.root/name).read_bytes()) for name in ('manifest.json','receipt.json'))
  with patch.object(m,'source_gate'),patch.object(m,'window_repair_pending_guard'),patch.object(m,'inactive'),patch.object(m,'CONTROL',control),patch.object(m,'renderer_policy',return_value=self.policy),patch.object(m,'verify_installed',side_effect=installed),patch.object(m,'verify_borderless'):
   self.assertTrue(m.renderer_operation(self.commit,'upgrade',candidate)['changed']);self.assert_images(self.after)
   self.assertFalse(m.renderer_operation(self.commit,'upgrade',candidate)['changed'])
   self.assertFalse(m.renderer_operation(self.commit,'recover')['changed'])
   self.assertTrue(m.renderer_operation(self.commit,'rollback')['changed']);self.assert_images(self.before)
   self.assertTrue(m.renderer_operation(self.commit,'return')['changed']);self.assert_images(self.after)
 def test_bounded_native_generations_bind_original_helper_and_next_refuses_before_stage(self):
  m.renderer_run(self.tx,'after')
  for generation in range(2,m.RENDERER_MAX_GENERATIONS+1):
   current=json.loads((self.root/'manifest.json').read_bytes());m.renderer_overlay_lifecycle(current,max_generations=m.RENDERER_MAX_GENERATIONS-1)
   self.before={name:path.read_bytes() for name,path in m.renderer_targets(self.policy).items()}
   self.policy=dict(self.policy,previousRendererSha256=m.renderer_hash(current),previousNativeRuntimeHashes=m.renderer_native_hashes(current))
   for name in ('d3d11.dll','winemac.so','winemetal.so','ntdll.so'):self.files[name]=(str(generation)+' '+name).encode()
   provenance=json.loads(self.files['provenance.json']);provenance.update(d3d11Sha256=m.digest_bytes(self.files['d3d11.dll']),nativeRuntimeHashes={rel:m.digest_bytes(self.files[name]) for rel,name in m.RENDERER_NATIVE.values()})
   self.files['provenance.json']=m.json_bytes(provenance);self.policy['candidateFiles']={name:m.digest_bytes(data) for name,data in self.files.items()}
   self.commit='%040x'%generation;self.tx=m.renderer_transaction(self.commit,native=True);self.rows=m.renderer_rows()
   self.after=m.renderer_after(self.before,self.modes,self.files,self.policy,self.commit,self.rows);self.make_transaction();m.renderer_run(self.tx,'after')
  current=json.loads(self.after['manifest']);self.assertEqual(m.renderer_overlay_lifecycle(current),m.digest_bytes(b'old helper'))
  with self.assertRaisesRegex(RuntimeError,'lifecycle_depth'):m.renderer_overlay_lifecycle(current,max_generations=m.RENDERER_MAX_GENERATIONS-1)
  with patch.object(m,'source_gate'),patch.object(m,'window_repair_pending_guard'),patch.object(m,'inactive'),patch.object(m,'renderer_policy',return_value=self.policy),patch.object(m,'verify_installed',return_value=(current,{})),patch.object(m,'verify_borderless'):
   with self.assertRaisesRegex(RuntimeError,'lifecycle_depth'):m.renderer_operation('%040x'%(m.RENDERER_MAX_GENERATIONS+1),'upgrade',self.tx/'source')
  self.assertFalse(m.renderer_transaction('%040x'%(m.RENDERER_MAX_GENERATIONS+1),native=True).exists());self.assertFalse(list(self.root.glob('.ds3-renderer-stage-*')));self.assert_images(self.after)
 def test_identity_predecessor_and_provenance_are_required(self):
  wrong=dict(self.policy,nativeIdentityHashes={rel:'f'*64 for rel in m.RENDERER_PE_IDENTITIES})
  with self.assertRaisesRegex(RuntimeError,'native_identity'):m.renderer_after(self.before,self.modes,self.files,wrong,self.commit,self.rows)
  wrong=dict(self.policy,previousNativeRuntimeHashes={rel:'f'*64 for rel in self.policy['previousNativeRuntimeHashes']})
  with self.assertRaisesRegex(RuntimeError,'native_predecessor'):m.renderer_after(self.before,self.modes,self.files,wrong,self.commit,self.rows)
  wrong=dict(self.policy,nativeIdentityHashes={next(iter(m.RENDERER_PE_IDENTITIES)):'f'*64})
  with self.assertRaisesRegex(RuntimeError,'native_policy_schema'):m.renderer_policy_validate(wrong)
  provenance=json.loads(self.files['provenance.json']);provenance['nativeBridgeModified']=False
  raw=m.json_bytes(provenance);path=self.tx/'source/provenance.json';path.write_bytes(raw)
  wrong=dict(self.policy,candidateFiles=dict(self.policy['candidateFiles'],**{'provenance.json':m.digest_bytes(raw)}))
  with self.assertRaisesRegex(RuntimeError,'renderer_provenance'):m.renderer_candidate(self.tx/'source',wrong)

if __name__=='__main__':unittest.main()
