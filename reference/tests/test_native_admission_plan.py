"""Private metadata preparation; synthetic preimages, no Wine or installed writes."""
import hashlib,importlib.machinery,json,shutil,unittest
from pathlib import Path
from unittest.mock import patch
import test_game_native_admission_bridge as fixture
ROOT=Path(__file__).resolve().parents[1]
m=importlib.machinery.SourceFileLoader('admission_planner',str(ROOT/'bin/game-native-admission-plan')).load_module()

class Plan(unittest.TestCase):
 def setUp(self):
  f=fixture.BridgeTests('run');f.setUp();self.addCleanup(f.doCleanups);self.f=f
  self.source=f.home/'source';(self.source/'lib').mkdir(parents=True,mode=0o700);(self.source/'manifests').mkdir(mode=0o700)
  shutil.copyfile(ROOT/'lib/game_native_admission_bridge.py',self.source/'lib/game_native_admission_bridge.py')
  self.targets={key:f.home/'targets'/key for key in m.TARGETS}
  for key,path in self.targets.items():f.put(path,f.before[key[4:]] if key.startswith('ds3.') else b'old '+key.encode())
  for owner,key,launcher in [('control-games-hub','hub.receipt','hub.launcher'),('control-cs2-standalone','cs2.receipt','cs2.launcher')]:f.put(self.targets[key],m.enc({'owner':owner,'launcherSha256':m.sha(self.targets[launcher].read_bytes()),'keep':[1,2]}))
  for key,rel in m.SOURCES.items():f.put(self.source/rel,f.new_lifecycle if key=='ds3.lifecycle' else b'new '+key.encode())
  self.runtime=f.root/'runtime/engine/lib/wine/x86_64-unix/ntdll.so';f.put(self.runtime,b'ntdll')
  self.target=f.root/'profiles/ds3/drive_c/Program Files (x86)/Steam/steamapps/common/DARK SOULS III/Game/DarkSoulsIII.exe';f.put(self.target,b'actual PE')
  self.intent={'state':'BLOCKED_NOT_INSTALLABLE','blocker':'Wine double-fork','preserveServerSha256':'c'*64,'preserveRendererPolicySha256':json.loads(f.before['manifest'])['rendererOverride']['policySha256'],'previousLifecycleSha256':m.sha(f.before['lifecycle']),'sourceFiles':{rel:m.sha((self.source/rel).read_bytes()) for rel in m.SOURCES.values()},'preserveRuntimeHashes':{'engine/lib/wine/x86_64-unix/ntdll.so':m.sha(b'ntdll')},'nativeRoute':{'targetSha256':m.sha(b'actual PE'),'image':r'C:\Program Files (x86)\Steam\steamapps\common\DARK SOULS III\Game\DarkSoulsIII.exe','machine':0x8664,'bundleIdentifier':'test.bound','bundleFiles':{'Contents/MacOS/wine':{'sha256':'a'*64},'Contents/Info.plist':{'sha256':'b'*64}}}}
  f.put(self.source/'manifests/game-native-launch-admission.json',m.enc(self.intent))
  for key,value in [('HERE',self.source),('HOME',f.home),('DS3',f.root),('HUB',f.home/'hub'),('CS2',f.home/'cs2'),('TARGETS',self.targets)]:
   patcher=patch.object(m,key,value);patcher.start();self.addCleanup(patcher.stop)
 def test_nine_after_images_preserve_unrelated_metadata_and_runtime(self):
  before={p:p.read_bytes() for p in self.targets.values()};report,old,new,policy,approval,routes=m.prepare('a'*40)
  self.assertEqual(len(new),9);self.assertEqual(before,{p:p.read_bytes() for p in self.targets.values()});self.assertEqual(report['state'],'BLOCKED_NOT_INSTALLABLE');self.assertFalse(report['publicationAdapterImplemented'])
  for key in ('hub.receipt','cs2.receipt'):self.assertEqual(json.loads(new[key][0])['keep'],[1,2])
  self.assertEqual(json.loads(new['ds3.manifest'][0])['rendererOverride'],json.loads(old['ds3.manifest'][0])['rendererOverride'])
  self.assertEqual(approval['machine'],0x8664);self.assertEqual(len(approval['files']),5);self.assertEqual(routes.count(b'\n'),2);self.assertEqual(self.runtime.read_bytes(),b'ntdll')
 def test_source_runtime_and_pe_drift_each_refuse_without_mutation(self):
  for path,error in [(self.source/'bin/games-play','source_binding'),(self.runtime,'runtime_drift'),(self.target,'target_changed')]:
   raw=path.read_bytes();path.write_bytes(b'changed')
   with self.assertRaisesRegex(RuntimeError,error):m.prepare('a'*40)
   path.write_bytes(raw)
 def test_owner_preimage_mismatch_refused(self):
  self.targets['hub.launcher'].write_bytes(b'foreign')
  with self.assertRaisesRegex(RuntimeError,'hub_receipt_preimage'):m.prepare('a'*40)
 def test_different_renderer_package_refused(self):
  raw=json.loads(self.targets['ds3.manifest'].read_bytes());raw['rendererOverride']['policySha256']='f'*64;self.targets['ds3.manifest'].write_bytes(m.enc(raw))
  with self.assertRaisesRegex(RuntimeError,'renderer_package_changed'):m.prepare('a'*40)
 def test_output_refuses_managed_namespace_and_symlink_parent(self):
  with self.assertRaisesRegex(RuntimeError,'managed_output'):m.private_output(self.f.root/'new-plan')
  link=self.f.home/'link';link.symlink_to(self.f.home,target_is_directory=True)
  with self.assertRaisesRegex(RuntimeError,'unsafe_output'):m.private_output(link/'new-plan')
 def test_exact_native_predecessor_uses_schema_two_and_retains_runtime(self):
  for key in fixture.b.TARGETS:self.f.put(self.targets['ds3.'+key],self.f.after[key])
  self.f.put(self.targets['admission.helper'],self.f.helper)
  self.intent.update(companionGeneration=2,previousManifestSha256=m.sha(self.f.after['manifest']),
      previousLifecycleSha256=m.sha(self.f.after['lifecycle']),
      previousAdmissionOverride=json.loads(self.f.after['manifest'])['launchAdmissionOverride'])
  self.f.put(self.source/'manifests/game-native-launch-admission.json',m.enc(self.intent))
  report,before,after,policy,approval,routes=m.prepare('a'*40)
  self.assertEqual(policy['schema'],2);self.assertEqual(policy['previousAdmission'],self.intent['previousAdmissionOverride'])
  self.assertEqual(json.loads(after['ds3.manifest'][0])['rendererOverride'],json.loads(before['ds3.manifest'][0])['rendererOverride'])
  self.assertEqual(json.loads(after['ds3.receipt'][0])['runtimeTreeSha256'],json.loads(before['ds3.receipt'][0])['runtimeTreeSha256'])
  self.assertEqual(len(after),9)
  self.intent['previousManifestSha256']='f'*64;self.f.put(self.source/'manifests/game-native-launch-admission.json',m.enc(self.intent))
  with self.assertRaisesRegex(RuntimeError,'predecessor_changed'):m.prepare('a'*40)

if __name__=='__main__':unittest.main()
