"""Fixed approval/route cutover, interruption and third-state tests; no Wine."""
import json,unittest
from pathlib import Path
import test_game_native_admission_bridge as fixture
from lib import game_native_admission_capability as c

class Capability(unittest.TestCase):
 def setUp(self):
  self.f=fixture.BridgeTests('run');self.f.setUp();self.addCleanup(self.f.doCleanups)
  self.intent={'preserveServerSha256':'c'*64,'preserveRuntimeHashes':{'engine/lib/wine/x86_64-unix/ntdll.so':'d'*64},'nativeRoute':{'image':r'C:\Program Files (x86)\Steam\steamapps\common\DARK SOULS III\Game\DarkSoulsIII.exe','machine':0x8664,'bundleIdentifier':'local.exact','targetSha256':'e'*64,'bundleFiles':{'Contents/MacOS/wine':{'sha256':'a'*64},'Contents/Info.plist':{'sha256':'b'*64}}}}
  (self.f.home/'AIDev/state').mkdir(mode=0o700);(self.f.root/'profiles/ds3').mkdir(parents=True,mode=0o700)
  self.tx=c.Transaction('a'*40,self.intent,lambda:True,_test_home=self.f.home)
  self.before={key:None for key in c.NAMES}
 def prepare(self):self.tx.prepare(self.before)
 def assert_side(self,side):
  _,files=self.tx.read();self.assertEqual({key:c.optional(path) for key,path in self.tx.targets.items()},files[side])
 def test_narrow_five_file_approval_and_exact_single_route(self):
  self.prepare();self.assertTrue(self.tx.run('after'));self.assertFalse(self.tx.run('after'));self.assert_side('after')
  value=json.loads(self.tx.targets['approval'].read_bytes());self.assertEqual(value['schema'],2);self.assertEqual(len(value['files']),5);self.assertEqual(value['machine'],34404)
  self.assertEqual(self.tx.targets['routes'].read_bytes().count(b'\n'),2)
  self.assertTrue(self.tx.run('before'));self.assertFalse(self.tx.run('before'));self.assert_side('before');self.tx.run('after');self.assert_side('after')
 def test_each_direction_and_publication_recovers(self):
  self.prepare()
  for direction in ('after','before'):
   for key in c.NAMES:
    self.tx.run('before' if direction=='after' else 'after');fired=[]
    def event(label):
     if label=='published:'+key and not fired:fired.append(True);raise SystemExit(81)
    self.tx.event=event
    with self.assertRaises(SystemExit):self.tx.run(direction)
    self.tx.event=lambda _:None
    with self.assertRaisesRegex(RuntimeError,'recovery_required'):self.tx.run(direction)
    self.tx.run(direction,recover=True);self.assert_side(direction)
 def test_partial_owned_publication_stage_resumes_and_foreign_stage_refuses(self):
  self.prepare();record,files=self.tx.read();record.update(phase='running',direction='after',intent='approval');self.tx.save(record)
  stage=self.tx.target_stage('approval');self.f.put(stage,files['after']['approval'][:13])
  self.tx=c.Transaction('a'*40,self.intent,lambda:True,_test_home=self.f.home);self.tx.run('after',recover=True);self.assert_side('after')
  self.tx.run('before');self.f.put(stage,b'foreign')
  with self.assertRaisesRegex(RuntimeError,'unowned_stage'):self.tx.run('after')
 def test_terminal_unrenamed_next_direction_record_keeps_durable_side(self):
  self.prepare();self.tx.run('after');record,_=self.tx.read();stage=self.tx.directory/'.record.next'
  self.f.put(stage,c.b.json_bytes(dict(record,phase='running',direction='before',intent=None))[:31])
  with self.assertRaisesRegex(RuntimeError,'unsettled_record_stage'):self.tx.run('after')
  self.assertFalse(self.tx.run('after',recover=True));self.assertFalse(stage.exists());self.assert_side('after')
 def test_running_postpublication_record_stage_follows_canonical_direction(self):
  self.prepare();record,files=self.tx.read();record.update(phase='running',direction='after',intent='approval');self.tx.save(record)
  c.replace(self.tx.targets['approval'],files['after']['approval'],None,self.tx.target_stage('approval'))
  self.f.put(self.tx.directory/'.record.next',c.b.json_bytes(dict(record,intent=None))[:-2])
  self.tx=c.Transaction('a'*40,self.intent,lambda:True,_test_home=self.f.home);self.tx.run('after',recover=True);self.assert_side('after')
 def test_terminal_intent_and_prepared_wrong_direction_are_malformed(self):
  self.prepare();self.tx.run('after');record,_=self.tx.read();record['intent']='approval';self.tx.save(record)
  with self.assertRaisesRegex(RuntimeError,'record_schema'):self.tx.read()
 def test_existing_route_and_approval_restore_exactly(self):
  for key,path in self.tx.targets.items():self.f.put(path,('before '+key).encode());self.before[key]=c.b.sha(path.read_bytes())
  self.prepare();self.tx.run('after');self.tx.run('before');self.assert_side('before')
 def test_unknown_endpoint_and_backup_drift_refuse_before_other_writes(self):
  self.prepare();path=self.tx.targets['routes'];self.f.put(path,b'unknown')
  with self.assertRaisesRegex(RuntimeError,'third_state'):self.tx.run('after')
  self.assertFalse(self.tx.targets['approval'].exists());path.unlink()
  snapshot=self.tx.directory/'approval.after';snapshot.write_bytes(b'drift')
  with self.assertRaisesRegex(RuntimeError,'snapshot_drift'):self.tx.run('after')
  self.assertFalse(self.tx.targets['approval'].exists())
 def test_prerequisite_unknown_or_symlink_refused(self):
  self.prepare();self.tx.guard=lambda:False
  with self.assertRaisesRegex(RuntimeError,'prerequisite_unknown'):self.tx.run('after')
  self.tx.guard=lambda:True;self.tx.targets['approval'].symlink_to(self.tx.directory/'approval.after')
  with self.assertRaises(OSError):self.tx.run('after')
 def test_drift_since_reviewed_prestate_and_wrong_route_rejected(self):
  self.f.put(self.tx.targets['routes'],b'late')
  with self.assertRaisesRegex(RuntimeError,'prestate_changed'):self.prepare()
  self.assertFalse(self.tx.directory.exists());self.intent['nativeRoute']['image']='C:\\Other.exe'
  with self.assertRaisesRegex(RuntimeError,'route_scope'):c.derive(self.intent,_test_home=self.f.home)

if __name__=='__main__':unittest.main()
