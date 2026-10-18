"""Source/deployment wiring only. Native observer remains blocked on real Wine."""
import hashlib
import importlib.machinery
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import test_game_native_admission_bridge as fixture

ROOT=Path(__file__).resolve().parents[1]
h=importlib.machinery.SourceFileLoader('native_layout_ds3',str(ROOT/'bin/ds3-runtime')).load_module()

class Layout(unittest.TestCase):
 def test_all_current_consumers_pin_exact_stable_helper(self):
  raw=(ROOT/'bin/game-launch-admission').read_bytes();pin=hashlib.sha256(raw).hexdigest()
  for name in ('games-play','cs2-play'):self.assertIn(pin,(ROOT/'bin'/name).read_text())
  self.assertEqual(h.ADMISSION_SHA,pin)
  self.assertEqual(json.loads((ROOT/'manifests/wine-runtime-update.json').read_text())['requiredLaunchAdmissionSha256'],pin)
  self.assertNotIn(b'/Documents/Codex/',raw);self.assertNotIn(b'/outputs/',raw)
  self.assertIn(b"AIDev/lib/game-launch-admission-v2/binding/native_launch_binding.py",raw)
  companion=(ROOT/'lib/game_launch_native/binding/native_launch_binding.py').read_bytes()
  self.assertIn(hashlib.sha256(companion).hexdigest().encode(),raw)
 def test_ds3_executes_only_pinned_bridge_and_binds_current_admission(self):
  f=fixture.BridgeTests('run');f.setUp();self.addCleanup(f.doCleanups)
  bridge=f.home/'AIDev/lib/game-launch-admission/bridge.py';bridge.parent.mkdir(parents=True,mode=0o700)
  bridge.write_bytes((ROOT/'lib/game_native_admission_bridge.py').read_bytes());bridge.chmod(0o600)
  manifest=fixture.b.decode(f.after['manifest'])
  with patch.object(h,'ROOT',f.root),patch.object(h,'ADMISSION_BRIDGE_PATH',bridge),patch.object(h,'ADMISSION_SHA',fixture.b.sha(f.helper)):
   self.assertEqual(h.native_admission_lifecycle(manifest),fixture.b.sha(f.new_lifecycle));h.native_admission_pending_guard()
   with patch.object(h,'ADMISSION_SHA','f'*64),self.assertRaisesRegex(RuntimeError,'helper_binding'):h.native_admission_lifecycle(manifest)
   original=bridge.read_bytes();bridge.write_bytes(original+b'\n# changed\n')
   with self.assertRaisesRegex(RuntimeError,'bridge_changed'):h.native_admission_lifecycle(manifest)
 def test_renderer_mutation_requires_admission_rollback_first(self):
  import test_ds3_native_renderer as native
  f=native.NativeRenderer('run');f.setUp();self.addCleanup(f.doCleanups)
  before=dict(f.after);manifest=json.loads(before['manifest']);manifest['launchAdmissionOverride']={};before['manifest']=h.json_bytes(manifest)
  policy=dict(f.policy,previousRendererSha256=h.renderer_hash(manifest))
  with self.assertRaisesRegex(RuntimeError,'admission_successor_blocks_renderer_upgrade'):h.renderer_after(before,f.modes,f.files,policy,'9'*40,f.rows)
  path=f.root/'manifest.json';path.write_bytes(before['manifest']);original={p:p.read_bytes() for p in (f.root/'ds3-runtime',path)}
  with patch.object(h,'ROOT',f.root),patch.object(h,'PREFIX',native.m.PREFIX):
   with self.assertRaisesRegex(RuntimeError,'rollback_native_admission_first'):h.renderer_run(f.tx,'before')
  self.assertEqual(original,{p:p.read_bytes() for p in original})

 def test_pending_admission_blocks_existing_renderer_rollback_without_writes(self):
  import test_ds3_native_renderer as native
  f=native.NativeRenderer('run');f.setUp();self.addCleanup(f.doCleanups)
  # Install the native side first: without the admission guard, rollback would
  # change these targets. The admission history has a valid header and all
  # eight hash-bound snapshots, rather than merely an empty/malformed folder.
  native.m.renderer_run(f.tx,'after')
  evidence=fixture.BridgeTests('run');evidence.setUp();self.addCleanup(evidence.doCleanups)
  pending=f.root/evidence.directory.name;pending.mkdir(mode=0o700)
  record=dict(evidence.record,phase='prepared')
  for side,images in (('before',evidence.before),('after',evidence.after)):
   for key,raw in images.items():
    path=pending/(key+'.'+side);path.write_bytes(raw);path.chmod(0o600)
  path=pending/'record.json';path.write_bytes(fixture.b.json_bytes(record));path.chmod(0o600)
  self.assertEqual(fixture.b.derive(evidence.before,record['policy'],record['commit'],evidence.after['lifecycle']),evidence.after)
  with self.assertRaisesRegex(RuntimeError,'admission_recovery_required'):fixture.b.pending_guard(f.root)
  bridge=f.root/'bridge.py';bridge.write_bytes((ROOT/'lib/game_native_admission_bridge.py').read_bytes());bridge.chmod(0o600)
  original={p:p.read_bytes() for p in f.root.rglob('*') if p.is_file()}
  with patch.object(h,'ROOT',f.root),patch.object(h,'PREFIX',native.m.PREFIX),patch.object(h,'ADMISSION_BRIDGE_PATH',bridge):
   with self.assertRaisesRegex(RuntimeError,'admission_recovery_required'):h.renderer_run(f.tx,'before')
  self.assertEqual(original,{p:p.read_bytes() for p in original})

if __name__=='__main__':unittest.main()
