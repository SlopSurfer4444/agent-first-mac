import contextlib
import hashlib
import os
import subprocess
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
loader=importlib.machinery.SourceFileLoader("cs2_install_test",str(ROOT/"bin/cs2-standalone"))
spec=importlib.util.spec_from_loader(loader.name,loader)
m=importlib.util.module_from_spec(spec); loader.exec_module(m)

class AdoptionTests(unittest.TestCase):
    def test_tree_rejects_escape_and_tracks_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve(); (root/'runtime').mkdir()
            base=root/'runtime'; (base/'file').write_bytes(b'original')
            first=m.tree(base); (base/'file').write_bytes(b'changed')
            self.assertNotEqual(first,m.tree(base))
            (base/'escape').symlink_to('../outside')
            with self.assertRaisesRegex(RuntimeError,'unsafe_link'):m.tree(base,True)

    def test_tree_rejects_writable_nested_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve(); (root/'nested').mkdir(); (root/'nested').chmod(0o777)
            with self.assertRaisesRegex(RuntimeError,'unsafe_nested_directory'):m.tree(root)

    def test_tree_allows_only_internal_relative_dependency(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve(); (root/'lib').mkdir(); (root/'Frameworks').mkdir()
            (root/'Frameworks/lib.dylib').write_bytes(b'library')
            (root/'lib/lib.dylib').symlink_to('../Frameworks/lib.dylib')
            self.assertEqual(len(m.tree(root,True)),64)
            with self.assertRaisesRegex(RuntimeError,'unsafe_link'):m.tree(root)

    def test_import_rejects_redirected_steamapps_without_copy(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp).resolve(); source=base/'donor'; dest=base/'destination'
            rel=Path('prefix/drive_c/Program Files (x86)/Steam')
            game=source/rel/'steamapps/common/Counter-Strike Global Offensive'
            game.mkdir(parents=True); (game/'test.vpk').write_bytes(b'game')
            (source/rel/'steamapps/appmanifest_730.acf').write_text('"appid" "730"\n"StateFlags" "4"\n"buildid" "123"\n"SizeOnDisk" "4"')
            steam=dest/rel; steam.mkdir(parents=True); (steam/'steam.exe').write_bytes(b'steam')
            outside=base/'outside'; outside.mkdir(); (steam/'steamapps').symlink_to(outside)
            with patch.object(m,'ROOT',dest),patch.object(m,'DONOR',source),patch.object(m,'source_gate'),patch.object(m,'verify'),patch.object(m,'run',return_value=b'') as run:
                with self.assertRaisesRegex(RuntimeError,'unsafe_directory'):m.import_game('a'*40)
                self.assertEqual(run.call_count,1)
                self.assertEqual(list(outside.iterdir()),[])

    def test_game_data_mode_requires_private_boundary_and_no_world_write(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp).resolve(); game=base/'prefix/Steam';game.mkdir(parents=True);game.chmod(0o775)
            with patch.object(m,'ROOT',base):
                m.directory(game,game_data=True)
                with self.assertRaisesRegex(RuntimeError,'unsafe_directory'):m.directory(game)
                game.chmod(0o777)
                with self.assertRaisesRegex(RuntimeError,'unsafe_directory'):m.directory(game,game_data=True)

    def test_update_rejects_bad_receipt_before_replacement(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp).resolve(); (base/'runtime').mkdir()
            (base/'cs2-play').write_bytes(b'old launcher')
            (base/'runtime/.manifest.json').write_bytes(b'old manifest')
            (base/'runtime/.owner.json').write_text(json.dumps({'schemaVersion':2,'owner':m.OWNER}))
            with patch.object(m,'ROOT',base),patch.object(m,'source_gate'),patch.object(m,'manifest',return_value={'previousRelease':{}}):
                with self.assertRaisesRegex(RuntimeError,'unknown_update_receipt'):m.update_launcher('a'*40)
            self.assertEqual((base/'cs2-play').read_bytes(),b'old launcher')
            self.assertFalse((base/'launcher-v1-recovery').exists())

    def test_unknown_existing_copy_target_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve(); (root/'src').write_bytes(b'new'); (root/'dst').write_bytes(b'old')
            with self.assertRaisesRegex(RuntimeError,'destination_collision'):m.copy_file(root/'src',root/'dst')
            self.assertEqual((root/'dst').read_bytes(),b'old')


class ControllerTests(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp).resolve();installed=base/'installed';source=base/'source'
            runtime=installed/'runtime';bus=runtime/m.WINEBUS
            bus.parent.mkdir(parents=True);source.joinpath('bin').mkdir(parents=True)
            source.joinpath('manifests').mkdir();candidate=base/'candidate';candidate.write_bytes(b'new SDL winebus');candidate.chmod(0o755)
            bus.write_bytes(b'original winebus');bus.chmod(0o755)
            (runtime/'unrelated.dll').write_bytes(b'graphics unchanged');(runtime/'unrelated.dll').chmod(0o644)
            for launcher in (installed/'cs2-play',source/'bin/cs2-play'):
                launcher.write_bytes(b'unchanged launcher');launcher.chmod(0o755)
            old={'schema':1,'id':'cs2-standalone','version':2,'owner':m.OWNER,
                 'expectedRuntimeTreeSha256':m.tree(runtime),'criticalHashes':{'unrelated.dll':m.sha(runtime/'unrelated.dll')}}
            oldraw=(json.dumps(old,indent=2)+'\n').encode()
            receipt={'schemaVersion':1,'owner':m.OWNER,'manifestSha256':m.data_sha(oldraw),
                     'runtimeTreeSha256':old['expectedRuntimeTreeSha256'],'criticalHashes':old['criticalHashes'],
                     'launcherSha256':m.sha(installed/'cs2-play')}
            rawreceipt=(json.dumps(receipt,indent=2)+'\n').encode()
            for name,raw in (('.manifest.json',oldraw),('.owner.json',rawreceipt)):
                (runtime/name).write_bytes(raw);(runtime/name).chmod(0o600)
            new=dict(old);new.update(version=3,source={'files':{'Sources/wine-source.tar.gz':'a'*64}},
                previousRelease={'manifestSha256':m.data_sha(oldraw),'ownerSha256':m.data_sha(rawreceipt),
                                 'launcherSha256':m.sha(installed/'cs2-play')})
            new['criticalHashes']=dict(old['criticalHashes']);new['criticalHashes'][m.WINEBUS]=m.sha(candidate)
            new['controllerUpdate']={'preparationOnly':False,'target':m.WINEBUS,
                'candidate':'~/AIDev/quarantine/cs2-controller-v3/winebus.so','candidateSha256':m.sha(candidate),
                'previousWinebusSha256':m.sha(bus),'previousRuntimeTreeSha256':old['expectedRuntimeTreeSha256'],
                'wineSourceSha256':'a'*64}
            new['expectedRuntimeTreeSha256']=m.tree(runtime,True,('.owner.json','.manifest.json'),{m.WINEBUS:m.sha(candidate)})
            (source/m.MANIFEST).write_text(json.dumps(new,indent=2)+'\n')
            with patch.object(m,'ROOT',installed),patch.object(m,'HERE',source),patch.object(m,'CONTROLLER_STAGE',candidate),\
                 patch.object(m,'source_gate') as gate,patch.object(m,'controller_source_unchanged'),\
                 patch.object(m,'verify_resolvers'),patch.object(m,'controller_inactive') as inactive:
                yield installed,source,candidate,new,gate,inactive

    def test_complete_update_noop_recovery_and_reapply(self):
        with self.fixture() as (root,source,candidate,new,gate,inactive):
            before=m.controller_snapshot(m.controller_paths())
            self.assertTrue(m.update_controller('a'*40)['changed']);m.verify(root)
            candidate.unlink()
            self.assertFalse(m.update_controller('a'*40)['changed'])
            self.assertTrue(m.recover_controller('a'*40)['changed'])
            self.assertEqual(m.controller_snapshot(m.controller_paths()),before)
            self.assertFalse(m.recover_controller('a'*40)['changed'])
            candidate.write_bytes(b'new SDL winebus');candidate.chmod(0o755)
            self.assertTrue(m.update_controller('a'*40)['changed']);m.verify(root)
            self.assertEqual(gate.call_count,5)

    def test_dry_run_writes_no_lock_or_backup(self):
        with self.fixture() as (root,*_):
            before=m.controller_snapshot(m.controller_paths())
            self.assertEqual(m.check_controller('a'*40)['status'],'CONTROLLER_UPDATE_READY')
            self.assertEqual(before,m.controller_snapshot(m.controller_paths()))
            self.assertFalse((root/'.launcher.lock').exists())
            self.assertFalse((root/'controller-v2-recovery').exists())

    def test_failure_after_each_replacement_recovers(self):
        for fail in (1,2,3):
            with self.subTest(fail=fail),self.fixture() as (root,*_):
                before=m.controller_snapshot(m.controller_paths());replace=m.controller_replace;calls=[]
                def faulty(*args):
                    replace(*args);calls.append(1)
                    if len(calls)==fail:raise OSError('injected interruption')
                with patch.object(m,'controller_replace',side_effect=faulty):
                    with self.assertRaises(OSError):m.update_controller('a'*40)
                self.assertTrue((root/'controller-v2-recovery').is_dir())
                self.assertTrue(m.recover_controller('a'*40)['changed'])
                self.assertEqual(before,m.controller_snapshot(m.controller_paths()))

    def test_failed_temporary_stage_write_requires_recognized_stage(self):
        with self.fixture() as (root,*_):
            replace=m.controller_replace
            def fail(target,data,mode):
                temp=target.with_name(target.name+'.controller-stage');temp.write_bytes(data);temp.chmod(0o600)
                raise OSError('before replacement')
            with patch.object(m,'controller_replace',side_effect=fail):
                with self.assertRaises(OSError):m.update_controller('a'*40)
            self.assertFalse(m.recover_controller('a'*40)['changed'])
            self.assertFalse((root/'runtime'/m.WINEBUS).with_name('winebus.so.controller-stage').exists())

    def test_unknown_temporary_stage_and_backup_preserved(self):
        for location in ('stage','backup'):
            with self.subTest(location=location),self.fixture() as (root,*_):
                before=m.controller_snapshot(m.controller_paths())
                path=(root/'runtime'/m.WINEBUS).with_name('winebus.so.controller-stage') if location=='stage' else root/'controller-v2-recovery'
                if location=='stage':path.write_bytes(b'unknown')
                else:path.mkdir();(path/'unknown').write_bytes(b'unknown')
                with self.assertRaises(RuntimeError):m.update_controller('a'*40)
                self.assertEqual(before,m.controller_snapshot(m.controller_paths()));self.assertTrue(path.exists())

    def test_active_session_preserves_runtime_and_creates_no_backup(self):
        with self.fixture() as (root,source,candidate,new,gate,inactive):
            before=m.controller_snapshot(m.controller_paths());inactive.side_effect=RuntimeError('controller_session_active')
            with self.assertRaisesRegex(RuntimeError,'controller_session_active'):m.update_controller('a'*40)
            self.assertEqual(before,m.controller_snapshot(m.controller_paths()));self.assertFalse((root/'controller-v2-recovery').exists())

    def test_wrong_target_tree_pin_blocks_before_backup(self):
        with self.fixture() as (root,source,candidate,new,*_):
            new['expectedRuntimeTreeSha256']='0'*64;(source/m.MANIFEST).write_text(json.dumps(new))
            with self.assertRaisesRegex(RuntimeError,'controller_target_tree_mismatch'):m.update_controller('a'*40)
            self.assertFalse((root/'controller-v2-recovery').exists())

    def test_candidate_drift_blocks_before_backup(self):
        with self.fixture() as (root,source,candidate,*_):
            candidate.write_bytes(b'unknown')
            with self.assertRaisesRegex(RuntimeError,'controller_candidate_drift'):m.update_controller('a'*40)
            self.assertFalse((root/'controller-v2-recovery').exists())

    def test_unrelated_runtime_drift_blocks_update_and_recovery(self):
        with self.fixture() as (root,*_):
            m.update_controller('a'*40);current=m.controller_snapshot(m.controller_paths())
            (root/'runtime/unrelated.dll').write_bytes(b'unknown graphics')
            with self.assertRaisesRegex(RuntimeError,'runtime_drift'):m.recover_controller('a'*40)
            self.assertEqual(current,m.controller_snapshot(m.controller_paths()))
            with self.assertRaisesRegex(RuntimeError,'runtime_drift'):m.update_controller('a'*40)

    def test_unknown_receipt_or_backup_drift_blocks(self):
        for location in ('live','backup'):
            with self.subTest(location=location),self.fixture() as (root,*_):
                if location=='backup':m.update_controller('a'*40)
                path=root/'controller-v2-recovery/owner.json' if location=='backup' else root/'runtime/.owner.json'
                value=json.loads(path.read_text());value['unknown']=True;path.write_text(json.dumps(value))
                operation=m.recover_controller if location=='backup' else m.update_controller
                with self.assertRaisesRegex(RuntimeError,'controller_receipt_drift'):operation('a'*40)

    def test_redirected_or_hardlinked_runtime_and_candidate_rejected(self):
        for name in ('winebus','candidate','launcher'):
            for kind in ('symlink','hardlink'):
                with self.subTest(name=name,kind=kind),self.fixture() as (root,source,candidate,*_):
                    path={'winebus':root/'runtime'/m.WINEBUS,'candidate':candidate,'launcher':root/'cs2-play'}[name]
                    saved=path.with_name(path.name+'.original');path.rename(saved)
                    if kind=='symlink':path.symlink_to(saved.name)
                    else:os.link(saved,path)
                    with self.assertRaises((OSError,RuntimeError)):m.update_controller('a'*40)
                    self.assertFalse((root/'controller-v2-recovery').exists())

    def test_source_gate_failure_never_writes(self):
        with self.fixture() as (root,source,candidate,new,gate,inactive):
            gate.side_effect=RuntimeError('fresh_accepted_doctor_required')
            with self.assertRaisesRegex(RuntimeError,'fresh_accepted_doctor_required'):m.update_controller('a'*40)
            self.assertFalse((root/'.launcher.lock').exists())

    def test_activity_probe_scrubbed_environment_timeout_and_failure(self):
        # Outside fixture's patched method, test the actual no-file-read subprocess seam.
        with patch.dict(os.environ,{'WINEPREFIX':'wrong','DYLD_INSERT_LIBRARIES':'bad'}):
            with patch.object(m.subprocess,'run',side_effect=subprocess.TimeoutExpired('wait',0.5)) as call:
                with self.assertRaisesRegex(RuntimeError,'controller_session_active'):m.controller_inactive()
                env=call.call_args.kwargs['env'];self.assertNotIn('DYLD_INSERT_LIBRARIES',env)
                self.assertEqual(env['WINEPREFIX'],str(m.ROOT/'prefix'));self.assertEqual(call.call_args.args[0][-1],'-w')
            with patch.object(m.subprocess,'run',return_value=subprocess.CompletedProcess([],1)):
                with self.assertRaisesRegex(RuntimeError,'controller_session_probe_failed'):m.controller_inactive()

    def test_busy_lock_blocks_update_and_dry_run_without_recovery(self):
        with self.fixture() as (root,*_):
            lock=m.controller_lock();before=m.controller_snapshot(m.controller_paths())
            try:
                for operation in (m.update_controller,m.check_controller):
                    with self.assertRaises(BlockingIOError):operation('a'*40)
            finally:os.close(lock)
            self.assertEqual(before,m.controller_snapshot(m.controller_paths()))
            self.assertFalse((root/'controller-v2-recovery').exists())

    def test_wrong_predecessor_mode_blocks_before_backup(self):
        with self.fixture() as (root,*_):
            (root/'runtime/.manifest.json').chmod(0o644)
            with self.assertRaisesRegex(RuntimeError,'controller_prestate_mode_drift'):m.update_controller('a'*40)
            self.assertFalse((root/'controller-v2-recovery').exists())

    def test_noop_rejects_reformatted_successor_receipt(self):
        with self.fixture() as (root,*_):
            m.update_controller('a'*40)
            path=root/'runtime/.owner.json';path.write_text(json.dumps(json.loads(path.read_text())))
            with self.assertRaisesRegex(RuntimeError,'controller_exact_receipt_drift'):m.update_controller('a'*40)

    def test_source_manifest_drift_after_probe_blocks_replacement(self):
        with self.fixture() as (root,source,candidate,new,gate,inactive):
            before=m.controller_snapshot(m.controller_paths())
            def changed():
                (source/m.MANIFEST).write_text(json.dumps(new))
            inactive.side_effect=changed
            with self.assertRaisesRegex(RuntimeError,'controller_source_manifest_changed'):m.update_controller('a'*40)
            self.assertEqual(before,m.controller_snapshot(m.controller_paths()))

    def test_unknown_partial_and_unknown_stage_block_recovery(self):
        for target in ('owner','stage'):
            with self.subTest(target=target),self.fixture() as (root,*_):
                m.update_controller('a'*40)
                path=root/'runtime/.owner.json' if target=='owner' else (root/'runtime'/m.WINEBUS).with_name('winebus.so.controller-stage')
                path.write_bytes(b'unknown');path.chmod(0o600)
                before=m.controller_snapshot(m.controller_paths())
                with self.assertRaisesRegex(RuntimeError,'controller_unknown'):m.recover_controller('a'*40)
                self.assertEqual(before,m.controller_snapshot(m.controller_paths()));self.assertEqual(path.read_bytes(),b'unknown')

    def test_preparation_and_invalid_types_block(self):
        for value in (True,0,None):
            with self.subTest(value=value),self.fixture() as (root,source,candidate,new,*_):
                new['controllerUpdate']['preparationOnly']=value;(source/m.MANIFEST).write_text(json.dumps(new))
                with self.assertRaisesRegex(RuntimeError,'controller_candidate_not_admitted'):m.update_controller('a'*40)
                self.assertFalse((root/'.launcher.lock').exists())

if __name__=='__main__':unittest.main()
