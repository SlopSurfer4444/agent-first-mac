"""Owned fixtures and mocked process seams only: no live Wine or profile read."""
import contextlib,hashlib,importlib.machinery,importlib.util,json,os,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
P=Path(__file__).resolve().parents[1]
def load(name):
    loader=importlib.machinery.SourceFileLoader(name.replace('-','_'),str(P/'bin'/name));spec=importlib.util.spec_from_loader(loader.name,loader);m=importlib.util.module_from_spec(spec);loader.exec_module(m);return m
h=load('game-launch-admission');games=load('games-play');ds3=load('ds3-runtime');cs2=load('cs2-play')
class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.home=Path(self.temp.name).resolve()
        (self.home/'AIDev/state').mkdir(parents=True,mode=0o700)
        self.request=h.Admission(self.home,'prince')
        self.patches=[patch.object(h.Admission,'start_watch'),patch.object(h.Admission,'processes',return_value=[])]
        for fixture_patch in self.patches:fixture_patch.start()
    def tearDown(self):
        for fixture_patch in reversed(self.patches):fixture_patch.stop()
        self.temp.cleanup()
    def test_duplicate_before_pid_publication_is_fail_closed(self):
        with self.request.locked(): self.request.begin()
        before=self.request.pending.read_bytes()
        with h.Admission(self.home,'cs2').locked() as other:
            with self.assertRaisesRegex(h.Blocked,'pending_launch_unconfirmed'):other.begin()
        self.assertEqual(self.request.pending.read_bytes(),before)
    def test_pending_alive_child_blocks_during_delayed_server_start(self):
        with self.request.locked():self.request.begin();self.request.dispatched([Mock(pid=123)])
        with patch.object(h.Admission,'active',return_value=False),patch.object(h.os,'kill') as kill:
            with self.assertRaisesRegex(h.Blocked,'launch_in_progress'):h.Admission(self.home,'ds3').begin()
        kill.assert_called_once_with(123,0)
    def test_active_helper_or_prewarm_server_does_not_release_pending(self):
        self.request.begin();self.request.dispatched([Mock(pid=123)])
        with patch.object(h.Admission,'active',return_value=True),patch.object(h.os,'kill'):
            with self.assertRaisesRegex(h.Blocked,'launch_in_progress'):h.Admission(self.home,'cs2').begin()
        self.assertTrue(self.request.pending.exists())
        with patch.object(h.Admission,'active',return_value=True),patch.object(h.os,'kill',side_effect=ProcessLookupError):
            with self.assertRaisesRegex(h.Blocked,'profile_active'):h.Admission(self.home,'cs2').begin()
        self.assertTrue(self.request.pending.exists())
    def test_stale_known_child_requires_all_prefixes_and_process_absence(self):
        self.request.begin();self.request.dispatched([Mock(pid=123)])
        with patch.object(h.os,'kill',side_effect=ProcessLookupError),patch.object(h.Admission,'active',return_value=False) as active,patch.object(h.subprocess,'run',return_value=Mock(returncode=0,stdout=b'/Applications/Steam.app/Contents/MacOS/steam_osx\n')):
            self.request.reconcile()
        self.assertEqual([c.args[0] for c in active.call_args_list],['prince','cs2','ds3','prince']);self.assertFalse(self.request.pending.exists())
    def test_unknown_request_explicit_recovery_refuses_running_wine(self):
        self.request.begin();before=self.request.pending.read_bytes()
        with patch.object(h.Admission,'active',return_value=False),patch.object(h.Admission,'processes',return_value=[(1,'/owned/engine/bin/wine')]):
            with self.assertRaisesRegex(h.Blocked,'pending_launch_unconfirmed'):self.request.recover()
        self.assertEqual(self.request.pending.read_bytes(),before)
    def test_unknown_recovery_blocks_preloader_and_arbitrary_windows_child(self):
        self.request.begin()
        for row in ('/runtime/wine64-preloader','/runtime/wine-preloader','[wine64]','(wine64-preloader)','[steam.exe]','/prefix/cs2.exe','/prefix/DarkSoulsIII.exe'):
            with self.subTest(row=row),patch.object(h.Admission,'active',return_value=False),patch.object(h.Admission,'processes',return_value=[(1,row)]):
                with self.assertRaisesRegex(h.Blocked,'pending_launch_unconfirmed'):self.request.recover()
            self.assertTrue(self.request.pending.exists())
    def test_explicit_recovery_safe_noop_after_success(self):
        self.request.begin()
        with patch.object(h.Admission,'active',return_value=False),patch.object(h.subprocess,'run',return_value=Mock(returncode=0,stdout=b'')):
            self.assertEqual(self.request.recover()['state'],'PENDING_LAUNCH_RECOVERED')
        self.assertEqual(self.request.recover()['state'],'NO_PENDING_LAUNCH')
    def test_recovery_does_not_clear_alive_child_or_active_other_prefix(self):
        self.request.begin();self.request.dispatched([Mock(pid=123)])
        with patch.object(h.os,'kill'):
            with self.assertRaisesRegex(h.Blocked,'launch_in_progress'):self.request.recover()
        with patch.object(h.os,'kill',side_effect=ProcessLookupError),patch.object(h.Admission,'active',side_effect=[False,True]):
            with self.assertRaisesRegex(h.Blocked,'profile_active'):self.request.recover()
        self.assertTrue(self.request.pending.exists())
    def test_pending_symlink_hardlink_invalid_json_and_pid_types_reject(self):
        target=self.home/'outside';target.write_bytes(b'keep')
        self.request.pending.symlink_to(target)
        with self.assertRaises(OSError):self.request.record()
        self.request.pending.unlink();os.link(target,self.request.pending)
        with self.assertRaisesRegex(h.Blocked,'unsafe_admission_file'):self.request.record()
        self.request.pending.unlink()
        for raw in (b'null',b'{"schema":1,"schema":1}',json.dumps({'schema':1,'route':'cs2','phase':'dispatched','children':[True],'request':'a'*32,'goal':'game'}).encode()):
            self.request.pending.write_bytes(raw)
            with self.assertRaises(h.Blocked):self.request.record()
        self.assertEqual(target.read_bytes(),b'keep')
    def test_same_shared_lock_conflicts_across_routes(self):
        with self.request.locked():
            with self.assertRaisesRegex(h.Blocked,'launcher_busy'):
                with h.Admission(self.home,'ds3').locked():pass
    def test_observer_confirms_exact_target_and_allows_later_relaunch(self):
        self.request.begin();self.request.dispatched([Mock(pid=123)])
        token=self.request.record()['request']
        with patch.object(h.Admission,'summary',return_value={'targetActive':True}) as summary:
            self.request.watch(token)
        summary.assert_called_once_with('prince',goal='client');self.assertEqual(self.request.record()['phase'],'confirmed')
        self.request.reconcile();self.assertFalse(self.request.pending.exists())
        self.request.begin();self.assertNotEqual(self.request.record()['request'],token)
    def test_cs2_steam_milestone_then_play_with_owned_client_open(self):
        steam_request=h.Admission(self.home,'cs2','client');steam_request.begin();steam_request.dispatched([Mock(pid=123)])
        client,target=steam_request.paths()
        with patch.object(h.Admission,'processes',return_value=[(1,str(client))]):steam_request.watch(steam_request.record()['request'])
        self.assertEqual(steam_request.record()['phase'],'confirmed');self.assertEqual(steam_request.record()['goal'],'client')
        play_request=h.Admission(self.home,'cs2','game')
        with patch.object(h.Admission,'processes',return_value=[(1,str(client))]):
            play_request.reconcile();summary=play_request.allow_client();play_request.begin()
        self.assertTrue(summary['clientActive']);self.assertFalse(summary['targetActive']);self.assertEqual(play_request.record()['goal'],'game')
    def test_observer_timeout_or_old_request_never_erases_uncertainty(self):
        self.request.begin();self.request.dispatched([Mock(pid=123)])
        value=self.request.record()
        with patch.object(h.time,'monotonic',side_effect=[0,200]):self.request.watch(value['request'])
        self.assertEqual(self.request.record(),value)
        self.request.watch('f'*32);self.assertEqual(self.request.record(),value)
    def test_observer_dispatch_uses_verified_source_bytes_and_clean_environment(self):
        self.patches[0].stop()
        raw=(P/'bin/game-launch-admission').read_bytes()
        with patch.dict(h.__dict__,{'__admission_source':raw}),patch.dict(os.environ,{'PRIVATE_TOKEN':'private'}),patch.object(h.subprocess,'Popen') as spawn:
            self.request.start_watch('a'*32)
        command=spawn.call_args.args[0];self.assertEqual(command[:3],['/usr/bin/python3','-I','-c']);self.assertEqual(command[3].encode(),raw)
        self.assertEqual(command[4:],['watch','a'*32]);self.assertNotIn('PRIVATE_TOKEN',spawn.call_args.kwargs['env'])
        self.patches[0].start()
    def test_pinned_helper_loader_uses_exact_fixture_bytes(self):
        dest=self.home/'AIDev/bin/game-launch-admission';dest.parent.mkdir();dest.write_bytes((P/'bin/game-launch-admission').read_bytes());dest.chmod(0o600)
        for module in (games,ds3,cs2):self.assertEqual(module.admission(self.home,'cs2').route,'cs2')
        dest.write_bytes(dest.read_bytes()+b'\n# drift\n')
        for module in (games,ds3,cs2):
            with self.assertRaisesRegex(RuntimeError,'admission_helper_changed'):module.admission(self.home,'cs2')
    def test_games_route_reserves_before_dispatch_and_records_exact_child(self):
        runtime=self.home/'runtime';engine=runtime/'engine';prefix=self.home/'profile'
        executable=prefix/'drive_c/Program Files (x86)/Steam/steam.exe';executable.parent.mkdir(parents=True);executable.write_bytes(b'fixture pe')
        logs=self.home/'hub/logs';logs.mkdir(parents=True)
        request=Mock();events=[]
        request.begin.side_effect=lambda:events.append('reserve')
        request.dispatched.side_effect=lambda children:events.append(('record',[x.pid for x in children]))
        def spawn(*args,**kwargs):events.append('dispatch');return Mock(pid=42)
        with patch.object(games,'ROOT',logs.parent),patch.object(games,'HOME',self.home),patch.object(games,'validate',return_value=(runtime,prefix,engine)),patch.object(games,'inactive'),patch.object(games,'no_foreign_steam'),patch.object(games.subprocess,'Popen',side_effect=spawn):
            result=games.launch('steam',request)
        self.assertEqual(events,['reserve','dispatch',('record',[42])]);self.assertFalse(result['gameplayVerified'])
    def test_cs2_route_preserves_exact_owned_symlink_resolver(self):
        target=self.home/'Library/Application Support/CS2 Standalone/cs2-play';target.parent.mkdir(parents=True)
        target.write_bytes(b'fixture launcher');target.chmod(0o700)
        (target.parent/'runtime').mkdir();(target.parent/'runtime/.owner.json').write_text(json.dumps({'schemaVersion':1,'owner':'control-cs2-standalone','launcherSha256':hashlib.sha256(target.read_bytes()).hexdigest()}))
        resolver=self.home/'AIDev/bin/cs2-play';resolver.parent.mkdir();resolver.symlink_to(target)
        with patch.object(games,'HOME',self.home),patch.object(games.sys,'argv',['games-play','cs2']),patch.object(games.os,'execve',side_effect=SystemExit(0)) as dispatch:
            with self.assertRaises(SystemExit):games.main()
        self.assertEqual(dispatch.call_args.args[0],str(target));self.assertEqual(dispatch.call_args.args[1],[str(target),'play'])
        resolver.unlink();resolver.symlink_to(self.home/'foreign')
        with patch.object(games,'HOME',self.home),patch.object(games.sys,'argv',['games-play','cs2']),patch.object(games.os,'execve') as dispatch:
            with self.assertRaisesRegex(RuntimeError,'cs2_resolver_drift'):games.main()
        dispatch.assert_not_called()
    def test_dispatch_failure_keeps_unknown_reservation_and_does_not_kill(self):
        self.request.begin()
        # A caller can fail or crash between reservation and recording child PID.
        with patch.object(h.Admission,'active') as active:
            with self.assertRaisesRegex(h.Blocked,'pending_launch_unconfirmed'):self.request.begin()
        active.assert_not_called();self.assertEqual(self.request.record()['phase'],'prepared')
class HubValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.home=Path(self.temp.name).resolve();self.root=self.home/'hub'
        for name in ('runtime/engine/bin','runtime/engine/lib/wine','runtime/Frameworks','profiles/prince','logs'):
            (self.root/name).mkdir(parents=True,mode=0o700,exist_ok=True)
        hashes={}
        for name in games.MIN_CRITICAL:
            path=self.root/'runtime'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(('fixture '+name).encode());path.chmod(0o700);hashes[name]=hashlib.sha256(path.read_bytes()).hexdigest()
        self.manifest={'schema':1,'id':'games-hub','owner':games.OWNER,'criticalHashes':hashes}
        self.write_manifest();(self.root/'games-play').write_bytes(b'fixture launcher')
        self.receipt={'schema':1,'owner':games.OWNER,'manifestSha256':hashlib.sha256((self.root/'manifest.json').read_bytes()).hexdigest(),'launcherSha256':hashlib.sha256((self.root/'games-play').read_bytes()).hexdigest()}
        self.write_receipt();self.patch=patch.object(games,'ROOT',self.root);self.patch.start()
    def tearDown(self):self.patch.stop();self.temp.cleanup()
    def write_manifest(self):(self.root/'manifest.json').write_text(json.dumps(self.manifest))
    def write_receipt(self):(self.root/'receipt.json').write_text(json.dumps(self.receipt))
    def test_exact_owner_manifest_self_and_controller_hashes_are_required(self):
        games.validate();self.receipt['owner']='other';self.write_receipt()
        with self.assertRaisesRegex(RuntimeError,'hub_owner_mismatch'):games.validate()
        self.receipt['owner']=games.OWNER;self.write_receipt();(self.root/'games-play').write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError,'launcher_changed'):games.validate()
    def test_critical_parent_escape_and_profile_symlink_are_rejected(self):
        self.manifest['criticalHashes']['engine/../../outside']='a'*64;self.write_manifest()
        self.receipt['manifestSha256']=hashlib.sha256((self.root/'manifest.json').read_bytes()).hexdigest();self.write_receipt()
        with self.assertRaisesRegex(RuntimeError,'invalid_runtime_hashes'):games.validate()
        del self.manifest['criticalHashes']['engine/../../outside'];self.write_manifest();self.receipt['manifestSha256']=hashlib.sha256((self.root/'manifest.json').read_bytes()).hexdigest();self.write_receipt()
        prefix=self.root/'profiles/prince';prefix.rmdir();prefix.symlink_to(self.root/'logs')
        with self.assertRaisesRegex(RuntimeError,'unsafe_directory'):games.validate()

class ExactIdentityTests(unittest.TestCase):
    def test_owned_steam_is_admitted_but_sibling_argument_and_bare_identity_block(self):
        request=h.Admission(Path('/fixture'),'cs2');client,target=request.paths()
        exact=[(1,str(client))]
        summary=request.summary(processes=exact);self.assertTrue(summary['clientActive']);self.assertFalse(summary['foreignSteam'])
        for path in (str(client).replace('/prefix/','/prefix-foreign/'),'steam.exe','[steam.exe]','/foreign/steam.exe'):
            summary=request.summary(processes=[(2,path)]);self.assertTrue(summary['foreignSteam']);self.assertFalse(summary['clientActive'])
        summary=request.summary(processes=[(3,'/foreign/steam.exe --log '+str(client))]);self.assertFalse(summary['clientActive'])
    def test_native_mac_steam_is_not_windows_session(self):
        request=h.Admission(Path('/fixture'),'cs2')
        self.assertFalse(request.summary(processes=[(1,'/Applications/Steam.app/Contents/MacOS/steam_osx')])['foreignSteam'])
    def test_prince_connect_can_activate_with_owned_same_prefix_steam(self):
        request=h.Admission(Path('/fixture'),'prince');steam,_=request.paths('steam')
        with patch.object(h.Admission,'processes',return_value=[(1,str(steam))]),patch.object(h.Admission,'active') as active:
            summary=request.allow_client()
        self.assertTrue(summary['steamActive']);self.assertFalse(summary['foreignSteam']);active.assert_not_called()
    def test_exact_target_and_comm_parser_require_unambiguous_pid_paths(self):
        request=h.Admission(Path('/fixture'),'cs2');client,target=request.paths()
        rows=(' 1 '+str(client)+'\n 2 '+str(target)+'\n').encode()
        with patch.object(h.subprocess,'run',return_value=Mock(returncode=0,stdout=rows)) as run:
            summary=request.summary()
        self.assertTrue(summary['targetActive']);self.assertEqual(run.call_args.args[0][-1],'pid=,comm=')
        for raw in (b'unknown',b' 1 /first\n 1 /second\n',b' 0 /bad\n'):
            with patch.object(h.subprocess,'run',return_value=Mock(returncode=0,stdout=raw)):
                with self.assertRaisesRegex(h.Blocked,'process_identity_unavailable'):request.processes()
if __name__=='__main__':unittest.main()
