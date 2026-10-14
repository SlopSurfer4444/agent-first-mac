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
        self.identity=lambda pid:{'pid':pid,'birth':'100:1','group':pid}
        self.patches=[patch.object(h.Admission,'start_watch'),patch.object(h.Admission,'processes',return_value=[]),
                      patch.object(h.Admission,'process_groups',return_value=[]),patch.object(h,'boot_identity',return_value='b'*64),
                      patch.object(h,'process_identity',side_effect=self.identity)]
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
        with patch.object(h.Admission,'active',return_value=False),patch.object(h,'process_identity',side_effect=lambda pid:self.identity(pid) if pid==123 else None):
            with self.assertRaisesRegex(h.Blocked,'launch_in_progress'):h.Admission(self.home,'ds3').begin()
    def test_active_helper_or_prewarm_server_does_not_release_pending(self):
        self.request.begin();self.request.dispatched([Mock(pid=123)])
        with patch.object(h.Admission,'active',return_value=True),patch.object(h,'process_identity',side_effect=lambda pid:self.identity(pid) if pid==123 else None):
            with self.assertRaisesRegex(h.Blocked,'launch_in_progress'):h.Admission(self.home,'cs2').begin()
        self.assertTrue(self.request.pending.exists())
        with patch.object(h.Admission,'active',return_value=True),patch.object(h,'process_identity',return_value=None):
            with self.assertRaisesRegex(h.Blocked,'profile_active'):h.Admission(self.home,'cs2').begin()
        self.assertTrue(self.request.pending.exists())
    def test_stale_known_child_requires_reserved_prefix_and_descendant_absence(self):
        self.request.begin();self.request.dispatched([Mock(pid=123)])
        with patch.object(h,'process_identity',return_value=None),patch.object(h.Admission,'active',return_value=False) as active:
            self.request.reconcile()
        self.assertEqual([c.args[0] for c in active.call_args_list],['prince']);self.assertFalse(self.request.pending.exists())
    def test_unknown_request_explicit_recovery_refuses_running_wine(self):
        self.request.begin();before=self.request.pending.read_bytes()
        runtime=self.home/'Library/Application Support/Adapted Games/runtime/engine/bin/wine'
        with patch.object(h,'process_identity',return_value=None),patch.object(h.Admission,'active',return_value=False),patch.object(h.Admission,'process_groups',return_value=[(1,0,1,str(runtime))]):
            with self.assertRaisesRegex(h.Blocked,'pending_launch_unconfirmed'):self.request.recover()
        self.assertEqual(self.request.pending.read_bytes(),before)
    def test_unknown_recovery_blocks_preloader_and_arbitrary_windows_child(self):
        self.request.begin()
        client,_=self.request.paths()
        for row in ('[wine64]','(wine64-preloader)','[steam.exe]',str(client.parent/'unknown.exe')):
            with self.subTest(row=row),patch.object(h,'process_identity',return_value=None),patch.object(h.Admission,'active',return_value=False),patch.object(h.Admission,'process_groups',return_value=[(1,0,1,row)]):
                with self.assertRaisesRegex(h.Blocked,'pending_launch_unconfirmed'):self.request.recover()
            self.assertTrue(self.request.pending.exists())
    def test_explicit_recovery_safe_noop_after_success(self):
        self.request.begin()
        with patch.object(h,'process_identity',return_value=None),patch.object(h.Admission,'active',return_value=False):
            self.assertEqual(self.request.recover()['state'],'PENDING_LAUNCH_RECOVERED')
        self.assertEqual(self.request.recover()['state'],'NO_PENDING_LAUNCH')
    def test_recovery_does_not_clear_alive_child_or_active_target_prefix(self):
        self.request.begin();self.request.dispatched([Mock(pid=123)])
        with patch.object(h,'process_identity',side_effect=lambda pid:self.identity(pid) if pid==123 else None):
            with self.assertRaisesRegex(h.Blocked,'launch_in_progress'):self.request.recover()
        with patch.object(h,'process_identity',return_value=None),patch.object(h.Admission,'active',return_value=True):
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
        summary.assert_called_once_with('prince',processes=[],goal='client');self.assertEqual(self.request.record()['phase'],'confirmed')
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
    def test_reused_pid_and_new_group_are_not_old_launch_ownership(self):
        self.request.begin();self.request.dispatched([Mock(pid=123)])
        reused={'pid':123,'birth':'101:2','group':123}
        with patch.object(h,'process_identity',side_effect=lambda pid:reused if pid==123 else None),patch.object(h.Admission,'active',return_value=False),patch.object(h.Admission,'process_groups',return_value=[(123,1,123,'/Applications/Unrelated.app/tool')]):
            self.assertEqual(self.request.recover()['state'],'PENDING_LAUNCH_RECOVERED')
    def test_reboot_does_not_bind_new_same_pid_but_target_still_blocks(self):
        self.request.begin();self.request.dispatched([Mock(pid=123)])
        with patch.object(h,'boot_identity',return_value='c'*64),patch.object(h,'process_identity') as identity,patch.object(h.Admission,'active',return_value=True):
            with self.assertRaisesRegex(h.Blocked,'profile_active'):self.request.recover()
        identity.assert_not_called()
        with patch.object(h,'boot_identity',return_value='c'*64),patch.object(h.Admission,'active',return_value=False),patch.object(h.Admission,'process_groups',return_value=[(123,1,123,'/unrelated/tool.exe')]):
            self.request.recover()
    def test_dispatcher_and_orphaned_group_descendant_are_protected(self):
        self.request.begin()
        with self.assertRaisesRegex(h.Blocked,'launch_dispatcher_active'):self.request.recover()
        self.request.dispatched([Mock(pid=123)])
        with patch.object(h,'process_identity',return_value=None),patch.object(h.Admission,'active',return_value=False),patch.object(h.Admission,'process_groups',return_value=[(456,1,123,'/unknown/native-child')]):
            with self.assertRaisesRegex(h.Blocked,'launch_descendant_active'):self.request.recover()
    def test_scoped_recovery_ignores_unrelated_full_path_wine_app_and_other_retired_route(self):
        self.request.begin()
        def target_only(route):
            self.assertEqual(route,'prince');return False
        with patch.object(h,'process_identity',return_value=None),patch.object(h.Admission,'active',side_effect=target_only),patch.object(h.Admission,'process_groups',return_value=[(88,1,88,'/independent/prefix/tool.exe'),(89,1,88,'/independent/runtime/engine/bin/wine')]):
            self.request.recover()
    def test_absent_route_has_no_server_probe_but_dangling_resolver_is_unknown(self):
        with patch.object(h.subprocess,'run',side_effect=AssertionError('no external process')):
            self.assertFalse(self.request.active('ds3'))
            resolver=self.home/'AIDev/bin/ds3-play';resolver.parent.mkdir();resolver.symlink_to('/absent/old/ds3-play')
            with self.assertRaisesRegex(h.Blocked,'absent_route_has_resolver'):self.request.active('ds3')
    def test_retired_route_metadata_is_explicit_and_unknown_archive_drift_blocks(self):
        base=self.home/'Library/Application Support';namespace=base/'.Adapted Games DS3.lifecycle';namespace.mkdir(parents=True,mode=0o700)
        archive=base/'Adapted Games DS3 retired aaaaaaaaaaaa';archive.mkdir(mode=0o700);facts=archive.lstat()
        value={'schema':1,'owner':'control-ds3-marshal-fix','state':'complete','operation':'retire','direction':'forward','commit':'a'*40,
               'binding':{'archive':str(archive),'rootIdentity':{'dev':facts.st_dev,'ino':facts.st_ino,'mode':0o700,'kind':'directory'}},'steps':[],'active':None,
               'directoryIdentity':{'dev':namespace.stat().st_dev,'ino':namespace.stat().st_ino,'mode':0o700,'kind':'directory'}}
        (namespace/'journal.json').write_text(json.dumps(value))
        self.assertEqual(self.request.route_status('ds3'),'RETIRED');self.assertFalse(self.request.active('ds3'))
        archive.chmod(0o750)
        with self.assertRaisesRegex(h.Blocked,'retired_route_archive_drift'):self.request.active('ds3')
    def test_malformed_or_completed_install_journal_cannot_turn_unknown_into_absence(self):
        base=self.home/'Library/Application Support';namespace=base/'.Adapted Games DS3.lifecycle';namespace.mkdir(parents=True,mode=0o700)
        value={'schema':1,'owner':'control-ds3-marshal-fix','state':'complete','operation':'install','direction':'forward','commit':'a'*40,
               'binding':{},'steps':[],'active':None,'directoryIdentity':{}}
        for operation in ('install',['malformed'],None):
            value['operation']=operation;(namespace/'journal.json').write_text(json.dumps(value))
            with self.assertRaisesRegex(h.Blocked,'route_recovery_required'):self.request.route_status('ds3')
    def test_observer_recomputes_remaining_after_lock_and_record_cost(self):
        self.request.begin();self.request.dispatched([Mock(pid=123)])
        value=self.request.record();clock=[0.0];observations=[]
        def record():clock[0]+=1.9;return value
        def processes(timeout=5):observations.append(timeout);clock[0]+=timeout;return []
        with patch.object(h.time,'monotonic',side_effect=lambda:clock[0]),patch.object(h.Admission,'record',side_effect=record),patch.object(h.Admission,'processes',side_effect=processes):
            self.request.watch(value['request'],timeout=2)
        self.assertEqual(len(observations),1);self.assertAlmostEqual(observations[0],0.1);self.assertAlmostEqual(clock[0],2)
    def test_child_and_watch_observation_cannot_overwrite_a_changed_request(self):
        self.request.begin();original=self.request.record()
        changed=dict(original,request='c'*32)
        def identity(pid):self.request.pending.write_text(json.dumps(changed));return self.identity(pid)
        with patch.object(h,'process_identity',side_effect=identity):
            with self.assertRaisesRegex(h.Blocked,'admission_request_changed'):self.request.dispatched([Mock(pid=123)])
        self.assertEqual(self.request.record(),changed)
        self.request.pending.write_text(json.dumps(original));self.request.dispatched([Mock(pid=123)])
        watched=self.request.record();changed=dict(watched,request='c'*32)
        def observed(timeout=5):self.request.pending.write_text(json.dumps(changed));return [(88,str(self.request.paths()[0]))]
        with patch.object(h.Admission,'processes',side_effect=observed):self.request.watch(watched['request'])
        self.assertEqual(self.request.record(),changed)
    def test_old_schema1_never_manufactures_incarnation_and_retains_conservative_recovery(self):
        self.request.publish({'schema':1,'route':'prince','phase':'prepared','children':[],'request':'a'*32,'goal':'client'})
        with patch.object(h.Admission,'active',return_value=False),patch.object(h.Admission,'process_groups',return_value=[(88,1,88,'/independent/tool.exe')]):
            with self.assertRaisesRegex(h.Blocked,'pending_launch_unconfirmed'):self.request.recover()
        self.assertEqual(self.request.record()['schema'],1)
    def test_missing_child_birth_does_not_publish_fake_dispatch_or_retry(self):
        self.request.begin();before=self.request.pending.read_bytes()
        with patch.object(h,'process_identity',return_value=None):
            with self.assertRaisesRegex(h.Blocked,'process_incarnation_unavailable'):self.request.dispatched([Mock(pid=123)])
        self.assertEqual(self.request.pending.read_bytes(),before)
    def test_observer_backoff_samples_and_deadline_are_bounded(self):
        self.request.begin();self.request.dispatched([Mock(pid=123)])
        clock=[0.0];sleeps=[];observations=[]
        def sleep(seconds):sleeps.append(seconds);clock[0]+=seconds
        def observe(timeout=5):observations.append(timeout);clock[0]+=min(0.002,timeout);return []
        with patch.object(h.time,'monotonic',side_effect=lambda:clock[0]),patch.object(h.time,'sleep',side_effect=sleep),patch.object(h.Admission,'processes',side_effect=observe):
            self.request.watch(self.request.record()['request'])
        self.assertLessEqual(len(observations),100);self.assertLessEqual(clock[0],190.002)
        self.assertGreater(max(sleeps),0.25);self.assertLess(observations[-1],0.011)
        self.assertEqual(self.request.record()['phase'],'dispatched')
    def test_observer_early_milestone_and_timeout_keep_truthful_state(self):
        self.request.begin();self.request.dispatched([Mock(pid=123)])
        client,_=self.request.paths()
        with patch.object(h.Admission,'processes',return_value=[(7,str(client))]):self.request.watch(self.request.record()['request'])
        self.assertEqual(self.request.record()['phase'],'confirmed')
        self.request.reconcile();self.request.begin();self.request.dispatched([Mock(pid=123)])
        before=self.request.record()
        with patch.object(h.Admission,'processes',side_effect=subprocess.TimeoutExpired('ps',1)):self.request.watch(before['request'])
        self.assertEqual(self.request.record(),before)
    def test_schema2_birth_boot_group_types_reject_without_mutation(self):
        self.request.begin();good=self.request.record()
        for changes in ({'boot':None},{'dispatcher':{'pid':True,'birth':'100:1','group':3}},{'dispatcher':{'pid':3,'birth':'unknown','group':3}}):
            raw=dict(good,**changes);self.request.pending.write_text(json.dumps(raw))
            with self.assertRaisesRegex(h.Blocked,'invalid_admission_record'):self.request.record()
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

class NativeIncarnationTests(unittest.TestCase):
    def test_darwin_birth_and_boot_queries_use_fixed_bounded_abi_not_argv(self):
        def proc(pid,flavor,arg,out,size):
            self.assertEqual((pid,flavor,arg,size),(123,3,0,136))
            value=out._obj;value.pid=pid;value.uid=os.getuid();value.pgid=pid;value.seconds=100;value.micros=7
            return size
        library=Mock(proc_pidinfo=Mock(side_effect=proc))
        with patch.object(h.ctypes,'CDLL',return_value=library):
            self.assertEqual(h.process_identity(123),{'pid':123,'birth':'100:7','group':123})
        def boot(name,out,size,unused,length):
            self.assertEqual(name,b'kern.boottime');self.assertEqual(size._obj.value,16)
            out._obj.seconds=100;out._obj.micros=7;return 0
        with patch.object(h.ctypes,'CDLL',return_value=Mock(sysctlbyname=Mock(side_effect=boot))):
            self.assertEqual(h.boot_identity(),hashlib.sha256(b'100:7').hexdigest())
    def test_native_absence_is_distinct_from_short_or_permission_unknown(self):
        with patch.object(h.ctypes,'CDLL',return_value=Mock(proc_pidinfo=Mock(return_value=0))),patch.object(h.ctypes,'get_errno',return_value=h.errno.ESRCH):
            self.assertIsNone(h.process_identity(123))
        with patch.object(h.ctypes,'CDLL',return_value=Mock(proc_pidinfo=Mock(return_value=1))):
            with self.assertRaisesRegex(h.Blocked,'process_incarnation_unavailable'):h.process_identity(123)
if __name__=='__main__':unittest.main()
