"""Complete private admission transitions, owned files and fake kernel/probe only."""
import copy
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import tempfile
import shutil
import stat
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[1]
loader=importlib.machinery.SourceFileLoader('native_admission_candidate',str(ROOT/'bin/game-launch-admission'))
spec=importlib.util.spec_from_loader(loader.name,loader);h=importlib.util.module_from_spec(spec);loader.exec_module(h)

class NativeAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.home=Path(self.temp.name).resolve()
        (self.home/'AIDev/state').mkdir(parents=True,mode=0o700)
        self.request=h.Admission(self.home,'ds3')
        self.client,self.target=self.request.paths();self.prefix=self.target.parents[7]
        # Derive the fixed route directly; no installed user profile is read.
        self.prefix=self.home/'Library/Application Support/Adapted Games DS3/profiles/ds3'
        self.ntdll=self.prefix.parent.parent/'runtime/engine/lib/wine/x86_64-unix/ntdll.so'
        self.server=self.prefix.parent.parent/'runtime/engine/bin/wineserver'
        self.app=self.home/'Owned DS3.app';self.loader=self.app/'Contents/MacOS/wine';self.plist=self.app/'Contents/Info.plist'
        for p in (self.target,self.ntdll,self.loader,self.server):p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'fixture')
        pe=bytearray(256);pe[:2]=b'MZ';pe[60:64]=(128).to_bytes(4,'little');pe[128:134]=b'PE\0\0\x64\x86';pe[150:152]=(2).to_bytes(2,'little');self.target.write_bytes(pe)
        self.plist.write_bytes(plistlib.dumps({'CFBundleIdentifier':'local.wave7.ds3.admission','CFBundleExecutable':'wine','CFBundlePackageType':'APPL'}))
        self.routes=self.prefix/'native-applications.routes'
        self.approval_path=self.home/'AIDev/state/ds3-native-launch-approval.json'
        self.rows=[];self.server_visible=True
        self.expected_game_birth='101:1'
        self.alive={os.getpid():self.identity(os.getpid()),100:self.identity(100),101:self.identity(101),300:self.identity(300)}
        self.patches=[patch.object(h,'process_identity',side_effect=lambda pid:self.alive.get(pid)),patch.object(h,'boot_identity',return_value='b'*64),
            patch.object(h.Admission,'start_watch'),patch.object(h.Admission,'processes',side_effect=lambda **kw:list(self.rows)+([(300,str(self.server))] if self.server_visible else [])),
            patch.object(h.Admission,'process_groups',return_value=[]),patch.object(h.Admission,'active',return_value=False)]
        for p in self.patches:p.start()
        lib=self.home/h.NATIVE_COMPANION.parent.parent
        shutil.copytree(ROOT/'lib/game_launch_native/binding',lib/'binding');shutil.copytree(ROOT/'lib/game_launch_native/native-identity',lib/'native-identity')
        # Frozen native outputs remain external to Git. Canonical checks may use
        # the installed owned closure or an explicit private frozen test input.
        import pwd
        installed=Path(pwd.getpwuid(os.getuid()).pw_dir)/'AIDev/lib/game-launch-admission/native-identity'
        default=installed if installed.is_dir() else ROOT.parent/'native-admission-payload-v2/companions/native-identity'
        assets=Path(os.environ.get('NATIVE_ADMISSION_TEST_ASSET_DIR',str(default)))
        for name in ('probe','prefix_probe'):shutil.copyfile(assets/name,lib/'native-identity'/name)
        self.real_native_module=h.native_module
        self.native=h.native_module(self.home)
        self.module_patch=patch.object(h,'native_module',return_value=self.native);self.module_patch.start()
        class Unknown(RuntimeError):pass
        self.Unknown=Unknown
        self.inspect=Mock(side_effect=self.observed)
        self.connection=Mock(side_effect=self.connected)
        self.real_identity_module=self.native['identity_module']
        self.native['identity_module']=lambda prefix=False:({'inspect_prefix_connection':self.connection,'Unknown':self.Unknown} if prefix else {'inspect_mapped':self.inspect,'Unknown':self.Unknown})
        self.native['server_directory']=self.directory_facts
        self.approval={'schema':2,'owner':'control-ds3-native-launch','route':'ds3','prefix':str(self.prefix),
            'image':self.native['IMAGE'],'machine':0x8664,'target':str(self.target),'loader':str(self.loader),
            'bundleIdentifier':'local.wave7.ds3.admission',
            'files':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (self.target,self.loader,self.plist,self.ntdll,self.server)}}
        self.enable()
    def tearDown(self):
        self.module_patch.stop()
        for p in reversed(self.patches):p.stop()
        self.temp.cleanup()
    def identity(self,pid,birth=None):return {'pid':pid,'birth':birth or str(pid)+':1','group':pid if pid!=101 else 100}
    def enable(self):
        self.routes.write_text('WINE-NATIVE-APPLICATIONS\t1\n8664\t'+self.native['IMAGE']+'\t'+str(self.loader)+'\n')
        self.approval_path.write_text(json.dumps(self.approval))
    def dispatch(self):
        with self.request.locked():self.request.begin();self.request.dispatched([Mock(pid=100)])
        return self.request.record()
    def observed(self,pid,birth,loader,target,timeout):
        self.assertEqual((pid,birth,loader,target),(101,self.expected_game_birth,str(self.loader),str(self.target)))
        self.assertLessEqual(timeout,2.5)
        return {'state':'MATCH_IMAGE','pid':pid,'birth':birth,'mappedExecutable':True,'ancestryStable':True,
            'ancestry':[{'pid':pid,'birth':birth,'ppid':1,'group':pid}],
            'targetDev':self.target.stat().st_dev&0xffffffff,'targetIno':self.target.stat().st_ino}
    def directory_facts(self,binding):
        p=Path('/tmp').resolve()/('.wine-'+str(os.getuid()))/('server-%x-%x'%(binding['prefixIdentity']['st_dev'],binding['prefixIdentity']['st_ino']))
        return {'path':str(p),'dev':self.prefix.stat().st_dev,'ino':333,'mode':stat.S_IFDIR|0o700,'uid':os.getuid()}
    def connected(self,game,owner,server,prefix,loader,server_executable,timeout):
        self.assertEqual((owner,server,prefix,loader,server_executable),(self.identity(100),self.identity(300),str(self.prefix),str(self.loader),str(self.server)))
        self.assertLessEqual(timeout,3.5)
        return {'state':'PREFIX_CONNECTION_OBSERVED','stable':True,'complete':True,'serverScopeBefore':True,'serverScopeAfter':True,
            'gameEdgesBefore':1,'gameEdgesAfter':1,'steamEdgesBefore':1,'steamEdgesAfter':1,
            'roles':[dict(i,role=n,zeroHandlesBefore=0,zeroHandlesAfter=0) for i,n in zip((game,owner,server),('game','steam','server'))]}
    def confirm(self):
        value=self.dispatch();self.rows=[(100,str(self.client)),(101,str(self.loader))]
        self.request.watch(value['request'],timeout=1)
        result=self.request.record();self.assertEqual(result['phase'],'confirmed');return result
    def test_native_watcher_records_actual_bound_milestone(self):
        result=self.confirm()
        self.assertEqual(result['schema'],4)
        self.assertEqual(result['targetObservation']['identity'],self.identity(101))
        self.assertEqual(result['targetObservation']['owner'],self.identity(100))
        self.assertEqual(self.inspect.call_count,2)
    def test_same_steam_second_launch_after_first_game_exit(self):
        old=self.confirm();self.alive.pop(101);self.rows=[(100,str(self.client))]
        self.alive[200]=self.identity(200)
        with self.request.locked():
            summary=self.request.allow_client();self.request.begin();self.request.dispatched([Mock(pid=200)])
        new=self.request.record();self.assertTrue(summary['clientActive']);self.assertEqual(new['phase'],'dispatched')
        self.assertNotEqual(new['request'],old['request']);self.assertEqual(new['children'],[self.identity(200)])
        self.assertEqual(new['nativeOwner'],self.identity(100))
        self.alive[101]=self.identity(101,'202:1');self.rows.append((101,self.native['IMAGE']))
        self.expected_game_birth='202:1'
        self.request.watch(new['request'],timeout=1)
        self.assertEqual(self.request.record()['phase'],'confirmed')
        self.assertEqual(self.request.record()['targetObservation']['owner'],self.identity(100))
    def test_confirmed_target_still_alive_blocks_even_if_comm_disappears(self):
        self.confirm();self.rows=[(100,str(self.client))]
        with self.request.locked(),self.assertRaisesRegex(h.Blocked,'game_active'):self.request.begin()
        self.assertEqual(self.request.record()['phase'],'confirmed')
    def recorded_previous_device(self):
        value=self.confirm()
        # Simulate a retained APFS record whose device number differs after
        # reboot; inode, approved bytes and persisted proof remain unchanged.
        binding=value['nativeBinding'];binding['prefixIdentity']['st_dev']+=2
        for facts in binding['files'].values():facts['st_dev']+=2
        proof=value['targetObservation'];proof['targetDev']=binding['files'][str(self.target)]['st_dev']&0xffffffff
        proof['serverDirectory'].update(self.directory_facts(binding))
        self.request.pending.write_text(json.dumps(value))
        self.assertEqual(self.request.record(),value)
        self.rows=[];self.server_visible=False
        return value
    def test_previous_boot_confirmed_device_drift_recovers_then_binds_fresh_launch(self):
        old=self.recorded_previous_device()
        with patch.object(h,'boot_identity',return_value='c'*64),patch.object(h,'process_identity') as identity:
            with self.request.locked():self.request.reconcile()
            identity.assert_not_called()  # Old PIDs cannot own this boot.
            self.assertIsNone(self.request.record())
        with patch.object(h,'boot_identity',return_value='c'*64),self.request.locked():self.request.begin()
        new=self.request.record()
        self.assertEqual(new['boot'],'c'*64);self.assertNotEqual(new['request'],old['request'])
        self.assertEqual(new['nativeBinding']['prefixIdentity'],{'st_dev':self.prefix.stat().st_dev,'st_ino':self.prefix.stat().st_ino})
    def test_current_boot_confirmed_device_drift_still_preserves_reservation(self):
        self.recorded_previous_device();before=self.request.pending.read_bytes()
        with self.request.locked(),self.assertRaisesRegex(h.Blocked,'native_prefix_changed'):self.request.reconcile()
        self.assertEqual(self.request.pending.read_bytes(),before)
    def test_previous_boot_reconcile_keeps_active_native_alias_or_prefix(self):
        value=self.recorded_previous_device();before=self.request.pending.read_bytes()
        with patch.object(h,'boot_identity',return_value='c'*64):
            for command in (str(self.loader),str(self.target),self.native['IMAGE']):
                self.rows=[(101,command)]
                with self.subTest(command=command),self.request.locked(),self.assertRaisesRegex(h.Blocked,'native_target_already_active'):
                    self.request.reconcile()
                self.assertEqual(self.request.pending.read_bytes(),before)
            self.rows=[]
            with patch.object(h.Admission,'active',return_value=True),self.request.locked(),self.assertRaisesRegex(h.Blocked,'profile_active'):
                self.request.reconcile()
        self.assertEqual(self.request.record(),value)
    def test_previous_boot_reconcile_keeps_ambiguous_wine_and_unknown_observations(self):
        self.recorded_previous_device();before=self.request.pending.read_bytes()
        with patch.object(h,'boot_identity',return_value='c'*64):
            for command in ('[wine64]',str(self.client),str(self.server)):
                with self.subTest(command=command),patch.object(h.Admission,'process_groups',return_value=[(100,1,100,command)]),self.request.locked(),self.assertRaisesRegex(h.Blocked,'pending_launch_unconfirmed'):
                    self.request.reconcile()
                self.assertEqual(self.request.pending.read_bytes(),before)
            with patch.object(h.Admission,'active',side_effect=h.Blocked('session_probe_failed')),self.request.locked(),self.assertRaisesRegex(h.Blocked,'session_probe_failed'):
                self.request.reconcile()
            with patch.object(h.Admission,'process_groups',side_effect=h.Blocked('process_probe_failed')),self.request.locked(),self.assertRaisesRegex(h.Blocked,'process_probe_failed'):
                self.request.reconcile()
        self.assertEqual(self.request.pending.read_bytes(),before)
    def test_pid_reuse_is_not_old_target_but_native_candidate_remains_ambiguous(self):
        self.confirm();self.alive[101]=self.identity(101,'999:2')
        with self.request.locked(),self.assertRaisesRegex(h.Blocked,'native_target_already_active'):self.request.begin()
        self.rows=[(100,str(self.client))]
        with self.request.locked():self.request.begin()
        self.assertEqual(self.request.record()['phase'],'prepared')
    def test_old_schema2_never_gains_native_proof_retroactively(self):
        self.routes.unlink();value=self.dispatch();self.assertEqual(value['schema'],2)
        self.alive.pop(os.getpid())
        self.enable();self.rows=[(100,str(self.client)),(101,str(self.loader))]
        with self.request.locked(),self.assertRaisesRegex(h.Blocked,'launch_in_progress'):self.request.reconcile()
        self.inspect.assert_not_called();self.assertEqual(self.request.record()['phase'],'dispatched')
    def test_present_native_route_without_approval_never_falls_back(self):
        self.approval_path.unlink()
        with self.assertRaisesRegex(h.Blocked,'native_route_unapproved'):self.request.begin()
        self.assertIsNone(self.request.record())
    def test_foreign_prefix_or_target_approval_is_rejected(self):
        for field in ('prefix','target'):
            value=copy.deepcopy(self.approval);value[field]=str(self.home/'foreign')
            self.approval_path.write_text(json.dumps(value))
            with self.subTest(field=field),self.assertRaisesRegex(h.Blocked,'native_binding_scope'):self.request.begin()
            self.assertIsNone(self.request.record())
    def test_approval_loader_route_and_target_drift_stop_before_dispatch(self):
        for path in (self.loader,self.routes,self.target,self.server):
            before=path.read_bytes();path.write_bytes(before+b'\n')
            with self.subTest(path=path),self.assertRaises(h.Blocked):self.request.begin()
            self.assertIsNone(self.request.record());path.write_bytes(before)
        self.approval['bundleIdentifier']='foreign.bundle';self.enable()
        with self.assertRaisesRegex(h.Blocked,'native_bundle_identity'):self.request.begin()
    def test_exact_approved_dos_comm_still_requires_actual_native_probe(self):
        value=self.dispatch();self.rows=[(100,str(self.client)),(101,self.native['IMAGE'])]
        self.request.watch(value['request'],timeout=1)
        self.assertEqual(self.request.record()['phase'],'confirmed');self.assertEqual(self.inspect.call_count,2)
    def test_changed_route_after_prepare_cannot_publish_dispatched(self):
        self.request.begin();self.routes.write_text('different')
        with self.assertRaisesRegex(h.Blocked,'native_route_changed'):self.request.dispatched([Mock(pid=100)])
        self.assertEqual(self.request.record()['phase'],'prepared')
    def test_retained_steam_owner_change_before_dispatch_is_not_rebound(self):
        self.rows=[(100,str(self.client))];self.request.begin()
        self.alive[100]=self.identity(100,'999:1');self.alive[200]=self.identity(200)
        with self.assertRaisesRegex(h.Blocked,'native_launch_owner_changed'):self.request.dispatched([Mock(pid=200)])
        self.assertEqual(self.request.record()['phase'],'prepared')
    def test_owner_pid_reuse_keeps_native_unconfirmed(self):
        value=self.dispatch();self.alive[100]=self.identity(100,'999:1');self.rows=[(101,str(self.loader))]
        self.request.watch(value['request'],timeout=.05)
        self.assertEqual(self.request.record()['phase'],'dispatched');self.inspect.assert_not_called()
    def test_foreign_lineage_and_startup_mapping_unknown_never_confirm(self):
        value=self.dispatch();self.rows=[(100,str(self.client)),(101,str(self.loader))];self.inspect.side_effect=self.Unknown('lineage')
        with patch.object(h.time,'sleep'):
            self.request.watch(value['request'],timeout=.02,max_samples=2)
        self.assertEqual(self.request.record()['phase'],'dispatched')
        self.inspect.assert_called()
    def test_retained_owner_exec_change_does_not_confirm(self):
        value=self.dispatch();self.rows=[(100,str(self.home/'foreign/steam.exe')),(101,self.native['IMAGE'])]
        self.request.watch(value['request'],timeout=.02)
        self.assertEqual(self.request.record()['phase'],'dispatched');self.inspect.assert_not_called()
    def test_companion_source_drift_is_rejected_before_execution(self):
        companion=self.home/'native_launch_binding.py';companion.write_bytes((self.home/h.NATIVE_COMPANION).read_bytes()+b'\n# drift\n')
        with patch.object(h,'NATIVE_COMPANION',companion),self.assertRaisesRegex(h.Blocked,'native_companion_changed'):
            self.real_native_module(self.home)
    def test_old_request_or_record_race_cannot_publish_observation(self):
        value=self.dispatch();self.rows=[(100,str(self.client)),(101,str(self.loader))]
        self.request.watch('f'*32,timeout=.01);self.inspect.assert_not_called()
        def changed(*args,**kwargs):
            raw=self.request.record();raw['request']='c'*32;self.request.pending.write_text(json.dumps(raw));return self.observed(*args,**kwargs)
        self.inspect.side_effect=changed;self.request.watch(value['request'],timeout=1)
        self.assertEqual(self.request.record()['phase'],'dispatched');self.assertEqual(self.request.record()['request'],'c'*32)
    def test_multiple_native_candidates_do_not_confirm(self):
        value=self.dispatch();self.rows=[(100,str(self.client)),(101,str(self.loader)),(102,str(self.loader))]
        self.request.watch(value['request'],timeout=.01)
        self.assertEqual(self.request.record()['phase'],'dispatched');self.inspect.assert_not_called()
    def test_late_observation_cannot_cross_watcher_deadline(self):
        value=self.dispatch();self.rows=[(100,str(self.client)),(101,str(self.loader))]
        clock=[0]
        def late(*args,**kwargs):clock[0]=2;return self.observed(*args,**kwargs)
        self.inspect.side_effect=late
        with patch.object(h.time,'monotonic',side_effect=lambda:clock[0]):self.request.watch(value['request'],timeout=1)
        self.assertEqual(self.request.record()['phase'],'dispatched')
        self.connection.assert_not_called()
    def test_no_native_route_keeps_normal_pe_schema_and_confirmation(self):
        self.routes.unlink();value=self.dispatch();self.assertEqual(value['schema'],2)
        self.rows=[(101,str(self.target))];self.request.watch(value['request'],timeout=1)
        self.assertEqual(self.request.record()['phase'],'confirmed');self.inspect.assert_not_called()
    def test_explicit_recovery_after_scoped_stop_allows_removed_native_route(self):
        self.confirm();self.alive.clear();self.rows=[];self.server_visible=False;self.routes.unlink()
        with self.request.locked():result=self.request.recover()
        self.assertEqual(result['state'],'PENDING_LAUNCH_RECOVERED');self.assertIsNone(self.request.record())

    def test_schema4_persists_complete_mapping_prefix_proof_without_ancestry(self):
        value=self.confirm();proof=value['targetObservation']
        self.assertEqual(value['schema'],4);self.assertEqual(proof['proof'],'mapped-pe-reciprocal-prefix-server-v1')
        self.assertEqual(proof['server'],self.identity(300));self.assertEqual(proof['serverExecutable'],str(self.server))
        self.assertTrue(proof['prefixConnectionVerified']);self.assertEqual(proof['connection']['opaqueHandles'],0)
        self.assertEqual(proof['connection']['gameEdges'],1);self.assertNotIn('ancestry',proof)
        self.assertEqual(self.inspect.call_count,2);self.connection.assert_called_once()
    def test_opaque_incomplete_wrong_scope_or_wrong_role_graph_never_confirms(self):
        value=self.dispatch();self.rows=[(100,str(self.client)),(101,str(self.loader))]
        changes=[lambda v:v.update(complete=False),lambda v:v.update(stable=False),lambda v:v.update(serverScopeAfter=False),
            lambda v:v.update(gameEdgesAfter=0),lambda v:v['roles'][0].update(zeroHandlesAfter=1),lambda v:v['roles'][2].update(birth='999:1')]
        for change in changes:
            def incomplete(*args,**kwargs):
                v=self.connected(*args,**kwargs);change(v);return v
            self.connection.side_effect=incomplete;self.request.watch(value['request'],timeout=.02)
            self.assertEqual(self.request.record()['phase'],'dispatched');self.assertIsNone(self.request.record()['targetObservation'])
    def test_unknown_foreign_prefix_graph_never_confirms_and_mapping_after_not_run(self):
        value=self.dispatch();self.rows=[(100,str(self.client)),(101,str(self.loader))]
        self.connection.side_effect=lambda *a,**k:{'state':'PREFIX_CONNECTION_UNKNOWN'}
        with patch.object(h.time,'sleep'):self.request.watch(value['request'],timeout=.05,max_samples=2)
        self.assertEqual(self.request.record()['phase'],'dispatched');self.assertEqual(self.inspect.call_count,self.connection.call_count)
    def test_server_pid_reuse_between_graph_and_final_checks_preserves_uncertainty(self):
        value=self.dispatch();self.rows=[(100,str(self.client)),(101,str(self.loader))]
        def reused(*args,**kwargs):
            v=self.connected(*args,**kwargs);self.alive[300]=self.identity(300,'999:1');return v
        self.connection.side_effect=reused;self.request.watch(value['request'],timeout=.1)
        self.assertEqual(self.request.record()['phase'],'dispatched')
    def test_multiple_server_processes_are_ambiguous_not_generic_wine_ownership(self):
        value=self.dispatch();self.rows=[(100,str(self.client)),(101,str(self.loader)),(301,str(self.server))]
        self.request.watch(value['request'],timeout=.1)
        self.assertEqual(self.request.record()['phase'],'dispatched');self.connection.assert_not_called();self.inspect.assert_not_called()
    def test_startup_without_game_alias_does_not_end_watch_on_steam_loader_name(self):
        value=self.dispatch();ready=[(100,str(self.client)),(101,self.native['IMAGE']),(300,str(self.server))]
        with patch.object(h.Admission,'processes',side_effect=[[(100,'/bootstrap/wine')],ready,ready]),patch.object(h.time,'sleep'):
            self.request.watch(value['request'],timeout=1,max_samples=2)
        self.assertEqual(self.request.record()['phase'],'confirmed')
    def test_missing_server_can_appear_next_sample_without_false_confirmation(self):
        value=self.dispatch();rows=[(100,str(self.client)),(101,self.native['IMAGE'])]
        with patch.object(h.Admission,'processes',side_effect=[rows,rows+[(300,str(self.server))],rows+[(300,str(self.server))]]),patch.object(h.time,'sleep'):
            self.request.watch(value['request'],timeout=1,max_samples=2)
        self.assertEqual(self.request.record()['phase'],'confirmed');self.connection.assert_called_once()
    def test_server_directory_change_after_graph_does_not_confirm(self):
        value=self.dispatch();self.rows=[(100,str(self.client)),(101,self.native['IMAGE'])];calls=[0]
        def changed(binding):
            calls[0]+=1;v=self.directory_facts(binding)
            if calls[0]>1:v['ino']+=1
            return v
        self.native['server_directory']=changed;self.request.watch(value['request'],timeout=.1)
        self.assertEqual(self.request.record()['phase'],'dispatched')
    def test_second_mapping_unknown_does_not_confirm_positive_graph_alone(self):
        value=self.dispatch();self.rows=[(100,str(self.client)),(101,self.native['IMAGE'])];count=[0]
        def lost(*args,**kwargs):
            count[0]+=1
            if count[0]%2==0:raise self.Unknown('mapping_after_unavailable')
            return self.observed(*args,**kwargs)
        self.inspect.side_effect=lost
        with patch.object(h.time,'sleep'):self.request.watch(value['request'],timeout=.05,max_samples=2)
        self.assertEqual(self.request.record()['phase'],'dispatched')
    def test_stage_uses_installed_home_layout_and_real_source_pins(self):
        ns=self.real_native_module(self.home)
        self.assertEqual(ns['IDENTITY_DIR'],self.home/h.NATIVE_COMPANION.parent.parent/'native-identity')
        self.assertIn('inspect_mapped',ns['identity_module']());self.assertIn('inspect_prefix_connection',ns['identity_module'](prefix=True))
        probe=ns['IDENTITY_DIR']/'prefix_probe';probe.write_bytes(probe.read_bytes()+b'drift')
        with self.assertRaisesRegex(h.Blocked,'native_inspector_changed'):ns['identity_module'](prefix=True)
    def test_old_experimental_schema3_never_upgrades_to_socket_proof(self):
        value=self.dispatch();value['schema']=3;self.request.pending.write_text(json.dumps(value));before=self.request.pending.read_bytes()
        self.rows=[(100,str(self.client)),(101,self.native['IMAGE'])];self.request.watch(value['request'],timeout=.05)
        self.assertEqual(self.request.pending.read_bytes(),before);self.inspect.assert_not_called();self.connection.assert_not_called()
        with self.assertRaisesRegex(h.Blocked,'invalid_admission_record'):self.request.record()
    def test_persisted_opaque_or_forged_server_scope_proof_is_rejected(self):
        value=self.confirm();value['targetObservation']['connection']['opaqueHandles']=1;self.request.pending.write_text(json.dumps(value))
        with self.assertRaisesRegex(h.Blocked,'invalid_native_observation'):self.request.record()
    def test_old_approval_schema1_is_not_native_graph_authority(self):
        self.approval['schema']=1;self.enable()
        with self.assertRaisesRegex(h.Blocked,'invalid_native_binding'):self.request.begin()
        self.assertIsNone(self.request.record())
    def test_hidden_game_older_than_request_child_cannot_be_attributed(self):
        value=self.dispatch();self.alive[101]=self.identity(101,'99:1');self.rows=[(100,str(self.client)),(101,self.native['IMAGE'])]
        self.request.watch(value['request'],timeout=.05)
        self.assertEqual(self.request.record()['phase'],'dispatched');self.inspect.assert_not_called();self.connection.assert_not_called()
    def test_equal_microsecond_game_and_dispatch_birth_remains_unknown(self):
        value=self.dispatch();self.alive[101]=self.identity(101,'100:1');self.rows=[(100,str(self.client)),(101,self.native['IMAGE'])]
        self.request.watch(value['request'],timeout=.05)
        self.assertEqual(self.request.record()['phase'],'dispatched');self.inspect.assert_not_called()
    def test_same_birth_exec_comm_change_during_probe_does_not_confirm(self):
        value=self.dispatch();self.rows=[(100,str(self.client)),(101,self.native['IMAGE'])]
        def comm_changed(*args,**kwargs):
            v=self.connected(*args,**kwargs);self.rows[0]=(100,str(self.home/'foreign/steam.exe'));return v
        self.connection.side_effect=comm_changed;self.request.watch(value['request'],timeout=.1)
        self.assertEqual(self.request.record()['phase'],'dispatched')
    def test_second_exact_server_appearing_during_probe_is_ambiguous(self):
        value=self.dispatch();self.rows=[(100,str(self.client)),(101,self.native['IMAGE'])]
        def extra_server(*args,**kwargs):
            v=self.connected(*args,**kwargs);self.rows.append((301,str(self.server)));return v
        self.connection.side_effect=extra_server;self.request.watch(value['request'],timeout=.1)
        self.assertEqual(self.request.record()['phase'],'dispatched')
    def test_game_alias_disappearing_while_same_birth_lives_is_unknown(self):
        value=self.dispatch();self.rows=[(100,str(self.client)),(101,self.native['IMAGE'])]
        def alias_changed(*args,**kwargs):
            v=self.connected(*args,**kwargs);self.rows=[(100,str(self.client))];return v
        self.connection.side_effect=alias_changed;self.request.watch(value['request'],timeout=.1)
        self.assertEqual(self.request.record()['phase'],'dispatched')
    def test_refresh_process_probe_failure_never_confirms(self):
        value=self.dispatch();ready=[(100,str(self.client)),(101,self.native['IMAGE']),(300,str(self.server))]
        with patch.object(h.Admission,'processes',side_effect=[ready,h.subprocess.TimeoutExpired('ps',1)]):self.request.watch(value['request'],timeout=.1)
        self.assertEqual(self.request.record()['phase'],'dispatched')

class ServerCommandAliasTests(unittest.TestCase):
    setUp=NativeAdmissionTests.setUp;tearDown=NativeAdmissionTests.tearDown
    identity=NativeAdmissionTests.identity;enable=NativeAdmissionTests.enable
    dispatch=NativeAdmissionTests.dispatch;observed=NativeAdmissionTests.observed
    directory_facts=NativeAdmissionTests.directory_facts;connected=NativeAdmissionTests.connected
    def alias(self):
        return str(self.server.parents[1]/'lib/wine/../../bin/wineserver')
    def ready(self,server_command):
        return [(100,str(self.client)),(101,self.native['IMAGE']),(300,server_command)]
    def test_actual_wine_spelling_confirms_with_canonical_kernel_probe_path(self):
        value=self.dispatch();self.server_visible=False;self.rows=self.ready(self.alias())
        self.request.watch(value['request'],timeout=1)
        result=self.request.record();self.assertEqual(result['phase'],'confirmed')
        self.assertEqual(result['targetObservation']['serverExecutable'],str(self.server))
        self.assertEqual(result['targetObservation']['server'],self.identity(300))
        self.assertEqual(self.inspect.call_count,2);self.connection.assert_called_once()
    def test_canonical_and_actual_alias_may_change_between_bounded_rows(self):
        for first,last in ((str(self.server),self.alias()),(self.alias(),str(self.server))):
            with self.subTest(first=first,last=last):
                binding=self.native['bind'](self.home,'ds3','game')
                observed=self.native['observe'](self.home,binding,self.identity(100),[self.identity(100)],self.ready(first),1,
                                                lambda **kwargs:self.ready(last))
                self.assertEqual(observed['server'],self.identity(300))
    def test_basename_foreign_and_same_bytes_other_runtime_are_not_candidates(self):
        binding=self.native['bind'](self.home,'ds3','game')
        foreign=self.home/'foreign/runtime/engine/bin/wineserver';foreign.parent.mkdir(parents=True);foreign.write_bytes(self.server.read_bytes())
        rows=[(300,'wineserver'),(301,str(foreign)),(302,'relative/engine/lib/wine/../../bin/wineserver'),(303,str(self.server)+'\0')]
        self.assertEqual(self.native['server_candidates'](rows,binding),[])
    def test_same_target_symlink_component_is_rejected_even_with_same_realpath(self):
        value=self.dispatch();link=self.server.parents[1]/'lib/link';link.symlink_to(link.parent/'wine',target_is_directory=True)
        alias=str(link/'../../bin/wineserver');self.assertEqual(Path(alias).resolve(),self.server)
        with self.assertRaisesRegex(h.Blocked,'unsafe_admission_directory'):
            self.native['server_candidates']([(300,alias)],value['nativeBinding'])
        self.assertEqual(self.request.record()['phase'],'dispatched');self.connection.assert_not_called()
    def test_lexically_equal_alias_resolving_into_foreign_runtime_is_rejected(self):
        value=self.dispatch();foreign=self.home/'foreign';(foreign/'lib/wine').mkdir(parents=True);(foreign/'bin').mkdir();(foreign/'bin/wineserver').write_bytes(self.server.read_bytes())
        link=self.server.parents[1]/'lib/link';link.symlink_to(foreign/'lib/wine',target_is_directory=True)
        with self.assertRaisesRegex(h.Blocked,'native_server_executable_alias'):
            self.native['server_candidates']([(300,str(link/'../../bin/wineserver'))],value['nativeBinding'])
        self.connection.assert_not_called()
    def test_multiple_canonical_and_alias_candidates_remain_ambiguous(self):
        value=self.dispatch();self.rows=[(100,str(self.client)),(101,self.native['IMAGE']),(301,self.alias())]
        self.request.watch(value['request'],timeout=.1)
        self.assertEqual(self.request.record()['phase'],'dispatched');self.inspect.assert_not_called();self.connection.assert_not_called()
    def test_second_alias_appearing_after_graph_rejects_final_comm_recheck(self):
        value=self.dispatch();self.rows=[(100,str(self.client)),(101,self.native['IMAGE'])]
        def extra_alias(*args,**kwargs):
            graph=self.connected(*args,**kwargs);self.rows.append((301,self.alias()));return graph
        self.connection.side_effect=extra_alias;self.request.watch(value['request'],timeout=.1)
        self.assertEqual(self.request.record()['phase'],'dispatched')
    def test_alias_does_not_bypass_native_prefix_unknown_or_server_birth_change(self):
        value=self.dispatch();self.server_visible=False;self.rows=self.ready(self.alias())
        self.connection.side_effect=lambda *args,**kwargs:{'state':'PREFIX_CONNECTION_UNKNOWN'}
        with patch.object(h.time,'sleep'):self.request.watch(value['request'],timeout=.1,max_samples=2)
        self.assertEqual(self.request.record()['phase'],'dispatched')
        def reused(*args,**kwargs):
            graph=self.connected(*args,**kwargs);self.alive[300]=self.identity(300,'999:1');return graph
        self.connection.side_effect=reused;self.request.watch(value['request'],timeout=.1)
        self.assertEqual(self.request.record()['phase'],'dispatched')
    def test_alias_content_hash_still_required_with_current_file_facts(self):
        binding=self.native['bind'](self.home,'ds3','game');self.server.write_bytes(b'changed same path')
        binding['files'][str(self.server)]=self.native['facts'](self.server)
        with self.assertRaisesRegex(h.Blocked,'native_server_executable_changed'):
            self.native['server_candidates']([(300,self.alias())],binding)

if __name__=='__main__':unittest.main()
