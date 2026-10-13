"""Real fixed-path adapter and descriptor transactions against owned fixtures only."""
import hashlib,importlib.machinery,importlib.util,json,os,shutil,stat,subprocess,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
P=Path(__file__).resolve().parents[1];COMMIT='a'*40
loader=importlib.machinery.SourceFileLoader('launch_update',str(P/'bin/game-launch-reliability-update'));spec=importlib.util.spec_from_loader(loader.name,loader);u=importlib.util.module_from_spec(spec);loader.exec_module(u)
class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.home=Path(self.tmp.name).resolve()
        self.mapping={name:self.home/name for name in ('hub','ds3','cs2','games','source','state','candidate','aid-bin')}
        for root in self.mapping.values():root.mkdir(mode=0o700)
        self.receipts={};self.desired={};self.previous={};self.source_files={};self.guards={};self.calls=[]
        self.source=self.mapping['source'];(self.source/'bin').mkdir();(self.source/'manifests').mkdir()
        shutil.copyfile(P/'bin/wine-runtime-overlay',self.source/'bin/wine-runtime-overlay')
        shutil.copyfile(P/'bin/game-launch-reliability-update',self.source/'bin/game-launch-reliability-update')
        apps={name:{'route':list(route),'routeNumber':i+1,'iconSource':'~/fixture.icns','iconSha256':'f'*64} for i,(name,route) in enumerate(zip(u.APPS,(('games-play','cs2'),('games-play','prince'),('games-play','steam'),('ds3-play','play'))))}
        self.old_native={'schema':1,'owner':'control-game-app-launchers','apps':apps,'builtApps':{}}
        self.new_native={'schema':1,'owner':'control-game-app-launchers','apps':apps,'builtApps':{}}
        for i,name in enumerate(u.APPS):
            row={}
            for rel,mode in (('Contents/Info.plist',0o600),('Contents/Resources/Game.icns',0o600),('Contents/MacOS/launcher',0o700)):
                data=('old '+name+' '+rel).encode();self.put('games/'+name+'/'+rel,data,mode)
                row[rel]=self.image('games/'+name+'/'+rel)
            self.old_native['builtApps'][name]=dict(row)
            raw=('new native '+name).encode();self.put('candidate/'+name+'/Contents/MacOS/launcher',raw,0o700)
            row['Contents/MacOS/launcher']=self.image('candidate/'+name+'/Contents/MacOS/launcher');self.new_native['builtApps'][name]=row
        self.old_native_raw=u.encode(self.old_native);self.put('source/manifests/game-app-launchers.json',self.old_native_raw)
        old_policy=u.digest(self.old_native_raw)
        for key,rel in u.SOURCES.items():
            old=('old '+key).encode();new=('reviewed source '+key).encode()
            if key!='helper':self.put(u.TARGETS[key],old,0o755 if key in ('hub.launcher','cs2.launcher') else 0o700)
            self.put('source/'+rel,new,0o755);self.source_files[rel]=u.digest(new)
            self.put('candidate/'+u.CANDIDATE_FILES[key],new,0o600 if key=='helper' else 0o755 if key in ('hub.launcher','cs2.launcher') else 0o700)
        self.put('source/bin/game-app-launcher.m',b'reviewed native source');self.source_files['bin/game-app-launcher.m']=u.digest(b'reviewed native source')
        self.new_native['sourceSha256']=self.source_files['bin/game-app-launcher.m'];self.new_native['previousPolicySha256']=old_policy;self.native_raw=u.encode(self.new_native);self.put('source/'+u.NATIVE_POLICY,self.native_raw)
        for name,owner,launcher_key in (('hub','control-games-hub','hub.launcher'),('ds3','control-ds3-marshal-fix','ds3.lifecycle'),('cs2','control-cs2-standalone','cs2.launcher')):
            root=self.mapping[name]
            prefix=root/('prefix' if name=='cs2' else 'profiles/ds3' if name=='ds3' else 'profiles/prince');prefix.mkdir(mode=0o700,parents=True)
            self.put(name+'/runtime/engine/bin/wineserver',('server '+name).encode(),0o700)
            manifest={'schema':1,'id':name,'owner':owner};self.put(name+('/runtime/.manifest.json' if name=='cs2' else '/manifest.json'),u.encode(manifest))
            raw_manifest=self.path(name+('/runtime/.manifest.json' if name=='cs2' else '/manifest.json')).read_bytes()
            receipt={'owner':owner,'schemaVersion' if name=='cs2' else 'schema':1,'manifestSha256':u.digest(raw_manifest),'runtimeTreeSha256':'c'*64,'commit':'b'*40,'opaqueOwnerField':{'preserve':['bytes',17]}}
            receipt['lifecycleSha256' if name=='ds3' else 'launcherSha256']=self.image(u.TARGETS[launcher_key])['sha256']
            if name!='cs2':
                names=[n for n in u.APPS if (n=='Dark Souls III.app')==(name=='ds3')]
                receipt.update(appPolicySha256=old_policy,appLaunchers={n:self.old_native['builtApps'][n] for n in names},appCommit='b'*40)
            self.receipts[name]=receipt;self.put(u.TARGETS[name+'.receipt'],u.encode(receipt))
        for rel in u.GUARDS:
            if not self.path(rel).exists():self.put(rel,('guard '+rel).encode())
            self.guards[rel]=self.image(rel)
        for name,root in (('games-play',self.mapping['hub']),('ds3-play',self.mapping['ds3']),('cs2-play',self.mapping['cs2'])):
            self.path('aid-bin/'+name).symlink_to(root/name)
        self.put('state/games-hub.lock',b'');self.put('cs2/.launcher.lock',b'')
        self.definition={'schema':1,'id':'game-launch-reliability','owner':'control-games-hub','nativePolicySha256':u.digest(self.native_raw),'previousNativePolicySha256':old_policy,
             'sourceFiles':self.source_files,'previousFiles':{key:self.image(rel) for key,rel in u.TARGETS.items()},
             'desiredFiles':{key:self.image('candidate/'+rel) for key,rel in u.CANDIDATE_FILES.items()},'guards':self.guards,
             'servers':{name:self.image(name+'/runtime/engine/bin/wineserver') for name in ('hub','ds3','cs2')}}
        self.put('source/'+u.POLICY,u.encode(self.definition))
        values={'HOME':self.home,'CONTROL':self.source,'SOURCE_PATH':self.source/'bin/game-launch-reliability-update','HUB':self.mapping['hub'],'DS3':self.mapping['ds3'],'CS2':self.mapping['cs2'],'GAMES':self.mapping['games'],'BIN':self.mapping['aid-bin'],'STATE':self.mapping['state'],'CANDIDATE':self.mapping['candidate']}
        for key,value in values.items():fixture_patch=patch.object(u,key,value);fixture_patch.start();self.addCleanup(fixture_patch.stop)
        self.doctor={'verdict':'PASS','gitOnly':False,'configurationSourceAccepted':True,'currentSentinelReady':True,'integratedMain':True};self.head=COMMIT;self.branch='main';self.dirty='';self.active=False
        fixture_patch=patch.object(u.subprocess,'run',self.command);fixture_patch.start();self.addCleanup(fixture_patch.stop)
        self.before=self.images();self.pin=u.operate('plan',COMMIT)['planSha256']
        self.assertEqual(sum(argv[0].endswith('current-doctor') for argv,_ in self.calls),1)
    def path(self,rel):base,inner=rel.split('/',1);return self.mapping[base]/inner
    def put(self,rel,raw,mode=0o600):
        path=self.path(rel);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(mode)
    def image(self,rel):
        path=self.path(rel)
        if not path.exists() and not path.is_symlink():return None
        return {'sha256':u.digest(path.read_bytes()),'mode':path.lstat().st_mode&0o777}
    def images(self):return {key:self.image(rel) for key,rel in u.TARGETS.items()}
    def command(self,argv,**kwargs):
        self.calls.append((argv,kwargs))
        if argv[0]=='/usr/bin/git':
            tail=argv[-2:]
            value=self.head if tail==['rev-parse','HEAD'] else self.branch if tail==['branch','--show-current'] else self.dirty if tail==['status','--porcelain'] else None
            assert value is not None;return SimpleNamespace(returncode=0,stdout=(value+'\n').encode())
        if argv==[str(self.source/'bin/current-doctor'),'--json']:return SimpleNamespace(returncode=0,stdout=u.encode(self.doctor))
        if argv[-1]=='-w' and argv[0].endswith('wineserver'):
            self.assertEqual(kwargs['timeout'],3);self.assertNotIn('PRIVATE_TOKEN',kwargs['env'])
            if self.active:raise subprocess.TimeoutExpired(argv,3)
            return SimpleNamespace(returncode=0,stdout=b'')
        raise AssertionError('unexpected command')
    def apply(self,event=lambda _:None):return u.operate('apply',COMMIT,self.pin,event)
    def rollback(self,event=lambda _:None):return u.operate('rollback',COMMIT,self.pin,event)
    def recover(self,event=lambda _:None):return u.operate('recover',COMMIT,self.pin,event)
    def once(self,operation,event=lambda _:None):
        start=len(self.calls);result=u.operate(operation,COMMIT,self.pin,event)
        self.assertEqual(sum(argv[0].endswith('current-doctor') for argv,_ in self.calls[start:]),1)
        return result
    def test_read_only_plan_then_apply_noop_rollback_noop_return_and_receipt_preservation(self):
        self.assertFalse((self.mapping['state']/u.NAMESPACE).exists());self.assertEqual(self.images(),self.before)
        self.assertTrue(self.once('apply')['liveStateChanged']);after=self.images();self.assertFalse(self.once('apply')['changed'])
        self.assertEqual(self.once('plan')['state'],'PLANNED_EXISTING_TRANSACTION')
        for name,old in self.receipts.items():
            now=u.decode(self.path(u.TARGETS[name+'.receipt']).read_bytes())
            for key in ('owner','manifestSha256','runtimeTreeSha256','commit','opaqueOwnerField'):self.assertEqual(now[key],old[key])
        self.assertTrue(self.once('rollback')['sourceRollbackSuccessorRequired']);self.assertEqual(self.images(),self.before);self.assertFalse(self.once('rollback')['changed'])
        self.assertTrue(self.once('return')['changed']);self.assertEqual(self.images(),after)
        self.assertEqual({rel:self.image(rel) for rel in u.GUARDS},self.guards)
    def test_helper_first_and_removed_last(self):
        events=[];self.apply(events.append);changed=[x.removeprefix('replaced:') for x in events if x.startswith('replaced:') and x.removeprefix('replaced:') in u.TARGETS.values()]
        self.assertEqual(changed,[u.TARGETS[key] for key in u.ORDER]);events=[];self.rollback(events.append)
        changed=[x.removeprefix('replaced:') for x in events if x.startswith('replaced:') and x.removeprefix('replaced:') in u.TARGETS.values()]
        self.assertEqual(changed,[u.TARGETS[key] for key in reversed(u.ORDER)])
    def test_interruption_each_apply_and_rollback_target_requires_explicit_recovery(self):
        for key in u.ORDER:
            wanted='replaced:'+u.TARGETS[key]
            def interrupt(event):
                if event==wanted:raise KeyboardInterrupt()
            with self.subTest(side='apply',key=key):
                with self.assertRaises(KeyboardInterrupt):self.apply(interrupt)
                with self.assertRaisesRegex(u.Blocked,'explicit_recovery_required'):self.apply()
                self.once('recover');self.rollback();self.assertEqual(self.images(),self.before)
            self.apply()
            with self.subTest(side='rollback',key=key):
                with self.assertRaises(KeyboardInterrupt):self.rollback(interrupt)
                with self.assertRaisesRegex(u.Blocked,'explicit_recovery_required'):self.rollback()
                self.once('recover');self.assertEqual(self.images(),self.before)
    def test_foreign_target_candidate_guard_and_rehashed_backup_are_never_overwritten(self):
        self.apply();target=self.path(u.TARGETS['hub.launcher']);target.write_bytes(b'foreign');before=self.images()
        with self.assertRaisesRegex(u.Blocked,'target_unknown_drift'):self.rollback()
        self.assertEqual(self.images(),before)
        target.write_bytes(self.path('candidate/games-play').read_bytes());target.chmod(self.definition['desiredFiles']['hub.launcher']['mode'])
        backup=self.mapping['state']/u.NAMESPACE/'transaction/native-0.after';backup.write_bytes(b'foreign')
        with self.assertRaisesRegex(u.Blocked,'backup_drift'):self.rollback()
    def test_gates_reject_nonbool_source_drift_active_and_pending_before_writes(self):
        for key,value in (('configurationSourceAccepted',1),('currentSentinelReady',False),('integratedMain',False),('gitOnly',True)):
            saved=self.doctor[key];self.doctor[key]=value
            with self.assertRaisesRegex(u.Blocked,'fresh_accepted_doctor_required'):self.apply()
            self.doctor[key]=saved;self.assertEqual(self.images(),self.before)
        for key,value in (('head','f'*40),('branch','review'),('dirty',' M file')):
            saved=getattr(self,key);setattr(self,key,value)
            with self.assertRaisesRegex(u.Blocked,'clean_exact_main_required'):self.apply()
            setattr(self,key,saved)
        self.active=True
        with self.assertRaisesRegex(u.Blocked,'prefix_active'):self.apply()
        self.active=False;self.put('state/game-launch-pending.json',b'pending')
        with self.assertRaisesRegex(u.Blocked,'launch_reservation_pending'):self.apply()
        self.assertEqual(self.images(),self.before)
    def test_local_source_drift_after_first_target_blocks_further_writes_and_recovers(self):
        def revoke(event):
            if event=='replaced:'+u.TARGETS['helper']:self.head='f'*40
        with self.assertRaisesRegex(u.Blocked,'clean_exact_main_required'):self.apply(revoke)
        current=self.images();self.assertIsNotNone(current['helper'])
        for key in u.ORDER[1:]:self.assertEqual(current[key],self.before[key])
        self.head=COMMIT;self.once('recover');self.assertFalse(self.once('apply')['changed'])
    def test_local_and_shared_busy_locks_source_rechecked_before_noop(self):
        for rel in ('cs2/.launcher.lock','state/games-hub.lock'):
            import fcntl
            with self.path(rel).open('rb') as held:
                fcntl.flock(held,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaisesRegex(u.Blocked,'launcher_busy'):self.apply()
            self.assertEqual(self.images(),self.before)
        self.apply();self.doctor['configurationSourceAccepted']=False
        with self.assertRaisesRegex(u.Blocked,'fresh_accepted_doctor_required'):self.apply()
    def test_helper_changed_at_delete_boundary_is_retained_and_recovery_blocks(self):
        self.apply();helper=self.path(u.TARGETS['helper'])
        def change(event):
            if event=='before-replace:'+u.TARGETS['helper']:helper.write_bytes(b'foreign helper bytes')
        with self.assertRaisesRegex(u.Blocked,'target_changed_before_replace'):self.rollback(change)
        self.assertEqual(helper.read_bytes(),b'foreign helper bytes');before=self.images()
        with self.assertRaisesRegex(u.Blocked,'target_unknown_drift'):self.recover()
        self.assertEqual(self.images(),before)
    def test_staged_journal_interrupt_requires_recovery_of_recorded_direction(self):
        def interrupt(event):
            if event=='staged:state/transaction/journal.json':raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.apply(interrupt)
        self.assertEqual(self.images(),self.before)
        with self.assertRaisesRegex(u.Blocked,'explicit_recovery_required'):self.apply()
        self.assertTrue(self.recover()['changed']);self.assertFalse(self.apply()['changed'])

    def test_wrong_plan_and_staging_failure_retry_leave_targets_exact(self):
        with self.assertRaisesRegex(u.Blocked,'prestate_changed_since_plan'):u.operate('apply',COMMIT,'0'*64)
        original=u.partial_write;count=[0]
        def fail(*args):
            count[0]+=1
            if count[0]==7:raise OSError('injected staging')
            return original(*args)
        with patch.object(u,'partial_write',side_effect=fail):
            with self.assertRaises(OSError):self.apply()
        self.assertEqual(self.images(),self.before);self.assertTrue(self.apply()['changed'])
    def test_partial_stage_prefix_can_resume_but_foreign_prefix_blocks(self):
        original=u.partial_write;count=[0]
        def fail(root,rel,wanted):
            count[0]+=1
            if count[0]==3:root.write_new(rel,wanted[0][:5],wanted[1]);raise OSError('partial write')
            return original(root,rel,wanted)
        with patch.object(u,'partial_write',side_effect=fail):
            with self.assertRaises(OSError):self.apply()
        self.assertEqual(self.images(),self.before);self.assertTrue(self.apply()['changed'])
    def test_partial_initial_journal_prefix_resumes_and_foreign_content_is_retained(self):
        original=u.partial_write
        def fail(root,rel,wanted):
            if rel=='state/transaction/journal.json':root.write_new(rel,wanted[0][:15],wanted[1]);raise OSError('partial journal')
            return original(root,rel,wanted)
        with patch.object(u,'partial_write',side_effect=fail):
            with self.assertRaises(OSError):self.apply()
        self.assertEqual(self.images(),self.before);self.assertTrue(self.apply()['changed'])
    def test_malformed_staged_journal_is_structured_block_and_retained(self):
        def interrupt(event):
            if event=='staged:state/transaction/journal.json':raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):self.apply(interrupt)
        staged=self.mapping['state']/u.NAMESPACE/'transaction'/('stage.'+u.digest(b'state/transaction/journal.json')[:16])
        original=staged.read_bytes()
        for changed in ({'phase':[]},{'planSha256':'f'*64},{'phase':'applied','intent':'helper'}):
            value=u.decode(original);value.update(changed);staged.write_bytes(u.encode(value));before=self.images()
            with self.assertRaises(u.Blocked):self.recover()
            self.assertEqual(self.images(),before);self.assertEqual(staged.read_bytes(),u.encode(value))
        staged.write_bytes(original);self.recover()
    def test_inactivity_drift_after_journal_intent_before_publication_blocks_target(self):
        def revoke(event):
            if event=='journal:applying:helper':self.active=True
        with self.assertRaisesRegex(u.Blocked,'prefix_active'):self.apply(revoke)
        self.assertEqual(self.images(),self.before);self.active=False;self.once('recover')

    def test_cross_updater_receipt_successor_refuses_rollback_and_invalid_predecessor_order(self):
        self.apply();receipt=self.path('hub/receipt.json');value=u.decode(receipt.read_bytes());value.update(manifestSha256='d'*64,runtimeTreeSha256='e'*64);receipt.write_bytes(u.encode(value));before=self.images()
        with self.assertRaisesRegex(u.Blocked,'target_unknown_drift'):self.rollback()
        self.assertEqual(self.images(),before)
    def test_real_overlay_order_and_reverse_rollback_preserve_launch_receipt_closure(self):
        integration=P;packet=P
        def load(name,path):
            loader=importlib.machinery.SourceFileLoader(name,str(path));spec=importlib.util.spec_from_loader(loader.name,loader);module=importlib.util.module_from_spec(spec);loader.exec_module(module);return module
        fixture_module=load('overlay_fixture_for_launch',integration/'tests/test_wine_runtime_overlay.py')
        overlay=fixture_module.Fixture();self.addCleanup(overlay.close)
        adapter=load('overlay_adapter_for_launch',packet/'bin/games-runtime-update')
        shutil.copyfile(packet/'bin/wine-runtime-overlay',self.source/'bin/wine-runtime-overlay')
        for name in ('hub','ds3'):
            shutil.rmtree(self.mapping[name]/'runtime');shutil.copytree(overlay.path/name/'runtime',self.mapping[name]/'runtime',symlinks=True)
            self.put(name+'/manifest.json',(overlay.path/name/'manifest.json').read_bytes())
            original=u.decode((overlay.path/name/'receipt.json').read_bytes())
            original.update({key:value for key,value in self.receipts[name].items() if key in ('appPolicySha256','appLaunchers','appCommit','opaqueOwnerField')})
            original['launcherSha256' if name=='hub' else 'lifecycleSha256']=self.image(u.TARGETS[name+'.launcher' if name=='hub' else 'ds3.lifecycle'])['sha256']
            if name=='ds3':original['launcherSha256']=self.image('ds3/ds3-play')['sha256']
            self.put(name+'/receipt.json',u.encode(original))
        shutil.rmtree(self.mapping['ds3']/'borderless');shutil.copytree(overlay.path/'ds3/borderless',self.mapping['ds3']/'borderless')
        self.put('source/manifests/ds3-source-hub-v1.json',(overlay.path/'payload/source-hub-v1.json').read_bytes())
        overlay_policy=u.decode((overlay.path/'payload/policy.json').read_bytes());overlay_policy['lifecycleSha256']=self.definition['desiredFiles']['ds3.lifecycle']['sha256']
        overlay_policy_raw=u.encode(overlay_policy);self.put('source/manifests/wine-runtime-overlay.json',overlay_policy_raw)
        hub_before=u.decode(self.path('hub/manifest.json').read_bytes());hub_after=dict(hub_before,criticalHashes=dict(overlay_policy['previousHubCriticalHashes'],**overlay_policy['desiredPEHashes']),runtimeOverlayPolicySha256=u.digest(overlay_policy_raw))
        self.put('source/manifests/games-hub.json',fixture_module.w.encode(hub_after))
        self.definition['previousFiles']={key:self.image(rel) for key,rel in u.TARGETS.items()}
        self.definition['guards']={rel:self.image(rel) for rel in u.GUARDS}
        self.definition['servers']={name:self.image(name+'/runtime/engine/bin/wineserver') for name in ('hub','ds3','cs2')}
        self.put('source/'+u.POLICY,u.encode(self.definition));self.before=self.images();self.pin=u.operate('plan',COMMIT)['planSha256']
        candidate=self.home/'overlay-candidate';candidate.mkdir()
        files={'winemac-i386.drv':b'new pe32','winemac-x86_64.drv':b'new pe64','wine-source.tar.gz':b'fixture sources','source.patch':b'fixture patch','LGPL-NOTICE.txt':b'fixture corresponding source notice'}
        files['build-provenance.json']=u.encode({'schema':1,'peHashes':overlay_policy['desiredPEHashes'],'sourceArchiveSha256':u.digest(files['wine-source.tar.gz']),'patchSha256':u.digest(files['source.patch']),'upstreamCommit':None,'installed':False})
        for name,raw in files.items():(candidate/name).write_bytes(raw);(candidate/name).chmod(0o600)
        delivery={'schema':1,'id':'wine-runtime-update','owner':'control-games-hub','overlayPolicySha256':u.digest(overlay_policy_raw),'candidateFiles':{name:u.digest(raw) for name,raw in files.items()},'requiredLaunchAdmissionSha256':self.definition['desiredFiles']['helper']['sha256']}
        self.put('source/manifests/wine-runtime-update.json',u.encode(delivery));shutil.copyfile(packet/'bin/games-runtime-update',self.source/'bin/games-runtime-update')
        bindings={'HOME':self.home,'CONTROL':self.source,'SOURCE_PATH':self.source/'bin/games-runtime-update','HUB':self.mapping['hub'],'DS3':self.mapping['ds3'],'STATE':self.mapping['state'],'CANDIDATE':candidate,'ADMISSION':self.path(u.TARGETS['helper'])}
        patches=[patch.object(adapter,key,value) for key,value in bindings.items()]
        for active_patch in patches:active_patch.start();self.addCleanup(active_patch.stop)
        with self.assertRaises(FileNotFoundError):adapter.operate('plan',COMMIT)
        self.assertEqual(self.images(),self.before)
        self.apply();launch_after=self.images();overlay_plan=adapter.operate('plan',COMMIT)['planSha256']
        adapter.operate('apply',COMMIT,overlay_plan);combined=self.images()
        self.assertEqual(combined['ds3.lifecycle'],launch_after['ds3.lifecycle']);self.assertEqual(combined['helper'],launch_after['helper'])
        with self.assertRaisesRegex(u.Blocked,'guard_drift'):self.rollback()
        self.assertEqual(self.images(),combined)
        adapter.operate('rollback',COMMIT,overlay_plan);self.assertEqual(self.images(),launch_after)
        self.rollback();self.assertEqual(self.images(),self.before)
        with self.assertRaises(FileNotFoundError):adapter.operate('return',COMMIT,overlay_plan)
        self.assertEqual(self.images(),self.before)
        u.operate('return',COMMIT,self.pin);adapter.operate('return',COMMIT,overlay_plan);self.assertEqual(self.images(),combined)

    def test_original_native_updater_rollback_cannot_clobber_launch_successor(self):
        integration=P
        loader=importlib.machinery.SourceFileLoader('legacy_native_update',str(integration/'bin/game-app-launcher-update'))
        spec=importlib.util.spec_from_loader(loader.name,loader);old=importlib.util.module_from_spec(spec);loader.exec_module(old);h=old.h
        native_only=self.home/'native-only';native_only.mkdir()
        for name in u.APPS:
            shutil.copytree(self.mapping['games']/name,native_only/name)
            shutil.copyfile(self.path('candidate/'+name+'/Contents/MacOS/launcher'),native_only/name/'Contents/MacOS/launcher')
        (native_only/'build.json').write_bytes(u.encode({'schema':1,'sourceSha256':self.source_files['bin/game-app-launcher.m'],'apps':self.new_native['builtApps']}))
        with patch.object(h,'HOME',self.home),patch.object(h,'HUB',self.mapping['hub']),patch.object(h,'DS3',self.mapping['ds3']),patch.object(h,'HERE',self.source),patch.object(h,'source_gate',side_effect=u.source_gate),patch.object(h,'status'):
            old.update(COMMIT,native_only)
            before=self.images()
            with self.assertRaisesRegex(u.Blocked,'predecessor_drift'):self.apply()
            self.assertEqual(self.images(),before)
            old.rollback(COMMIT,COMMIT);self.assertEqual(self.images(),self.before)
            self.apply();before=self.images()
            with self.assertRaisesRegex(RuntimeError,'update_target_drift'):old.rollback(COMMIT,COMMIT)
            self.assertEqual(self.images(),before)

    def test_helper_symlink_and_hardlink_and_redirected_ancestor_block(self):
        helper=self.path(u.TARGETS['helper']);outside=self.home/'outside';outside.write_bytes(b'keep');helper.symlink_to(outside)
        with self.assertRaises(OSError):self.apply()
        self.assertEqual(outside.read_bytes(),b'keep');helper.unlink();os.link(outside,helper)
        with self.assertRaisesRegex(RuntimeError,'unsafe_file'):self.apply()
        helper.unlink();old=self.mapping['hub'];renamed=self.home/'hub-old';old.rename(renamed);old.symlink_to(self.mapping['ds3'])
        with self.assertRaises(OSError):self.apply()
        self.assertEqual(outside.read_bytes(),b'keep')
    def test_no_arbitrary_root_or_offline_authority_switch(self):
        with patch.object(u,'SOURCE_PATH',P/'bin/game-launch-reliability-update'):
            with self.assertRaisesRegex(u.Blocked,'canonical_source_required'):self.apply()
        source=(P/'bin/game-launch-reliability-update').read_text();self.assertNotIn('--root',source);self.assertNotIn('--offline-fixture-gates',source)

    def test_entry_doctor_under_both_locks_and_vendor_change_observed_on_next_invocation(self):
        import fcntl
        real=self.command
        def locked(argv,**kwargs):
            if argv[0].endswith('current-doctor'):
                for rel in ('cs2/.launcher.lock','state/games-hub.lock'):
                    with self.path(rel).open('rb') as other:
                        with self.assertRaises(BlockingIOError):fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
            return real(argv,**kwargs)
        def vendor_change(event):
            if event=='replaced:'+u.TARGETS['helper']:self.doctor['currentSentinelReady']=False
        with patch.object(u.subprocess,'run',locked):self.assertTrue(self.once('apply',vendor_change)['changed'])
        journal=self.mapping['state']/u.NAMESPACE/'transaction/journal.json';old=journal.read_bytes();before=self.images()
        for operation in ('apply','rollback','return','recover','plan'):
            start=len(self.calls)
            with self.assertRaisesRegex(u.Blocked,'fresh_accepted_doctor_required'):u.operate(operation,COMMIT,self.pin)
            self.assertEqual(sum(argv[0].endswith('current-doctor') for argv,_ in self.calls[start:]),1)
            self.assertEqual(self.images(),before);self.assertEqual(journal.read_bytes(),old)

    def test_local_drift_at_first_publication_blocks_before_helper(self):
        candidate=self.path('candidate/game-launch-admission');original=candidate.read_bytes()
        for kind,reason in (('head','clean_exact_main_required'),('dirty','clean_exact_main_required'),
                            ('candidate','candidate_drift'),('active','prefix_active'),('pending','launch_reservation_pending')):
            with self.subTest(kind=kind):
                def drift(event):
                    if event=='before-replace:'+u.TARGETS['helper']:
                        if kind=='head':self.head='f'*40
                        elif kind=='dirty':self.dirty=' M source'
                        elif kind=='candidate':candidate.write_bytes(b'foreign candidate')
                        elif kind=='active':self.active=True
                        else:self.put('state/game-launch-pending.json',b'pending')
                start=len(self.calls)
                with self.assertRaisesRegex(u.Blocked,reason):self.apply(drift)
                self.assertEqual(sum(argv[0].endswith('current-doctor') for argv,_ in self.calls[start:]),1)
                self.assertEqual(self.images(),self.before)
                self.head=COMMIT;self.dirty='';self.active=False;candidate.write_bytes(original)
                pending=self.path('state/game-launch-pending.json')
                if pending.exists():pending.unlink()
                self.once('recover');self.once('rollback')

    def test_lock_binding_drift_before_publication_blocks_helper(self):
        lock=self.path('state/games-hub.lock')
        def drift(event):
            if event=='before-replace:'+u.TARGETS['helper']:
                lock.rename(lock.with_name('retained-lock'));lock.write_bytes(b'');lock.chmod(0o600)
        with self.assertRaisesRegex(u.Blocked,'lock_binding_drift'):self.apply(drift)
        self.assertEqual(self.images(),self.before);self.once('recover')
if __name__=='__main__':unittest.main()
