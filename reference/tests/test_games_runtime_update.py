"""Exercise real adapter gates with fixed native paths mapped to owned fixtures."""
import sys
sys.dont_write_bytecode=True
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import subprocess
import os
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from test_wine_runtime_overlay import Fixture, COMMIT, w

SOURCE=Path(__file__).resolve().parents[1]/'bin/games-runtime-update'
loader=importlib.machinery.SourceFileLoader('games_runtime_update',str(SOURCE))
spec=importlib.util.spec_from_loader(loader.name,loader)
a=importlib.util.module_from_spec(spec)
loader.exec_module(a)


class Tests(unittest.TestCase):
    def setUp(self):
        self.f=Fixture();self.addCleanup(self.f.close)
        home=self.f.path
        self.control=home/'control'
        self.candidate=home/'payload/candidate'
        self.f.put('control/bin/wine-runtime-overlay',(SOURCE.parent/'wine-runtime-overlay').read_bytes(),0o700)
        self.f.put('control/bin/games-runtime-update',SOURCE.read_bytes(),0o700)
        self.f.put('control/bin/ds3-runtime',self.f.root.read('payload/ds3-runtime')[0],0o700)
        self.f.put('control/manifests/wine-runtime-overlay.json',self.f.root.read('payload/policy.json')[0])
        self.f.put('control/manifests/ds3-source-hub-v1.json',self.f.root.read('payload/source-hub-v1.json')[0])
        hub=w.decode(self.f.root.read('hub/manifest.json')[0])
        hub['criticalHashes'].update({a.PE32:w.digest(b'new pe32'),a.PE64:w.digest(b'new pe64')})
        hub['runtimeOverlayPolicySha256']=self.f.policy_sha
        self.f.put('control/manifests/games-hub.json',w.encode(hub))
        self.f.put('admission/game-launch-admission',b'reviewed admission helper',0o700)
        (home/'hub/profiles/prince').mkdir(mode=0o700)
        (home/'ds3/profiles/ds3').mkdir(mode=0o700)
        with self.f.root.lock():pass
        files={'winemac-i386.drv':b'new pe32','winemac-x86_64.drv':b'new pe64',
               'wine-source.tar.gz':b'fixture corresponding Wine sources','source.patch':b'fixture PE WM_QUIT correction',
               'LGPL-NOTICE.txt':b'Wine LGPL notice and corresponding sources accompany these exact PE files'}
        provenance={'schema':1,'peHashes':{a.PE32:w.digest(b'new pe32'),a.PE64:w.digest(b'new pe64')},
                    'sourceArchiveSha256':w.digest(files['wine-source.tar.gz']),'patchSha256':w.digest(files['source.patch']),
                    'upstreamCommit':None,'installed':False}
        files['build-provenance.json']=w.encode(provenance)
        for name,data in files.items():self.f.put('payload/candidate/'+name,data)
        self.definition={'schema':1,'id':'wine-runtime-update','owner':'control-games-hub',
                         'overlayPolicySha256':self.f.policy_sha,'candidateFiles':{name:w.digest(data) for name,data in files.items()},
                         'requiredLaunchAdmissionSha256':w.digest(b'reviewed admission helper')}
        self.f.put('control/manifests/wine-runtime-update.json',w.encode(self.definition))
        for path in a.ARCHIVE_IMMUTABLE_SOURCE:
            if not (self.control/path).exists():self.f.put('control/'+path,b'unchanged reviewed source fixture')
        self.source_blobs={path:(self.control/path).read_bytes() for path in a.ARCHIVE_IMMUTABLE_SOURCE}
        self.ancestor=True
        self.calls=[]
        self.doctor={'verdict':'PASS','gitOnly':False,'configurationSourceAccepted':True,'currentSentinelReady':True,'integratedMain':True}
        self.branch='main';self.dirty='';self.head=COMMIT;self.active=False
        mapping={'HOME':home,'CONTROL':self.control,'SOURCE_PATH':self.control/'bin/games-runtime-update',
                 'HUB':home/'hub','DS3':home/'ds3','STATE':home/'state','CANDIDATE':self.candidate,
                 'ADMISSION':home/'admission/game-launch-admission'}
        for key,value in mapping.items():
            active_patch=patch.object(a,key,value);active_patch.start();self.addCleanup(active_patch.stop)
        active_patch=patch.object(a.subprocess,'run',self.command);active_patch.start();self.addCleanup(active_patch.stop)

    def command(self,argv,**kwargs):
        self.calls.append((argv,kwargs))
        if argv[0] == '/usr/bin/git':
            if argv[-2:] == ['rev-parse','HEAD']:value=self.head
            elif argv[-2:] == ['branch','--show-current']:value=self.branch
            elif argv[-2:] == ['status','--porcelain']:value=self.dirty
            elif len(argv) >= 3 and argv[-3:-1] == ['cat-file','-t']:value='commit'
            elif 'merge-base' in argv:
                return SimpleNamespace(returncode=0 if self.ancestor else 1,stdout=b'')
            elif argv[-2] == 'show':
                return SimpleNamespace(returncode=0,stdout=self.source_blobs[argv[-1].split(':',1)[1]])
            else:raise AssertionError('unexpected git query')
            return SimpleNamespace(returncode=0,stdout=(value+'\n').encode())
        if argv == [str(self.control/'bin/current-doctor'),'--json']:
            return SimpleNamespace(returncode=0,stdout=json.dumps(self.doctor).encode())
        if argv[0] in (str(self.f.path/'hub/runtime/engine/bin/wineserver'),str(self.f.path/'ds3/runtime/engine/bin/wineserver')) and argv[1:] == ['-w']:
            self.assertEqual(kwargs['timeout'],3)
            self.assertEqual(set(kwargs['env']),{'HOME','PATH','WINEPREFIX','WINESERVER'})
            self.assertEqual(kwargs['env']['WINESERVER'],argv[0])
            if self.active:raise subprocess.TimeoutExpired(argv,3)
            return SimpleNamespace(returncode=0,stdout=b'')
        raise AssertionError('unexpected external command')

    def images(self):return self.f.images()

    def once(self,operation,commit=COMMIT,pin=None,old=None):
        start=len(self.calls)
        result=a.operate(operation,commit,pin,old)
        self.assertEqual(sum(argv[0].endswith('current-doctor') for argv,_ in self.calls[start:]),1)
        return result

    def test_plan_is_read_only_then_exact_apply_noop_rollback_return(self):
        before=self.images()
        plan=self.once('plan')
        self.assertEqual(plan['state'],'PLANNED_READ_ONLY')
        self.assertEqual(self.images(),before)
        self.assertFalse((self.f.path/'state/wine-runtime-overlay').exists())
        self.assertEqual([x[0][1] for x in self.calls if x[0][0].endswith('wineserver')],['-w','-w'])
        pin=plan['planSha256']
        changed=self.once('apply',pin=pin)
        self.assertTrue(changed['liveStateChanged']);self.assertFalse(changed['installedAcceptanceClaimed'])
        self.assertFalse(self.once('apply',pin=pin)['changed'])
        status=self.once('plan',pin=pin)
        self.assertEqual(status['journalPhase'],'applied')
        rollback=self.once('rollback',pin=pin)
        self.assertTrue(rollback['sourceRollbackSuccessorRequired'])
        self.assertEqual(self.images(),before)
        self.assertFalse(self.once('rollback',pin=pin)['changed'])
        self.assertTrue(self.once('return',pin=pin)['changed'])

    def test_doctor_fresh_exact_main_and_source_drift_gate_real_responses(self):
        before=self.images()
        variants=[dict(self.doctor,gitOnly=True),dict(self.doctor,currentSentinelReady=False),
                  dict(self.doctor,configurationSourceAccepted=1),dict(self.doctor,integratedMain=False),dict(self.doctor,verdict='PREPARED')]
        for doctor in variants:
            with self.subTest(doctor=doctor):
                self.doctor=doctor
                with self.assertRaisesRegex(a.Blocked,'fresh_accepted_doctor_required'):a.operate('plan',COMMIT)
                self.assertEqual(self.images(),before)
        self.doctor={'verdict':'PASS','gitOnly':False,'configurationSourceAccepted':True,'currentSentinelReady':True,'integratedMain':True}
        for key,value in (('branch','review-branch'),('dirty',' M bin/games-runtime-update'),('head','0'*40)):
            original=getattr(self,key);setattr(self,key,value)
            with self.assertRaisesRegex(a.Blocked,'clean_exact_main_required'):a.operate('plan',COMMIT)
            setattr(self,key,original)
        original=self.command
        def drift(argv,**kwargs):
            result=original(argv,**kwargs)
            if argv[0].endswith('current-doctor'):self.head='0'*40
            return result
        with patch.object(a.subprocess,'run',drift):
            with self.assertRaisesRegex(a.Blocked,'clean_exact_main_required'):a.operate('plan',COMMIT)
        self.assertEqual(self.images(),before)

    def test_active_pending_missing_helper_server_and_payload_drift_block_before_state_creation(self):
        before=self.images()
        self.active=True
        with self.assertRaisesRegex(a.Blocked,'prefix_active'):a.operate('plan',COMMIT)
        self.active=False
        self.f.put('state/game-launch-pending.json',b'owned pending marker')
        with self.assertRaisesRegex(a.Blocked,'launch_reservation_pending'):a.operate('plan',COMMIT)
        (self.f.path/'state/game-launch-pending.json').unlink()
        cases=[('admission/game-launch-admission','launch_admission_prerequisite'),
               ('hub/runtime/engine/bin/wineserver','unchanged_server_drift'),('payload/candidate/source.patch','candidate_source_drift')]
        for rel,reason in cases:
            path=self.f.path/rel;original=path.read_bytes();path.write_bytes(b'drift')
            with self.assertRaisesRegex(a.Blocked,reason):a.operate('plan',COMMIT)
            path.write_bytes(original)
        self.assertEqual(self.images(),before)
        self.assertFalse((self.f.path/'state/wine-runtime-overlay').exists())

    def test_exact_plan_binding_and_unknown_successor_receipt(self):
        plan=a.operate('plan',COMMIT)
        with self.assertRaisesRegex(a.Blocked,'prestate_changed_since_plan'):a.operate('apply',COMMIT,'0'*64)
        self.assertFalse((self.f.path/'state/wine-runtime-overlay').exists())
        a.operate('apply',COMMIT,plan['planSha256'])
        self.f.put('hub/receipt.json',b'newer native receipt')
        before=self.images()
        with self.assertRaisesRegex(RuntimeError,'target_unknown_drift'):a.operate('rollback',COMMIT,plan['planSha256'])
        self.assertEqual(self.images(),before)

    def test_source_only_adapter_has_no_arbitrary_root_or_fixture_authority_flag(self):
        with patch.object(a,'SOURCE_PATH',SOURCE):
            with self.assertRaisesRegex(a.Blocked,'canonical_source_required'):a.operate('plan',COMMIT)
        self.assertNotIn('--root',SOURCE.read_text())
        self.assertNotIn('--offline-fixture-gates',SOURCE.read_text())

    def test_source_provenance_binding_and_candidate_symlink_hardlink_drift(self):
        original=self.f.root.read('payload/candidate/build-provenance.json')[0]
        data=w.decode(original);data['installed']=True
        raw=w.encode(data);self.f.put('payload/candidate/build-provenance.json',raw)
        definition=dict(self.definition,candidateFiles=dict(self.definition['candidateFiles'],**{'build-provenance.json':w.digest(raw)}))
        self.f.put('control/manifests/wine-runtime-update.json',w.encode(definition))
        with self.assertRaisesRegex(a.Blocked,'candidate_provenance_binding'):a.operate('plan',COMMIT)

    def test_adapter_interruption_recovery_obeys_durable_apply_and_rollback_direction(self):
        before=self.images()
        plan=a.operate('plan',COMMIT);pin=plan['planSha256']
        real=a.os.replace
        hit=False
        def interrupt(*args,**kwargs):
            nonlocal hit
            result=real(*args,**kwargs)
            if args[1] == 'winemac.drv' and not hit:
                hit=True;raise OSError('injected after first PE publication')
            return result
        with patch.object(a.os,'replace',interrupt):
            with self.assertRaises(OSError):a.operate('apply',COMMIT,pin)
        self.assertTrue(self.once('recover',pin=pin)['changed'])
        after=self.images();self.assertNotEqual(after,before)
        hit=False
        def rollback_interrupt(*args,**kwargs):
            nonlocal hit
            result=real(*args,**kwargs)
            if args[1] == 'receipt.json' and not hit:
                hit=True;raise OSError('injected after first rollback publication')
            return result
        with patch.object(a.os,'replace',rollback_interrupt):
            with self.assertRaises(OSError):a.operate('rollback',COMMIT,pin)
        result=self.once('recover',pin=pin)
        self.assertEqual(result['state'],'ROLLED-BACK')
        self.assertTrue(result['sourceRollbackSuccessorRequired'])
        self.assertEqual(self.images(),before)

    def test_fixed_mapping_rejects_arbitrary_candidate_or_state_paths_and_existing_state_collision(self):
        engine=a.load_engine();root=a.make_root(engine)
        try:
            for rel in ('payload/candidate/../../foreign','state/transaction-other','payload/unlisted','admission/other'):
                with self.subTest(rel=rel):
                    with self.assertRaises(a.Blocked):root.read(rel)
        finally:root.close()
        plan=a.operate('plan',COMMIT)
        self.f.put('state/wine-runtime-overlay/owner.json',b'unknown existing owner')
        before=self.images()
        with self.assertRaisesRegex(a.Blocked,'state_namespace_collision'):a.operate('apply',COMMIT,plan['planSha256'])
        self.assertEqual(self.images(),before)

    def test_read_only_plan_refuses_missing_lock_and_candidate_link_aliases(self):
        lock=self.f.path/'state/games-hub.lock';lock.unlink()
        with self.assertRaises(FileNotFoundError):a.operate('plan',COMMIT)
        self.assertFalse((self.f.path/'state/wine-runtime-overlay').exists())
        with self.f.root.lock():pass
        candidate=self.f.path/'payload/candidate/winemac-i386.drv'
        original=candidate.read_bytes()
        outside=self.f.path/'outside-file';outside.write_bytes(original);outside.chmod(0o600)
        candidate.unlink();candidate.symlink_to(outside)
        with self.assertRaises(OSError):a.operate('plan',COMMIT)
        self.assertEqual(outside.read_bytes(),original)

    def test_existing_namespace_owner_drift_deletion_and_unknown_inventory_block_before_rollback(self):
        plan=a.operate('plan',COMMIT);pin=plan['planSha256']
        a.operate('apply',COMMIT,pin)
        before=self.images()
        marker=self.f.path/'state/wine-runtime-overlay/owner.json'
        original=marker.read_bytes()
        marker.write_bytes(b'unknown owner')
        for operation in ('plan','apply','rollback','return','recover'):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(a.Blocked,'state_namespace_collision'):a.operate(operation,COMMIT,pin)
                self.assertEqual(self.images(),before)
        marker.unlink()
        with self.assertRaises(FileNotFoundError):a.operate('rollback',COMMIT,pin)
        self.f.put('state/wine-runtime-overlay/owner.json',original)
        self.f.put('state/wine-runtime-overlay/unknown',b'preserve foreign state')
        with self.assertRaisesRegex(a.Blocked,'state_namespace_drift'):a.operate('rollback',COMMIT,pin)
        self.assertEqual(self.images(),before)

    def test_current_hub_source_bytes_must_match_declared_exact_successor(self):
        source=self.control/'manifests/games-hub.json'
        source.write_bytes(source.read_bytes()+b'\n')
        before=self.images()
        with self.assertRaisesRegex(a.Blocked,'declared_hub_source_successor_drift'):a.operate('plan',COMMIT)
        self.assertEqual(self.images(),before)

    def test_current_hub_status_overlay_validator_keeps_exact_critical_and_policy_binding(self):
        source=SOURCE.parent/'games-hub'
        if not source.is_file():source=SOURCE.parents[1].parent/'wiring/bin/games-hub'
        hub_loader=importlib.machinery.SourceFileLoader('candidate_hub_overlay',str(source))
        hub_spec=importlib.util.spec_from_loader(hub_loader.name,hub_loader)
        h=importlib.util.module_from_spec(hub_spec);hub_loader.exec_module(h)
        current=w.decode((self.control/'manifests/games-hub.json').read_bytes())
        with patch.object(h,'HERE',self.control):
            h.verify_overlay_manifest(current)
            wrong=dict(current,criticalHashes=dict(current['criticalHashes'],**{'engine/lib/wine/x86_64-unix/winebus.so':'0'*64}))
            with self.assertRaisesRegex(RuntimeError,'overlay_critical_binding'):h.verify_overlay_manifest(wrong)
            wrong=dict(current,runtimeOverlayPolicySha256='0'*64)
            with self.assertRaisesRegex(RuntimeError,'overlay_policy_pin'):h.verify_overlay_manifest(wrong)

    def test_fixed_adapter_plan_accepts_exact_internal_framework_directory_alias(self):
        for name in ('hub','ds3'):
            self.f.put(name+'/runtime/Frameworks/libfixture.dylib',b'framework code',0o700)
            deps=self.f.path/name/'runtime/deps';deps.mkdir(mode=0o700)
            (deps/'Frameworks').symlink_to('../Frameworks',target_is_directory=True)
            receipt=w.decode(self.f.root.read(name+'/receipt.json')[0])
            receipt['runtimeTreeSha256']=w.tree_hash(w.tree_rows(self.f.root,name+'/runtime'))
            self.f.put(name+'/receipt.json',w.encode(receipt))
        receipt=w.decode(self.f.root.read('ds3/borderless/receipt.json')[0])
        receipt['baseRuntimeTreeSha256']=w.decode(self.f.root.read('ds3/receipt.json')[0])['runtimeTreeSha256']
        self.f.put('ds3/borderless/receipt.json',w.encode(receipt))
        # Native adapter loads the canonical engine copy, as it would in source.
        self.f.put('control/bin/wine-runtime-overlay',(SOURCE.parent/'wine-runtime-overlay').read_bytes(),0o700)
        before=self.images()
        plan=a.operate('plan',COMMIT)
        self.assertEqual(plan['state'],'PLANNED_READ_ONLY')
        self.assertEqual(self.images(),before)
        self.assertFalse((self.f.path/'state/wine-runtime-overlay').exists())

    def prepare_large_old_transaction(self):
        engine=a.load_engine();real=engine.tree_rows
        extras=[[f'engine/lib/wine/x86_64-windows/archive-fixture-module-{i:05d}.dll',0o644,w.digest(str(i).encode())] for i in range(2400)]
        engine.tree_rows=lambda root,runtime:sorted(real(root,runtime)+extras,key=lambda row:row[0])
        active_patch=patch.object(a,'load_engine',return_value=engine);active_patch.start();self.addCleanup(active_patch.stop)
        for name in ('hub','ds3'):
            receipt=w.decode(self.f.root.read(name+'/receipt.json')[0]);receipt['runtimeTreeSha256']=w.tree_hash(engine.tree_rows(self.f.root,name+'/runtime'))
            self.f.put(name+'/receipt.json',w.encode(receipt))
        receipt=w.decode(self.f.root.read('ds3/borderless/receipt.json')[0]);receipt['baseRuntimeTreeSha256']=w.decode(self.f.root.read('ds3/receipt.json')[0])['runtimeTreeSha256']
        self.f.put('ds3/borderless/receipt.json',w.encode(receipt))
        root=a.make_root(engine)
        try:
            with a.read_only_lock(root):
                a.gate(engine,root,COMMIT);root.ensure_namespace()
                definition,policy=a.delivery(engine,root)
                result=engine.build(root,COMMIT,policy['desiredPEHashes'][a.PE32],policy['desiredPEHashes'][a.PE64],definition['overlayPolicySha256'],source_only=False)
        finally:root.close()
        self.head='b'*40
        return engine,result['planSha256']

    def namespace_image(self,path):
        info=path.lstat()
        rows=[('.',info.st_ino,stat.S_IMODE(info.st_mode),'directory')]
        for item in sorted(path.rglob('*')):
            info=item.lstat()
            rows.append((str(item.relative_to(path)),info.st_ino,stat.S_IMODE(info.st_mode),
                         'directory' if item.is_dir() else w.digest(item.read_bytes())))
        return rows

    def test_archive_prepared_large_old_transaction_retains_exact_namespace_and_targets(self):
        engine,pin=self.prepare_large_old_transaction()
        namespace=self.f.path/'state'/a.NAMESPACE
        retained=self.namespace_image(namespace);before=self.images()
        result=self.once('archive-prepared',self.head,pin,COMMIT)
        self.assertEqual(result['state'],'PREPARED_TRANSACTION_ARCHIVED')
        self.assertFalse(result['installedTargetsChanged']);self.assertFalse(result['oldTransactionRebound'])
        destination=self.f.path/'state'/a.ARCHIVES/(COMMIT+'-'+pin)
        self.assertFalse(namespace.exists());self.assertEqual(self.namespace_image(destination),retained)
        self.assertEqual(self.images(),before)
        self.assertEqual(w.decode((destination/'transaction/plan.json').read_bytes(),limit=engine.MAX_PLAN_BYTES)['acceptedCommit'],COMMIT)

    def test_archive_prepared_no_clobber_empty_nonempty_and_symlink_destination(self):
        engine,pin=self.prepare_large_old_transaction()
        self.f.put('state/'+a.ARCHIVES+'/owner.json',a.ARCHIVE_OWNER_BYTES)
        archive=self.f.path/'state'/a.ARCHIVES;archive.chmod(0o700)
        destination=archive/(COMMIT+'-'+pin)
        namespace=self.f.path/'state'/a.NAMESPACE
        retained=self.namespace_image(namespace);before=self.images()
        for kind in ('empty','nonempty','symlink'):
            with self.subTest(kind=kind):
                if kind == 'symlink':destination.symlink_to(namespace,target_is_directory=True)
                else:
                    destination.mkdir(mode=0o700)
                    if kind == 'nonempty':(destination/'sentinel').write_bytes(b'preserve')
                saved=None if kind == 'symlink' else self.namespace_image(destination)
                with self.assertRaises((a.Blocked,FileExistsError)):
                    a.operate('archive-prepared',self.head,pin,COMMIT)
                self.assertEqual(self.namespace_image(namespace),retained);self.assertEqual(self.images(),before)
                if kind == 'symlink':self.assertTrue(destination.is_symlink());destination.unlink()
                else:
                    self.assertEqual(self.namespace_image(destination),saved)
                    if kind == 'nonempty':(destination/'sentinel').unlink()
                    destination.rmdir()

    def test_archive_refuses_missing_lock_foreign_source_stages_and_nonprepared_without_target_writes(self):
        engine,pin=self.prepare_large_old_transaction();before=self.images()
        lock=self.f.path/'state/games-hub.lock';lock.unlink()
        with self.assertRaises(FileNotFoundError):a.operate('archive-prepared',self.head,pin,COMMIT)
        self.assertFalse(lock.exists())
        with self.f.root.lock():pass
        self.ancestor=False
        with self.assertRaisesRegex(a.Blocked,'old_source_not_ancestor'):a.operate('archive-prepared',self.head,pin,COMMIT)
        self.ancestor=True
        original=self.source_blobs[a.POLICY];self.source_blobs[a.POLICY]=b'foreign source'
        with self.assertRaisesRegex(a.Blocked,'archive_source_scope_changed'):a.operate('archive-prepared',self.head,pin,COMMIT)
        self.source_blobs[a.POLICY]=original
        journal=self.f.path/'state'/a.NAMESPACE/'transaction/journal.json';original=journal.read_bytes()
        for phase,intent in (('prepared','hub.pe32'),('applying',None),('rolling-back',None),('applied',None),('rolled-back',None)):
            data=w.decode(original);data.update(phase=phase,intent=intent);journal.write_bytes(w.encode(data))
            with self.assertRaisesRegex(a.Blocked,'archive_requires_prepared_null_intent'):a.operate('archive-prepared',self.head,pin,COMMIT)
        journal.write_bytes(original)
        stage=self.f.path/'state'/a.NAMESPACE/'transaction'/Path(engine.Root.stage_name('hub/runtime/'+a.PE32)).name
        stage.write_bytes(b'unknown stage');stage.chmod(0o600)
        with self.assertRaisesRegex(a.Blocked,'archive_requires_no_stages'):a.operate('archive-prepared',self.head,pin,COMMIT)
        stage.unlink()
        target=self.f.path/'hub/runtime'/a.PE32;mode=stat.S_IMODE(target.stat().st_mode);target.chmod(0o700)
        with self.assertRaisesRegex(RuntimeError,'target_unknown_drift'):a.operate('archive-prepared',self.head,pin,COMMIT)
        target.chmod(mode)
        self.assertEqual(self.images(),before)
        self.assertFalse((self.f.path/'state'/a.ARCHIVES).exists())

    def test_archive_requires_exact_before_backup_namespace_owner_and_old_bindings(self):
        engine,pin=self.prepare_large_old_transaction();before=self.images()
        for old,plan in (('bad',pin),(COMMIT,'0'*64),(self.head,pin)):
            with self.assertRaises((a.Blocked,RuntimeError)):a.operate('archive-prepared',self.head,plan,old)
        root=a.make_root(engine)
        try:
            tx=engine.Transaction(root,pin,gate=lambda _:a.gate(engine,root,self.head),source_only=False)
            target=self.f.path/'hub/runtime'/a.PE32;original=target.read_bytes();target.write_bytes(tx.images['hub.pe32']['after'][0])
            with self.assertRaisesRegex(a.Blocked,'archive_requires_complete_before'):a.operate('archive-prepared',self.head,pin,COMMIT)
            target.write_bytes(original)
        finally:root.close()
        base=self.f.path/'state'/a.NAMESPACE
        for rel in ('owner.json','transaction/hub.receipt.before'):
            path=base/rel;original=path.read_bytes();path.write_bytes(b'foreign')
            with self.assertRaises((a.Blocked,RuntimeError)):a.operate('archive-prepared',self.head,pin,COMMIT)
            path.write_bytes(original)
        self.assertEqual(self.images(),before)

    def test_archive_final_fresh_gate_journal_and_valid_target_stage_drift_preserve_namespace(self):
        engine,pin=self.prepare_large_old_transaction()
        namespace=self.f.path/'state'/a.NAMESPACE
        journal=namespace/'transaction/journal.json';original_journal=journal.read_bytes()
        before=self.images();identity=namespace.stat().st_ino
        real_gate=a.local_gate
        for kind in ('journal','target-stage'):
            with self.subTest(kind=kind):
                calls=0
                injected=None
                def mutate_after_final_gate(*args,**kwargs):
                    nonlocal calls,injected
                    result=real_gate(*args,**kwargs);calls+=1
                    if calls == 3:
                        if kind == 'journal':
                            data=w.decode(journal.read_bytes());data.update(phase='applying',intent='hub.pe32')
                            journal.write_bytes(w.encode(data))
                        else:
                            root=args[1]
                            data,mode=root.read('state/transaction/hub.pe32.after')
                            injected=namespace/engine.Root.stage_name('hub/runtime/'+a.PE32).split('/',1)[1]
                            injected.write_bytes(data);injected.chmod(mode)
                    return result
                reason='archive_requires_prepared_null_intent' if kind == 'journal' else 'archive_requires_no_stages'
                with patch.object(a,'local_gate',mutate_after_final_gate):
                    with self.assertRaisesRegex(a.Blocked,reason):
                        a.operate('archive-prepared',self.head,pin,COMMIT)
                self.assertEqual(calls,3)
                self.assertEqual(namespace.stat().st_ino,identity);self.assertEqual(self.images(),before)
                self.assertFalse((self.f.path/'state'/a.ARCHIVES/(COMMIT+'-'+pin)).exists())
                journal.write_bytes(original_journal)
                if injected is not None:injected.unlink()

    def test_doctor_under_lock_and_next_failed_invocation_blocks_noop_and_recovery(self):
        import fcntl
        real=self.command
        def locked(argv,**kwargs):
            if argv[0].endswith('current-doctor'):
                with (self.f.path/'state/games-hub.lock').open('rb') as other:
                    with self.assertRaises(BlockingIOError):fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
            return real(argv,**kwargs)
        with patch.object(a.subprocess,'run',locked):
            pin=self.once('plan')['planSha256'];self.once('apply',pin=pin)
        journal=self.f.path/'state'/a.NAMESPACE/'transaction/journal.json'
        before=self.images();old=journal.read_bytes();self.doctor['currentSentinelReady']=False
        for operation in ('apply','rollback','return','recover','plan'):
            start=len(self.calls)
            with self.assertRaisesRegex(a.Blocked,'fresh_accepted_doctor_required'):a.operate(operation,COMMIT,pin)
            self.assertEqual(sum(argv[0].endswith('current-doctor') for argv,_ in self.calls[start:]),1)
            self.assertEqual(self.images(),before);self.assertEqual(journal.read_bytes(),old)

    def test_local_drift_at_first_publication_is_checked_without_second_doctor(self):
        pin=self.once('plan')['planSha256'];real_make=a.make_root
        target=self.f.path/'hub/runtime'/a.PE32;original_target=target.read_bytes()
        candidate=self.candidate/'source.patch';original_candidate=candidate.read_bytes()
        cases=(('head','clean_exact_main_required'),('dirty','clean_exact_main_required'),
               ('active','prefix_active'),('candidate','candidate_source_drift'),('preimage','target_changed_before_replace'))
        for kind,reason in cases:
            with self.subTest(kind=kind):
                def make(engine):
                    root=real_make(engine);replace=root.replace
                    def mutate(rel,data,mode,expected,event=lambda _:None):
                        def boundary(name):
                            event(name)
                            if name=='before-replace:hub/runtime/'+a.PE32:
                                if kind=='head':self.head='f'*40
                                elif kind=='dirty':self.dirty=' M source'
                                elif kind=='active':self.active=True
                                elif kind=='candidate':candidate.write_bytes(b'foreign candidate')
                                else:target.write_bytes(b'foreign target')
                        return replace(rel,data,mode,expected,boundary)
                    root.replace=mutate;return root
                start=len(self.calls)
                with patch.object(a,'make_root',make):
                    with self.assertRaisesRegex(RuntimeError,reason):a.operate('apply',COMMIT,pin)
                self.assertEqual(sum(argv[0].endswith('current-doctor') for argv,_ in self.calls[start:]),1)
                self.assertEqual(target.read_bytes(),b'foreign target' if kind=='preimage' else original_target)
                self.head=COMMIT;self.dirty='';self.active=False;candidate.write_bytes(original_candidate);target.write_bytes(original_target)
                self.once('recover',pin=pin);self.once('rollback',pin=pin)

    def test_entry_vendor_observation_is_not_repeated_mid_operation(self):
        pin=self.once('plan')['planSha256'];real=a.os.replace
        def changed(*args,**kwargs):
            result=real(*args,**kwargs)
            if args[1]=='winemac.drv':self.doctor['currentSentinelReady']=False
            return result
        with patch.object(a.os,'replace',changed):self.assertTrue(self.once('apply',pin=pin)['changed'])
        before=self.images()
        with self.assertRaisesRegex(a.Blocked,'fresh_accepted_doctor_required'):a.operate('apply',COMMIT,pin)
        self.assertEqual(self.images(),before)

    def test_root_lock_reentry_exception_cleanup_and_separate_root_isolation(self):
        engine=a.load_engine();root=a.make_root(engine);other=a.make_root(engine)
        try:
            with self.assertRaisesRegex(RuntimeError,'injected'):
                with root.lock():
                    with root.lock():
                        with self.assertRaises(BlockingIOError):
                            with other.lock():pass
                        raise RuntimeError('injected')
            self.assertFalse(hasattr(root,'_operation_lock_check'))
            with other.lock():pass
            with root.lock():pass
        finally:root.close();other.close()

    def test_lock_binding_drift_before_publication_blocks_target(self):
        pin=self.once('plan')['planSha256'];make=a.make_root
        lock=self.f.path/'state/games-hub.lock';target=self.f.path/'hub/runtime'/a.PE32;before=target.read_bytes()
        def changed(engine):
            root=make(engine);replace=root.replace
            def publish(rel,data,mode,expected,event=lambda _:None):
                def drift(name):
                    event(name)
                    if name=='before-replace:hub/runtime/'+a.PE32:
                        lock.rename(lock.with_name('retained-lock'));lock.write_bytes(b'');lock.chmod(0o600)
                return replace(rel,data,mode,expected,drift)
            root.replace=publish;return root
        with patch.object(a,'make_root',changed):
            with self.assertRaisesRegex(a.Blocked,'lock_binding_drift'):a.operate('apply',COMMIT,pin)
        self.assertEqual(target.read_bytes(),before)
        self.once('recover',pin=pin)

    def test_direct_engine_root_retains_legacy_explicit_full_gate(self):
        engine=a.load_engine();root=a.make_root(engine)
        try:
            with root.lock():
                a.gate(engine,root,COMMIT)
                definition,policy=a.delivery(engine,root);root.ensure_namespace()
                prepared=engine.build(root,COMMIT,policy['desiredPEHashes'][a.PE32],policy['desiredPEHashes'][a.PE64],definition['overlayPolicySha256'],source_only=False)
            self.assertFalse(hasattr(root,'_publication_check'))
            start=len(self.calls)
            tx=engine.Transaction(root,prepared['planSha256'],gate=lambda exact:a.gate(engine,root,exact),source_only=False)
            self.assertTrue(tx.run('after')['changed'])
            self.assertGreater(sum(argv[0].endswith('current-doctor') for argv,_ in self.calls[start:]),1)
        finally:root.close()


if __name__ == '__main__':unittest.main()
