"""Offline contract tests. Every mutation is under disposable fixture roots."""
import sys
sys.dont_write_bytecode = True
import copy
import fcntl
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]/'bin/wine-runtime-overlay'
DS3_SOURCE = SOURCE.parent/'ds3-runtime'
if not DS3_SOURCE.is_file():
    DS3_SOURCE = Path(__file__).resolve().parents[2]/'wiring/bin/ds3-runtime'
loader = importlib.machinery.SourceFileLoader('wine_runtime_overlay', str(SOURCE))
spec = importlib.util.spec_from_loader(loader.name, loader)
w = importlib.util.module_from_spec(spec)
loader.exec_module(w)
COMMIT = 'a'*40


class Interrupted(BaseException):
    pass


def gates(_):
    return {'sourceAccepted':True,'doctorReady':True,'prefixesInactive':True}


class Fixture:
    def __init__(self):
        self.path = Path(tempfile.mkdtemp(prefix='wine-overlay-fixture-')).resolve()
        self.path.chmod(0o700)
        def put(rel, data, mode=0o600):
            p = self.path/rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
            p.chmod(mode)
        self.put = put
        put('.fixture-only',w.MARKER)
        (self.path/'state').mkdir(mode=0o700)
        critical = {
            'engine/bin/wine':b'wine','engine/bin/wineserver':b'server',
            'engine/lib/wine/x86_64-unix/ntdll.so':b'ntdll',
            w.METAL:b'original dxmt',
            'engine/lib/wine/x86_64-windows/d3d11.dll':b'd3d11',
            'engine/lib/wine/x86_64-windows/dxgi.dll':b'dxgi',
            'engine/lib/wine/x86_64-unix/winebus.so':b'controllers',
            'engine/lib/wine/x86_64-unix/libgtm-controller-SDL2.dylib':b'SDL2',
        }
        for name in ('hub','ds3'):
            for rel,data in critical.items():
                put(name+'/runtime/'+rel, data, 0o700)
            put(name+'/runtime/'+w.UNIX,b'unchanged unix',0o700)
            put(name+'/runtime/'+w.PE32,b'old pe32',0o600)
            put(name+'/runtime/'+w.PE,b'old pe64',0o600)
            put(name+'/runtime/sources/notices.txt',b'LGPL/MIT source notices')
            # Profile poison ensures no profile/account/save content is opened.
            (self.path/name/'profiles').mkdir(mode=0o700)
            (self.path/name/'profiles'/'private-sentinel').symlink_to('/not-readable-or-writable')
        put('ds3/runtime/'+w.METAL,b'ds3 dxmt with marshal fix',0o700)
        put('ds3/runtime/'+w.DONOR,b'original dxmt',0o700)
        put('hub/games-play',b'hub launcher',0o700)
        put('ds3/ds3-play',b'ds3 launcher',0o700)
        put('ds3/ds3-runtime',b'ds3 lifecycle',0o700)
        hm = {'schema':1,'id':'games-hub','owner':'control-games-hub','criticalHashes':{k:w.digest(v) for k,v in critical.items()},'controllerOverlay':{'winebus.so':w.digest(b'controllers')},'profilePolicy':'opaque-only'}
        put('hub/manifest.json',w.encode(hm))
        dm = {'schema':1,'id':'ds3-marshal-fix','owner':'control-ds3-marshal-fix','sourceCriticalHashes':hm['criticalHashes'],'sourceHubManifestSha256':w.digest(w.encode(hm)),'candidateSha256':w.digest(b'ds3 dxmt with marshal fix'),'donorSha256':w.digest(b'original dxmt'),'provenanceSha256':'e'*64,'singleLauncher':True,'windowMode':'WINDOW'}
        put('ds3/manifest.json',w.encode(dm))
        bm = {'schema':1,'id':'ds3-borderless','owner':'control-ds3-marshal-fix','nativeBinding':{'winemetalSha256':dm['candidateSha256'],'donorSha256':dm['donorSha256'],'d3d11Sha256':hm['criticalHashes']['engine/lib/wine/x86_64-windows/d3d11.dll']},'helperSha256':w.digest(b'borderless helper'),'sourceSha256':w.digest(b'helper source'),'provenanceSha256':w.digest(b'helper provenance'),'fixtureReportSha256':w.digest(b'helper fixtures')}
        put('ds3/borderless/manifest.json',w.encode(bm))
        put('ds3/borderless/helper.exe',b'borderless helper')
        put('ds3/borderless/helper.c',b'helper source')
        put('ds3/borderless/build-provenance.json',b'helper provenance')
        put('ds3/borderless/final-fixture-results.json',b'helper fixtures')
        self.root = w.Root(self.path)
        for name,manifest,owner in (('hub',hm,'control-games-hub'),('ds3',dm,'control-ds3-marshal-fix')):
            receipt = {'schema':1,'owner':owner,'commit':'b'*40,'manifestSha256':w.digest(w.encode(manifest)),'runtimeTreeSha256':w.tree_hash(w.tree_rows(self.root,name+'/runtime')),'launcherSha256':w.digest((self.path/name/('games-play' if name == 'hub' else 'ds3-play')).read_bytes()),'appPolicySha256':'c'*64,'appLaunchers':{'preserve':'native app inventory'},'profileFiles':123}
            if name == 'ds3':
                receipt.update(lifecycleSha256=w.digest(b'ds3 lifecycle'),sourceRuntimeTreeSha256='d'*64,graphics={'Width':1920,'Height':1080})
                self.ds3_receipt = receipt
            put(name+'/receipt.json',w.encode(receipt))
        dr = self.ds3_receipt
        put('ds3/borderless/receipt.json',w.encode({'schema':1,'owner':'control-ds3-marshal-fix','commit':'b'*40,'manifestSha256':w.digest(w.encode(bm)),'baseRuntimeTreeSha256':dr['runtimeTreeSha256'],'baseManifestSha256':dr['manifestSha256']}))
        put('payload/winemac-i386.drv',b'new pe32',0o600)
        put('payload/winemac-x86_64.drv',b'new pe64',0o600)
        lifecycle=DS3_SOURCE.read_bytes()
        put('payload/ds3-runtime',lifecycle,0o700)
        policy={'schema':1,'id':'wine-runtime-overlay','owner':'control-games-hub',
                'previousHubManifestSha256':w.digest(w.encode(hm)),'previousDS3ManifestSha256':w.digest(w.encode(dm)),
                'previousHubCriticalHashes':hm['criticalHashes'],'sourceHubManifestSha256':dm['sourceHubManifestSha256'],
                'sourceCriticalHashes':dm['sourceCriticalHashes'],'desiredPEHashes':{w.PE32:w.digest(b'new pe32'),w.PE:w.digest(b'new pe64')},'lifecycleSha256':w.digest(lifecycle)}
        self.policy_sha=w.digest(w.encode(policy))
        put('payload/policy.json',w.encode(policy))
        put('payload/source-hub-v1.json',w.encode(hm))

    def plan(self):
        with self.root.lock():
            result = w.build(self.root,COMMIT,w.digest(b'new pe32'),w.digest(b'new pe64'),self.policy_sha)
        self.plan_sha = result['planSha256']
        return result

    def tx(self, event=lambda _: None, gate=gates):
        return w.Transaction(self.root,self.plan_sha,event,gate)

    def images(self):
        return {key:self.root.read(rel) for key,rel in w.TARGETS.items()}

    def close(self):
        self.root.close()
        shutil.rmtree(self.path)


class Tests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.addCleanup(self.f.close)

    def test_apply_noop_rollback_return_preserve_every_unrelated_binding(self):
        before = self.f.images()
        old_hm = w.decode(before['hub.manifest'][0])
        old_dm = w.decode(before['ds3.manifest'][0])
        original_rows = {name:w.tree_rows(self.f.root,name+'/runtime') for name in ('hub','ds3')}
        self.f.plan()
        tx = self.f.tx()
        self.assertTrue(tx.run('after')['changed'])
        self.assertFalse(self.f.tx().run('after')['changed'])
        for name in ('hub','ds3'):
            current = w.decode(self.f.root.read(name+'/receipt.json')[0])
            previous = w.decode(before[name+'.receipt'][0])
            for key in set(previous)-{'commit','manifestSha256','runtimeTreeSha256','lifecycleSha256'}:
                self.assertEqual(current[key],previous[key])
            self.assertEqual(current['runtimeTreeSha256'],w.tree_hash(w.tree_rows(self.f.root,name+'/runtime')))
            for row in w.tree_rows(self.f.root,name+'/runtime'):
                if row[0] not in (w.PE32,w.PE):
                    self.assertIn(row,original_rows[name])
        hm = w.decode(self.f.root.read('hub/manifest.json')[0])
        dm = w.decode(self.f.root.read('ds3/manifest.json')[0])
        for key in set(old_hm)-{'criticalHashes'}:
            self.assertEqual(hm[key],old_hm[key])
        for key in set(old_dm)-{'schema'}:
            self.assertEqual(dm[key],old_dm[key])
        self.assertEqual(dm['runtimeOverrides'],{w.PE32:w.digest(b'new pe32'),w.PE:w.digest(b'new pe64')})
        self.assertEqual(dm['schema'],2)
        self.assertEqual(dm['sourceCriticalHashes'],old_dm['sourceCriticalHashes'])
        self.assertEqual(dm['sourceHubManifestSha256'],old_dm['sourceHubManifestSha256'])
        self.assertTrue(self.f.tx().run('before')['changed'])
        self.assertEqual(self.f.images(),before)
        self.assertFalse(self.f.tx().run('before')['changed'])
        self.assertTrue(self.f.tx().run('after')['changed'])

    def test_every_target_journal_and_stage_interruption_recovers(self):
        self.f.plan()
        events=[]
        self.f.tx(events.append).run('after')
        # Each event is a distinct durable boundary; inject both forward and rollback.
        for side in ('after','before'):
            for index in range(len(events)):
                with self.subTest(side=side,index=index):
                    f=Fixture()
                    try:
                        f.plan()
                        if side == 'before':
                            f.tx().run('after')
                        count=0
                        def stop(_):
                            nonlocal count
                            if count == index:
                                raise Interrupted()
                            count+=1
                        try:
                            f.tx(stop).run(side)
                        except Interrupted:
                            f.tx().run('after',recover=True)
                        self.assertTrue(f.tx().side(side))
                    finally:
                        f.close()

    def test_os_replace_interruption_before_and_after_each_write(self):
        self.f.plan()
        actual_replace = os.replace
        counts=[]
        def count(*args,**kwargs):
            counts.append(1)
            return actual_replace(*args,**kwargs)
        with patch.object(w.os,'replace',count):
            self.f.tx().run('after')
        for side in ('after','before'):
            for after in (False,True):
                for nth in range(len(counts)):
                    with self.subTest(side=side,after=after,nth=nth):
                        f=Fixture()
                        try:
                            f.plan()
                            if side == 'before':
                                f.tx().run('after')
                            called=0
                            def replace(*args,**kwargs):
                                nonlocal called
                                current=called
                                called+=1
                                if current == nth and not after:
                                    raise Interrupted()
                                value=actual_replace(*args,**kwargs)
                                if current == nth and after:
                                    raise Interrupted()
                                return value
                            with patch.object(w.os,'replace',replace):
                                with self.assertRaises(Interrupted):
                                    f.tx().run(side)
                            f.tx().run('after',recover=True)
                            self.assertTrue(f.tx().side(side))
                        finally:
                            f.close()

    def test_unknown_successor_receipt_blocks_rollback_before_any_target_write(self):
        self.f.plan()
        self.f.tx().run('after')
        self.f.put('hub/receipt.json',b'newer independent native launcher receipt')
        before=self.f.images()
        with self.assertRaisesRegex(w.Blocked,'target_unknown_drift'):
            self.f.tx().run('before')
        self.assertEqual(self.f.images(),before)

    def test_runtime_guard_and_backup_drift_block_all_mutation(self):
        cases=('hub/runtime/engine/lib/wine/x86_64-unix/winebus.so','ds3/ds3-play','state/transaction/hub.receipt.before')
        for rel in cases:
            with self.subTest(rel=rel):
                f=Fixture()
                try:
                    f.plan()
                    p=f.path/rel
                    original=p.read_bytes()
                    p.write_bytes(b'drift')
                    before=f.images()
                    with self.assertRaises(w.Blocked):
                        f.tx().run('after')
                    self.assertEqual(f.images(),before)
                    p.write_bytes(original)
                finally:
                    f.close()

    def test_candidate_and_plan_pins_are_external_required_bindings(self):
        with self.assertRaisesRegex(w.Blocked,'payload_pin_mismatch'):
            w.build(self.f.root,COMMIT,'0'*64,w.digest(b'new pe64'),self.f.policy_sha)
        self.assertFalse((self.f.path/'state/transaction').exists())
        self.f.plan()
        with self.assertRaisesRegex(w.Blocked,'plan_binding_drift'):
            w.Transaction(self.f.root,'0'*64,gate=gates)

    def test_fresh_gates_are_exact_and_rechecked_under_lock(self):
        self.f.plan()
        before=self.f.images()
        for result in ({'sourceAccepted':True,'doctorReady':True,'prefixesInactive':False},
                       {'sourceAccepted':1,'doctorReady':True,'prefixesInactive':True},
                       {'sourceAccepted':True,'doctorReady':True,'prefixesInactive':True,'extra':True}):
            with self.assertRaisesRegex(w.Blocked,'fresh_gate_rejected'):
                self.f.tx(gate=lambda _,value=result:value).run('after')
            self.assertEqual(self.f.images(),before)
        with self.assertRaisesRegex(w.Blocked,'fresh_gate_required'):
            self.f.tx(gate=None).run('after')

    def test_symlink_and_hardlink_targets_and_backups_rejected(self):
        for rel in ('hub/runtime/'+w.UNIX,'hub/receipt.json','state/transaction/hub.pe32.before'):
            for link in ('symlink','hardlink'):
                with self.subTest(rel=rel,link=link):
                    f=Fixture()
                    try:
                        f.plan()
                        p=f.path/rel
                        other=f.path/'outside-sentinel'
                        saved=p.read_bytes()
                        other.write_bytes(saved)
                        other.chmod(0o600)
                        p.unlink()
                        (p.symlink_to(other) if link == 'symlink' else os.link(other,p))
                        with self.assertRaises((w.Blocked,OSError)):
                            f.tx().run('after')
                        self.assertEqual(other.read_bytes(),saved)
                    finally:
                        f.close()

    def test_shared_lock_blocks_second_writer_and_hardlink_lock(self):
        self.f.plan()
        with self.f.root.lock():
            with self.assertRaises(BlockingIOError):
                self.f.tx().run('after')
        p=self.f.path/'state/games-hub.lock'
        os.link(p,self.f.path/'other-lock')
        with self.assertRaisesRegex(w.Blocked,'unsafe_file'):
            self.f.tx().run('after')

    def test_stage_hijack_does_not_replace_target(self):
        self.f.plan()
        before=self.f.images()
        def hijack(event):
            if event == 'before-replace:hub/runtime/'+w.PE32:
                rel=self.f.root.stage_name('hub/runtime/'+w.PE32)
                self.f.put(rel,b'unknown bytes',0o600)
        with self.assertRaisesRegex(w.Blocked,'replacement_stage_drift'):
            self.f.tx(hijack).run('after')
        self.assertEqual(self.f.images(),before)

    def test_stage_mode_symlink_and_hardlink_drift_never_replace_target(self):
        for kind in ('mode','symlink','hardlink'):
            with self.subTest(kind=kind):
                f=Fixture()
                try:
                    f.plan()
                    before=f.images()
                    outside=f.path/'outside-sentinel'
                    outside.write_bytes(b'outside untouched');outside.chmod(0o600)
                    def drift(event):
                        if event == 'before-replace:hub/runtime/'+w.PE32:
                            stage=f.path/f.root.stage_name('hub/runtime/'+w.PE32)
                            if kind == 'mode':
                                stage.chmod(0o700)
                            else:
                                stage.unlink()
                                (stage.symlink_to(outside) if kind == 'symlink' else os.link(outside,stage))
                    with self.assertRaises((w.Blocked,OSError)):
                        f.tx(drift).run('after')
                    self.assertEqual(f.images(),before)
                    self.assertEqual(outside.read_bytes(),b'outside untouched')
                finally:
                    f.close()

    def test_partial_stage_write_failure_retains_target_and_fails_closed_recovery(self):
        self.f.plan()
        before=self.f.images()
        original=os.write
        def partial(fd,data):
            original(fd,data[:1])
            raise OSError('injected partial write')
        with patch.object(w.os,'write',partial):
            with self.assertRaises(OSError):
                self.f.tx().run('after')
        self.assertEqual(self.f.images(),before)
        with self.assertRaises(w.Blocked):
            self.f.tx().run('after',recover=True)
        self.assertEqual(self.f.images(),before)

    def test_directory_symlink_redirection_does_not_touch_outside(self):
        self.f.plan()
        outside=self.f.path/'outside-directory'
        outside.mkdir()
        (outside/'winemac.so').write_bytes(b'outside untouched')
        directory=self.f.path/'hub/runtime/engine/lib/wine/i386-windows'
        def redirect(event):
            if event == 'before-replace:hub/runtime/'+w.PE32:
                directory.rename(directory.with_name('saved-unix'))
                directory.symlink_to(outside,target_is_directory=True)
        with self.assertRaises((w.Blocked,OSError)):
            self.f.tx(redirect).run('after')
        self.assertEqual((outside/'winemac.so').read_bytes(),b'outside untouched')
        self.assertEqual(sorted(p.name for p in outside.iterdir()),['winemac.so'])

    def test_arbitrary_root_and_arbitrary_target_schema_rejected(self):
        with self.assertRaisesRegex(w.Blocked,'fixture_root_required'):
            w.Root(Path('/Users/example-user/Library/Application Support/Adapted Games'))
        self.f.plan()
        rel='state/transaction/plan.json'
        plan=w.decode(self.f.root.read(rel)[0])
        plan['targets']['arbitrary-path']={'before':{'sha256':'0'*64,'mode':0o600},'after':{'sha256':'0'*64,'mode':0o600}}
        raw=w.encode(plan)
        self.f.put(rel,raw)
        with self.assertRaisesRegex(w.Blocked,'plan_scope'):
            w.Transaction(self.f.root,w.digest(raw),gate=gates)

    def test_builder_failure_across_all_snapshot_writes_changes_no_target(self):
        self.f.plan()
        total=len(w.TARGETS)*2+2
        for nth in range(total):
            with self.subTest(nth=nth):
                f=Fixture()
                try:
                    before=f.images()
                    original=f.root.write_new
                    count=0
                    def fail(*args,**kwargs):
                        nonlocal count
                        if count == nth:
                            raise OSError('injected write failure')
                        count+=1
                        return original(*args,**kwargs)
                    with patch.object(f.root,'write_new',fail):
                        with self.assertRaises(OSError):
                            f.plan()
                    self.assertEqual(f.images(),before)
                    with self.assertRaisesRegex(w.Blocked,'transaction_exists'):
                        f.plan()
                finally:
                    f.close()

    def test_prepared_rollback_journal_interruption_recovers_exact_noop(self):
        self.f.plan()
        original=os.replace
        def fail(*args,**kwargs):
            raise Interrupted()
        with patch.object(w.os,'replace',fail):
            with self.assertRaises(Interrupted):
                self.f.tx().run('before')
        self.assertFalse(self.f.tx().run('after',recover=True)['changed'])
        self.assertTrue(self.f.tx().side('before'))

    def test_outstanding_journal_stage_blocks_ordinary_plan_noop_rollback_and_return(self):
        self.f.plan();self.f.tx().run('after')
        before=self.f.images()
        stage=self.f.root.stage_name('state/transaction/journal.json')
        cases=(b'{malformed journal',w.encode({'schema':1,'planSha256':'0'*64,'phase':'rolling-back','intent':None}))
        for raw in cases:
            with self.subTest(stage=raw):
                self.f.root.write_new(stage,raw)
                try:
                    tx=self.f.tx()
                    # Existing native plan calls preflight(mixed=True); mixed
                    # target allowance must not imply journal-stage allowance.
                    with self.assertRaisesRegex(w.Blocked,'outstanding_journal_stage_requires_recovery'):
                        tx.preflight(mixed=True)
                    for side in ('after','before','after'):
                        with self.assertRaisesRegex(w.Blocked,'outstanding_journal_stage_requires_recovery'):
                            self.f.tx().run(side)
                        self.assertEqual(self.f.images(),before)
                    with self.assertRaises(w.Blocked):
                        self.f.tx().run('after',recover=True)
                    self.assertEqual(self.f.images(),before)
                    self.assertEqual(self.f.root.read(stage)[0],raw)
                    self.assertEqual(self.f.tx().journal()['phase'],'applied')
                finally:
                    # Delete only this test's exact owned fixture injection.
                    (self.f.path/stage).unlink()

    def test_natural_rollback_journal_stage_refuses_applied_noop_then_recovery_rolls_back(self):
        original_before=self.f.images()
        self.f.plan();self.f.tx().run('after')
        applied=self.f.images()
        original_replace=os.replace
        def interrupt(src,dst,**kwargs):
            if dst == 'journal.json':
                raise Interrupted()
            return original_replace(src,dst,**kwargs)
        with patch.object(w.os,'replace',interrupt):
            with self.assertRaises(Interrupted):
                self.f.tx().run('before')
        self.assertEqual(self.f.tx().journal()['phase'],'applied')
        stage=self.f.root.stage_name('state/transaction/journal.json')
        self.assertEqual(w.decode(self.f.root.read(stage)[0])['phase'],'rolling-back')
        self.assertEqual(self.f.images(),applied)
        with self.assertRaisesRegex(w.Blocked,'outstanding_journal_stage_requires_recovery'):
            self.f.tx().preflight(mixed=True)
        for side in ('after','before'):
            with self.assertRaisesRegex(w.Blocked,'outstanding_journal_stage_requires_recovery'):
                self.f.tx().run(side)
        recovered=self.f.tx().run('after',recover=True)
        self.assertEqual(recovered['state'],'ROLLED-BACK')
        self.assertTrue(recovered['changed'])
        self.assertEqual(self.f.images(),original_before)
        self.assertFalse(self.f.root.exists(stage))
        self.assertEqual(self.f.tx().journal()['phase'],'rolled-back')
        self.assertFalse(self.f.tx().run('before')['changed'])

    def test_journal_stage_appearing_during_fresh_gate_still_blocks_readiness_noop(self):
        self.f.plan();self.f.tx().run('after')
        before=self.f.images()
        stage=self.f.root.stage_name('state/transaction/journal.json')
        def creates_stage(commit):
            self.f.root.write_new(stage,w.encode({'schema':1,'planSha256':self.f.plan_sha,'phase':'rolling-back','intent':None}))
            return gates(commit)
        with self.assertRaisesRegex(w.Blocked,'outstanding_journal_stage_requires_recovery'):
            self.f.tx(gate=creates_stage).run('after')
        self.assertEqual(self.f.images(),before)
        self.assertEqual(self.f.tx().journal()['phase'],'applied')

    def test_realistic_large_plan_roundtrip_preserves_small_metadata_cap(self):
        real=w.tree_rows
        extras=[[f'engine/lib/wine/x86_64-windows/fixture-runtime-module-{i:05d}.dll',0o644,w.digest(str(i).encode())] for i in range(2400)]
        def rows(root,runtime):return sorted(real(root,runtime)+extras,key=lambda row:row[0])
        for name in ('hub','ds3'):
            receipt=w.decode(self.f.root.read(name+'/receipt.json')[0]);receipt['runtimeTreeSha256']=w.tree_hash(rows(self.f.root,name+'/runtime'))
            self.f.put(name+'/receipt.json',w.encode(receipt))
        receipt=w.decode(self.f.root.read('ds3/borderless/receipt.json')[0]);receipt['baseRuntimeTreeSha256']=w.decode(self.f.root.read('ds3/receipt.json')[0])['runtimeTreeSha256']
        self.f.put('ds3/borderless/receipt.json',w.encode(receipt))
        with patch.object(w,'tree_rows',rows):
            self.f.plan()
            raw=self.f.root.read('state/transaction/plan.json')[0]
            self.assertGreater(len(raw),w.MAX_METADATA_BYTES)
            self.assertLessEqual(len(raw),w.MAX_PLAN_BYTES)
            with self.assertRaisesRegex(w.Blocked,'metadata_limit'):w.decode(raw)
            tx=self.f.tx();tx.preflight();self.assertTrue(tx.side('before'))
            self.assertEqual(w.encode(tx.plan),raw)

    def test_over_plan_cap_writer_refuses_before_any_transaction_staging(self):
        real=w.tree_rows
        extras=[[f'engine/lib/wine/x86_64-windows/fixture-runtime-module-{i:05d}.dll',0o644,w.digest(str(i).encode())] for i in range(16000)]
        def rows(root,runtime):return sorted(real(root,runtime)+extras,key=lambda row:row[0])
        for name in ('hub','ds3'):
            receipt=w.decode(self.f.root.read(name+'/receipt.json')[0]);receipt['runtimeTreeSha256']=w.tree_hash(rows(self.f.root,name+'/runtime'))
            self.f.put(name+'/receipt.json',w.encode(receipt))
        receipt=w.decode(self.f.root.read('ds3/borderless/receipt.json')[0]);receipt['baseRuntimeTreeSha256']=w.decode(self.f.root.read('ds3/receipt.json')[0])['runtimeTreeSha256']
        self.f.put('ds3/borderless/receipt.json',w.encode(receipt))
        before=self.f.images()
        with patch.object(w,'tree_rows',rows),patch.object(self.f.root,'mkdir',side_effect=AssertionError('must not stage')),patch.object(self.f.root,'write_new',side_effect=AssertionError('must not stage')):
            for publish in (False,True):
                with self.assertRaisesRegex(w.Blocked,'plan_metadata_limit'):
                    w.build(self.f.root,COMMIT,w.digest(b'new pe32'),w.digest(b'new pe64'),self.f.policy_sha,publish=publish)
        self.assertFalse((self.f.path/'state/transaction').exists());self.assertEqual(self.f.images(),before)

    def test_malformed_metadata_cli_returns_structured_blocked(self):
        self.f.put('hub/manifest.json',b'[]')
        result=subprocess.run([sys.executable,'-B',str(SOURCE),'plan',str(self.f.path),'--commit',COMMIT,
                               '--pe32-sha256',w.digest(b'new pe32'),'--pe64-sha256',w.digest(b'new pe64'),
                               '--policy-sha256',self.f.policy_sha,'--offline-fixture-gates'],capture_output=True,text=True)
        self.assertEqual(result.returncode,1)
        self.assertEqual(json.loads(result.stdout)['state'],'BLOCKED')
        self.assertEqual(result.stderr,'')

    def test_cli_plan_apply_noop_rollback_return_fixture_only(self):
        args=[sys.executable,'-B',str(SOURCE)]
        def command(operation,*extra):
            result=subprocess.run(args+[operation,str(self.f.path),'--offline-fixture-gates',*extra],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertEqual(result.stderr,'')
            data=json.loads(result.stdout)
            self.assertFalse(data['liveStateChanged'])
            return data
        plan=command('plan','--commit',COMMIT,'--pe32-sha256',w.digest(b'new pe32'),'--pe64-sha256',w.digest(b'new pe64'),'--policy-sha256',self.f.policy_sha)
        for operation,changed in (('apply',True),('apply',False),('rollback',True),('return',True)):
            self.assertEqual(command(operation,'--plan-sha256',plan['planSha256'])['changed'],changed)

    def test_observed_framework_directory_alias_fingerprints_literal_link_without_duplicate_traversal(self):
        for name in ('hub','ds3'):
            self.f.put(name+'/runtime/Frameworks/libfixture.dylib',b'framework code',0o700)
            deps=self.f.path/name/'runtime/deps';deps.mkdir(mode=0o700)
            (deps/'Frameworks').symlink_to('../Frameworks',target_is_directory=True)
            rows=w.tree_rows(self.f.root,name+'/runtime')
            self.assertIn(['deps/Frameworks','link','../Frameworks'],rows)
            self.assertEqual(len([row for row in rows if row[0] == 'Frameworks/libfixture.dylib']),1)
            self.assertFalse(any(row[0].startswith('deps/Frameworks/') for row in rows))
            receipt=w.decode(self.f.root.read(name+'/receipt.json')[0])
            receipt['runtimeTreeSha256']=w.tree_hash(rows)
            self.f.put(name+'/receipt.json',w.encode(receipt))
        receipt=w.decode(self.f.root.read('ds3/borderless/receipt.json')[0])
        receipt['baseRuntimeTreeSha256']=w.decode(self.f.root.read('ds3/receipt.json')[0])['runtimeTreeSha256']
        self.f.put('ds3/borderless/receipt.json',w.encode(receipt))
        before=self.f.images()
        self.f.plan();self.f.tx().run('after');self.f.tx().run('before')
        self.assertEqual(self.f.images(),before)

    def test_framework_alias_escape_multihop_other_directory_and_writeable_target_rejected(self):
        self.f.put('hub/runtime/Frameworks/code',b'code')
        deps=self.f.path/'hub/runtime/deps';deps.mkdir(mode=0o700)
        alias=deps/'Frameworks'
        for value in ('../../outside','/tmp','../OtherFrameworks'):
            with self.subTest(target=value):
                (self.f.path/'hub/runtime/OtherFrameworks').mkdir(exist_ok=True)
                alias.symlink_to(value,target_is_directory=True)
                with self.assertRaises((w.Blocked,OSError)):w.tree_rows(self.f.root,'hub/runtime')
                alias.unlink()
        framework=self.f.path/'hub/runtime/Frameworks'
        framework.rename(framework.with_name('Frameworks-original'))
        framework.symlink_to('Frameworks-original',target_is_directory=True)
        alias.symlink_to('../Frameworks',target_is_directory=True)
        with self.assertRaises((w.Blocked,OSError)):w.tree_rows(self.f.root,'hub/runtime')
        framework.unlink();framework.with_name('Frameworks-original').rename(framework)
        framework.chmod(0o777)
        with self.assertRaises(w.Blocked):w.tree_rows(self.f.root,'hub/runtime')
        framework.chmod(0o700)

    def test_schema2_canonical_selector_accepts_exact_overlay_rejects_extra_missing_and_ancestry_tamper(self):
        self.f.plan()
        self.f.tx().run('after')
        wiring=self.f.path/'ds3/ds3-runtime'
        canonical_loader=importlib.machinery.SourceFileLoader('candidate_ds3_overlay',str(wiring))
        canonical_spec=importlib.util.spec_from_loader(canonical_loader.name,canonical_loader)
        h=importlib.util.module_from_spec(canonical_spec)
        canonical_loader.exec_module(h)
        self.assertEqual(h.HERE,self.f.path)
        control=self.f.path/'control'
        self.f.put('control/manifests/ds3-source-hub-v1.json',self.f.root.read('payload/source-hub-v1.json')[0])
        self.f.put('control/manifests/wine-runtime-overlay.json',self.f.root.read('payload/policy.json')[0])
        self.f.put('control/manifests/games-hub.json',self.f.root.read('hub/manifest.json')[0])
        self.f.put('control/bin/ds3-runtime',self.f.root.read('payload/ds3-runtime')[0],0o700)
        mp=self.f.path/'ds3/manifest.json'
        original=mp.read_bytes()
        with patch.object(h,'CONTROL',control):
            m=h.manifest(mp)
            pins=h.installed_critical_hashes(m)
            for rel,expected in pins.items():
                self.assertEqual(w.digest(self.f.root.read('ds3/runtime/'+rel)[0]),expected)
            legacy=w.decode(self.f.root.read('state/transaction/ds3.manifest.before')[0])
            self.assertEqual(m['sourceCriticalHashes'],legacy['sourceCriticalHashes'])
            self.assertEqual(m['sourceHubManifestSha256'],legacy['sourceHubManifestSha256'])
            variants=[]
            wrong=copy.deepcopy(m);wrong['schema']=True;variants.append(wrong)
            wrong=copy.deepcopy(m);wrong['runtimeOverrides'].pop(w.PE32);variants.append(wrong)
            wrong=copy.deepcopy(m);wrong['runtimeOverrides'][w.UNIX]='0'*64;variants.append(wrong)
            wrong=copy.deepcopy(m);wrong['sourceCriticalHashes'][w.METAL]='0'*64;variants.append(wrong)
            wrong=copy.deepcopy(m);wrong['extra']='unexpected';variants.append(wrong)
            for bad in variants:
                with self.subTest(variant=bad):
                    mp.write_bytes(w.encode(bad))
                    with self.assertRaises(RuntimeError):
                        h.manifest(mp)
            mp.write_bytes(original)
            # First-install source_check still requires the exact original hub;
            # it rejects the upgraded hub before inspecting any prefix.
            with patch.object(h,'SOURCE',self.f.path/'hub'):
                with self.assertRaisesRegex(RuntimeError,'source_hub_manifest_drift'):
                    h.source_check(m)


if __name__ == '__main__':
    unittest.main()
