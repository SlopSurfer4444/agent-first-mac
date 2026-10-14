"""Combined DS3 window/schema fixtures; all command/native clone calls blocked."""
import json, os, stat, unittest
from pathlib import Path
from unittest.mock import patch
import test_ds3_runtime as fixture
from lib import game_operation_readiness as game
from lib import operation_readiness as operation

h=fixture.h

class WindowRepair(unittest.TestCase):
    def setUp(self):
        self.f=fixture.DS3Tests();self.f.setUp();self.addCleanup(self.f.tearDown)
        self.gate=patch.object(h,'source_gate');self.gate.start();self.addCleanup(self.gate.stop)
        self.inactive=patch.object(h,'inactive');self.inactive.start();self.addCleanup(self.inactive.stop)
        self.commands=patch.object(h,'run',side_effect=AssertionError('native command forbidden'));self.commands.start();self.addCleanup(self.commands.stop)
        self.processes=patch.object(h.subprocess,'Popen',side_effect=AssertionError('process launch forbidden'));self.processes.start();self.addCleanup(self.processes.stop)
        def plain_copy(source,parent,name):
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=parent)
            try:
                with os.fdopen(os.dup(fd),'wb') as out:
                    for raw in iter(lambda:os.read(source,1048576),b''):out.write(raw)
            finally:os.close(fd)
        def plain_rename(src,dst,src_dir_fd,dst_dir_fd):
            try:os.stat(dst,dir_fd=dst_dir_fd,follow_symlinks=False)
            except FileNotFoundError:pass
            else:raise RuntimeError('lifecycle_destination_collision')
            os.rename(src,dst,src_dir_fd=src_dir_fd,dst_dir_fd=dst_dir_fd)
        for name,implementation in (('lifecycle_clone',plain_copy),('lifecycle_rename',plain_rename)):
            p=patch.object(h,name,side_effect=implementation);p.start();self.addCleanup(p.stop)
        self.f.installed();self.root=self.f.root;self.prefix=self.f.prefix;self.target=self.prefix/h.CONFIG_REL
        self.raw=self.f.graphics;self.target.write_bytes(self.raw)
        self.registry=b'[Software\\\\Wine\\\\Mac Driver] 1\n"RetinaMode"="Y"\n"Other"="keep"\n';(self.prefix/'user.reg').write_bytes(self.registry)
        self.base=h.load(self.root/'manifest.json');self.base.update(aspectFit=True,singleLauncher=True)
        self.root.joinpath('manifest.json').write_text(json.dumps(self.base));self.rebind_receipts()
    def rebind_receipts(self):
        receipt=h.load(self.root/'receipt.json');receipt['manifestSha256']=h.sha(self.root/'manifest.json');receipt['runtimeTreeSha256']=h.code_tree(self.root/'runtime')
        self.root.joinpath('receipt.json').write_text(json.dumps(receipt))
        borderless=h.load(self.root/'borderless/receipt.json');borderless.update(baseManifestSha256=receipt['manifestSha256'],baseRuntimeTreeSha256=receipt['runtimeTreeSha256'])
        self.root.joinpath('borderless/receipt.json').write_text(json.dumps(borderless))
    def schema(self,version):
        paths=h.RUNTIME_EXTENDED_PATHS if version==3 else h.RUNTIME_OVERRIDE_PATHS
        overrides={}
        for rel in paths:
            p=self.root/'runtime'/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(('synthetic '+rel).encode());overrides[rel]=h.sha(p)
        policy={name:'a'*64 for name in h.RUNTIME_OVERLAY_POLICY_FIELDS-{'desiredPEHashes','previousHubCriticalHashes','sourceCriticalHashes'}}
        policy.update(schema=2 if version==3 else 1,id='wine-runtime-overlay',owner='control-games-hub',previousHubCriticalHashes=self.base['sourceCriticalHashes'],sourceCriticalHashes=self.base['sourceCriticalHashes'],sourceHubManifestSha256=self.base['sourceHubManifestSha256'],lifecycleSha256=h.sha(self.f.control/'bin/ds3-runtime'))
        policy['desiredRuntimeHashes' if version==3 else 'desiredPEHashes']=overrides
        p=self.f.control/h.RUNTIME_OVERLAY_POLICY;p.write_text(json.dumps(policy));digest=h.sha(p)
        current=h.load(self.f.control/'manifests/games-hub.json');current['criticalHashes'].update(overrides);current['runtimeOverlayPolicySha256']=digest
        self.f.control.joinpath('manifests/games-hub.json').write_text(json.dumps(current))
        self.base.update(schema=version,runtimeOverrides=overrides,runtimeOverlayPolicySha256=digest)
        self.root.joinpath('manifest.json').write_text(json.dumps(self.base));self.rebind_receipts();return policy
    def connected_gate(self):
        self.gate.stop();self.calls=[];self.commit='a'*40
        def command(argv,**kwargs):
            self.calls.append([str(x) for x in argv]);self.assertEqual(str(argv[0]),'/usr/bin/git')
            tail=argv[-2:];value=self.commit if tail==['rev-parse','HEAD'] else 'main' if tail==['branch','--show-current'] else ''
            return value.encode()
        self.commands.stop();p=patch.object(h,'run',side_effect=command);p.start();self.addCleanup(p.stop)
        p=patch.object(h,'readiness_bridge',return_value=game);p.start();self.addCleanup(p.stop)
        self.scopes=[]
        def scoped(control,commit,name,**kwargs):
            self.scopes.append((name,set(kwargs['checks'])));return operation.evaluate(name,commit,source_guard=lambda:True,**kwargs)
        p=patch.object(game,'ready',side_effect=scoped);p.start();self.addCleanup(p.stop)
        p=patch.dict(h.__dict__,{'__file__':str(self.f.control/'bin/ds3-runtime')});p.start();self.addCleanup(p.stop)
    def test_apply_noop_restore(self):
        self.assertTrue(h.repair_window('a'*40)['changed']);self.assertFalse(h.repair_window('a'*40)['changed']);self.assertEqual((self.prefix/'user.reg').read_bytes(),self.registry)
        expected=self.raw.decode('utf-16-le').replace('<ScreenMode>FULLSCREEN</ScreenMode>','<ScreenMode>WINDOW</ScreenMode>').replace('<Resolution-WindowScreenWidth>1680','<Resolution-WindowScreenWidth>2560').replace('<Resolution-WindowScreenHeight>945','<Resolution-WindowScreenHeight>1440').encode('utf-16-le');self.assertEqual(self.target.read_bytes(),expected)
        self.assertTrue(h.rollback_window('b'*40,'a'*40)['changed']);self.assertFalse(h.rollback_window('b'*40,'a'*40)['changed']);self.assertEqual(self.target.read_bytes(),self.raw)
    def test_gate_failure_zero_mutation(self):
        with patch.object(h,'source_gate',side_effect=RuntimeError('doctor')):
            with self.assertRaisesRegex(RuntimeError,'doctor'):h.repair_window('a'*40)
        self.assertEqual(self.target.read_bytes(),self.raw);self.assertFalse(h.window_repair_transaction('a'*40).exists())
    def test_active_failure_zero_mutation(self):
        with patch.object(h,'inactive',side_effect=RuntimeError('profile_active')):
            with self.assertRaisesRegex(RuntimeError,'profile_active'):h.repair_window('a'*40)
        self.assertEqual(self.target.read_bytes(),self.raw)
    def test_postcheck_failure_restores(self):
        with patch.object(h,'verify_window_config',side_effect=RuntimeError('observation_failed')):
            with self.assertRaisesRegex(RuntimeError,'observation_failed'):h.repair_window('a'*40)
        self.assertEqual(self.target.read_bytes(),self.raw)
    def test_changed_preimage_refused(self):
        original=h.window_repair_replace
        def drift(target,data,mode,expected):target.write_bytes(b'new owner data');original(target,data,mode,expected)
        with patch.object(h,'window_repair_replace',side_effect=drift):
            with self.assertRaisesRegex(RuntimeError,'window_repair_target_changed'):h.repair_window('a'*40)
        self.assertEqual(self.target.read_bytes(),b'new owner data')
    def test_rollback_third_state_refused(self):
        h.repair_window('a'*40);self.target.write_bytes(b'owner changed')
        with self.assertRaisesRegex(RuntimeError,'window_repair_rollback_drift'):h.rollback_window('b'*40,'a'*40)
        self.assertEqual(self.target.read_bytes(),b'owner changed')
    def test_retina_not_changed(self):
        raw=self.registry.replace(b'"Y"',b'"N"');(self.prefix/'user.reg').write_bytes(raw)
        with self.assertRaisesRegex(RuntimeError,'retina_not_enabled'):h.repair_window('a'*40)
        self.assertEqual((self.prefix/'user.reg').read_bytes(),raw);self.assertEqual(self.target.read_bytes(),self.raw)
    def test_invalid_xml_refused(self):
        text=self.raw.decode('utf-16-le')
        for bad in (text.replace('</config>','<ScreenMode>WINDOW</ScreenMode></config>'),text.replace('1680','999999'),text.replace('<config>','<!DOCTYPE config><config>'),text.replace('FULLSCREEN','INVALID')):
            with self.assertRaises(RuntimeError):h.repair_window_plan(bad.encode('utf-16-le'))
    def test_backup_drift_refused(self):
        h.repair_window('a'*40);current=self.target.read_bytes();h.window_repair_transaction('a'*40).joinpath('before.xml').write_bytes(b'changed backup')
        with self.assertRaisesRegex(RuntimeError,'window_repair_backup_drift'):h.rollback_window('b'*40,'a'*40)
        self.assertEqual(self.target.read_bytes(),current)
    def test_window_comment_fullscreen_is_preserved_exactly(self):
        text=self.raw.decode('utf-16-le').replace('<ScreenMode>FULLSCREEN</ScreenMode>','<ScreenMode>WINDOW</ScreenMode>').replace('</config>','<!--<ScreenMode>FULLSCREEN</ScreenMode>--></config>')
        after=h.repair_window_plan(text.encode('utf-16-le')).decode('utf-16-le');expected=text.replace('<Resolution-WindowScreenWidth>1680','<Resolution-WindowScreenWidth>2560').replace('<Resolution-WindowScreenHeight>945','<Resolution-WindowScreenHeight>1440');self.assertEqual(after,expected)
    def test_mode_drift_refuses_publication(self):
        original=h.window_repair_replace
        def changed(target,data,mode,expected):target.chmod(0o700);original(target,data,mode,expected)
        with patch.object(h,'window_repair_replace',side_effect=changed):
            with self.assertRaisesRegex(RuntimeError,'window_repair_target_changed'):h.repair_window('a'*40)
        self.assertEqual(self.target.read_bytes(),self.raw)
    def test_failure_after_atomic_replace_restores_exact_preimage(self):
        original=h.window_repair_replace;called=[]
        def interrupted(*args):
            original(*args);called.append(True)
            if len(called)==1:raise OSError('after publication')
        with patch.object(h,'window_repair_replace',side_effect=interrupted):
            with self.assertRaisesRegex(OSError,'after publication'):h.repair_window('a'*40)
        self.assertEqual(self.target.read_bytes(),self.raw)
    def test_abrupt_publication_has_explicit_twice_rollback(self):
        def interrupt(name):
            if name=='replace:published':raise KeyboardInterrupt()
        with patch.object(h,'window_repair_checkpoint',side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):h.repair_window('a'*40)
        self.assertEqual(self.target.read_bytes(),h.repair_window_plan(self.raw))
        self.assertTrue(h.rollback_window('b'*40,'a'*40)['changed']);self.assertFalse(h.rollback_window('b'*40,'a'*40)['changed']);self.assertEqual(self.target.read_bytes(),self.raw)
    def test_partial_backup_does_not_mutate_and_retry_collision_is_retained(self):
        def interrupt(name):
            if name=='backup/before.xml:durable':raise KeyboardInterrupt()
        with patch.object(h,'window_repair_checkpoint',side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):h.repair_window('a'*40)
        transaction=h.window_repair_transaction('a'*40);self.assertEqual({x.name for x in transaction.iterdir()},{'before.xml'})
        with self.assertRaisesRegex(RuntimeError,'window_repair_backup_collision'):h.repair_window('a'*40)
        self.assertEqual(self.target.read_bytes(),self.raw);self.assertEqual((transaction/'before.xml').read_bytes(),self.raw)
    def test_before_hash_mode_drift_is_not_a_rollback_noop(self):
        h.repair_window('a'*40);h.rollback_window('b'*40,'a'*40);self.target.chmod(0o700)
        with self.assertRaisesRegex(RuntimeError,'window_repair_rollback_drift'):h.rollback_window('b'*40,'a'*40)
        self.assertEqual(self.target.read_bytes(),self.raw);self.assertEqual(stat.S_IMODE(self.target.stat().st_mode),0o700)
    def test_parent_swaps_before_and_during_replace_never_write_outside(self):
        outside=self.f.base/'outside';outside.mkdir();original=h.os.replace;mode=stat.S_IMODE(self.target.stat().st_mode)
        for seam in ('replace:held','replace:staged','replace:syscall'):
            with self.subTest(seam=seam):
                parent=self.target.parent;retained=parent.with_name(parent.name+'-retained');fired=[]
                def swap():os.rename(parent,retained);parent.symlink_to(outside);fired.append(True)
                def checkpoint(name):
                    if name==seam:swap()
                def replace(src,dst,**kwargs):
                    if seam=='replace:syscall' and dst==self.target.name:swap()
                    return original(src,dst,**kwargs)
                try:
                    with patch.object(h,'window_repair_checkpoint',side_effect=checkpoint),patch.object(h.os,'replace',side_effect=replace):
                        with self.assertRaises((RuntimeError,OSError)):h.window_repair_replace(self.target,h.repair_window_plan(self.raw),mode,h.digest_bytes(self.raw))
                    self.assertEqual(fired,[True]);self.assertEqual(list(outside.iterdir()),[])
                    self.assertEqual(list(retained.glob('.window-repair-*')),[])
                finally:
                    if parent.is_symlink():parent.unlink();os.rename(retained,parent)
                    self.target.write_bytes(self.raw);self.target.chmod(mode)
    def test_pending_lifecycle_blocks_window_mutations_even_with_mocked_source_gate(self):
        for kind in ('install','retire'):
            j=h.lifecycle_load();j.update(operation=kind,state='pending');h.lifecycle_save(j)
            for action in (lambda:h.repair_window('a'*40),lambda:h.rollback_window('b'*40,'a'*40)):
                with self.assertRaisesRegex(RuntimeError,'lifecycle_recovery_required'):action()
            self.assertEqual(self.target.read_bytes(),self.raw);self.assertFalse(h.window_repair_transaction('a'*40).exists())
    def test_schema_three_exact_scope_and_legacy_two_remain_verified(self):
        for version in (2,3):
            with self.subTest(version=version):
                self.schema(version);manifest,_=h.verify_installed();pins=h.installed_critical_hashes(manifest)
                self.assertEqual(manifest['schema'],version);self.assertTrue(all(pins[rel]==digest for rel,digest in manifest['runtimeOverrides'].items()));self.assertEqual(pins[h.METAL],manifest['candidateSha256']);self.assertEqual(pins[h.DONOR],manifest['donorSha256'])
        bad=dict(self.base);bad['runtimeOverrides']=dict(bad['runtimeOverrides']);bad['runtimeOverrides']['engine/foreign.dll']='a'*64;self.root.joinpath('manifest.json').write_text(json.dumps(bad))
        with self.assertRaisesRegex(RuntimeError,'runtime_override_schema'):h.manifest(self.root/'manifest.json')
    def test_connected_schema_three_fullscreen_repair_and_scoped_rollback(self):
        self.schema(3);self.connected_gate();self.assertTrue(h.repair_window(self.commit)['changed']);self.assertTrue(h.rollback_window(self.commit,self.commit)['changed']);self.assertFalse(h.rollback_window(self.commit,self.commit)['changed'])
        self.assertEqual(self.target.read_bytes(),self.raw);self.assertEqual(self.scopes[0],('wine-install',{'payload-owner','wine-target','recovery'}));self.assertEqual(self.scopes[1],('wine-recovery',{'payload-owner','recovery'}));self.assertGreaterEqual(h.inactive.call_count,3)
        self.assertTrue(all(row[0]=='/usr/bin/git' for row in self.calls))
    def test_connected_pending_and_record_drift_cannot_grant_scope(self):
        self.schema(3);h.repair_window('a'*40);self.connected_gate();h.window_repair_transaction('a'*40).joinpath('record.json').write_text('{}')
        with self.assertRaisesRegex(RuntimeError,'window_repair_record_drift'):h.rollback_window(self.commit,'a'*40)
        self.assertEqual(self.target.read_bytes(),h.repair_window_plan(self.raw));j=h.lifecycle_load();j['state']='pending';h.lifecycle_save(j)
        with self.assertRaisesRegex(RuntimeError,'lifecycle_recovery_required'):h.source_gate(self.commit,'repair-window')
    def test_connected_completed_history_does_not_pin_current_owner_data(self):
        self.schema(3);self.target.write_bytes(self.raw.replace('<TextureQuality>HIGH</TextureQuality>'.encode('utf-16-le'),'<TextureQuality>MAX</TextureQuality>'.encode('utf-16-le')));before=self.target.read_bytes();self.connected_gate()
        self.assertTrue(h.repair_window(self.commit)['changed']);self.assertTrue(h.rollback_window(self.commit,self.commit)['changed']);self.assertEqual(self.target.read_bytes(),before)
    def test_staged_source_substitution_is_refused_before_publication(self):
        for kind in ('file','link','same-inode'):
            with self.subTest(kind=kind):
                foreign=self.f.base/('foreign-'+kind);foreign.write_bytes(b'foreign private sentinel');names=[]
                def changed(name):
                    if name=='replace:staged':
                        temporary=next(self.target.parent.glob('.window-repair-*'));names.append(temporary)
                        if kind!='same-inode':temporary.rename(temporary.with_name(temporary.name+'.retained'))
                        if kind=='link':temporary.symlink_to(foreign)
                        else:temporary.write_bytes(b'foreign stage')
                with patch.object(h,'window_repair_checkpoint',side_effect=changed):
                    with self.assertRaisesRegex(RuntimeError,'window_repair_staging_drift'):
                        h.window_repair_replace(self.target,h.repair_window_plan(self.raw),stat.S_IMODE(self.target.stat().st_mode),h.digest_bytes(self.raw))
                self.assertEqual(self.target.read_bytes(),self.raw);self.assertEqual(foreign.read_bytes(),b'foreign private sentinel');self.assertTrue(names[0].exists() or names[0].is_symlink())
                for p in self.target.parent.glob('.window-repair-*'):p.unlink()

if __name__=='__main__':unittest.main()
