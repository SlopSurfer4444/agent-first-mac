"""Owned fixture transactions only; never dispatch a game or touch real HOME."""
import importlib.machinery,importlib.util,json,os,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
P=Path(__file__).resolve().parents[1]
def load_script(name,path):
    loader=importlib.machinery.SourceFileLoader(name,str(path)); spec=importlib.util.spec_from_loader(name,loader); module=importlib.util.module_from_spec(spec); loader.exec_module(module); return module
h=load_script('game_app_launchers',P/'bin/game-app-launchers')
class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.base=Path(self.tmp.name).resolve(); self.home=self.base/'home'; self.source=self.base/'source'; self.candidate=self.base/'candidate';self.hub=self.home/'hub';self.ds3=self.home/'ds3'
        for p in (self.home/'Games',self.hub,self.ds3,self.source/'bin',self.source/'manifests',self.source/'docs',self.candidate):p.mkdir(parents=True,exist_ok=True)
        self.patches=[patch.object(h,k,v) for k,v in {'HOME':self.home,'HUB':self.hub,'DS3':self.ds3,'HERE':self.source}.items()]
        for p in self.patches:p.start()
        for name,(resolver,arg) in h.COMMANDS.items(): h.write_image(self.home/'Games'/name,('#!/bin/zsh\nexec "$HOME/AIDev/bin/'+resolver+'" '+arg+'\n').encode(),0o700)
        for name in h.NAMES:
            for rel,mode in h.FILES.items():
                p=self.candidate/name/rel;p.parent.mkdir(parents=True,exist_ok=True);h.write_image(p,(name+rel).encode(),mode)
        h.write_image(self.ds3/'ds3-runtime',b'old lifecycle',0o700);h.write_image(self.source/'bin/ds3-runtime',b'new lifecycle',0o755)
        h.write_image(self.home/'Games/README.txt',b'old readme');h.write_image(self.source/'docs/game-app-launchers-README.txt',b'new readme')
        h.write_image(self.source/'bin/game-app-launcher.m',b'fixture native source')
        self.dr={'owner':'control-ds3','lifecycleSha256':h.sha(self.ds3/'ds3-runtime'),'runtimeTreeSha256':'c'*64}
        self.hr={'owner':'control-games-hub','runtimeTreeSha256':'d'*64}
        h.write_image(self.hub/'receipt.json',h.jb(self.hr));h.write_image(self.ds3/'receipt.json',h.jb(self.dr))
        self.policy={'schema':1,'owner':'control-game-app-launchers','apps':{n:{'route':list(route),'routeNumber':i,'iconSource':'~/icon.icns','iconSha256':'a'*64} for i,(n,route) in enumerate(h.NAMES.items(),1)},'builtApps':h.bundle_inventory(self.candidate),'previousDs3LifecycleSha256':h.sha(self.ds3/'ds3-runtime'),'previousReadmeSha256':h.sha(self.home/'Games/README.txt')}
        h.write_image(self.source/h.MANIFEST,h.jb(self.policy));h.write_image(self.candidate/'build.json',h.jb({'schema':1,'sourceSha256':h.sha(self.source/'bin/game-app-launcher.m'),'apps':self.policy['builtApps']}))
        self.fake_hub=types.SimpleNamespace(status=lambda:None)
        server=self.ds3/'runtime/engine/bin/wineserver';server.parent.mkdir(parents=True);h.write_image(server,b'unchanged server',0o700)
        self.fake_ds3=types.SimpleNamespace(manifest=lambda _: {'sourceCriticalHashes':{'engine/bin/wineserver':h.sha(server)}},ROOT=self.ds3,PREFIX=self.ds3/'profile',verify_installed=lambda:({'singleLauncher':True},h.load(self.ds3/'receipt.json')),verify_borderless=lambda:None,inactive=lambda *a:None,stop_attestation=lambda:None)
        self.patches += [patch.object(h,'source_gate'),patch.object(h,'module',side_effect=lambda name:self.fake_hub if name=='games-hub' else self.fake_ds3)]
        for p in self.patches[4:]:p.start()
        self.before={k:h.image(p) for k,p in h.targets().items()}
        self.commit='b'*40
    def tearDown(self):
        for p in reversed(self.patches):p.stop()
        self.tmp.cleanup()
    def apply(self): return h.install(self.commit,self.candidate)
    def test_apply_noop_rollback_return_preserves_other_state(self):
        sentinel=self.home/'Games/owner.txt';sentinel.write_bytes(b'keep');save=self.ds3/'save';save.write_bytes(b'opaque save')
        self.assertTrue(self.apply()['changed']);self.assertFalse(self.apply()['changed']);self.assertTrue(h.verify_apps(self.policy))
        self.assertEqual(h.load(self.ds3/'receipt.json')['runtimeTreeSha256'],'c'*64)
        h.rollback(self.commit,self.commit);self.assertEqual({k:h.image(p) for k,p in h.targets().items()},self.before)
        h.rollback(self.commit,self.commit);self.assertTrue(self.apply()['changed']);self.assertFalse(self.apply()['changed'])
        self.assertEqual(sentinel.read_bytes(),b'keep');self.assertEqual(save.read_bytes(),b'opaque save')
    def test_failure_each_step_restores_exact_state(self):
        original=h.replace_image
        for failure in range(1,len(h.targets())+1):
            calls=[0]
            def inject(*args):
                calls[0]+=1
                if calls[0]==failure:raise OSError('injected')
                return original(*args)
            with patch.object(h,'replace_image',side_effect=inject):
                with self.assertRaises(OSError):self.apply()
            self.assertEqual({k:h.image(p) for k,p in h.targets().items()},self.before)
    def test_explicit_recovery_after_interrupted_lifecycle_receipt_pair(self):
        self.apply()
        transaction=self.hub/('.game-app-launchers-'+self.commit)
        # Recreate abrupt termination after new lifecycle but before new receipt.
        h.replace_image(transaction/'ds3-receipt.before',self.ds3/'receipt.json',h.image(self.ds3/'receipt.json'))
        self.assertNotEqual(h.load(self.ds3/'receipt.json')['lifecycleSha256'],h.sha(self.ds3/'ds3-runtime'))
        h.rollback(self.commit,self.commit)
        self.assertEqual({k:h.image(p) for k,p in h.targets().items()},self.before)
    def test_staging_failure_allows_retry_without_live_change(self):
        with patch.object(h,'copy_image',side_effect=OSError('staging')):
            with self.assertRaises(OSError):self.apply()
        self.assertEqual({k:h.image(p) for k,p in h.targets().items()},self.before)
        self.assertFalse((self.hub/('.game-app-launchers-'+self.commit)).exists())
        self.assertTrue(self.apply()['changed'])
    def test_app_removal_is_atomic_and_retained(self):
        self.apply();h.rollback(self.commit,self.commit)
        transaction=self.hub/('.game-app-launchers-'+self.commit)
        retained=list(transaction.glob('retired-app-*/app'))
        self.assertEqual(len(retained),4)
        for p in retained:self.assertEqual(h.image(p)['kind'],'app')
    def test_rollback_rejects_rehashed_foreign_command_backup(self):
        self.apply();transaction=self.hub/('.game-app-launchers-'+self.commit)
        backup=transaction/'command-0.before';backup.write_bytes(b'foreign command')
        journal=h.load(transaction/'transaction.json');journal['command-0']['before']=h.image(backup);h.write_image(transaction/'transaction.json',h.jb(journal))
        before={k:h.image(p) for k,p in h.targets().items()}
        with self.assertRaisesRegex(RuntimeError,'transaction_command_binding'):h.rollback(self.commit,self.commit)
        self.assertEqual({k:h.image(p) for k,p in h.targets().items()},before)
    def test_return_rejects_rehashed_foreign_readme_after(self):
        self.apply();h.rollback(self.commit,self.commit);transaction=self.hub/('.game-app-launchers-'+self.commit)
        backup=transaction/'readme.after';backup.write_bytes(b'foreign readme')
        journal=h.load(transaction/'transaction.json');journal['readme']['after']=h.image(backup);h.write_image(transaction/'transaction.json',h.jb(journal))
        with self.assertRaisesRegex(RuntimeError,'transaction_file_binding'):self.apply()
    def test_candidate_tamper_blocks_before_change(self):
        (self.candidate/'CS2.app/Contents/MacOS/launcher').write_bytes(b'foreign')
        with self.assertRaisesRegex(RuntimeError,'candidate_drift'):self.apply()
        self.assertEqual({k:h.image(p) for k,p in h.targets().items()},self.before)
    def test_foreign_command_blocks_before_change(self):
        (self.home/'Games/Stop Dark Souls III.command').write_bytes(b'owner modified')
        with self.assertRaisesRegex(RuntimeError,'shortcut_preimage_drift'):self.apply()
        self.assertFalse((self.home/'Games/CS2.app').exists())
    def test_app_symlink_collision_blocks(self):
        (self.home/'Games/CS2.app').symlink_to(self.candidate/'CS2.app')
        with self.assertRaisesRegex(RuntimeError,'unsafe_file'):self.apply()
    def test_fallback_requires_prior_follow(self):
        (self.home/'Games/Dark Souls III - 1080p.command').write_bytes(b'fallback')
        with self.assertRaisesRegex(RuntimeError,'follow_upgrade_required'):self.apply()
    def test_rollback_drift_blocks_all_changes(self):
        self.apply();(self.home/'Games/CS2.app/Contents/MacOS/launcher').write_bytes(b'owner modified')
        before={k:h.image(p) for k,p in h.targets().items()}
        with self.assertRaisesRegex(RuntimeError,'transaction_target_drift'):h.rollback(self.commit,self.commit)
        self.assertEqual({k:h.image(p) for k,p in h.targets().items()},before)
    def test_backup_drift_blocks_rollback(self):
        self.apply();(self.hub/('.game-app-launchers-'+self.commit)/'readme.before').write_bytes(b'foreign')
        with self.assertRaisesRegex(RuntimeError,'backup_drift'):h.rollback(self.commit,self.commit)
    def test_status_rejects_reintroduced_stop(self):
        self.apply();(self.home/'Games/Stop Dark Souls III.command').write_bytes(b'new')
        with self.assertRaisesRegex(RuntimeError,'legacy_shortcut_collision'):h.status()
    def test_source_gate_refuses_worktree(self):
        self.patches[-2].stop()
        with self.assertRaisesRegex(RuntimeError,'canonical_source_required'):h.source_gate(self.commit)

class InventoryTests(unittest.TestCase):
    def test_both_payload_validators_detect_tamper_and_extras(self):
        for filename in ('games-hub','ds3-runtime'):
            m=load_script('inventory_'+filename.replace('-','_'),P/'bin'/filename)
            with tempfile.TemporaryDirectory() as td:
                home=Path(td).resolve();app=home/'Games/CS2.app'
                for rel,mode in h.FILES.items():
                    p=app/rel;p.parent.mkdir(parents=True,exist_ok=True);h.write_image(p,b'data',mode)
                receipt={'appPolicySha256':'a'*64,'appLaunchers':{'CS2.app':h.image(app)['files']}}
                with patch.object(m,'HOME',home):
                    m.verify_app_shortcuts(receipt,{'CS2.app':'CS2.command'})
                    (app/'Contents/MacOS/launcher').write_bytes(b'changed')
                    with self.assertRaisesRegex(RuntimeError,'app_file_drift'):m.verify_app_shortcuts(receipt,{'CS2.app':'CS2.command'})
                    (app/'Contents/MacOS/launcher').write_bytes(b'data');(app/'extra').mkdir()
                    with self.assertRaisesRegex(RuntimeError,'app_inventory_drift'):m.verify_app_shortcuts(receipt,{'CS2.app':'CS2.command'})
    def test_native_source_fixed_routes(self):
        s=(P/'bin/game-app-launcher.m').read_text()
        for text in ('getpwuid(getuid())','task.arguments = @[argument]','waitUntilExit','runModal'):self.assertIn(text,s)
        for text in ('osascript','Terminal.app','system(','/bin/sh'):self.assertNotIn(text,s)
    def test_icon_extractor_malformed(self):
        m=load_script('extract_icon',P/'bin/game-app-extract-icon')
        for data in (b'',b'not a PE',b'MZ'+b'\0'*100):
            with self.assertRaises(ValueError):m.extract_icon(data)
if __name__=='__main__':unittest.main()
