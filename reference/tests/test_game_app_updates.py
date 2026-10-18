"""Six-file native update and interrupted recovery fixtures; no game dispatch."""
import copy,unittest
from unittest.mock import patch
from pathlib import Path
import test_game_app_launchers as T
u=T.load_script('app_update',T.P/'bin/game-app-launcher-update')
class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.fixture=T.MigrationTests();self.fixture.setUp();self.fixture.apply();self.h=T.h;self.patch=patch.object(u,'h',self.h);self.patch.start()
        self.commit='c'*40;self.before={k:self.h.image(p) for k,p in u.targets().items()}
        self.gate=patch.object(u,'source_gate',return_value=lambda:True);self.gate.start()
        self.source_check=patch.object(u,'source_check');self.source_check.start()
        old=self.h.policy();new=copy.deepcopy(old);new['previousPolicySha256']=self.h.sha(self.fixture.source/self.h.MANIFEST)
        for name in self.h.NAMES:(self.fixture.candidate/name/'Contents/MacOS/launcher').write_bytes(('new error handling '+name).encode())
        new['builtApps']=self.h.bundle_inventory(self.fixture.candidate)
        self.h.write_image(self.fixture.source/self.h.ERROR_POLICY,self.h.jb(new))
        self.h.write_image(self.fixture.candidate/'build.json',self.h.jb({'schema':1,'sourceSha256':self.h.sha(self.fixture.source/'bin/game-app-launcher.m'),'apps':new['builtApps']}))
    def tearDown(self):self.source_check.stop();self.gate.stop();self.patch.stop();self.fixture.tearDown()
    def apply(self):return u.update(self.commit,self.fixture.candidate)
    def test_update_noop_rollback_return(self):
        self.assertTrue(self.apply()['changed']);self.assertFalse(self.apply()['changed']);self.assertTrue(self.h.status()['sourcePolicyCurrent'])
        u.rollback(self.commit,self.commit);self.assertEqual({k:self.h.image(p) for k,p in u.targets().items()},self.before);self.assertFalse(self.h.status()['sourcePolicyCurrent'])
        u.rollback(self.commit,self.commit);self.assertTrue(self.apply()['changed'])
    def test_each_abrupt_apply_interruption_recovers(self):
        original=self.h.replace_image
        for failure in range(1,7):
            calls=[0]
            def interrupt(*args):
                result=original(*args);calls[0]+=1
                if calls[0]==failure:raise KeyboardInterrupt()
                return result
            with patch.object(self.h,'replace_image',side_effect=interrupt):
                with self.assertRaises(KeyboardInterrupt):self.apply()
            u.rollback(self.commit,self.commit);self.assertEqual({k:self.h.image(p) for k,p in u.targets().items()},self.before)
    def test_each_abrupt_rollback_interruption_recovers(self):
        original=self.h.replace_image
        for failure in range(1,7):
            self.apply();calls=[0]
            def interrupt(*args):
                result=original(*args);calls[0]+=1
                if calls[0]==failure:raise KeyboardInterrupt()
                return result
            with patch.object(self.h,'replace_image',side_effect=interrupt):
                with self.assertRaises(KeyboardInterrupt):u.rollback(self.commit,self.commit)
            u.rollback(self.commit,self.commit);self.assertEqual({k:self.h.image(p) for k,p in u.targets().items()},self.before)
    def test_unknown_target_blocks_without_overwrite(self):
        self.apply();target=u.targets()['0'];target.write_bytes(b'owner modified');before={k:self.h.image(p) for k,p in u.targets().items()}
        with self.assertRaisesRegex(RuntimeError,'update_target_drift'):u.rollback(self.commit,self.commit)
        self.assertEqual({k:self.h.image(p) for k,p in u.targets().items()},before)
    def test_rehashed_backup_rejected(self):
        self.apply();transaction=self.h.HUB/('.game-app-errors-'+self.commit);backup=transaction/'0.before';backup.write_bytes(b'foreign')
        j=self.h.load(transaction/'journal.json');j['0']['before']=self.h.image(backup);self.h.write_image(transaction/'journal.json',self.h.jb(j))
        with self.assertRaisesRegex(RuntimeError,'update_executable_binding'):u.rollback(self.commit,self.commit)
    def test_staging_failure_retry(self):
        with patch.object(self.h,'copy_image',side_effect=OSError('injected')):
            with self.assertRaises(OSError):self.apply()
        self.assertEqual({k:self.h.image(p) for k,p in u.targets().items()},self.before);self.assertTrue(self.apply()['changed'])
    def test_normal_failure_rolls_back(self):
        original=self.h.replace_image;calls=[0]
        def fail(*args):
            calls[0]+=1
            if calls[0]==4:raise OSError('injected')
            return original(*args)
        with patch.object(self.h,'replace_image',side_effect=fail):
            with self.assertRaises(OSError):self.apply()
        self.assertEqual({k:self.h.image(p) for k,p in u.targets().items()},self.before)
    def test_old_install_does_not_claim_false_noop(self):
        with self.assertRaisesRegex(RuntimeError,'native_app_update_required'):self.h.install(self.commit,self.fixture.candidate)
    def test_executable_update_and_rollback_ignore_runtime_and_migration_health(self):
        # The six-file operation does not consume these historical assets.
        (self.fixture.home/'Games/README.txt').write_bytes(b'owner notes')
        (self.fixture.ds3/'ds3-runtime').write_bytes(b'later lifecycle')
        with patch.object(self.h,'status',side_effect=AssertionError('whole game doctor forbidden')),patch.object(self.h,'module',side_effect=AssertionError('Wine gate forbidden')):
            self.assertTrue(self.apply()['changed'])
            self.assertFalse(self.apply()['changed'])
            u.rollback(self.commit,self.commit)
        self.assertEqual((self.fixture.home/'Games/README.txt').read_bytes(),b'owner notes')
        self.assertEqual((self.fixture.ds3/'ds3-runtime').read_bytes(),b'later lifecycle')
    def test_single_readiness_round_and_final_target_guard(self):
        calls=[]
        with patch.object(u,'source_gate',return_value=lambda:calls.append('held') or True) as gate:
            self.apply()
        self.assertEqual(gate.call_count,1);self.assertEqual(calls,['held'])
    def test_target_guard_drift_before_publication_preserves_owner_change(self):
        target=self.fixture.home/'Games/CS2.app/Contents/Info.plist'
        def changed():target.write_bytes(b'owner changed');return False
        with patch.object(u,'source_gate',return_value=changed),self.assertRaisesRegex(RuntimeError,'launcher_target_drift'):self.apply()
        self.assertEqual(target.read_bytes(),b'owner changed')
        self.assertEqual({k:self.h.image(p) for k,p in u.targets().items()},self.before)
    def test_connected_scope_uses_only_launcher_assets_and_owned_receipts(self):
        from lib import game_operation_readiness as bridge
        from lib import operation_readiness as readiness
        receipt=self.h.load(self.fixture.ds3/'receipt.json');receipt['owner']='control-ds3-marshal-fix'
        self.h.write_image(self.fixture.ds3/'receipt.json',self.h.jb(receipt))
        self.gate.stop()
        def evaluate(control,commit,operation,**kwargs):
            return readiness.evaluate(operation,commit,source_guard=lambda:True,**kwargs)
        with patch.object(self.h,'module_bridge',return_value=bridge),patch.object(bridge,'ready',side_effect=evaluate),patch.object(self.h,'module',side_effect=AssertionError('runtime dependency forbidden')):
            held=u.source_gate(self.commit)
            self.assertIs(held(),True)
            (self.fixture.home/'Games/README.txt').write_bytes(b'owner notes')
            self.assertIs(held(),True)
            target=self.fixture.home/'Games/CS2.app/Contents/Resources/Game.icns';target.write_bytes(b'owner icon')
            self.assertIs(held(),False)
    def test_connected_scope_unknown_receipt_owner_blocks(self):
        from lib import game_operation_readiness as bridge
        from lib import operation_readiness as readiness
        self.gate.stop()
        def evaluate(control,commit,operation,**kwargs):
            return readiness.evaluate(operation,commit,source_guard=lambda:True,**kwargs)
        with patch.object(self.h,'module_bridge',return_value=bridge),patch.object(bridge,'ready',side_effect=evaluate),self.assertRaisesRegex(RuntimeError,'operation_payload_owner'):
            u.source_gate(self.commit)
if __name__=='__main__':unittest.main()
