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
        old=self.h.policy();new=copy.deepcopy(old);new['previousPolicySha256']=self.h.sha(self.fixture.source/self.h.MANIFEST)
        for name in self.h.NAMES:(self.fixture.candidate/name/'Contents/MacOS/launcher').write_bytes(('new error handling '+name).encode())
        new['builtApps']=self.h.bundle_inventory(self.fixture.candidate)
        self.h.write_image(self.fixture.source/self.h.ERROR_POLICY,self.h.jb(new))
        self.h.write_image(self.fixture.candidate/'build.json',self.h.jb({'schema':1,'sourceSha256':self.h.sha(self.fixture.source/'bin/game-app-launcher.m'),'apps':new['builtApps']}))
    def tearDown(self):self.patch.stop();self.fixture.tearDown()
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
if __name__=='__main__':unittest.main()
