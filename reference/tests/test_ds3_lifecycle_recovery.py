"""Synthetic APFS lifecycle fixtures only: no user's games, Wine or auth state."""
import json, os, stat, unittest
from pathlib import Path
from unittest.mock import patch
import test_ds3_runtime as fixture

h=fixture.h

class DS3LifecycleRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.f=fixture.DS3Tests();self.f.setUp()
        self.gate=patch.object(h,'source_gate');self.gate.start()
        self.inactive=patch.object(h,'inactive');self.inactive.start()
    def tearDown(self):
        self.inactive.stop();self.gate.stop();self.f.tearDown()
    def install(self):return h.install('a'*40,self.f.candidate)
    def recover_twice(self):
        first=h.recover('c'*40);second=h.recover('c'*40)
        self.assertTrue(first['recovered']);self.assertFalse(second['changed'])
    def reset_fixture(self):
        self.f.tearDown();self.f=fixture.DS3Tests();self.f.setUp()
    def interrupt_at(self,name,call):
        fired=[]
        def interrupt(event):
            if event==name:fired.append(event);raise KeyboardInterrupt()
        with patch.object(h,'lifecycle_checkpoint',side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):call()
        self.assertEqual(fired,[name])
        if (h.lifecycle_directory()/'journal.json').exists():self.assertEqual(h.lifecycle_load()['state'],'pending')
        else:self.assertTrue(h.lifecycle_bootstrap_path().is_file())
    def test_install_every_mutation_edge_recovers_twice(self):
        events=[]
        with patch.object(h,'lifecycle_checkpoint',side_effect=events.append):self.install()
        edges=[e for e in events if e.endswith(':applied')]
        self.assertIn('receipt:applied',edges);self.assertIn('publish-root:applied',edges)
        self.assertTrue(any(e.startswith('profile/') for e in edges))
        for edge in edges:
            with self.subTest(edge=edge):
                self.reset_fixture();before=h.snapshot(self.f.source/'profiles/prince');source=h.code_tree(self.f.source/'runtime')
                self.interrupt_at(edge,self.install);self.recover_twice()
                self.assertEqual(before,h.snapshot(self.f.source/'profiles/prince'));self.assertEqual(source,h.code_tree(self.f.source/'runtime'))
                self.assertEqual(h.status()['state'],'INSTALLED_CANDIDATE')
    def test_publication_intent_and_durable_edges_recovers_twice(self):
        for name in ('publish-root','resolver','shortcut/Dark Souls III.command','shortcut/Stop Dark Souls III.command'):
            for suffix in (':intent',':durable'):
                with self.subTest(edge=name+suffix):
                    self.reset_fixture();self.interrupt_at(name+suffix,self.install);self.recover_twice()
    def test_interrupted_partial_private_copy_resumes_same_inode(self):
        original=h.lifecycle_clone;partial=[]
        def interrupted(source_fd,parent_fd,name):
            if name=='steam.exe':
                fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=parent_fd)
                try:os.write(fd,os.read(source_fd,4))
                finally:os.close(fd)
                dst=h.lifecycle_directory()/'stage/profiles/ds3/drive_c/Program Files (x86)/Steam/steam.exe';partial.append((dst,dst.stat().st_ino));raise KeyboardInterrupt()
            return original(source_fd,parent_fd,name)
        with patch.object(h,'lifecycle_clone',side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):self.install()
        destination,inode=partial[0];self.assertEqual(destination.read_bytes(),b'fake')
        self.recover_twice();published=self.f.prefix/'drive_c/Program Files (x86)/Steam/steam.exe'
        self.assertEqual(published.read_bytes(),b'fake client');self.assertEqual(published.stat().st_ino,inode)
    def test_partial_private_foreign_bytes_rejected_without_recopy(self):
        original=h.lifecycle_clone;partial=[]
        def interrupted(source_fd,parent_fd,name):
            if name=='steam.exe':
                fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=parent_fd)
                try:os.write(fd,b'evil')
                finally:os.close(fd)
                dst=h.lifecycle_directory()/'stage/profiles/ds3/drive_c/Program Files (x86)/Steam/steam.exe';partial.append(dst);raise KeyboardInterrupt()
            return original(source_fd,parent_fd,name)
        with patch.object(h,'lifecycle_clone',side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):self.install()
        inode=partial[0].stat().st_ino
        with self.assertRaisesRegex(RuntimeError,'lifecycle_partial_copy_drift'):h.recover('c'*40)
        self.assertEqual(partial[0].read_bytes(),b'evil');self.assertEqual(partial[0].stat().st_ino,inode);self.assertFalse(self.f.root.exists())
    def test_source_profile_drift_blocks_recovery(self):
        self.interrupt_at('profile/user.reg:applied',self.install)
        (self.f.source/'profiles/prince/user.reg').write_bytes(b'owner changed synthetic registry')
        with self.assertRaisesRegex(RuntimeError,'lifecycle_profile_source_drift'):h.recover('c'*40)
        self.assertFalse(self.f.root.exists())
    def test_stage_unknown_link_and_foreign_target_rejected(self):
        self.interrupt_at('profile/user.reg:durable',self.install)
        stage=h.lifecycle_directory()/'stage';p=stage/'profiles/ds3/user.reg';before=p.read_bytes();p.unlink();p.symlink_to(self.f.source/'profiles/prince/user.reg')
        with self.assertRaisesRegex(RuntimeError,'lifecycle_target_drift'):h.recover('c'*40)
        self.assertTrue(p.is_symlink());self.assertEqual((self.f.source/'profiles/prince/user.reg').read_bytes(),before)
        p.unlink();p.write_bytes(before);unknown=stage/'opaque-owner-data';unknown.write_bytes(b'keep')
        with self.assertRaisesRegex(RuntimeError,'lifecycle_tree_collision'):h.recover('c'*40)
        self.assertEqual(unknown.read_bytes(),b'keep')
    def test_retire_every_unlink_rename_and_journal_edge_recovers_twice(self):
        self.install();events=[]
        with patch.object(h,'lifecycle_checkpoint',side_effect=events.append):h.retire('b'*40)
        edges=[e for e in events if e.startswith(('remove/','archive-root'))]
        self.assertEqual(len(edges),12)
        for edge in edges:
            with self.subTest(edge=edge):
                self.reset_fixture();self.install();before=h.snapshot(self.f.prefix)
                self.interrupt_at(edge,lambda:h.retire('b'*40));self.recover_twice()
                archive=self.f.root.with_name(self.f.root.name+' retired '+('b'*12))
                self.assertEqual(before,h.snapshot(archive/'profiles/ds3'));self.assertFalse(self.f.root.exists())
                self.assertTrue((h.lifecycle_directory()/'journal.json').is_file())
    def test_retire_ordinary_rename_failure_retains_forward_recovery(self):
        self.install();original=h.lifecycle_rename
        def fail_root(src,dst,**kwargs):
            if str(src)==self.f.root.name:raise OSError('synthetic archive failure')
            return original(src,dst,**kwargs)
        with patch.object(h,'lifecycle_rename',side_effect=fail_root):
            with self.assertRaises(OSError):h.retire('b'*40)
        self.assertEqual(h.lifecycle_load()['direction'],'forward');self.assertTrue(self.f.prefix.is_dir())
        self.recover_twice()
    def test_retire_third_state_and_archive_collision_are_preserved(self):
        self.install();self.interrupt_at('remove/resolver:durable',lambda:h.retire('b'*40))
        shortcut=self.f.home/'Games/Dark Souls III.command';shortcut.write_bytes(b'owner third state')
        with self.assertRaisesRegex(RuntimeError,'lifecycle_target_drift|lifecycle_entrypoint_preimage'):h.recover('c'*40)
        self.assertEqual(shortcut.read_bytes(),b'owner third state');self.assertTrue(self.f.prefix.is_dir())
        self.reset_fixture();self.install();archive=self.f.root.with_name(self.f.root.name+' retired '+('b'*12));archive.mkdir();(archive/'keep').write_bytes(b'keep')
        with self.assertRaisesRegex(RuntimeError,'archive_collision'):h.retire('b'*40)
        self.assertEqual((archive/'keep').read_bytes(),b'keep');h.verify_installed()
    def test_malformed_journal_and_namespace_link_reject(self):
        self.interrupt_at('stage:intent',self.install);journal=h.lifecycle_directory()/'journal.json';old=journal.read_bytes();journal.write_bytes(b'{"schema":1,"schema":1}')
        with self.assertRaisesRegex(RuntimeError,'lifecycle_duplicate_key'):h.recover('c'*40)
        journal.write_bytes(old);j=json.loads(old);j['direction']='delete';journal.write_text(json.dumps(j))
        with self.assertRaisesRegex(RuntimeError,'lifecycle_journal_schema'):h.recover('c'*40)
        self.assertFalse(self.f.root.exists())
    def test_foreign_owner_and_publication_collision_block(self):
        self.interrupt_at('stage:durable',self.install);original=h.lifecycle_facts
        def foreign(p,*args,**kwargs):
            if p==h.lifecycle_directory()/'stage':raise RuntimeError('lifecycle_foreign_owner')
            return original(p,*args,**kwargs)
        with patch.object(h,'lifecycle_facts',side_effect=foreign):
            with self.assertRaisesRegex(RuntimeError,'lifecycle_foreign_owner'):h.recover('c'*40)
        self.f.root.mkdir();(self.f.root/'keep').write_bytes(b'keep')
        with self.assertRaisesRegex(RuntimeError,'lifecycle_destination_collision'):h.recover('c'*40)
        self.assertEqual((self.f.root/'keep').read_bytes(),b'keep')
    def test_recovery_gate_failure_precedes_journal_or_payload_reads(self):
        with patch.object(h,'source_gate',side_effect=RuntimeError('gate_failed')),patch.object(h,'lifecycle_load',side_effect=AssertionError('journal accessed')):
            with self.assertRaisesRegex(RuntimeError,'gate_failed'):h.recover('c'*40)
    def test_partial_private_postimage_write_resumes_and_rejects_foreign_prefix(self):
        for valid in (True,False):
            with self.subTest(valid=valid):
                self.reset_fixture();raw=(self.f.control/'bin/ds3-runtime').read_bytes()
                def interrupt(event):
                    if event=='helper/ds3-runtime:intent':
                        j=h.lifecycle_load();temp=h.lifecycle_directory()/('write-'+str(j['active']))
                        temp.write_bytes(raw[:31] if valid else b'unknown foreign bytes');temp.chmod(0o700);raise KeyboardInterrupt()
                with patch.object(h,'lifecycle_checkpoint',side_effect=interrupt):
                    with self.assertRaises(KeyboardInterrupt):self.install()
                if valid:self.recover_twice()
                else:
                    with self.assertRaisesRegex(RuntimeError,'lifecycle_staging_drift'):h.recover('c'*40)
                    self.assertFalse(self.f.root.exists())
    def test_namespace_symlink_and_unjournaled_archive_move_reject(self):
        self.install();directory=h.lifecycle_directory();retained=directory.with_name('retained-fixture-journal');os.rename(directory,retained);directory.symlink_to(retained)
        with self.assertRaisesRegex(RuntimeError,'unsafe_directory'):h.recover('c'*40)
        self.assertTrue(directory.is_symlink());directory.unlink();os.rename(retained,directory)
        self.interrupt_at('remove/resolver:intent',lambda:h.retire('b'*40));shortcut=self.f.home/'Games/Dark Souls III.command';before=shortcut.read_bytes()
        archive=self.f.root.with_name(self.f.root.name+' retired '+('b'*12));os.rename(self.f.root,archive)
        with self.assertRaisesRegex(RuntimeError,'lifecycle_retire_drift'):h.recover('c'*40)
        self.assertEqual(shortcut.read_bytes(),before);self.assertTrue((self.f.home/'AIDev/bin/ds3-play').is_symlink())
    def test_completed_retire_repeat_is_noop(self):
        self.install();h.retire('b'*40);self.assertFalse(h.retire('c'*40)['changed']);self.recover_twice()
    def test_archived_owner_data_is_history_only_after_durable_retire(self):
        for terminal in (False,True):
            with self.subTest(terminal=terminal):
                self.reset_fixture();self.install()
                if terminal:h.retire('b'*40)
                else:self.interrupt_at('archive-root:applied',lambda:h.retire('b'*40))
                archive=self.f.root.with_name(self.f.root.name+' retired '+('b'*12));target=archive/'profiles/ds3/user.reg'
                target.write_bytes(target.read_bytes()+b'\nowner archive edit\n');before=target.read_bytes()
                if terminal:
                    self.recover_twice();self.assertFalse(h.retire('c'*40)['changed'])
                else:
                    with self.assertRaisesRegex(RuntimeError,'lifecycle_retire_drift'):h.recover('c'*40)
                    self.assertEqual(h.lifecycle_load()['state'],'pending')
                self.assertEqual(target.read_bytes(),before);self.assertFalse(self.f.root.exists())
    def test_no_outside_write_when_profile_parent_swapped_before_or_during_clone(self):
        for during in (False,True):
            with self.subTest(during=during):
                self.reset_fixture();outside=self.f.base/'outside';outside.mkdir();original=h.lifecycle_clone;swapped=[]
                def swap():
                    parent=h.lifecycle_directory()/'stage/profiles/ds3';os.rename(parent,parent.with_name('ds3-original'));parent.symlink_to(outside);swapped.append(True)
                def checkpoint(event):
                    if not during and event=='profile/user.reg:intent':swap()
                def clone(source_fd,parent_fd,name):
                    if during and name=='user.reg' and not swapped:swap()
                    return original(source_fd,parent_fd,name)
                with patch.object(h,'lifecycle_checkpoint',side_effect=checkpoint),patch.object(h,'lifecycle_clone',side_effect=clone):
                    with self.assertRaises((RuntimeError,OSError)):self.install()
                self.assertEqual(list(outside.iterdir()),[]);self.assertFalse(self.f.root.exists())
    def test_bootstrap_namespace_creation_interrupt_recovers_twice(self):
        for edge in ('namespace:intent','namespace:applied'):
            with self.subTest(edge=edge):
                self.reset_fixture();self.interrupt_at(edge,self.install);self.recover_twice()
    def test_partial_retained_journal_resumes_exact_prefix_without_losing_current(self):
        self.install();directory=h.lifecycle_directory();raw=(directory/'journal.json').read_bytes();retained=directory/('install-'+('a'*40)+'.json');retained.write_bytes(raw[:16]);retained.chmod(0o600)
        inode=retained.stat().st_ino;h.retire('b'*40);self.assertEqual(retained.read_bytes(),raw);self.assertEqual(retained.stat().st_ino,inode);self.recover_twice()
    def test_concurrent_empty_publication_collision_never_overwritten(self):
        for retirement in (False,True):
            with self.subTest(retirement=retirement):
                self.reset_fixture();original=h.lifecycle_rename;inodes=[]
                if retirement:self.install()
                target=self.f.root.with_name(self.f.root.name+' retired '+('b'*12)) if retirement else self.f.root
                def racing(src,dst,**kwargs):
                    if dst==target.name:target.mkdir();inodes.append(target.stat().st_ino)
                    return original(src,dst,**kwargs)
                with patch.object(h,'lifecycle_rename',side_effect=racing):
                    with self.assertRaisesRegex(RuntimeError,'lifecycle_destination_collision'):
                        h.retire('b'*40) if retirement else self.install()
                self.assertEqual(target.stat().st_ino,inodes[0]);self.assertEqual(list(target.iterdir()),[])
    def test_namespace_swap_during_journal_open_never_writes_outside(self):
        self.install();directory=h.lifecycle_directory();outside=self.f.base/'outside';outside.mkdir();original=h.os.open;fired=[]
        def racing(path,*args,**kwargs):
            if str(path)=='journal.next' and not fired:
                os.rename(directory,directory.with_name('journal-original'));directory.symlink_to(outside);fired.append(True)
            return original(path,*args,**kwargs)
        j=h.lifecycle_load()
        with patch.object(h.os,'open',side_effect=racing):
            with self.assertRaises((RuntimeError,OSError)):h.lifecycle_save(j)
        self.assertEqual(fired,[True]);self.assertEqual(list(outside.iterdir()),[])
    def test_partial_initial_intent_has_exact_repeat_install_handoff(self):
        self.interrupt_at('namespace:intent',self.install);marker=h.lifecycle_bootstrap_path();raw=marker.read_bytes();marker.write_bytes(raw[:24]);inode=marker.stat().st_ino
        with self.assertRaisesRegex(RuntimeError,'lifecycle_bootstrap_incomplete_retry_exact_install'):h.recover('c'*40)
        self.assertFalse(h.lifecycle_directory().exists());self.assertFalse(self.f.root.exists())
        self.install();self.assertEqual(marker.stat().st_ino,inode);self.assertEqual(marker.read_bytes(),raw);self.recover_twice()

if __name__=='__main__':unittest.main()
