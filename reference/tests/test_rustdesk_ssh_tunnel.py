import importlib.machinery
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

M = importlib.machinery.SourceFileLoader('rustdesk_tunnel', str(Path(__file__).resolve().parents[1] / 'bin/rustdesk-ssh-tunnel')).load_module()

class TunnelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve() / 'tunnel.plist'
        p = patch.object(M, 'target', return_value=self.path)
        p.start(); self.addCleanup(p.stop)

    def install_file(self):
        self.path.write_bytes(M.rendered()); self.path.chmod(0o600)

    def test_scope_is_loopback_fixed(self):
        d = plistlib.loads(M.rendered())
        self.assertEqual(d['ProgramArguments'], M.ARGS)
        self.assertIn('127.0.0.1:22118:127.0.0.1:21118', M.ARGS)
        self.assertEqual(M.ARGS[-1], 'windows-host')
        self.assertNotIn('-g', M.ARGS)
        self.assertEqual(d['StandardErrorPath'], '/dev/null')

    def test_unknown_file_preserved(self):
        self.path.write_bytes(b'owner'); self.path.chmod(0o600)
        with self.assertRaisesRegex(M.Failure, 'managed_plist_drift'):
            M.apply(lambda: True)
        self.assertEqual(self.path.read_bytes(), b'owner')

    def test_foreign_listener_refuses_install(self):
        with patch.object(M, 'loaded_pid', return_value=None), patch.object(M, 'listener_pids', return_value={99:['127.0.0.1:22118']}):
            with self.assertRaisesRegex(M.Failure, 'port_already_owned'):
                M.apply(lambda: True)
        self.assertFalse(self.path.exists())

    def test_unowned_service_refuses_install(self):
        with patch.object(M, 'loaded_pid', return_value=99):
            with self.assertRaisesRegex(M.Failure, 'unowned_service_conflict'):
                M.apply(lambda: True)
        self.assertFalse(self.path.exists())

    def test_exact_noop_checks_doctor(self):
        self.install_file()
        with patch.object(M, 'doctor') as check:
            self.assertFalse(M.apply(lambda: True))
            check.assert_called_once()

    def test_successful_apply(self):
        with patch.object(M, 'loaded_pid', return_value=None), patch.object(M, 'listener_pids', return_value={}), patch.object(M, 'run', return_value=subprocess.CompletedProcess([],0,b'',b'')), patch.object(M,'doctor'):
            self.assertTrue(M.apply(lambda: True))
        self.assertEqual(self.path.read_bytes(), M.rendered())

    def test_bootstrap_failure_removes_exact_file(self):
        with patch.object(M,'loaded_pid',return_value=None), patch.object(M,'listener_pids',return_value={}), patch.object(M,'run',return_value=subprocess.CompletedProcess([],1,b'',b'')):
            with self.assertRaisesRegex(M.Failure,'bootstrap_failed'):
                M.apply(lambda: True)
        self.assertFalse(self.path.exists())

    def test_rollback_never_unloads_without_owned_file(self):
        with patch.object(M,'loaded_pid',return_value=99), patch.object(M,'run') as run:
            with self.assertRaisesRegex(M.Failure,'unowned_service_conflict'):
                M.rollback(lambda: True)
            run.assert_not_called()

    def test_doctor_rejects_wildcard_listener(self):
        self.install_file()
        with patch.object(M,'verify_loaded_job'), patch.object(M,'loaded_pid',return_value=99), patch.object(M,'run',return_value=subprocess.CompletedProcess([],0,' '.join(M.ARGS).encode(),b'')), patch.object(M,'listener_pids',return_value={99:['*:22118']}):
            with self.assertRaisesRegex(M.Failure,'tunnel_listener_mismatch'):
                M.doctor()

    def test_symlink_preserved(self):
        other=Path(self.temp.name)/'owner';other.write_bytes(b'owner')
        self.path.symlink_to(other)
        with self.assertRaises(M.Failure):M.apply(lambda: True)
        self.assertEqual(other.read_bytes(),b'owner')

    def test_invalid_guard_before_apply_writes_nothing(self):
        with patch.object(M, 'run') as run:
            with self.assertRaisesRegex(M.Failure, 'current_source_drift'):
                M.apply(lambda: False)
            run.assert_not_called()
        self.assertFalse(self.path.exists())

    def test_guard_drift_after_publication_preserves_exact_recovery_file(self):
        calls = []
        def guard():
            calls.append(True)
            return len(calls) < 3
        with patch.object(M, 'loaded_pid', return_value=None), patch.object(M, 'listener_pids', return_value={}), patch.object(M, 'run') as run:
            with self.assertRaisesRegex(M.Failure, 'current_source_drift'):
                M.apply(guard)
            run.assert_not_called()
        self.assertEqual(self.path.read_bytes(), M.rendered())
        with patch.object(M, 'loaded_pid', return_value=None):
            self.assertTrue(M.rollback(lambda: True))
        self.assertFalse(self.path.exists())

    def test_guard_drift_prevents_rollback_deletion(self):
        self.install_file()
        calls = []
        def guard():
            calls.append(True)
            return len(calls) == 1
        with patch.object(M, 'loaded_pid', return_value=None):
            with self.assertRaisesRegex(M.Failure, 'current_source_drift'):
                M.rollback(guard)
        self.assertEqual(self.path.read_bytes(), M.rendered())

    def test_admitted_source_callback_holds_guard_without_full_probe(self):
        import sys
        sys.path.insert(0, str(M.ROOT))
        from lib import workstation_maintenance_delivery as delivery
        commit = 'a' * 40
        events = []
        def admission(root, *, full, operation_check):
            self.assertFalse(full)
            self.assertEqual(root, M.ROOT)
            events.append('opened')
            operation_check(commit, source_guard=lambda: events.append('guard') or True)
            events.append('closed')
        def operation(guard):
            self.assertEqual(events[0], 'opened')
            self.assertNotIn('closed', events)
            self.assertTrue(guard())
            return True
        with patch.object(delivery, 'admitted_source', side_effect=admission), patch.object(M, 'apply', side_effect=operation):
            self.assertTrue(M.admitted_mutation('apply', commit))
        self.assertEqual(events[-1], 'closed')

    def loaded_output(self, args=None, path=None):
        return (f'path = {path or self.path}\nprogram = /usr/bin/ssh\narguments = {{\n'
                + '\n'.join(args or M.ARGS) + '\n}\n').encode()

    def test_loaded_identity_accepts_exact_arguments(self):
        with patch.object(M, 'run', return_value=subprocess.CompletedProcess([], 0, self.loaded_output(), b'')):
            M.verify_loaded_job(self.path)

    def test_rollback_refuses_same_path_different_cached_arguments(self):
        self.install_file()
        other_args = M.ARGS[:-1] + ['other-host']
        with patch.object(M, 'loaded_pid', return_value=99), patch.object(M, 'run', return_value=subprocess.CompletedProcess([], 0, self.loaded_output(other_args), b'')) as run:
            with self.assertRaisesRegex(M.Failure, 'loaded_job_identity_mismatch'):
                M.rollback(lambda: True)
            self.assertEqual(run.call_count, 1)
            self.assertEqual(run.call_args.args[0][1], 'print')
        self.assertTrue(self.path.exists())

    def test_loaded_identity_rejects_wrong_source_or_duplicate_blocks(self):
        for output in (self.loaded_output(path='/other/source.plist'), self.loaded_output() + b'arguments = {\n/usr/bin/ssh\n}\n'):
            with patch.object(M, 'run', return_value=subprocess.CompletedProcess([], 0, output, b'')):
                with self.assertRaisesRegex(M.Failure, 'loaded_job_identity_mismatch'):
                    M.verify_loaded_job(self.path)

    def test_guard_invalidated_during_final_listener_check_prevents_bootstrap(self):
        valid = [True]
        calls = []
        def listeners():
            calls.append(True)
            if len(calls) == 2:
                valid[0] = False
            return {}
        with patch.object(M, 'loaded_pid', return_value=None), patch.object(M, 'listener_pids', side_effect=listeners), patch.object(M, 'run') as run:
            with self.assertRaisesRegex(M.Failure, 'current_source_drift'):
                M.apply(lambda: valid[0])
            run.assert_not_called()
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.path.read_bytes(), M.rendered())

if __name__ == '__main__':
    unittest.main()
