"""W18/W41 regression coverage; only temporary fixtures, never owner HOME."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SHELL = ROOT / 'bin/shell-nofile'
LEGACY = ROOT / 'bin/phase5-config-transaction'
M = runpy.run_path(str(SHELL))


class ShellRecovery(unittest.TestCase):
    def child(self, directory, operation, crash=None):
        # Every invocation imports a fresh module in a fresh process. _exit
        # deliberately bypasses catch/cleanup and models a process interruption.
        script = '''
import os, runpy, sys
m = runpy.run_path(sys.argv[1])
fd = os.open(sys.argv[2], os.O_RDONLY | os.O_DIRECTORY)
operation, crash = sys.argv[3:5]
if crash.startswith('create:'):
    real_create = m['create_at']
    def create(fd, name, data):
        real_create(fd, name, data)
        if name == crash.split(':', 1)[1]: os._exit(73)
    m['transaction'].__globals__['create_at'] = create
if crash.startswith('link:') or crash.startswith('before-link:'):
    real = os.link
    def link(source, target, **kwargs):
        if crash.startswith('before-link:') and target == crash.split(':', 1)[1]: os._exit(73)
        real(source, target, **kwargs)
        if target == crash.split(':', 1)[1]: os._exit(73)
    os.link = link
elif crash.startswith('unlink:') or crash.startswith('before-unlink:'):
    real = os.unlink
    def unlink(name, **kwargs):
        if crash.startswith('before-unlink:') and name == crash.split(':', 1)[1]: os._exit(73)
        real(name, **kwargs)
        if name == crash.split(':', 1)[1]: os._exit(73)
    os.unlink = unlink
try: print(m['transaction'](fd, operation, None if operation == 'status' else 'a'*40))
finally: os.close(fd)
'''
        return subprocess.run([sys.executable, '-c', script, str(SHELL), str(directory), operation, crash or ''], capture_output=True, text=True, timeout=10)

    def test_fresh_process_install_and_rollback_recovery(self):
        for phase, crash in (('apply', 'before-link:.zshrc'), ('apply', 'link:.zshrc'), ('apply', 'link:.aid-shell-nofile-receipt.json'), ('apply', 'unlink:.aid-shell-nofile-target.pending'), ('apply', 'unlink:.aid-shell-nofile-receipt.pending'), ('rollback', 'before-unlink:.zshrc'), ('rollback', 'unlink:.zshrc'), ('rollback', 'unlink:.aid-shell-nofile-receipt.json')):
            with self.subTest(phase=phase, crash=crash), tempfile.TemporaryDirectory() as directory:
                if phase == 'rollback': self.assertEqual(self.child(directory, 'apply').returncode, 0)
                self.assertEqual(self.child(directory, phase, crash).returncode, 73)
                status = self.child(directory, 'status')
                self.assertEqual(status.returncode, 0, status.stderr)
                self.assertEqual(status.stdout.strip(), 'RECOVERY_REQUIRED')
                before = {p.name: p.read_bytes() for p in Path(directory).iterdir()}
                refused = self.child(directory, phase)
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn('explicit_recovery_required', refused.stderr)
                self.assertEqual(before, {p.name: p.read_bytes() for p in Path(directory).iterdir()})
                recovered = self.child(directory, 'recover')
                self.assertEqual(recovered.returncode, 0, recovered.stderr)
                self.assertEqual(recovered.stdout.strip(), 'INSTALLED' if phase == 'apply' else 'REMOVED')
                self.assertEqual(self.child(directory, 'status').stdout.strip(), 'INSTALLED' if phase == 'apply' else 'ABSENT')
                names = {p.name for p in Path(directory).iterdir()}
                self.assertEqual(names, {M['TARGET'], M['RECEIPT']} if phase == 'apply' else set())

    def test_short_writes_complete_and_zero_write_never_publishes_target(self):
        for zero in (False, True):
            with self.subTest(zero=zero), tempfile.TemporaryDirectory() as directory:
                fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                real = os.write
                def short(leaf, value): return 0 if zero else real(leaf, value[:3])
                try:
                    with mock.patch('os.write', side_effect=short):
                        if zero:
                            with self.assertRaisesRegex(RuntimeError, 'write_incomplete'): M['transaction'](fd, 'apply', 'a'*40)
                        else: self.assertEqual(M['transaction'](fd, 'apply', 'a'*40), 'INSTALLED')
                    if zero:
                        self.assertFalse((Path(directory)/M['TARGET']).exists())
                        self.assertFalse((Path(directory)/M['RECEIPT']).exists())
                        with self.assertRaisesRegex(RuntimeError, 'unowned_pending_collision'): M['transaction'](fd, 'recover', 'a'*40)
                finally: os.close(fd)

    def test_prepublication_interruptions_preserve_bounded_inspection_handoff(self):
        for leaf in (M['PENDING_TARGET'], M['PENDING_RECEIPT'], M['JOURNAL']):
            with self.subTest(leaf=leaf), tempfile.TemporaryDirectory() as directory:
                self.assertEqual(self.child(directory, 'apply', 'create:'+leaf).returncode, 73)
                self.assertFalse((Path(directory)/M['TARGET']).exists())
                self.assertFalse((Path(directory)/M['RECEIPT']).exists())
                if leaf == M['JOURNAL']:
                    self.assertEqual(self.child(directory, 'status').stdout.strip(), 'RECOVERY_REQUIRED')
                    self.assertEqual(self.child(directory, 'recover').stdout.strip(), 'INSTALLED')
                else:
                    before = {p.name: p.read_bytes() for p in Path(directory).iterdir()}
                    for operation in ('status', 'recover'):
                        result = self.child(directory, operation)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn('unowned_pending_collision', result.stderr)
                        self.assertEqual(before, {p.name: p.read_bytes() for p in Path(directory).iterdir()})

    def test_unknown_exact_payload_is_not_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / M['TARGET']; target.write_bytes(M['PAYLOAD'])
            before = target.stat().st_ino
            result = self.child(directory, 'recover')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('unowned_zshrc_collision', result.stderr)
            self.assertEqual(target.read_bytes(), M['PAYLOAD'])
            self.assertEqual(target.stat().st_ino, before)

    def test_settled_receipt_retains_target_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.child(directory, 'apply').returncode, 0)
            target = Path(directory)/M['TARGET']
            replacement = Path(directory)/'owner-replacement'; replacement.write_bytes(target.read_bytes())
            os.replace(replacement, target)
            before = {p.name: (p.stat().st_ino, p.read_bytes()) for p in Path(directory).iterdir()}
            for operation in ('status', 'apply', 'rollback', 'recover'):
                result = self.child(directory, operation)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('target_identity_drift', result.stderr)
                self.assertEqual(before, {p.name: (p.stat().st_ino, p.read_bytes()) for p in Path(directory).iterdir()})

    def legacy_pair(self, directory):
        target = Path(directory)/M['TARGET']; target.write_bytes(M['PAYLOAD']); target.chmod(0o600)
        receipt = Path(directory)/M['RECEIPT']
        receipt.write_text(json.dumps({'schema': 1, 'commit': 'b'*40, 'sha256': hashlib.sha256(M['PAYLOAD']).hexdigest()}, sort_keys=True)+'\n')
        receipt.chmod(0o600)
        return target

    def test_legacy_pair_requires_explicit_receipt_only_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self.legacy_pair(directory)
            preimage = target.read_bytes(), target.stat().st_ino, target.stat().st_mode
            self.assertEqual(self.child(directory, 'status').stdout.strip(), 'INSTALLED')
            self.assertEqual(self.child(directory, 'apply').stdout.strip(), 'INSTALLED')
            refused = self.child(directory, 'rollback')
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn('legacy_receipt_requires_explicit_migration', refused.stderr)
            migrated = self.child(directory, 'migrate-receipt')
            self.assertEqual(migrated.returncode, 0, migrated.stderr)
            self.assertEqual(migrated.stdout.strip(), 'RECEIPT_MIGRATED')
            self.assertEqual(preimage, (target.read_bytes(), target.stat().st_ino, target.stat().st_mode))
            receipt = json.loads((Path(directory)/M['RECEIPT']).read_bytes())
            self.assertEqual(receipt['schema'], 2)
            self.assertEqual(receipt['targetIdentity']['inode'], target.stat().st_ino)
            self.assertEqual(self.child(directory, 'migrate-receipt').stdout.strip(), 'INSTALLED')
            self.assertEqual(self.child(directory, 'rollback').stdout.strip(), 'REMOVED')
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_fresh_process_receipt_migration_recovery(self):
        for crash in ('before-unlink:'+M['RECEIPT'], 'unlink:'+M['RECEIPT'], 'link:'+M['RECEIPT'], 'unlink:'+M['PENDING_RECEIPT'], 'unlink:'+M['PENDING_LEGACY']):
            with self.subTest(crash=crash), tempfile.TemporaryDirectory() as directory:
                target = self.legacy_pair(directory)
                preimage = target.read_bytes(), target.stat().st_ino, target.stat().st_mode
                self.assertEqual(self.child(directory, 'migrate-receipt', crash).returncode, 73)
                self.assertEqual(self.child(directory, 'status').stdout.strip(), 'RECOVERY_REQUIRED')
                recovered = self.child(directory, 'recover')
                self.assertEqual(recovered.returncode, 0, recovered.stderr)
                self.assertEqual(recovered.stdout.strip(), 'RECEIPT_MIGRATED')
                self.assertEqual(preimage, (target.read_bytes(), target.stat().st_ino, target.stat().st_mode))
                self.assertEqual({p.name for p in Path(directory).iterdir()}, {M['TARGET'], M['RECEIPT']})
                self.assertEqual(self.child(directory, 'status').stdout.strip(), 'INSTALLED')

    def test_migration_refuses_unknown_target_bytes_and_preserves_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            target = self.legacy_pair(directory); target.write_bytes(b'# owner content\n')
            before = {p.name: p.read_bytes() for p in Path(directory).iterdir()}
            result = self.child(directory, 'migrate-receipt')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(before, {p.name: p.read_bytes() for p in Path(directory).iterdir()})

    def test_recovery_refuses_changed_or_replaced_target_and_receipt(self):
        for leaf, replace in ((M['TARGET'], False), (M['TARGET'], True), (M['RECEIPT'], True)):
            with self.subTest(leaf=leaf, replace=replace), tempfile.TemporaryDirectory() as directory:
                crash = 'link:' + (M['RECEIPT'] if leaf == M['RECEIPT'] else M['TARGET'])
                self.assertEqual(self.child(directory, 'apply', crash).returncode, 73)
                target = Path(directory)/leaf
                if replace:
                    original = target.read_bytes()
                    replacement = Path(directory)/'owner-replacement'; replacement.write_bytes(original)
                    os.replace(replacement, target)
                else: target.write_bytes(b'# owner content\n')
                before = {p.name: (p.stat().st_ino, p.read_bytes()) for p in Path(directory).iterdir()}
                result = self.child(directory, 'recover')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(before, {p.name: (p.stat().st_ino, p.read_bytes()) for p in Path(directory).iterdir()})

    def test_duplicate_journal_and_symlink_do_not_grant_ownership(self):
        for kind in ('duplicate', 'symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                journal = Path(directory)/M['JOURNAL']
                if kind == 'duplicate': journal.write_bytes(b'{"schema":1,"schema":1}\n')
                else: journal.symlink_to(Path(directory)/'foreign')
                result = self.child(directory, 'recover')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual({p.name for p in Path(directory).iterdir()}, {M['JOURNAL']})

    def test_named_pipe_cannot_block_inspection_or_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            os.mkfifo(Path(directory)/M['TARGET'], 0o600)
            for operation in ('status', 'recover'):
                result = self.child(directory, operation)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('unsafe_file', result.stderr)
            self.assertTrue((Path(directory)/M['TARGET']).exists())

    def test_scoped_gate_consumes_actual_target_without_vendor_probe(self):
        from lib import operation_readiness
        for operation in ('apply', 'rollback', 'recover', 'migrate-receipt'):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                namespace = M['gate'].__globals__
                before = {key: namespace[key] for key in ('HOME', 'CONTROL', 'HERE', '__file__')}
                try:
                    control = Path(directory)/'AIDev/control'
                    namespace.update(HOME=Path(directory), CONTROL=control, HERE=control, __file__=str(control/'bin/shell-nofile'))
                    def observed(control, kind, commit, *, checks, target_guard):
                        self.assertEqual(kind, 'shell-apply' if operation == 'apply' else 'shell-recovery')
                        return operation_readiness.evaluate(kind, commit, checks=checks, source_guard=lambda: True, target_guard=target_guard)
                    with mock.patch.object(operation_readiness, 'require_scoped_operation_ready', side_effect=observed), mock.patch('subprocess.run', side_effect=AssertionError('unrelated vendor must not launch')):
                        report = M['gate']('a'*40, fd, operation)
                    self.assertTrue(report['scopedCandidateReady'])
                    self.assertFalse(report['machineMutationAuthorized'])
                finally:
                    namespace.update(before); os.close(fd)

    def test_scoped_gate_catches_target_drift_at_boundary(self):
        from lib import operation_readiness
        with tempfile.TemporaryDirectory() as directory:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            namespace = M['gate'].__globals__
            before = {key: namespace[key] for key in ('HOME', 'CONTROL', 'HERE', '__file__')}
            try:
                control = Path(directory)/'AIDev/control'
                namespace.update(HOME=Path(directory), CONTROL=control, HERE=control, __file__=str(control/'bin/shell-nofile'))
                def drift(control, kind, commit, *, checks, target_guard):
                    (Path(directory)/M['TARGET']).write_bytes(b'# owner content\n')
                    return operation_readiness.evaluate(kind, commit, checks=checks, source_guard=lambda: True, target_guard=target_guard)
                with mock.patch.object(operation_readiness, 'require_scoped_operation_ready', side_effect=drift):
                    with self.assertRaisesRegex(RuntimeError, 'operation_target_drift'): M['gate']('a'*40, fd, 'recover')
                self.assertEqual((Path(directory)/M['TARGET']).read_bytes(), b'# owner content\n')
            finally: namespace.update(before); os.close(fd)


class LegacyRetired(unittest.TestCase):
    def test_pure_merge_and_imported_writers_retired(self):
        legacy = runpy.run_path(str(LEGACY))
        current = b'# owner\napproval_policy = "on-request" # comment\nsandbox_mode = "workspace-write"\n[desktop]\nnotifications = true\n'
        with mock.patch('subprocess.run', side_effect=AssertionError('no subprocess')), mock.patch('os.open', side_effect=AssertionError('no filesystem')):
            self.assertEqual(legacy['merge'](current), current.replace(b'"on-request"', b'"never"').replace(b'"workspace-write"', b'"danger-full-access"'))
            for command in ('stage', 'apply', 'rollback', 'main'):
                with self.assertRaisesRegex(SystemExit, 'legacy executor retired'): legacy[command](object())
        self.assertNotIn('atomic_replace', legacy)
        self.assertNotIn('write_private', legacy)

    def test_actual_descriptor_runner_imports_retained_pure_api(self):
        runner = runpy.run_path(str(ROOT/'bin/phase5-apply-transaction'))
        current = b'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n'
        with mock.patch('subprocess.run', side_effect=AssertionError('no native parser or mutation')):
            tool = runner['load_merge_tool']()
            self.assertEqual(tool.merge(current), b'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')

    def test_merge_fail_closed_inputs_and_missing_keys(self):
        legacy = runpy.run_path(str(LEGACY))
        for current in (b'\xff', b'approval_policy = "never"\napproval_policy = "never"\n', b'approval_policy = { value = "never" }\n', b'model = "fixture"'):
            with self.subTest(current=current), self.assertRaises(SystemExit): legacy['merge'](current)
        current = b'model = "fixture"\n[desktop]\nnotifications = true\n'
        merged = legacy['merge'](current)
        self.assertIn(current.splitlines()[0], merged)
        self.assertIn(b'approval_policy = "never"', merged)
        self.assertIn(b'[desktop]\nnotifications = true\n', merged)

    def test_valid_legacy_cli_vectors_preserve_concurrent_owner_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); home = root/'.codex'; home.mkdir()
            target = home/'config.toml'; target.write_bytes(b'# concurrent owner edit\n')
            staged = root/'staged'; staged.write_bytes(b'# unrelated staging\n')
            backup = root/'backup'; backup.write_bytes(b'# old owner state\n')
            receipt = root/'receipt'; receipt.write_text(json.dumps({'schema':1, 'target':'config.toml', 'managedKeys':['approval_policy','sandbox_mode'], 'reviewedCommit':'a'*40, 'beforeSHA256':hashlib.sha256(target.read_bytes()).hexdigest(), 'afterSHA256':hashlib.sha256(staged.read_bytes()).hexdigest()}))
            before = {str(p.relative_to(root)): (p.stat().st_ino, p.stat().st_mode, p.read_bytes()) for p in root.rglob('*') if p.is_file()}
            common = ['--codex-home', str(home), '--current', str(target), '--receipt', str(receipt), '--reviewed-commit', 'a'*40]
            for command in ('stage', 'apply', 'rollback'):
                args = [command, *common, '--backup' if command == 'rollback' else '--staged', str(backup if command == 'rollback' else staged)]
                if command == 'stage': args += ['--backup', str(root/'never-created/backup')]
                result = subprocess.run([sys.executable, str(LEGACY), *args], capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('legacy executor retired', result.stderr)
                self.assertEqual(before, {str(p.relative_to(root)): (p.stat().st_ino, p.stat().st_mode, p.read_bytes()) for p in root.rglob('*') if p.is_file()})
                self.assertFalse((root/'never-created').exists())
            for args in ([], ['--help'], ['garbage']):
                result = subprocess.run([sys.executable, str(LEGACY), *args], capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('legacy executor retired', result.stderr)


if __name__ == '__main__': unittest.main()
