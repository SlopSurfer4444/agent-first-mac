"""Synthetic owner filesystem only. No sudo, native doctor, installer or build."""
import contextlib
import copy
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('delivery', ROOT / 'lib/root_delivery.py')
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)


class DeliveryTests(unittest.TestCase):
    def test_current_source_closure_and_emergency_pin_match_release(self):
        release = D.load_release(ROOT)
        self.assertEqual(release['sourceAcceptanceRole'], 'reference-only-not-release-self-acceptance')
        source = (ROOT / 'Sources/AidAdminEmergencyCore/AidAdminEmergencyCore.swift').read_text()
        pin = re.search(r'binarySHA256: "([0-9a-f]{64})",\s+binarySize: ([0-9_]+)', source)
        self.assertIsNotNone(pin)
        expected = {'sha256': pin[1], 'size': int(pin[2].replace('_', ''))}
        self.assertEqual(release['installedContracts']['successor']['broker'], expected)
        self.assertNotEqual(release['installedContracts']['predecessor']['broker'], expected)
        self.assertIn('Sources/AidAdminCore/GitObservation.swift', release['sourceArtifactSHA256'])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='root-delivery-test-')
        self.base = Path(self.temp.name).resolve()
        self.home = self.base / 'home'
        self.install, self.emergency = self.base / 'install', self.base / 'emergency'
        for directory in (self.home, self.install, self.emergency):
            directory.mkdir(mode=0o700)
        self.uid = os.getuid()
        self.release = json.loads((ROOT / D.MANIFEST).read_bytes())
        for role, row in self.release['artifacts'].items():
            raw = ('synthetic artifact ' + role + '\n').encode()
            row.update(sha256=D.digest(raw), size=len(raw))
            path = (self.install if row['bundle'] == 'install' else self.emergency) / row['file']
            path.write_bytes(raw)
            path.chmod(int(row['mode'], 8))
        for role in ('broker', 'policy'):
            self.release['installedContracts']['successor'][role] = {key: self.release['artifacts'][role][key] for key in ('sha256', 'size')}

    def tearDown(self):
        self.temp.cleanup()

    def stage(self, guard=lambda: True):
        return D.stage_release(self.release, self.install, self.emergency, self.home, self.uid, source_guard=guard)

    def pending(self, parent=None):
        parent = parent or self.home / Path(D.SUFFIX).parent
        return list(parent.glob('.' + D.RELEASE_ID + '.pending-*'))

    def test_stage_verify_noop_preserves_originals(self):
        original = {p: p.read_bytes() for folder in (self.install, self.emergency) for p in folder.iterdir()}
        result = self.stage()
        self.assertEqual(result['status'], 'STAGED')
        self.assertFalse(result['installed'])
        self.assertEqual(D.verify_durable(self.release, self.home, self.uid)['releaseID'], D.RELEASE_ID)
        emergency = Path(result['emergency'])
        self.assertEqual(emergency.stat().st_uid, self.uid)
        self.assertEqual(emergency.stat().st_mode & 0o777, 0o555)
        inode = emergency.stat().st_ino
        self.assertEqual(self.stage()['status'], 'UNCHANGED')
        self.assertEqual(emergency.stat().st_ino, inode)
        self.assertEqual({p: p.read_bytes() for p in original}, original)

    def test_unknown_existing_target_never_overwritten(self):
        target = self.home / D.SUFFIX
        target.mkdir(parents=True, mode=0o700)
        foreign = target / 'foreign'
        foreign.write_bytes(b'owner data')
        with self.assertRaises(D.Fault):
            self.stage()
        self.assertEqual(foreign.read_bytes(), b'owner data')

    def test_existing_release_drift_refused(self):
        self.stage()
        path = self.home / D.SUFFIX / 'aid-admin-emergency-action'
        path.chmod(0o755)
        path.write_bytes(b'foreign bytes')
        with self.assertRaises(D.Fault):
            self.stage()
        self.assertEqual(path.read_bytes(), b'foreign bytes')

    def test_symlink_hardlink_fifo_and_wrong_mode_inputs(self):
        path = self.emergency / 'aid-admin-emergency-action'
        original = path.read_bytes()
        path.unlink()
        path.symlink_to(self.install / 'aid-admin')
        with self.assertRaises((OSError, D.Fault)):
            self.stage()
        path.unlink()
        os.link(self.install / 'aid-admin', path)
        with self.assertRaises(D.Fault):
            self.stage()
        path.unlink()
        os.mkfifo(path, mode=0o600)
        with self.assertRaises(D.Fault):
            self.stage()
        path.unlink()
        path.write_bytes(original)
        path.chmod(0o777)
        with self.assertRaises(D.Fault):
            self.stage()
        self.assertFalse((self.home / 'AIDev').exists())

    def test_parent_symlink_no_outside_write(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (self.home / 'AIDev').symlink_to(outside)
        with self.assertRaises((OSError, D.Fault)):
            self.stage()
        self.assertEqual(list(outside.iterdir()), [])

    def test_source_guard_failure_retains_partial_without_publishing(self):
        calls = 0
        def guard():
            nonlocal calls
            calls += 1
            return calls < 6
        with self.assertRaises(D.Fault):
            self.stage(guard)
        parent = self.home / Path(D.SUFFIX).parent
        self.assertFalse((self.home / D.SUFFIX).exists())
        pending, = self.pending(parent)
        self.assertTrue(pending.is_dir())
        retained = {p.name: p.read_bytes() for p in pending.iterdir()}
        self.assertEqual(self.stage()['status'], 'STAGED')
        self.assertEqual({p.name: p.read_bytes() for p in pending.iterdir()}, retained)

    def test_bundle_drift_before_publication_refused(self):
        real = D.verify_bundles
        calls = 0
        def changing(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                path = self.install / 'aid-admin'
                path.chmod(0o755)
                path.write_bytes(b'drift')
                path.chmod(0o555)
            return real(*args)
        with patch.object(D, 'verify_bundles', changing), self.assertRaises(D.Fault):
            self.stage()
        self.assertFalse((self.home / D.SUFFIX).exists())

    def test_exclusive_publication_collision(self):
        real = D.rename_exclusive
        def collide(fd, source, target):
            os.mkdir(target, mode=0o700, dir_fd=fd)
            real(fd, source, target)
        with patch.object(D, 'rename_exclusive', collide), self.assertRaises(OSError):
            self.stage()
        self.assertEqual(list((self.home / D.SUFFIX).iterdir()), [])
        self.assertEqual(len(self.pending()), 1)

    def test_manifest_closed_no_path_or_authority_substitution(self):
        for key, value in [('releaseID', '../outside'), ('destinationSuffix', '/outside'),
            ('independentReleaseReviewRequired', False), ('sourceAcceptedCommit', '0' * 40)]:
            changed = copy.deepcopy(self.release)
            changed[key] = value
            with self.assertRaises(D.Fault):
                D.validate_release(changed)
        changed = copy.deepcopy(self.release)
        changed['artifacts']['emergency']['destination'] = '../outside'
        with self.assertRaises(D.Fault):
            D.validate_release(changed)
        with self.assertRaises(D.Fault):
            D.parse(b'{"schema":1,"schema":1}')

    def test_native_gate_order_and_no_launcher_before_preflight(self):
        events = []
        def gate(*, full, operation_check=None):
            self.assertFalse(full, 'unrelated full vendor gate')
            events.append('full' if full else 'git')
            if operation_check:
                operation_check(D.BASE, source_guard=lambda: True)
        with patch.object(D, 'load_release', return_value=self.release), patch.object(D, 'admitted_source', gate), \
                patch.object(D.pwd, 'getpwuid', return_value=type('Owner', (), {'pw_dir': str(self.home)})()):
            staged = D.native('stage', self.install, self.emergency)
            self.assertEqual(events, ['git'])
            self.assertNotIn('launcher', staged)
            self.assertNotIn('launcher', D.native('verify'))
        with patch.object(D, 'load_release', return_value=self.release), \
                patch.object(D, 'admitted_source', side_effect=D.Fault('source_unadmitted')), \
                patch.object(D, 'stage_release') as stage:
            with self.assertRaises(D.Fault):
                D.native('stage', self.install, self.emergency)
            stage.assert_not_called()

    def test_cli_rejects_unpaired_arguments_without_native(self):
        with patch.object(D, 'native') as native, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(D.main(['stage', '--install-bundle', str(self.install)]), 1)
            self.assertEqual(D.main(['verify', '--emergency-bundle', str(self.emergency)]), 1)
        native.assert_not_called()

    def test_connected_native_source_gate_never_launches_vendor_and_keeps_target_guards(self):
        from lib import current_doctor_native as N
        root = self.home / 'AIDev/control'
        root.mkdir(parents=True, mode=0o700)
        doctor = SimpleNamespace(public_report=lambda value, **kwargs: value)
        calls = []
        source_ok = [True]
        def native(loaded, git_only, *, operation_check):
            self.assertIs(loaded, doctor)
            self.assertIs(git_only, True, 'unrelated vendor sentinel requested')
            calls.append(git_only)
            if not source_ok[0]:
                raise D.Fault('source_unadmitted')
            self.assertIs(operation_check(D.BASE, source_guard=lambda: True), True)
            return {'integratedMain': True, 'verdict': 'GIT_ONLY_VALID'}
        with patch.object(D, 'ROOT', root), patch.object(D, 'load_release', return_value=self.release), \
                patch.object(D.pwd, 'getpwuid', return_value=SimpleNamespace(pw_dir=str(self.home))), \
                patch.object(D.importlib.machinery.SourceFileLoader, 'load_module', return_value=doctor), \
                patch.object(N, 'native', side_effect=native), \
                patch.object(N.probe, 'observe', side_effect=AssertionError('vendor launch forbidden')):
            source_ok[0] = False
            with patch.object(D, 'stage_release') as stage, self.assertRaises(D.Fault):
                D.native('stage', self.install, self.emergency)
            stage.assert_not_called()
            source_ok[0] = True
            artifact = self.install / self.release['artifacts']['broker']['file']
            original = artifact.read_bytes()
            artifact.chmod(0o700)
            artifact.write_bytes(b'unknown target')
            artifact.chmod(0o555)
            with self.assertRaises(D.Fault):
                D.native('stage', self.install, self.emergency)
            artifact.chmod(0o700)
            artifact.write_bytes(original)
            artifact.chmod(0o555)
            self.assertEqual(D.native('stage', self.install, self.emergency)['status'], 'STAGED')
        self.assertEqual(calls, [True, True, True])

    def test_handoff_requires_held_source_and_known_predecessor_not_vendor(self):
        self.stage()
        events = []
        def gate(*, full, operation_check=None):
            self.assertFalse(full, 'unrelated full vendor gate')
            events.append('full' if full else 'git')
            if operation_check:
                operation_check(D.BASE, source_guard=lambda: True)
        def health(release, home, uid, source_guard, *, allow_predecessor):
            self.assertTrue(allow_predecessor)
            self.assertTrue(source_guard())
            events.append('health')
            return {'verdict': 'PREDECESSOR_READY'}
        with patch.object(D, 'load_release', return_value=self.release), patch.object(D, 'admitted_source', gate), \
                patch.object(D.pwd, 'getpwuid', return_value=SimpleNamespace(pw_dir=str(self.home))), \
                patch.dict(sys.modules, {'lib.root_runtime_health': SimpleNamespace(native_health=health)}):
            result = D.native('handoff')
            self.assertEqual(events, ['git', 'health'])
            self.assertEqual(result['status'], 'OWNER_NATIVE_HANDOFF')
            self.assertEqual(Path(result['launcher']).name, 'launch-owner-authenticated-install.zsh')
            self.assertFalse(result['installerExecuted'])
        with patch.object(D, 'load_release', return_value=self.release), patch.object(D, 'admitted_source', gate), \
                patch.object(D.pwd, 'getpwuid', return_value=SimpleNamespace(pw_dir=str(self.home))), \
                patch.dict(sys.modules, {'lib.root_runtime_health': SimpleNamespace(native_health=lambda *a, **k: {'verdict': 'ROOT_RUNTIME_READY'})}):
            result = D.native('handoff')
            self.assertEqual(result['status'], 'ROOT_ALREADY_INSTALLED')
            self.assertNotIn('launcher', result)
        with patch.object(D, 'load_release', return_value=self.release), patch.object(D, 'admitted_source', gate), \
                patch.object(D.pwd, 'getpwuid', return_value=SimpleNamespace(pw_dir=str(self.home))), \
                patch.dict(sys.modules, {'lib.root_runtime_health': SimpleNamespace(native_health=lambda *a, **k: {'verdict': 'BLOCKED'})}):
            with self.assertRaisesRegex(D.Fault, 'installed_preflight_failed'):
                D.native('handoff')

    def test_held_parent_replacement_refused_before_payload_write(self):
        calls = 0
        def guard():
            nonlocal calls
            calls += 1
            if calls == 4:
                parent = self.home / Path(D.SUFFIX).parent
                parent.rename(parent.with_name('retained-parent'))
                parent.mkdir(mode=0o700)
            return True
        with self.assertRaises((OSError, D.Fault)):
            self.stage(guard)
        parent = self.home / Path(D.SUFFIX).parent
        self.assertEqual(list(parent.iterdir()), [])
        pending, = self.pending(parent.with_name('retained-parent'))
        self.assertEqual(list(pending.iterdir()), [])

    def test_legacy_and_foreign_pending_are_preserved_not_consumed(self):
        parent = self.home / Path(D.SUFFIX).parent
        parent.mkdir(parents=True, mode=0o700)
        legacy = parent / ('.' + D.RELEASE_ID + '.pending')
        legacy.mkdir(mode=0o700)
        (legacy / 'owner-data').write_bytes(b'never adopt or delete')
        foreign = parent / (legacy.name + '-foreign')
        foreign.symlink_to(self.emergency, target_is_directory=True)
        self.assertEqual(self.stage()['status'], 'STAGED')
        self.assertEqual((legacy / 'owner-data').read_bytes(), b'never adopt or delete')
        self.assertTrue(foreign.is_symlink())
        self.assertEqual(self.stage()['status'], 'UNCHANGED')

    def test_retention_limit_is_explicit_and_published_target_still_works(self):
        parent = self.home / Path(D.SUFFIX).parent
        parent.mkdir(parents=True, mode=0o700)
        for index in range(D.MAX_RETAINED_ATTEMPTS):
            (parent / ('.' + D.RELEASE_ID + '.pending-' + str(index))).mkdir(mode=0o700)
        with self.assertRaisesRegex(D.Fault, 'retained_attempt_limit_preserve_and_review'):
            self.stage()
        self.assertEqual(len(self.pending()), D.MAX_RETAINED_ATTEMPTS)
        # The bound applies to new staging only, not verification/no-op.
        with patch.object(D, 'MAX_RETAINED_ATTEMPTS', D.MAX_RETAINED_ATTEMPTS + 1):
            self.stage()
        self.assertEqual(self.stage()['status'], 'UNCHANGED')

    def test_failure_after_each_filesystem_mutation_can_retry_without_cleanup(self):
        operations = [(D.os, name) for name in ('mkdir', 'write', 'fchmod', 'fsync')]
        operations.append((D, 'rename_exclusive'))
        observed = []
        def run_with_failure(fail_at):
            events = []
            with contextlib.ExitStack() as stack:
                for module, name in operations:
                    real = getattr(module, name)
                    def wrapped(*args, _real=real, _name=name, **kwargs):
                        result = _real(*args, **kwargs)
                        events.append(_name)
                        if len(events) == fail_at:
                            raise RuntimeError('injected crash')
                        return result
                    stack.enter_context(patch.object(module, name, wrapped))
                self.stage()
            return events
        observed = run_with_failure(None)
        for index, name in enumerate(observed, 1):
            with self.subTest(index=index, operation=name):
                self.home = self.base / ('fault-home-' + str(index))
                self.home.mkdir(mode=0o700)
                with self.assertRaisesRegex(RuntimeError, 'injected crash'):
                    run_with_failure(index)
                parent = self.home / Path(D.SUFFIX).parent
                retained = {p: (p.stat().st_ino, p.read_bytes())
                    for directory in self.pending(parent) for p in directory.iterdir()}
                self.assertIn(self.stage()['status'], ('STAGED', 'UNCHANGED'))
                self.assertEqual({p: (p.stat().st_ino, p.read_bytes()) for p in retained}, retained)
                self.assertEqual(self.stage()['status'], 'UNCHANGED')


if __name__ == '__main__':
    unittest.main()
