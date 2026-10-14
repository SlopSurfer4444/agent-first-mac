"""Disposable-root tests; never invoke a native runtime or adapter live route."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


b = load('offline_policy_bootstrap', HERE.parent / 'bin/ds3-policy-source-bootstrap')
w = load('offline_bootstrap_root', HERE.parent / 'bin/wine-runtime-overlay')


class Interrupted(BaseException):
    pass


class Fixture:
    def __init__(self):
        self.path = Path(tempfile.mkdtemp(prefix='wine-overlay-fixture-')).resolve()
        self.path.chmod(0o700)
        (self.path / '.fixture-only').write_bytes(w.MARKER)
        self.root = w.Root(self.path)
        self.policy = b'{"schema":2,"installedPolicy":"exact ancestry"}\n'
        self.hub = b'{"id":"games-hub","immutableSource":"exact ancestry"}\n'
        self.kw = {'policy_sha256': b.digest(self.policy), 'source_hub_sha256': b.digest(self.hub)}
        self.gates = 0
        # Poison profile content proves this core never reads or follows it.
        (self.path / 'profiles').mkdir(mode=0o700)
        (self.path / 'profiles/account').symlink_to('/never-read-bootstrap-account')

    def gate(self):
        self.gates += 1

    def run(self, **options):
        return b.bootstrap(self.root, self.policy, self.hub, gate=options.pop('gate', self.gate), **self.kw, **options)

    def ready(self):
        return b.verify_ready(self.root, self.policy, self.hub, **self.kw)

    def close(self):
        self.root.close()
        shutil.rmtree(self.path)


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.addCleanup(self.f.close)

    def test_exact_publication_noop_modes_and_userdata(self):
        with self.assertRaisesRegex(b.Blocked, 'bootstrap_not_ready'):
            self.f.ready()
        self.assertTrue(self.f.run()['changed'])
        self.assertTrue(self.f.ready())
        before = {str(p.relative_to(self.f.path)): (p.stat().st_ino, p.read_bytes())
                  for p in self.f.path.rglob('*') if p.is_file() and not p.is_symlink()}
        gates = self.f.gates
        self.assertFalse(self.f.run()['changed'])
        self.assertGreater(self.f.gates, gates)
        after = {str(p.relative_to(self.f.path)): (p.stat().st_ino, p.read_bytes())
                 for p in self.f.path.rglob('*') if p.is_file() and not p.is_symlink()}
        self.assertEqual(before, after)
        for directory in (b.STATE, b.DESTINATION):
            self.assertEqual((self.f.path / directory).stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.f.root.read(b.DESTINATION + '/' + b.FILES[0]), (self.f.policy, 0o600))
        self.assertEqual(self.f.root.read(b.DESTINATION + '/' + b.FILES[1]), (self.f.hub, 0o600))
        self.assertTrue((self.f.path / 'profiles/account').is_symlink())

    def test_every_declared_boundary_resumes_without_adopting_scratch(self):
        events = []
        self.f.run(event=events.append)
        for boundary in events:
            with self.subTest(boundary=boundary):
                f = Fixture()
                try:
                    def interrupt(event):
                        if event == boundary:
                            raise Interrupted()
                    with self.assertRaises(Interrupted):
                        f.run(event=interrupt)
                    scratch = list(f.path.glob(b.STATE + '.prepare-*'))
                    retained = {p.name: sorted(str(x.relative_to(p)) for x in p.rglob('*')) for p in scratch}
                    if boundary != 'directory-published':
                        with self.assertRaises(b.Blocked):
                            f.ready()
                    f.run()
                    self.assertTrue(f.ready())
                    for p in scratch:
                        self.assertEqual(retained[p.name], sorted(str(x.relative_to(p)) for x in p.rglob('*')))
                finally:
                    f.close()

    def test_before_and_after_each_exclusive_rename_resume(self):
        for operation in (1, 2):
            for after in (False, True):
                with self.subTest(operation=operation, after=after):
                    f = Fixture()
                    try:
                        original = b.exclusive_rename
                        count = 0
                        def interrupt(*args):
                            nonlocal count
                            count += 1
                            if count == operation and not after:
                                raise Interrupted()
                            original(*args)
                            if count == operation and after:
                                raise Interrupted()
                        with patch.object(b, 'exclusive_rename', interrupt):
                            with self.assertRaises(Interrupted):
                                f.run()
                        f.run()
                        self.assertTrue(f.ready())
                    finally:
                        f.close()

    def test_pin_and_gate_fail_before_any_bootstrap_state(self):
        with self.assertRaisesRegex(b.Blocked, 'bootstrap_input_pin'):
            b.bootstrap(self.f.root, self.f.policy, self.f.hub, policy_sha256='0' * 64,
                        source_hub_sha256=self.f.kw['source_hub_sha256'], gate=self.f.gate)
        def inactive_failed():
            raise RuntimeError('prefix_active')
        with self.assertRaisesRegex(RuntimeError, 'prefix_active'):
            self.f.run(gate=inactive_failed)
        with self.assertRaisesRegex(b.Blocked, 'bootstrap_gate_must_assert'):
            self.f.run(gate=lambda: True)
        self.assertEqual(list(self.f.path.glob(b.STATE + '*')), [])

    def test_exact_unowned_destination_is_never_adopted(self):
        self.f.root.mkdir(b.DESTINATION)
        for name, raw in zip(b.FILES, (self.f.policy, self.f.hub)):
            self.f.root.write_new(b.DESTINATION + '/' + name, raw)
        with self.assertRaisesRegex(b.Blocked, 'bootstrap_unowned_destination'):
            self.f.run()
        with self.assertRaisesRegex(b.Blocked, 'bootstrap_not_ready'):
            self.f.ready()
        self.assertFalse((self.f.path / b.STATE).exists())

    def test_partial_unknown_state_is_retained_and_blocks(self):
        self.f.root.mkdir(b.STATE)
        self.f.root.write_new(b.STATE + '/owner.json', b'partial')
        with self.assertRaisesRegex(b.Blocked, 'bootstrap_state_inventory'):
            self.f.run()
        self.assertEqual(self.f.root.read(b.STATE + '/owner.json')[0], b'partial')
        self.assertFalse((self.f.path / b.DESTINATION).exists())

    def test_ready_drift_symlink_hardlink_mode_and_extra_files_block(self):
        for drift in ('bytes', 'symlink', 'hardlink', 'mode', 'extra', 'directory-mode', 'journal', 'owner'):
            with self.subTest(drift=drift):
                f = Fixture()
                try:
                    f.run()
                    target = f.path / b.DESTINATION / b.FILES[0]
                    if drift == 'bytes': target.write_bytes(b'unknown')
                    elif drift in ('symlink', 'hardlink'):
                        target.unlink()
                        outside = f.path / 'unrelated'; outside.write_bytes(f.policy); outside.chmod(0o600)
                        if drift == 'symlink': target.symlink_to(outside)
                        else: os.link(outside, target)
                    elif drift == 'mode': target.chmod(0o640)
                    elif drift == 'extra': (target.parent / 'unknown').write_bytes(b'keep')
                    elif drift == 'directory-mode': target.parent.chmod(0o750)
                    elif drift == 'journal': (f.path / b.STATE / 'journal.json').write_bytes(b'changed')
                    elif drift == 'owner': (f.path / b.STATE / 'owner.json').write_bytes(b'changed')
                    observed = target.lstat()
                    with self.assertRaises((b.Blocked, w.Blocked, OSError)): f.run()
                    with self.assertRaises((b.Blocked, w.Blocked, OSError)): f.ready()
                    self.assertEqual(target.lstat().st_ino, observed.st_ino)
                finally:
                    f.close()

    def test_gate_drift_before_publication_retains_intent_and_blocks_launch(self):
        calls = 0
        def gate():
            nonlocal calls
            calls += 1
            if calls == 3:
                (self.f.path / b.STATE / 'publish' / b.FILES[0]).write_bytes(b'unknown third state')
        with self.assertRaisesRegex(b.Blocked, 'bootstrap_image_drift'):
            self.f.run(gate=gate)
        self.assertFalse((self.f.path / b.DESTINATION).exists())
        with self.assertRaises(b.Blocked): self.f.ready()
        self.assertEqual(self.f.root.read(b.STATE + '/publish/' + b.FILES[0])[0], b'unknown third state')

    def test_exclusive_destination_collision_never_clobbers(self):
        original = b.exclusive_rename
        def collision(source_parent, source_name, destination_parent, destination_name):
            if destination_name == b.DESTINATION:
                os.mkdir(destination_name, 0o700, dir_fd=destination_parent)
            return original(source_parent, source_name, destination_parent, destination_name)
        with patch.object(b, 'exclusive_rename', collision):
            with self.assertRaises(FileExistsError): self.f.run()
        self.assertEqual(list((self.f.path / b.DESTINATION).iterdir()), [])
        self.assertTrue((self.f.path / b.STATE / 'publish').is_dir())
        with self.assertRaisesRegex(b.Blocked, 'bootstrap_publication_state'): self.f.run()


if __name__ == '__main__':
    unittest.main()
