import base64
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'bin/windows-to-mac-ssh'
loader = importlib.machinery.SourceFileLoader('reverse_ssh', str(SOURCE))
spec = importlib.util.spec_from_loader(loader.name, loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)
KEY = b'ssh-ed25519 ' + base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0 ' + b'x' * 32) + b'\n'

class ReverseSSHTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.state = self.base / 'state'
        self.plists = [self.base / (x + '.plist') for x in m.LABELS]

    def seed(self, phase='pending'):
        self.state.mkdir(mode=0o700)
        expected = m.payload(self.state, self.plists, KEY)
        receipt = {'schema': 1, 'commit': 'a' * 40, 'phase': phase,
                   'hostPublicHash': '', 'files': {
                       str(p): {'sha256': m.digest(data), 'mode': mode}
                       for p, (data, mode) in expected.items()}}
        m.save_receipt(self.state, receipt)
        return expected, receipt

    def read(self):
        with patch.object(m, 'safe_chain'):
            return m.load_receipt(self.state, self.plists)

    def test_public_key_rejects_multiple_keys_and_options(self):
        self.assertEqual(m.public_key(KEY), KEY)
        for bad in (KEY + KEY, b'command="oops" ' + KEY, b'ssh-ed25519 eA==\n', b'\xff'):
            with self.assertRaises(m.ContractError):
                m.public_key(bad)

    def test_server_is_loopback_key_only_and_owner_bound(self):
        config = m.render_config(self.state, 'owner').decode()
        for required in ('ListenAddress 127.0.0.1\n', 'AllowUsers owner\n',
                         'UsePAM no\n', 'AuthenticationMethods publickey\n',
                         'DisableForwarding yes\n', 'Subsystem sftp internal-sftp\n'):
            self.assertIn(required, config)
        with self.assertRaises(m.ContractError):
            m.render_config(self.state, 'owner\nPermitRootLogin yes')

    def test_reverse_listener_explicitly_loopback(self):
        generated = m.payload(self.state, self.plists, KEY)
        p = plistlib.loads(generated[self.plists[1]][0])
        self.assertIn('127.0.0.1:22222:127.0.0.1:22222', p['ProgramArguments'])
        self.assertIn('ExitOnForwardFailure=yes', p['ProgramArguments'])
        self.assertEqual(p['ProgramArguments'][-1], 'windows-host')
        self.assertTrue(p['KeepAlive'])

    def test_exclusive_write_never_overwrites_unknown_file(self):
        target = self.base / 'unknown'
        target.write_bytes(b'owner data')
        with self.assertRaises(FileExistsError):
            m.atomic_new(target, b'replacement', 0o600)
        self.assertEqual(target.read_bytes(), b'owner data')

    def test_pending_allows_missing_files_but_applied_rejects(self):
        _, receipt = self.seed()
        self.assertEqual(self.read()['phase'], 'pending')
        receipt['phase'] = 'applied'
        m.save_receipt(self.state, receipt)
        with self.assertRaises(m.ContractError):
            self.read()

    def test_drift_blocks_cleanup_before_any_job_stop(self):
        expected, receipt = self.seed()
        p, (_, mode) = next(iter(expected.items()))
        m.atomic_new(p, b'unrelated bytes', mode)
        with patch.object(m, 'safe_chain'), patch.object(m, 'run') as command:
            with self.assertRaises(m.ContractError):
                m.stop_and_remove(self.state, self.plists, receipt)
            command.assert_not_called()
        self.assertEqual(p.read_bytes(), b'unrelated bytes')

    def test_pending_cleanup_is_repeatable_and_preserves_keys(self):
        expected, receipt = self.seed()
        for p, (data, mode) in list(expected.items())[:2]:
            m.atomic_new(p, data, mode)
        m.atomic_new(self.state / 'host_ed25519', b'private-never-read', 0o600)
        m.atomic_new(self.state / 'host_ed25519.pub', KEY, 0o644)
        receipt['hostPublicHash'] = m.digest(KEY)
        m.save_receipt(self.state, receipt)
        original = Path.read_bytes
        def guarded(path):
            if path.name == 'host_ed25519':
                raise AssertionError('private key read')
            return original(path)
        with patch.object(m, 'safe_chain'), patch.object(m, 'loaded', return_value=False), patch.object(Path, 'read_bytes', guarded):
            m.stop_and_remove(self.state, self.plists, receipt)
            stopped = m.load_receipt(self.state, self.plists)
            m.stop_and_remove(self.state, self.plists, stopped)
        self.assertTrue((self.state / 'host_ed25519').exists())
        self.assertEqual(self.read()['phase'], 'stopped')

    def test_symlink_and_unknown_state_fail_closed(self):
        expected, _ = self.seed()
        target = self.base / 'owner-data'
        target.write_bytes(b'owner data')
        (self.state / 'authorized_keys').symlink_to(target)
        with self.assertRaises(m.ContractError):
            self.read()
        (self.state / 'authorized_keys').unlink()
        (self.state / 'unknown').write_bytes(b'x')
        with self.assertRaises(m.ContractError):
            self.read()

    def test_receipt_cannot_authorize_arbitrary_removal(self):
        _, receipt = self.seed()
        receipt['files'][str(self.base / 'victim')] = {'sha256': 'a' * 64, 'mode': 0o600}
        m.save_receipt(self.state, receipt)
        with self.assertRaises(m.ContractError):
            self.read()

    def test_noop_requires_same_key_and_commit(self):
        expected = m.payload(self.state, self.plists, KEY)
        receipt = {'phase': 'applied', 'commit': 'a' * 40, 'files': {
            str(p): {'sha256': m.digest(data), 'mode': mode} for p, (data, mode) in expected.items()}}
        source = self.base / 'public'
        source.write_bytes(KEY)
        with patch.object(m, 'exact_commit'), patch.object(m, 'prepare'), patch.object(m, 'paths', return_value=(self.state, self.plists)), patch.object(m, 'load_receipt', return_value=receipt), patch.object(m, 'doctor', return_value={'result': 'pass'}), patch.object(m, 'atomic_new') as create:
            self.assertTrue(m.apply('a' * 40, source)['applyNoop'])
            with self.assertRaises(m.ContractError):
                m.apply('b' * 40, source)
            create.assert_not_called()

if __name__ == '__main__':
    unittest.main()
