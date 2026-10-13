"""Client preservation and collision behavior against an isolated home."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'bin/windows-to-mac-client'


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        stub = self.home / 'bin'
        stub.mkdir()
        ssh = stub / 'ssh'
        ssh.write_text('#!/bin/sh\nif [ "$1" = -G ]; then echo "hostname mac"; else exit 1; fi\n')
        ssh.chmod(0o755)
        self.env = dict(os.environ, HOME=str(self.home), PATH=str(stub) + ':' + os.environ['PATH'])

    def call(self, action, **values):
        return subprocess.run(['/bin/bash', str(SCRIPT), action], env=dict(self.env, **values),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def install(self):
        import base64
        return self.call('install', MAC_USER='fixture', MAC_HOST_PUBLIC_B64=base64.b64encode(self.pub).decode())

    def prepare(self):
        r = self.call('prepare')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.pub = r.stdout

    def test_preserves_config_and_idempotence_and_rollback(self):
        self.prepare()
        config = self.home / '.ssh/config'
        original = b'Host unrelated\r\n  HostName example.invalid\r\n'
        config.write_bytes(original)
        self.assertEqual(self.install().returncode, 0)
        installed = config.read_bytes()
        self.assertEqual(installed, b'Include ~/.ssh/aidev-mac/config\n' + original)
        self.assertEqual(self.install().returncode, 0)
        self.assertEqual(config.read_bytes(), installed)
        self.assertEqual(self.call('rollback').returncode, 0)
        self.assertEqual(config.read_bytes(), original)
        self.assertTrue((self.home / '.ssh/aidev-mac/id_ed25519').is_file())

    def test_unknown_directory_is_not_adopted(self):
        target = self.home / '.ssh/aidev-mac'
        target.mkdir(parents=True)
        self.assertNotEqual(self.call('prepare').returncode, 0)
        self.assertEqual(list(target.iterdir()), [])

    def test_ssh_directory_symlink_rejected(self):
        dest = self.home / 'other'
        dest.mkdir()
        (self.home / '.ssh').symlink_to(dest)
        self.assertNotEqual(self.call('prepare').returncode, 0)
        self.assertEqual(list(dest.iterdir()), [])

    def test_existing_alias_preserved(self):
        self.prepare()
        config = self.home / '.ssh/config'
        old = b'Host mac\n  HostName example.invalid\n'
        config.write_bytes(old)
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(config.read_bytes(), old)

    def test_host_pin_drift_rejected(self):
        self.prepare()
        self.assertEqual(self.install().returncode, 0)
        known = self.home / '.ssh/aidev-mac/known_hosts'
        known.write_text('unknown\n')
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(known.read_text(), 'unknown\n')


if __name__ == '__main__':
    unittest.main()
