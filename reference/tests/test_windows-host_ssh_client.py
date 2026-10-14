import base64
import hashlib
import importlib.machinery
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader(
    "windows-host_ssh_client", str(ROOT / "bin/windows-host-ssh-client")
)
module = loader.load_module()


class WindowsHostSSHClientTests(unittest.TestCase):
    def test_public_blob_fingerprint(self):
        blob = b"synthetic-ed25519-host-key-fixture"
        body = base64.b64encode(blob).decode("ascii")
        expected = "SHA256:" + base64.b64encode(
            hashlib.sha256(blob).digest()
        ).decode("ascii").rstrip("=")
        self.assertEqual(module.public_blob_fingerprint(body), expected)

    def test_known_host_is_hashed(self):
        body = base64.b64encode(b"fixture").decode("ascii")
        rendered = module.hashed_known_host("100.64.0.1", "ssh-ed25519", body)
        self.assertTrue(rendered.startswith(b"|1|"))
        self.assertNotIn(b"100.64.0.1", rendered)
        self.assertIn(b" ssh-ed25519 ", rendered)

    def test_alias_is_strict(self):
        rendered = module.render_alias_config("100.64.0.1", "fixture-user").decode()
        self.assertIn("StrictHostKeyChecking yes", rendered)
        self.assertIn("PasswordAuthentication no", rendered)
        self.assertIn("KbdInteractiveAuthentication no", rendered)
        self.assertIn("IdentitiesOnly yes", rendered)
        self.assertIn("ForwardAgent no", rendered)
        self.assertNotIn("StrictHostKeyChecking no", rendered)

    def test_apply_has_exact_noop_path(self):
        source = (ROOT / "bin/windows-host-ssh-client").read_text()
        self.assertIn("already_applied_runtime_identity_mismatch", source)
        self.assertIn("apply_noop=", source)

    def test_doctor_uses_the_canonical_posix_remote_shell(self):
        source = (ROOT / "bin/windows-host-ssh-client").read_text()
        self.assertIn('"printf BRIDGE_STRICT_OK"', source)
        self.assertNotIn("cmd.exe /d /c echo BRIDGE_STRICT_OK", source)

    def fixture(self, directory):
        home = Path(directory)
        paths = module.layout(home)
        paths["ssh"].mkdir(mode=0o700)
        paths["config_dir"].mkdir(mode=0o700)
        paths["state"].mkdir(parents=True, mode=0o700)
        for key, mode in (("private", 0o600), ("public", 0o644)):
            paths[key].write_bytes(b"opaque never-read fixture")
            paths[key].chmod(mode)
        body = base64.b64encode(b"synthetic fixture").decode()
        images = {"main": module.render_main_config(),
                  "alias": module.render_alias_config("100.64.0.1", "fixture"),
                  "known": module.hashed_known_host("100.64.0.1", "ssh-ed25519", body)}
        for key, data in images.items():
            paths[key].write_bytes(data)
            paths[key].chmod(0o600)
        receipt = {"schema": 1, "status": "applied", "host": "100.64.0.1", "user": "fixture",
            "hostFingerprint": module.public_blob_fingerprint(body),
            "managed": {alias: module.sha256_bytes(images[name]) for name, alias in
                        (("main", "config"), ("alias", "alias"), ("known", "knownHosts"))}}
        paths["receipt"].write_text(json.dumps(receipt))
        paths["receipt"].chmod(0o600)
        return home, paths

    def test_routine_doctor_authenticates_pin_without_keyscan_or_full_doctor(self):
        with tempfile.TemporaryDirectory(prefix="ssh-client-fixture-") as directory:
            home, paths = self.fixture(directory)
            effective = "\n".join(("stricthostkeychecking true", "passwordauthentication no",
                "kbdinteractiveauthentication no", "identitiesonly yes", "forwardagent no",
                "preferredauthentications publickey", "pubkeyauthentication yes"))
            with patch.object(module, "canonical_home", return_value=home), \
                 patch.object(module, "resolve_windows_peer", return_value="100.64.0.1"), \
                 patch.object(module, "scan_ed25519_host_key", side_effect=AssertionError("routine keyscan")), \
                 patch.object(module.subprocess, "run", side_effect=[SimpleNamespace(stdout=effective),
                    SimpleNamespace(stdout="BRIDGE_STRICT_OK")]) as run:
                module.doctor()
            self.assertEqual(run.call_count, 2)
            smoke = run.call_args.args[0]
            for option in ("BatchMode=yes", "StrictHostKeyChecking=yes", "HostKeyAlgorithms=ssh-ed25519",
                           "GlobalKnownHostsFile=/dev/null", "PreferredAuthentications=publickey",
                           "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "ForwardAgent=no"):
                self.assertIn(option, smoke)
            self.assertIn(f"UserKnownHostsFile={paths['known']}", smoke)

    def test_changed_host_key_fails_strict_smoke_without_fallback(self):
        with tempfile.TemporaryDirectory(prefix="ssh-client-fixture-") as directory:
            home, _ = self.fixture(directory)
            effective = "\n".join(("stricthostkeychecking true", "passwordauthentication no",
                "kbdinteractiveauthentication no", "identitiesonly yes", "forwardagent no",
                "preferredauthentications publickey", "pubkeyauthentication yes"))
            with patch.object(module, "canonical_home", return_value=home), \
                 patch.object(module, "resolve_windows_peer", return_value="100.64.0.1"), \
                 patch.object(module, "scan_ed25519_host_key", side_effect=AssertionError("routine keyscan")), \
                 patch.object(module.subprocess, "run", side_effect=[SimpleNamespace(stdout=effective),
                    subprocess.CalledProcessError(255, "ssh")]) as run:
                with self.assertRaises(subprocess.CalledProcessError):
                    module.doctor()
                self.assertEqual(run.call_count, 2)

    def test_enrollment_retains_independent_keyscan_fingerprint_check(self):
        with tempfile.TemporaryDirectory(prefix="ssh-enrollment-fixture-") as directory:
            home = Path(directory)
            paths = module.layout(home)
            paths["ssh"].mkdir(mode=0o700)
            for key, mode in (("private", 0o600), ("public", 0o644)):
                paths[key].write_bytes(b"opaque never-read fixture")
                paths[key].chmod(mode)
            body = base64.b64encode(b"fixture").decode()
            with patch.object(module, "canonical_home", return_value=home), \
                 patch.object(module, "resolve_windows_peer", return_value="100.64.0.1"), \
                 patch.object(module, "scan_ed25519_host_key", return_value=("100.64.0.1", "ssh-ed25519", body)) as scan:
                with self.assertRaisesRegex(module.ProfileError, "independent_host_fingerprint_mismatch"):
                    module.prepare("SHA256:" + "A" * 43, "fixture")
                scan.assert_called_once()



class TransportMigrationTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from unittest.mock import patch
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.paths = module.layout(self.home)
        self.paths['ssh'].mkdir(mode=0o700)
        self.paths['config_dir'].mkdir(mode=0o700)
        self.paths['state'].mkdir(parents=True, mode=0o700)
        for name, mode in (('private', 0o600), ('public', 0o644)):
            self.paths[name].write_bytes(b'fixture')
            self.paths[name].chmod(mode)
        import json
        body = base64.b64encode(b'fixture').decode()
        values = {'main': module.render_main_config(),
                  'alias': module.render_alias_config('100.64.0.1', 'fixture-user'),
                  'known': module.hashed_known_host('100.64.0.1', 'ssh-ed25519', body)}
        receipt = {'schema': 1, 'status': 'applied', 'host': '100.64.0.1',
                   'user': 'fixture-user', 'hostFingerprint': module.public_blob_fingerprint(body),
                   'managed': {target: module.sha256_bytes(values[name]) for name, target in
                               (('main', 'config'), ('alias', 'alias'), ('known', 'knownHosts'))}}
        values['receipt'] = (json.dumps(receipt) + '\n').encode()
        for name, data in values.items():
            self.paths[name].write_bytes(data)
            self.paths[name].chmod(0o600)
        self.before = {name: self.paths[name].read_bytes() for name in values}
        for name, value in (('canonical_home', self.home), ('tailscale_cli', Path('/fixture'))):
            patcher = patch.object(module, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_migrate_noop_and_restore_exact(self):
        from unittest.mock import patch
        with patch.object(module, 'doctor') as doctor:
            self.assertTrue(module.migrate_transport())
            self.assertFalse(module.migrate_transport())
            self.assertEqual(doctor.call_count, 2)
        self.assertIn(b'ProxyCommand ', self.paths['alias'].read_bytes())
        module.transport_restore(self.paths)
        for name, value in self.before.items():
            self.assertEqual(self.paths[name].read_bytes(), value)

    def test_failed_smoke_restores_exact(self):
        from unittest.mock import patch
        with patch.object(module, 'doctor', side_effect=module.ProfileError('smoke_failed')):
            with self.assertRaisesRegex(module.ProfileError, 'smoke_failed'):
                module.migrate_transport()
        for name, value in self.before.items():
            self.assertEqual(self.paths[name].read_bytes(), value)

    def test_drift_is_preserved(self):
        self.paths['alias'].write_bytes(b'owner change')
        with self.assertRaisesRegex(module.ProfileError, 'managed_bytes_drift'):
            module.migrate_transport()
        self.assertEqual(self.paths['alias'].read_bytes(), b'owner change')

    def test_recovery_refuses_unknown_poststate(self):
        from unittest.mock import patch
        with patch.object(module, 'doctor'):
            module.migrate_transport()
        self.paths['alias'].write_bytes(b'owner change')
        with self.assertRaisesRegex(module.ProfileError, 'transport_recovery_drift'):
            module.transport_restore(self.paths)
        self.assertEqual(self.paths['alias'].read_bytes(), b'owner change')

    def test_interrupted_alias_only_transaction_recovers(self):
        from unittest.mock import patch
        with patch.object(module, 'doctor'):
            module.migrate_transport()
        self.paths['receipt'].write_bytes(self.before['receipt'])
        module.transport_restore(self.paths)
        for name, value in self.before.items():
            self.assertEqual(self.paths[name].read_bytes(), value)

    def test_existing_backup_is_not_overwritten(self):
        journal = self.paths['state'] / 'transport-backup.json'
        journal.write_bytes(b'previous transaction')
        journal.chmod(0o600)
        with self.assertRaisesRegex(module.ProfileError, 'managed_target_collision'):
            module.migrate_transport()
        self.assertEqual(journal.read_bytes(), b'previous transaction')
        self.assertEqual(self.paths['alias'].read_bytes(), self.before['alias'])

    def test_doctor_proxy_checks_pin_and_avoids_direct_scan(self):
        from unittest.mock import patch
        import subprocess
        with patch.object(module, 'doctor'):
            module.migrate_transport()
        effective = '\n'.join(['stricthostkeychecking true', 'passwordauthentication no',
                               'kbdinteractiveauthentication no', 'identitiesonly yes',
                               'forwardagent no', f'proxycommand {module.PROXY}',
                               'preferredauthentications publickey', 'pubkeyauthentication yes',
                               'hostkeyalgorithms ssh-ed25519', 'globalknownhostsfile /dev/null',
                               'batchmode yes', f"userknownhostsfile {self.paths['known']}"])
        results = [subprocess.CompletedProcess([], 0, effective),
                   subprocess.CompletedProcess([], 0, 'BRIDGE_STRICT_OK')]
        with patch.object(module, 'resolve_windows_peer', return_value='100.64.0.1'), \
             patch.object(module, 'scan_ed25519_host_key', side_effect=AssertionError('direct scan')), \
             patch.object(module.subprocess, 'run', side_effect=results):
            module.doctor()
        import json
        receipt = json.loads(self.paths['receipt'].read_text())
        receipt['hostFingerprint'] = 'SHA256:wrong'
        self.paths['receipt'].write_text(json.dumps(receipt))
        with patch.object(module, 'resolve_windows_peer', return_value='100.64.0.1'):
            with self.assertRaisesRegex(module.ProfileError, 'pinned_host_key_drift'):
                module.doctor()

    def test_proxy_pin_for_other_host_is_rejected_before_ssh(self):
        with patch.object(module, 'doctor'):
            module.migrate_transport()
        body = base64.b64encode(b'fixture').decode()
        wrong = module.hashed_known_host('100.64.0.2', 'ssh-ed25519', body)
        self.paths['known'].write_bytes(wrong)
        receipt = json.loads(self.paths['receipt'].read_text())
        receipt['managed']['knownHosts'] = module.sha256_bytes(wrong)
        self.paths['receipt'].write_text(json.dumps(receipt))
        with patch.object(module, 'resolve_windows_peer', return_value='100.64.0.1'), \
             patch.object(module.subprocess, 'run') as run:
            with self.assertRaisesRegex(module.ProfileError, 'pinned_host_key_drift'):
                module.doctor()
            run.assert_not_called()

    def test_proxy_cannot_silently_fall_back_to_direct_alias(self):
        with patch.object(module, 'doctor'):
            module.migrate_transport()
        direct = self.before['alias']
        self.paths['alias'].write_bytes(direct)
        receipt = json.loads(self.paths['receipt'].read_text())
        receipt['managed']['alias'] = module.sha256_bytes(direct)
        self.paths['receipt'].write_text(json.dumps(receipt))
        with patch.object(module, 'resolve_windows_peer', return_value='100.64.0.1'), \
             patch.object(module.subprocess, 'run') as run:
            with self.assertRaisesRegex(module.ProfileError, 'managed_policy_drift'):
                module.doctor()
            run.assert_not_called()

    def test_unknown_transport_is_not_treated_as_direct(self):
        receipt = json.loads(self.paths['receipt'].read_text())
        receipt['transport'] = 'unexpected'
        self.paths['receipt'].write_text(json.dumps(receipt))
        with patch.object(module, 'resolve_windows_peer', return_value='100.64.0.1'), \
             patch.object(module.subprocess, 'run') as run:
            with self.assertRaisesRegex(module.ProfileError, 'unsupported_transport'):
                module.doctor()
            run.assert_not_called()

if __name__ == "__main__":
    unittest.main()
