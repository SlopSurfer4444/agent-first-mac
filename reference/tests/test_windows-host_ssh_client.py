import base64
import hashlib
import importlib.machinery
from pathlib import Path
import unittest


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


if __name__ == "__main__":
    unittest.main()
