import importlib.machinery
import json
from pathlib import Path
import plistlib
import unittest


ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader(
    "codex_windows-host_ssh_app_server_holder",
    str(ROOT / "bin/codex-windows-host-ssh-app-server-holder"),
)
module = loader.load_module()


class CodexWindowsHostSshAppServerHolderTests(unittest.TestCase):
    def test_plist_is_user_background_keepalive_without_logs(self):
        runtime = Path("/bounded/runtime")
        payload = plistlib.loads(module.render_plist(runtime))
        self.assertEqual(payload["Label"], module.LABEL)
        self.assertEqual(payload["ProgramArguments"], [str(runtime)])
        self.assertTrue(payload["RunAtLoad"])
        self.assertTrue(payload["KeepAlive"])
        self.assertEqual(payload["StandardOutPath"], "/dev/null")
        self.assertEqual(payload["StandardErrorPath"], "/dev/null")

    def test_websocket_validator_accepts_only_upgrade(self):
        valid = (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
        )
        self.assertTrue(module.validate_websocket_upgrade(valid))
        self.assertFalse(module.validate_websocket_upgrade(
            b"HTTP/1.1 200 OK\r\n\r\n"
        ))

    def test_manifest_preserves_unrelated_state(self):
        manifest = json.loads((
            ROOT / "manifests/codex-windows-host-ssh-app-server-holder.json"
        ).read_text())
        self.assertIn("RDP, RustDesk and SMB", manifest["preservedState"])
        self.assertFalse(manifest["dataBoundary"]["privateKeyReadOrCopied"])

    def test_exact_commit_and_hash_gates_are_present(self):
        source = (
            ROOT / "bin/codex-windows-host-ssh-app-server-holder"
        ).read_text()
        self.assertIn("require_exact_commit", source)
        self.assertIn("replace_receipt", source)
        self.assertIn("receipt_rebind_postcheck_failed_restored", source)
        self.assertIn("rollback_target_hash_mismatch", source)
        self.assertIn("apply_failed_rolled_back", source)
        self.assertNotIn("killpg", source)


if __name__ == "__main__":
    unittest.main()
