import importlib.machinery
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader(
    "codex_windows-host_ssh_stdio_compat",
    str(ROOT / "bin/codex-windows-host-ssh-stdio-compat"),
)
module = loader.load_module()


class CodexWindowsHostSshStdioCompatTests(unittest.TestCase):
    def test_existing_environment_classification(self):
        self.assertEqual(module.classify_existing_env(""), "absent")
        self.assertEqual(module.classify_existing_env("1"), "exact")
        self.assertEqual(module.classify_existing_env("0"), "conflict")
        self.assertEqual(module.classify_existing_env("unexpected"), "conflict")

    def test_initialize_response_accepts_only_windows_result(self):
        valid = json.dumps({
            "id": 1,
            "result": {
                "platformFamily": "windows",
                "platformOs": "windows",
                "userAgent": "synthetic",
                "codexHome": "synthetic-private-path-that-must-be-ignored",
            },
        })
        self.assertTrue(module.validate_initialize_line(valid))
        self.assertFalse(module.validate_initialize_line("not-json"))
        self.assertFalse(module.validate_initialize_line(json.dumps({
            "id": 1,
            "result": {
                "platformFamily": "unix",
                "platformOs": "macos",
                "userAgent": "synthetic",
            },
        })))
        self.assertFalse(module.validate_initialize_line(json.dumps({
            "id": 2,
            "result": {
                "platformFamily": "windows",
                "platformOs": "windows",
                "userAgent": "synthetic",
            },
        })))

    def test_receipt_state_accepts_only_owned_legacy_or_native_shapes(self):
        legacy = {
            "schema": 1,
            "profile": module.PROFILE,
            "commit": "a" * 40,
            "previousAbsent": True,
        }
        native = {
            "schema": 2,
            "profile": module.PROFILE,
            "commit": "b" * 40,
            "mode": "native_ssh",
            "previousEnvironment": "exact",
            "previousReceiptCommit": "a" * 40,
        }
        self.assertEqual(module.receipt_state(None), "absent")
        self.assertEqual(module.receipt_state(legacy), "legacy_stdio")
        self.assertEqual(module.receipt_state(native), "native_ssh")
        self.assertEqual(module.receipt_state({**native, "mode": "other"}),
                         "invalid")
        self.assertEqual(module.receipt_state({**legacy, "commit": "short"}),
                         "invalid")

    def test_websocket_upgrade_validator_is_fail_closed(self):
        valid = (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
        )
        self.assertTrue(module.validate_websocket_upgrade(valid))
        self.assertFalse(module.validate_websocket_upgrade(
            valid.replace(b"101", b"200", 1)
        ))
        self.assertFalse(module.validate_websocket_upgrade(
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n"
        ))

    def test_apply_migrates_exact_legacy_receipt_to_native(self):
        old_commit = "a" * 40
        new_commit = "b" * 40
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            receipt = state / "receipt.json"
            receipt.write_text(json.dumps({
                "schema": 1,
                "profile": module.PROFILE,
                "commit": old_commit,
                "previousAbsent": True,
                "sessionScoped": True,
            }))
            completed = subprocess.CompletedProcess([], 0, "", "")
            with (
                mock.patch.object(module, "STATE", state),
                mock.patch.object(module, "RECEIPT", receipt),
                mock.patch.object(module, "require_exact_commit"),
                mock.patch.object(module, "preflight", return_value={
                    "verdict": "PASS", "environment_state": "exact",
                }),
                mock.patch.object(module, "current_env", return_value=""),
                mock.patch.object(module, "run", return_value=completed) as run,
            ):
                result = module.apply(new_commit)
            migrated = json.loads(receipt.read_text())
            self.assertEqual(result["verdict"], "PASS")
            self.assertEqual(migrated["mode"], "native_ssh")
            self.assertEqual(migrated["commit"], new_commit)
            self.assertEqual(migrated["previousReceiptCommit"], old_commit)
            run.assert_called_once_with(["/bin/launchctl", "unsetenv", module.FLAG])

    def test_rollback_restores_exact_legacy_receipt(self):
        old_commit = "a" * 40
        new_commit = "b" * 40
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            receipt = state / "receipt.json"
            receipt.write_text(json.dumps({
                "schema": 2,
                "profile": module.PROFILE,
                "commit": new_commit,
                "mode": "native_ssh",
                "previousEnvironment": "exact",
                "previousReceiptCommit": old_commit,
                "sessionScoped": True,
            }))
            completed = subprocess.CompletedProcess([], 0, "", "")
            with (
                mock.patch.object(module, "STATE", state),
                mock.patch.object(module, "RECEIPT", receipt),
                mock.patch.object(module, "current_env", side_effect=["", "1"]),
                mock.patch.object(module, "run", return_value=completed) as run,
            ):
                result = module.rollback()
            restored = json.loads(receipt.read_text())
            self.assertEqual(result["verdict"], "PASS")
            self.assertEqual(restored["schema"], 1)
            self.assertEqual(restored["commit"], old_commit)
            run.assert_called_once_with(
                ["/bin/launchctl", "setenv", module.FLAG, module.VALUE]
            )
    def test_manifest_keeps_scope_session_only(self):
        manifest = json.loads((
            ROOT / "manifests/codex-windows-host-ssh-stdio-compat.json"
        ).read_text())
        self.assertTrue(manifest["compatibility"]["sessionScoped"])
        self.assertTrue(manifest["compatibility"]["requiresDesktopRestart"])
        self.assertEqual(
            manifest["compatibility"]["desiredEnvironmentState"], "absent"
        )
        self.assertFalse(manifest["dataBoundary"]["rawLogsRead"])

    def test_rollback_is_receipt_and_drift_guarded(self):
        source = (ROOT / "bin/codex-windows-host-ssh-stdio-compat").read_text()
        self.assertIn("receipt_missing", source)
        self.assertIn("rollback_previous_state_unknown", source)
        self.assertIn("rollback_refuses_environment_drift", source)

    def test_native_probe_is_disposable_and_sanitized(self):
        source = (ROOT / "bin/codex-windows-host-ssh-stdio-compat").read_text()
        self.assertIn("remote_native_websocket_handshake_passes", source)
        self.assertIn("mktemp -d", source)
        self.assertIn('rm -rf -- "$probe_home"', source)
        self.assertIn("app-server proxy", source)
        self.assertIn("HTTP/1.1 101", source)
        self.assertIn("upgrade: websocket", source)
        self.assertIn("REMOTE_CONTROL_FLAG", source)

    def test_runtime_doctor_checks_duplicate_local_server_absent(self):
        source = (ROOT / "bin/codex-windows-host-ssh-stdio-compat").read_text()
        self.assertIn("local_desktop_app_server_is_single", source)
        self.assertIn("single_local_desktop_app_server", source)

    def test_strict_ssh_probe_filters_runtime_identifiers(self):
        source = (ROOT / "bin/codex-windows-host-ssh-stdio-compat").read_text()
        self.assertIn("ssh -G windows-host", source)
        self.assertIn("identitiesonly", source)
        self.assertIn("stricthostkeychecking", source)
        self.assertIn("runtime identifiers never enter", source)

    def test_probe_cleanup_targets_only_the_exact_child(self):
        source = (ROOT / "bin/codex-windows-host-ssh-stdio-compat").read_text()
        self.assertNotIn("killpg", source)
        self.assertIn("process.terminate()", source)


if __name__ == "__main__":
    unittest.main()
