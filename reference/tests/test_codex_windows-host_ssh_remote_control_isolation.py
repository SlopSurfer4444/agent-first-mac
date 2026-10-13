import importlib.machinery
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader(
    "codex_windows-host_ssh_remote_control_isolation",
    str(ROOT / "bin/codex-windows-host-ssh-remote-control-isolation"),
)
module = loader.load_module()


class CodexWindowsHostSshRemoteControlIsolationTests(unittest.TestCase):
    def test_remote_result_accepts_one_sanitized_object(self):
        valid = json.dumps({
            "profile": module.PROFILE,
            "verdict": "PASS",
            "block_state": "absent",
        })
        self.assertEqual(module.parse_single_json(valid)["verdict"], "PASS")
        with self.assertRaises(module.ContractError):
            module.parse_single_json(valid + "\n" + valid)
        with self.assertRaises(module.ContractError):
            module.parse_single_json(json.dumps({
                "profile": "other", "verdict": "PASS",
            }))

    def test_manifest_is_ssh_session_only(self):
        manifest = json.loads((
            ROOT / "manifests/codex-windows-host-ssh-remote-control-isolation.json"
        ).read_text())
        self.assertEqual(manifest["scope"], "New inbound OpenSSH sessions only")
        self.assertIn(
            "Windows desktop Codex Remote Control outside SSH sessions",
            manifest["preservedState"],
        )
        self.assertFalse(manifest["dataBoundary"]["rawLogsRead"])

    def test_policy_is_hash_and_receipt_guarded(self):
        source = (
            ROOT / "policy/windows/codex-windows-host-ssh-remote-control-isolation.ps1"
        ).read_text()
        self.assertIn("beforeHash", source)
        self.assertIn("afterHash", source)
        self.assertIn("rollback_hash_mismatch", source)
        self.assertIn("receipt_state", source)
        self.assertIn("Test-Candidate", source)
        self.assertIn("$Backup", source)
        self.assertIn("replace_cleanup_failed", source)
        self.assertIn("$ExactFlagLines", source)
        self.assertIn("$ExactSkipLines", source)
        self.assertIn("$ExactCombinedLines", source)
        self.assertIn("legacy_exact", source)
        self.assertIn("split_exact", source)
        self.assertIn("legacy_restored", source)
        self.assertIn("receipt_commit_mismatch", source)

    def test_probe_filters_identifiers_remotely(self):
        source = (
            ROOT / "bin/codex-windows-host-ssh-remote-control-isolation"
        ).read_text()
        self.assertIn("remote awk emits only the enum status", source)
        self.assertIn("status/read", source)
        self.assertNotIn("installationId", source)
        self.assertNotIn("environmentId", source)
        self.assertNotIn("serverId", source)

    def test_exact_commit_gate_is_present(self):
        source = (
            ROOT / "bin/codex-windows-host-ssh-remote-control-isolation"
        ).read_text()
        self.assertIn("require_exact_commit", source)
        self.assertIn("wrong_task_branch", source)
        self.assertIn("dirty_worktree", source)
        self.assertIn("noop_postcheck_failed_state_preserved", source)

    def test_session_contract_carries_both_exact_flags(self):
        source = (
            ROOT / "bin/codex-windows-host-ssh-remote-control-isolation"
        ).read_text()
        self.assertIn("CODEX_INTERNAL_APP_SERVER_REMOTE_CONTROL_DISABLED", source)
        self.assertIn("CODEX_SSH_SKIP_APP_SERVER_BOOT", source)
        self.assertIn("session_flags=legacy", source)
        self.assertIn("session_bootstrap_skip_exact", source)
        self.assertNotIn("killpg", source)


if __name__ == "__main__":
    unittest.main()
