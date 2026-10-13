import importlib.machinery
import json
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader(
    "codex_bridge_drop_smb",
    str(ROOT / "bin" / "codex-bridge-drop-smb"),
)
module = loader.load_module()


class CodexBridgeDropTests(unittest.TestCase):
    def test_manifest_keeps_windows_and_network_owners_separate(self):
        manifest = json.loads((
            ROOT / "manifests" / "codex-bridge-drop-smb.json"
        ).read_text())
        self.assertEqual(manifest["schema"], 2)
        self.assertFalse(
            manifest["remoteDependency"]["managedByThisRepository"]
        )
        self.assertFalse(
            manifest["transports"]["smb"]["directTailscaleTcp445Grant"]
        )
        self.assertFalse(
            manifest["transports"]["smb"]["windowsFirewallMutation"]
        )
        self.assertTrue(
            manifest["transports"]["smb"]["automaticMount"]
        )
        self.assertFalse(
            manifest["transports"]["smb"][
                "ownerCredentialActionRemainingOnThisMac"
            ]
        )
        self.assertFalse(
            manifest["dataBoundary"]["privateOrPublicKeyMaterialReadOrCopied"]
        )

    def test_grants_remain_three_port_policy(self):
        grants = json.loads((
            ROOT / "manifests" / "tailscale-grants-windows-host.json"
        ).read_text())
        self.assertEqual(
            grants["targetPolicy"]["networkCapabilities"],
            ["tcp:22", "tcp:3389", "tcp:21118"],
        )
        self.assertEqual(
            grants["policyTests"]["acceptPorts"],
            [22, 3389, 21118],
        )
        self.assertNotIn("followOnSmbChange", grants)

    def test_plist_contract_is_localhost_only(self):
        expected = module.expected_tunnel_plist()
        self.assertEqual(expected["Label"], module.TUNNEL_LABEL)
        self.assertEqual(expected["ProgramArguments"], module.PROGRAM_ARGUMENTS)
        self.assertIn(
            "127.0.0.1:14445:127.0.0.1:445",
            expected["ProgramArguments"],
        )
        self.assertNotIn("100.", json.dumps(expected))
        self.assertEqual(expected["StandardOutPath"], "/dev/null")
        self.assertEqual(expected["StandardErrorPath"], "/dev/null")

    def test_automount_source_is_bounded_and_credential_blind(self):
        source = module.AUTOMOUNT_SOURCE.read_text()
        self.assertIn("/usr/bin/pgrep -x Finder", source)
        self.assertIn("/usr/bin/nc -z -w 3 127.0.0.1 14445", source)
        self.assertIn("automount-paused", source)
        self.assertIn("umask 077", source)
        self.assertNotIn("security ", source)
        self.assertNotIn("password", source.lower())

    @mock.patch.object(module, "remote_smb_loopback_passes", return_value=True)
    @mock.patch.object(module, "strict_ssh_passes", return_value=True)
    @mock.patch.object(module, "local_port_open", return_value=False)
    @mock.patch.object(module, "managed_state", return_value="absent")
    def test_preflight_accepts_clean_absent_state(
        self,
        _managed,
        _port,
        _ssh,
        _smb,
    ):
        result = module.preflight()
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["firewall_mutation_count"], 0)
        self.assertEqual(result["tailscale_policy_mutation_count"], 0)

    @mock.patch.object(module, "remote_smb_loopback_passes", return_value=True)
    @mock.patch.object(module, "strict_ssh_passes", return_value=True)
    @mock.patch.object(module, "local_port_open", return_value=True)
    @mock.patch.object(
        module, "managed_state", return_value="legacy_tunnel_only"
    )
    def test_preflight_accepts_exact_tunnel_only_upgrade(
        self,
        _managed,
        _port,
        _ssh,
        _smb,
    ):
        result = module.preflight()
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["managed_state"], "legacy_tunnel_only")

    @mock.patch.object(module, "automount_probe", return_value=True)
    @mock.patch.object(module, "automount_state_valid", return_value=True)
    @mock.patch.object(module, "automount_plist_exact", return_value=True)
    @mock.patch.object(module, "sftp_probe", return_value=True)
    @mock.patch.object(module, "remote_smb_loopback_passes", return_value=True)
    @mock.patch.object(module, "strict_ssh_passes", return_value=True)
    @mock.patch.object(module, "local_port_open", return_value=True)
    @mock.patch.object(module, "managed_state", return_value="exact")
    def test_doctor_accepts_exact_tunnel_and_sftp(
        self,
        _managed,
        _port,
        _ssh,
        _smb,
        _sftp,
        _automount_plist,
        _automount_state,
        _automount_probe,
    ):
        result = module.doctor()
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["bounded_sftp_probe_pass"])
        self.assertTrue(result["finder_automount_pass"])
        self.assertEqual(result["firewall_mutation_count"], 0)

    def test_exact_commit_and_typed_apply_gates_exist(self):
        source = (ROOT / "bin" / "codex-bridge-drop-smb").read_text()
        self.assertIn("require_exact_commit", source)
        self.assertIn("wrong_task_branch", source)
        self.assertIn("dirty_worktree", source)
        self.assertIn("/usr/local/libexec/aid-admin", source)
        self.assertIn("postapply_failed_exact_rollback_commit_required", source)

    def test_duplicate_windows_policy_is_removed(self):
        self.assertFalse((
            ROOT / "policy" / "windows" / "codex-bridge-drop-smb.ps1"
        ).exists())


if __name__ == "__main__":
    unittest.main()
