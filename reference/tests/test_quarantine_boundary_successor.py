"""Current source policy plus synthetic launcher effects, never the vendor CLI.

The zsh fixture substitutes only the account-home binding and executable path.
Its capture executable emits argv/environment, not a model/server operation.
Actual product sandbox behavior is separate parent-operated native evidence.
"""
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from vendor.tomli import loads
from lib import vendor_compatibility_probe as V
from lib import phase5_current_quarantine as HISTORICAL

PROFILE = (ROOT / "codex/quarantine.config.toml").read_bytes()
LAUNCHER = (ROOT / "bin/codex-quarantine").read_bytes()
MANIFEST = json.loads((ROOT / "manifests/quarantine-boundary-successor.json").read_bytes())
OLD_PROFILE = (ROOT / "tests/fixtures/phase5-quarantine-before-temp-deny.config.toml").read_bytes()
OLD_LAUNCHER = (ROOT / "tests/fixtures/phase5-quarantine-before-current-cli.zsh").read_bytes()
OWNER_LINE = "readonly OWNER_HOME=$(/usr/bin/python3 -c 'import os, pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')"
CLI_LINE = "readonly CODEX_BINARY='" + V.CLI + "'"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class SuccessorTests(unittest.TestCase):
    def test_current_delivery_hashes_and_launcher_pin_change_together(self):
        self.assertEqual(MANIFEST["status"], "SOURCE_CANDIDATE")
        expected = {"codex/quarantine.config.toml": PROFILE, "bin/codex-quarantine": LAUNCHER}
        self.assertEqual({row["source"] for row in MANIFEST["deliverySet"]}, set(expected))
        for row in MANIFEST["deliverySet"]:
            self.assertEqual(row["sha256"], sha(expected[row["source"]]))
        self.assertIn(("readonly QUARANTINE_PROFILE_SHA256='" + sha(PROFILE) + "'").encode(), LAUNCHER)
        self.assertTrue(MANIFEST["delivery"]["coherentProfileAndLauncherRequired"])
        self.assertTrue(MANIFEST["delivery"]["existingFullDoctorCutoverGateRetained"])
        self.assertTrue(all(value is False for value in MANIFEST["claims"].values()))
        self.assertEqual(len(MANIFEST["sourceClosure"]), len(set(MANIFEST["sourceClosure"])))
        self.assertTrue(all((ROOT / path).is_file() for path in MANIFEST["sourceClosure"]))

    def test_only_explicit_temporary_denies_change_profile_policy(self):
        current, previous = loads(PROFILE.decode()), loads(OLD_PROFILE.decode())
        previous["permissions"]["quarantine"]["filesystem"].update({":slash_tmp": "deny", ":tmpdir": "deny"})
        self.assertEqual(current, previous)
        self.assertEqual(current["default_permissions"], "quarantine")
        filesystem = current["permissions"]["quarantine"]["filesystem"]
        self.assertEqual(filesystem[":minimal"], "read")
        self.assertEqual(filesystem[":workspace_roots"]["."], "read")
        self.assertEqual(current["permissions"]["quarantine"]["network"], {"enabled": False})
        self.assertNotIn("sandbox_mode", current)
        self.assertNotIn("sandbox_workspace_write", current)

    def test_predecessor_receipts_and_pure_protocol_are_not_rebound(self):
        self.assertEqual(sha(OLD_PROFILE), HISTORICAL.PROFILE_SHA256)
        self.assertEqual(sha(OLD_LAUNCHER), HISTORICAL.LAUNCHER_SHA256)
        self.assertEqual(MANIFEST["predecessor"]["profileSha256"], sha(OLD_PROFILE))
        self.assertEqual(MANIFEST["predecessor"]["launcherSha256"], sha(OLD_LAUNCHER))
        old_manifest = json.loads((ROOT / "manifests/codex-contract.json").read_bytes())
        old_sources = {row["source"]: row["sha256"] for row in old_manifest["generatedFiles"]}
        self.assertEqual(old_sources["codex/quarantine.config.toml"], sha(OLD_PROFILE))
        self.assertEqual(old_sources["bin/codex-quarantine"], sha(OLD_LAUNCHER))
        self.assertNotEqual(sha(PROFILE), HISTORICAL.PROFILE_SHA256)
        self.assertNotEqual(sha(LAUNCHER), HISTORICAL.LAUNCHER_SHA256)

    def test_fixed_current_cli_and_no_unsupported_exec_permission_flag(self):
        text = LAUNCHER.decode()
        self.assertIn(CLI_LINE, text)
        self.assertEqual(MANIFEST["policy"]["canonicalCli"], V.CLI)
        self.assertNotIn("--permission-profile", text)
        self.assertNotIn("--sandbox", text)
        self.assertNotIn("command -v", text)
        self.assertNotIn("shutil.which", text)
        self.assertIn("--config 'default_permissions=\"quarantine\"'", text)
        for flag in ("--ignore-user-config", "--ignore-rules", "--ephemeral", "--profile quarantine"):
            self.assertIn(flag, text)
        environment_block = text.split("exec /usr/bin/env -i ", 1)[1]
        self.assertEqual(re.findall(r"^  ([A-Z_]+)=", environment_block, re.M),
                         ["HOME", "CODEX_HOME", "PATH", "LANG", "LC_ALL", "SHELL"])

    def run_fixture(self, case="valid", prompt="--literal prompt", *, profile=PROFILE, pin=None):
        with tempfile.TemporaryDirectory(prefix="quarantine-source-test.", dir="/private/tmp") as directory:
            fixture = Path(directory)
            home = fixture / "owner home"
            codex = home / ".codex"
            workspace = home / "AIDev/quarantine/project with spaces"
            codex.mkdir(parents=True, mode=0o700)
            workspace.mkdir(parents=True, mode=0o700)
            target = codex / "quarantine.config.toml"
            if case != "missing-profile":
                target.write_bytes(profile + (b"\n# drift\n" if case == "wrong-profile" else b""))
                target.chmod(0o600)
            if case == "symlink-profile":
                outside = fixture / "profile-image"
                target.rename(outside)
                target.symlink_to(outside)
            cli = fixture / "capture-cli"
            if case != "missing-cli":
                # Native shell capture avoids Python/CoreFoundation startup
                # inserting host-specific __CF_USER_TEXT_ENCODING. The shell's
                # own generated variables are not source-emitted environment;
                # the exact six source assignments are separately checked above.
                cli.write_text('#!/bin/sh\nfor arg do printf "%s\\0" "$arg"; done\n'
                    'printf "W26_CAPTURE_ENVIRONMENT\\0"\nunset PWD SHLVL _\n/usr/bin/env\n')
                cli.chmod(0o700)
            text = LAUNCHER.decode()
            self.assertEqual(text.count(OWNER_LINE), 1)
            self.assertEqual(text.count(CLI_LINE), 1)
            text = text.replace(OWNER_LINE, "readonly OWNER_HOME=" + shlex.quote(str(home)))
            text = text.replace(CLI_LINE, "readonly CODEX_BINARY=" + shlex.quote(str(cli)))
            if pin is not None:
                old_pin = "readonly QUARANTINE_PROFILE_SHA256='" + sha(PROFILE) + "'"
                self.assertEqual(text.count(old_pin), 1)
                text = text.replace(old_pin, "readonly QUARANTINE_PROFILE_SHA256='" + pin + "'")
            script = fixture / "launcher"
            script.write_text(text)
            script.chmod(0o700)
            result = subprocess.run(["/bin/zsh", str(script), "--root", str(workspace), "--", prompt],
                cwd=fixture, env={"PATH": "/untrusted", "HOME": "/not-the-owner", "LC_ALL": "C"},
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=8, check=False)
            return result, str(home), str(workspace)

    def test_actual_fixture_emitted_argv_and_environment(self):
        result, home, workspace = self.run_fixture()
        self.assertEqual((result.returncode, result.stderr), (0, b""))
        parts = result.stdout.split(b"\0")
        boundary = parts.index(b"W26_CAPTURE_ENVIRONMENT")
        argv = [part.decode() for part in parts[:boundary]]
        environment = dict(line.split("=", 1) for line in parts[boundary + 1].decode().splitlines())
        self.assertEqual(argv[:9], ["exec", "--ignore-user-config", "--ignore-rules", "--ephemeral",
            "--profile", "quarantine", "--cd", workspace, "--config"])
        configs = [argv[i + 1] for i, value in enumerate(argv) if value == "--config"]
        self.assertEqual(configs, ['approval_policy="never"', 'default_permissions="quarantine"',
            'web_search="disabled"', 'allow_login_shell=false', 'mcp_servers={}',
            'features.apps=false', 'features.plugins=false', 'features.remote_plugin=false',
            'projects."' + workspace + '".trust_level="untrusted"'])
        self.assertEqual(argv[-2:], ["--", "--literal prompt"])
        self.assertEqual(environment, {"HOME": home, "CODEX_HOME": home + "/.codex",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C", "SHELL": "/bin/zsh",
            "_": "/usr/bin/env"})  # the capture shell sets this at its env exec

    def test_missing_wrong_and_symlink_profile_refuse_before_cli_exec(self):
        for case in ("missing-profile", "wrong-profile", "symlink-profile", "missing-cli"):
            with self.subTest(case=case):
                result, _, _ = self.run_fixture(case)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"unavailable" if case != "wrong-profile" else b"changed", result.stderr)

    def test_coherent_future_profile_pin_upgrade_is_not_permanently_stale(self):
        # A fixture-only successor generation: no installed change or review claim.
        upgraded = PROFILE + b"\n# next exact reviewed delivery fixture\n"
        rejected, _, _ = self.run_fixture(profile=upgraded)
        self.assertEqual((rejected.returncode, rejected.stdout), (2, b""))
        accepted, _, _ = self.run_fixture(profile=upgraded, pin=sha(upgraded))
        self.assertEqual((accepted.returncode, accepted.stderr), (0, b""))


if __name__ == "__main__":
    unittest.main()
