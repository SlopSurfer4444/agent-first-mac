"""Extract real activation shell; mock all absolute commands in private fixtures.

These tests exercise control flow with errexit disabled, actual filesystem
collisions/symlinks and synthetic root metadata. They do not invoke macOS
installers, ownership changes, vendor tools, package queries, or system probes.
Application identity is an injected fixture outcome, not a signature proof.
"""
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULES = ("windows-app", "rustdesk-controller")
MARKERS = {
    "windows-app": "11.3.8|47052e0aba8d5b2ad9a5468349f72bee317b69c07300a40ccadefb96050b1251\n",
    "rustdesk-controller": "1.4.6|0cd498e3f99c878bfa3c54996089b9671fdd15aee5d1ac160444841f95ea01bc\n",
}
MOCK = r'''#!/usr/bin/python3
import json, os, pathlib, shutil, stat, sys
root = pathlib.Path(os.environ['FIXTURE_ROOT']).absolute()
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / 'commands.jsonl').open('a') as log:
    log.write(json.dumps([name, *args]) + '\n')
def path(value):
    p = pathlib.Path(value)
    if not str(p.absolute()).startswith(str(root) + '/'):
        raise RuntimeError('outside fixture')
    return p
if name == 'stat':
    p = path(args[-1]); value = p.lstat()
    owner = '501' if os.environ.get('FIXTURE_NONROOT_PARENT') == str(p) else '0'
    mode = format(stat.S_IMODE(value.st_mode), 'o')
    result = owner + ':' + mode
    if args[1] == '%u:%Lp:%l': result += ':' + str(value.st_nlink)
    print(result)
elif name == 'ls':
    p = path(args[-1])
    if os.environ.get('FIXTURE_ACL_FAIL') == '1': sys.exit(26)
    if os.environ.get('FIXTURE_ACL_PATH') == str(p):
        print('drwxr-xr-x+ root wheel fixture\n 0: user:synthetic allow write')
    else: print('drwxr-xr-x root wheel fixture')
elif name == 'cmp':
    sys.exit(0 if path(args[-2]).read_bytes() == path(args[-1]).read_bytes() else 1)
elif name == 'install':
    if os.environ.get('FIXTURE_INSTALL_FAIL') == '1': sys.exit(23)
    dest = path(args[-1])
    if '-d' in args:
        dest.mkdir(parents=True, exist_ok=True); dest.chmod(0o755)
    else:
        data = path(args[-2]).read_bytes()
        # The fixture preserves install's overwrite semantics: a missing guard
        # really would clobber a conflicting regular marker and fail the test.
        dest.write_bytes(data); dest.chmod(0o644)
elif name == 'pkgutil':
    if args == ['--pkgs']:
        if os.environ.get('FIXTURE_RECEIPTS_FAIL') == '1': sys.exit(24)
        print(os.environ.get('FIXTURE_RECEIPTS', ''))
    elif args[0] == '--check-signature':
        print('Developer ID Installer: Microsoft Corporation (UBF8T346G9)\nNotarization: trusted')
    elif args[0] == '--forget': pass
    else: sys.exit(90)
elif name == 'shasum':
    print(os.environ['FIXTURE_HASH'] + '  fixture')
elif name == 'awk':
    print(sys.stdin.read().split()[0])
elif name == 'grep':
    sys.exit(0 if args[-1] in sys.stdin.read() else 1)
elif name == 'installer':
    if os.environ.get('FIXTURE_INSTALLER_FAIL') == '1': sys.exit(25)
    app = path(os.environ['FIXTURE_APP']); app.mkdir()
    (app / '.valid').write_text('synthetic app identity')
elif name == 'cat':
    sys.stdout.write(path(args[-1]).read_text())
elif name == 'rm':
    for item in args:
        if item.startswith('-'): continue
        p = path(item)
        if p.is_symlink() or p.is_file(): p.unlink()
        elif p.is_dir(): shutil.rmtree(p)
elif name == 'rmdir':
    path(args[-1]).rmdir()
elif name == 'plutil':
    key = args[1]
    print(os.environ.get('FIXTURE_BUNDLE' if key == 'CFBundleIdentifier' else 'FIXTURE_VERSION',
                         'com.carriez.rustdesk' if key == 'CFBundleIdentifier' else '1.4.6'))
elif name == 'codesign':
    if '--verify' in args: sys.exit(int(os.environ.get('FIXTURE_SIGNATURE_FAIL', '0')))
    print('TeamIdentifier=' + os.environ.get('FIXTURE_TEAM', 'HZF9JMC8YN'))
elif name == 'sed':
    value = sys.stdin.read()
    print(value.split('TeamIdentifier=')[-1].splitlines()[0])
elif name == 'spctl':
    sys.exit(int(os.environ.get('FIXTURE_GATEKEEPER_FAIL', '0')))
else:
    # Every native command is intercepted. Unanticipated operations cannot run.
    sys.exit(91)
'''


def activation(module):
    source = (ROOT / "darwin" / (module + ".nix")).read_text()
    return source.split("system.activationScripts.extraActivation.text = lib.mkAfter ''", 1)[1].rsplit("'';", 1)[0]


class ModuleFixture:
    def __init__(self, root, module, enabled=True, action=None, real_identity=False):
        self.root, self.module, self.enabled = Path(root), module, enabled
        self.action = action
        self.real_identity = real_identity
        self.state = self.root / "state"
        self.state.mkdir(mode=0o755)
        self.directory = self.state / module
        self.directory.mkdir(mode=0o755)
        self.marker = self.directory / "managed-source"
        self.source = self.root / "marker-source"
        self.source.write_text(MARKERS[module])
        self.app = self.root / "App.app"
        self.app.mkdir()
        (self.app / ".valid").write_text("synthetic identity")
        self.tools = self.root / "tools"
        self.tools.mkdir()

    def render(self):
        code = activation(self.module)
        code = code.replace("/var/db/agent-first-mac", str(self.state))
        code = code.replace("/Applications/Windows App.app", str(self.app))
        code = code.replace("/Applications/RustDesk.app", str(self.app))
        code = code.replace("${managedMarker}", str(self.source))
        code = code.replace("${windowsAppPkg}", str(self.root / "package.pkg"))
        code = code.replace("${rustDeskDmg}", str(self.root / "package.dmg"))
        code = code.replace('${if action == "install" then rustDeskDmg else ""}', str(self.root / "package.dmg"))
        code = code.replace('${if action != "preserve" then managedMarker else ""}', str(self.source))
        code = code.replace('${action}', self.action or ("install" if self.enabled else "remove"))
        code = re.sub(r'\$\{if (?:windowsAppEnabled|rustDeskControllerEnabled) then "true" else "false"\}',
                      "true" if self.enabled else "false", code)
        # Real source functions and branch ordering stay unchanged. Only the
        # unrelated signature probe is replaced with a synthetic identity seam.
        marker = "    marker_prestate || fail conflicting_or_unsafe_managed_marker"
        self_test = '\nverify_app() { test -d "$app" && ! test -L "$app" && test -f "$app/.valid"; }\n'
        if not self.real_identity:
            code = code.replace(marker, self_test + marker)
        commands = set(re.findall(r"/(?:usr/(?:bin|sbin)|bin)/[a-zA-Z0-9_-]+", code))
        for command in sorted(commands, key=len, reverse=True):
            mock = self.tools / Path(command).name
            mock.write_text(MOCK)
            mock.chmod(0o755)
            code = code.replace(command, shlex.quote(str(mock)))
        assert "${" not in code, "unrendered Nix expression"
        assert not re.search(r"/(?:usr/(?:bin|sbin)|bin)/", code), "native command escaped fixture"
        return "set +e\n" + code + "\nprintf 'FIXTURE_CONTINUED\\n'\n"

    def run(self, **extra):
        env = {"PATH": "/usr/bin:/bin", "FIXTURE_ROOT": str(self.root),
               "FIXTURE_APP": str(self.app), "FIXTURE_HASH": MARKERS[self.module].split("|")[1].strip(),
               **extra}
        return subprocess.run(["/bin/sh", "-c", self.render()], env=env,
                              capture_output=True, text=True, timeout=10)

    def commands(self):
        path = self.root / "commands.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


class ResumeModuleGuardTests(unittest.TestCase):
    def test_preserve_nix_evaluation_has_no_vendor_payload_dependency(self):
        nix = shutil.which("nix-instantiate")
        if not nix:
            self.skipTest("Nix evaluator unavailable; shell activation fixtures still run")
        module = json.dumps(str(ROOT / "darwin/rustdesk-controller.nix"))
        expression = '''let module = import (builtins.toPath MODULE) {
          config.agentFirst.rustDeskController.action = "preserve";
          lib = { mkAfter = x: x; mkOption = x: x; types.enum = x: x; };
          pkgs = { fetchurl = x: throw "unexpected DMG dependency";
                   writeText = n: x: throw "unexpected marker dependency"; };
        }; in { defaultAction = module.options.agentFirst.rustDeskController.action.default;
                activation = module.config.system.activationScripts.extraActivation.text; }
        '''.replace("MODULE", module)
        result = subprocess.run([nix, "--eval", "--strict", "--json", "--expr", expression],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        evaluated = json.loads(result.stdout)
        self.assertEqual(evaluated["defaultAction"], "preserve")
        self.assertIn("action='preserve'", evaluated["activation"])
        self.assertIn("dmg=''", evaluated["activation"])

    def each(self, test):
        for module in MODULES:
            with self.subTest(module=module), tempfile.TemporaryDirectory() as tmp:
                test(ModuleFixture(tmp, module))

    def assert_blocked_without_mutation(self, fixture, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("FIXTURE_CONTINUED", result.stdout)
        self.assertFalse(any(cmd[0] in ("install", "installer", "ditto", "rm", "rmdir", "hdiutil") for cmd in fixture.commands()), fixture.commands())

    def test_conflicting_marker_never_overwritten_with_errexit_off(self):
        def check(fixture):
            fixture.marker.write_text("foreign owner marker\n")
            before = fixture.marker.stat()
            self.assert_blocked_without_mutation(fixture, fixture.run())
            self.assertEqual(fixture.marker.read_text(), "foreign owner marker\n")
            self.assertEqual(fixture.marker.stat().st_ino, before.st_ino)
        self.each(check)

    def test_rustdesk_default_preserve_reaches_remaining_activation_without_any_probe(self):
        # Exercise the real extracted activation, not just Nix text presence.
        # Even unusable state is unrelated to activation when no RustDesk action
        # was requested; nothing may inspect, adopt, repair or delete it.
        module = (ROOT / "darwin/rustdesk-controller.nix").read_text()
        self.assertIn('default = "preserve";', module)
        for state in ("absent", "newer-owner-app", "invalid-app", "foreign-marker", "symlink-marker"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as tmp:
                fixture = ModuleFixture(tmp, "rustdesk-controller", action="preserve")
                if state == "absent":
                    (fixture.app / ".valid").unlink()
                    fixture.app.rmdir()
                elif state == "newer-owner-app":
                    (fixture.app / "owner-version").write_text("1.4.9")
                elif state == "invalid-app":
                    (fixture.app / ".valid").unlink()
                elif state == "foreign-marker":
                    fixture.marker.write_text("owner state")
                else:
                    fixture.marker.symlink_to(fixture.root / "unknown")
                before = [(str(p.relative_to(fixture.root)), p.lstat().st_ino,
                           p.lstat().st_mtime_ns) for p in fixture.root.rglob("*")]
                result = fixture.run()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("FIXTURE_CONTINUED", result.stdout)
                self.assertEqual(fixture.commands(), [])
                for name, inode, mtime in before:
                    # Render creates tool stubs inside tools, so its mtime changes.
                    if name == "tools": continue
                    current = (fixture.root / name).lstat()
                    self.assertEqual((inode, mtime), (current.st_ino, current.st_mtime_ns))
                self.assertEqual(fixture.app.exists(), state != "absent")
                self.assertEqual(fixture.marker.exists(), state == "foreign-marker")

    def test_explicit_rustdesk_install_retains_actual_identity_probe_flow(self):
        for failure in ({"FIXTURE_VERSION": "1.4.9"}, {"FIXTURE_BUNDLE": "foreign"},
                        {"FIXTURE_TEAM": "foreign"}, {"FIXTURE_SIGNATURE_FAIL": "1"},
                        {"FIXTURE_GATEKEEPER_FAIL": "1"}, {}):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                fixture = ModuleFixture(tmp, "rustdesk-controller", action="install", real_identity=True)
                executable = fixture.app / "Contents/MacOS/RustDesk"
                executable.parent.mkdir(parents=True)
                executable.write_text("inert fixture")
                executable.chmod(0o755)
                result = fixture.run(**failure)
                if failure:
                    self.assert_blocked_without_mutation(fixture, result)
                    self.assertFalse(fixture.marker.exists())
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("FIXTURE_CONTINUED", result.stdout)
                    self.assertEqual(fixture.marker.read_text(), MARKERS[fixture.module])
                self.assertTrue(executable.exists())

    def test_symlink_and_dangling_symlink_never_followed(self):
        for exists in (True, False):
            def check(fixture):
                target = fixture.root / "foreign"
                if exists: target.write_text(MARKERS[fixture.module])
                fixture.marker.symlink_to(target)
                self.assert_blocked_without_mutation(fixture, fixture.run())
                self.assertTrue(fixture.marker.is_symlink())
                self.assertEqual(target.exists(), exists)
            self.each(check)

    def test_fifo_and_directory_markers_deny_without_opening(self):
        for fifo in (True, False):
            def check(fixture):
                os.mkfifo(fixture.marker) if fifo else fixture.marker.mkdir()
                self.assert_blocked_without_mutation(fixture, fixture.run())
            self.each(check)

    def test_existing_exact_managed_marker_is_inode_preserving_noop(self):
        def check(fixture):
            fixture.marker.write_text(MARKERS[fixture.module])
            fixture.marker.chmod(0o644)
            before = fixture.marker.stat()
            result = fixture.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("FIXTURE_CONTINUED", result.stdout)
            self.assertFalse(any(cmd[0] == "install" for cmd in fixture.commands()))
            after = fixture.marker.stat()
            self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))
        self.each(check)

    def test_valid_application_missing_marker_is_adopted_without_installer(self):
        def check(fixture):
            result = fixture.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(fixture.marker.read_text(), MARKERS[fixture.module])
            self.assertEqual(sum(cmd[0] == "install" for cmd in fixture.commands()), 1)
            self.assertFalse(any(cmd[0] in ("installer", "ditto", "pkgutil") for cmd in fixture.commands()))
        self.each(check)

    def test_marker_directory_can_be_created_only_below_admitted_parent(self):
        def check(fixture):
            fixture.directory.rmdir()
            result = fixture.run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(fixture.marker.read_text(), MARKERS[fixture.module])
        self.each(check)

    def test_marker_parent_symlink_world_writable_and_nonroot_deny(self):
        for kind in ("symlink", "world-writable", "nonroot"):
            def check(fixture):
                extra = {}
                if kind == "symlink":
                    fixture.directory.rmdir()
                    foreign = fixture.root / "foreign-directory"
                    foreign.mkdir()
                    fixture.directory.symlink_to(foreign)
                elif kind == "world-writable":
                    fixture.directory.chmod(0o777)
                else:
                    extra["FIXTURE_NONROOT_PARENT"] = str(fixture.state)
                self.assert_blocked_without_mutation(fixture, fixture.run(**extra))
            self.each(check)

    def test_exact_marker_with_wrong_permissions_or_hardlink_denied(self):
        for hardlink in (True, False):
            def check(fixture):
                fixture.marker.write_text(MARKERS[fixture.module])
                fixture.marker.chmod(0o644)
                if hardlink: os.link(fixture.marker, fixture.root / "other-link")
                else: fixture.marker.chmod(0o666)
                self.assert_blocked_without_mutation(fixture, fixture.run())
            self.each(check)

    def test_marker_and_parent_acl_or_failed_acl_observation_deny(self):
        for target in ("state", "directory", "marker", "failed-probe"):
            def check(fixture):
                fixture.marker.write_text(MARKERS[fixture.module])
                fixture.marker.chmod(0o644)
                extra = ({"FIXTURE_ACL_FAIL": "1"} if target == "failed-probe"
                         else {"FIXTURE_ACL_PATH": str(getattr(fixture, target))})
                self.assert_blocked_without_mutation(fixture, fixture.run(**extra))
                self.assertEqual(fixture.marker.read_text(), MARKERS[fixture.module])
            self.each(check)

    def test_invalid_app_and_marker_install_failure_abort_explicitly(self):
        def check(fixture):
            (fixture.app / ".valid").unlink()
            self.assert_blocked_without_mutation(fixture, fixture.run())
        self.each(check)
        def check_install(fixture):
            result = fixture.run(FIXTURE_INSTALL_FAIL="1")
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("FIXTURE_CONTINUED", result.stdout)
            self.assertFalse(fixture.marker.exists())
        self.each(check_install)

    def test_windows_partial_receipts_or_failed_inventory_prevent_installer(self):
        for receipts in ("com.microsoft.rdc.macos", "com.microsoft.rdc.installer.scripts",
                         "unrelated\ncom.microsoft.rdc.macos\nanother", "error"):
            with self.subTest(receipts=receipts), tempfile.TemporaryDirectory() as tmp:
                fixture = ModuleFixture(tmp, "windows-app")
                (fixture.app / ".valid").unlink(); fixture.app.rmdir()
                options = {"FIXTURE_RECEIPTS_FAIL": "1"} if receipts == "error" else {"FIXTURE_RECEIPTS": receipts}
                self.assert_blocked_without_mutation(fixture, fixture.run(**options))
                self.assertFalse(fixture.app.exists())
                self.assertFalse(fixture.marker.exists())

    def test_windows_true_receipt_absence_permits_mock_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = ModuleFixture(tmp, "windows-app")
            (fixture.app / ".valid").unlink(); fixture.app.rmdir()
            result = fixture.run(FIXTURE_RECEIPTS="unrelated.receipt\ncom.microsoft.rdc.macos.other")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(sum(cmd[0] == "installer" for cmd in fixture.commands()), 1)
            self.assertEqual(fixture.marker.read_text(), MARKERS["windows-app"])

    def test_disabled_state_foreign_marker_also_stops_before_removal(self):
        def check(fixture):
            fixture.enabled = False
            fixture.marker.write_text("foreign\n")
            self.assert_blocked_without_mutation(fixture, fixture.run())
            self.assertTrue(fixture.app.is_dir())
        self.each(check)

    def test_capability_markers_in_generated_activation_not_only_nix_comments(self):
        for module, capability in (("windows-app", "windows"), ("rustdesk-controller", "rustdesk")):
            code = activation(module)
            self.assertIn("# aid-admin-resume-" + capability + "-marker-guards-v1", code)
            self.assertNotIn("python", code.lower())
            self.assertLess(code.index("marker_prestate || fail conflicting"), code.index("    if ${if"))


if __name__ == "__main__":
    unittest.main()
