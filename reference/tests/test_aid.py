"""Pure facade/exec seams and repository catalog references; no native probes."""
import copy
import importlib.machinery
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
A = importlib.machinery.SourceFileLoader("tested_aid_facade", str(ROOT / "bin/aid")).load_module()


def fixture_catalog():
    return {"schema": 1, "kind": "DECLARED_CAPABILITY_CATALOG", "complete": False,
        "items": [{"id": "fixture", "owner": "Fixture owner", "versionPolicy": "immutable-lock",
            "source": "manifests/fixture.json", "doctorSection": "current", "lifecycle": "docs/fixture.md"}]}


def raw(value):
    return json.dumps(value, sort_keys=True).encode()


class Adapter:
    def __init__(self, content=None):
        self.content = raw(fixture_catalog()) if content is None else content
        self.calls = []

    def read_catalog(self):
        self.calls.append("catalog")
        return self.content

    def doctor(self, section):
        self.calls.append(("doctor", section))
        raise SystemExit(37)  # deterministic stand-in for process replacement

    def maintenance(self, operation, json_output):
        self.calls.append(("maintenance", operation, json_output))
        raise SystemExit(37)


class AidTests(unittest.TestCase):
    def test_help_and_no_arguments_have_no_operational_io(self):
        for args in ([], ["help"], ["--help"]):
            output = []
            self.assertEqual(A.main(args, adapter_factory=lambda: self.fail("unexpected IO"), emit=output.append), 0)
            self.assertIn("read-only", output[0])
            self.assertIn("unsupported", output[0])

    def test_closed_grammar_unknown_or_mutation_arguments_fail_before_any_io(self):
        arguments = [[name] for name in ("install", "adopt", "upgrade", "remove", "rollback", "apply", "unknown")]
        arguments += [["doctor", "--section", "unknown"], ["doctor", "--section"],
            ["doctor", "--section", "current", "--json"], ["doctor", "--json", "--json"],
            ["doctor", "--root", "/tmp"], ["doctor", "--section", "current; command"],
            ["doctor", "--section", "current", "--section", "revision"],
            ["inventory", "--section", "current"], ["plan", "--apply"],
            ["--json", "inventory"], ["help", "--json"], ["inventory", "--json", "--json"],
            ["doctor", "--fixture"], ["--env", "HOME=/tmp"], [True], "help"]
        for args in arguments:
            with self.subTest(args=args):
                output = []
                self.assertEqual(A.main(args, adapter_factory=lambda: self.fail("unexpected IO"), emit=output.append), 2)
                self.assertNotIn("/tmp", "".join(output))

    def test_all_doctor_sections_and_default_preserve_exec_exit(self):
        for section in A.DOCTORS:
            for options in ([], ["--json"]):
                adapter = Adapter()
                output = []
                with self.assertRaises(SystemExit) as stopped:
                    A.main(["doctor", *options, "--section", section], adapter_factory=lambda: adapter, emit=output.append)
                self.assertEqual(stopped.exception.code, 37)
                self.assertEqual(adapter.calls, [("doctor", section)])
                self.assertEqual(output, [])
        adapter = Adapter()
        with self.assertRaises(SystemExit):
            A.main(["doctor"], adapter_factory=lambda: adapter)
        self.assertEqual(adapter.calls, [("doctor", "current")])

    def test_maintenance_views_dispatch_without_catalog_or_output_translation(self):
        for operation in ("status", "schedule-status"):
            for options in ([], ["--json"]):
                adapter, output = Adapter(), []
                with self.assertRaises(SystemExit) as stopped:
                    A.main(["maintenance", operation, *options], adapter_factory=lambda: adapter, emit=output.append)
                self.assertEqual(stopped.exception.code, 37)
                self.assertEqual(adapter.calls, [("maintenance", operation, bool(options))])
                self.assertEqual(output, [])

    def test_maintenance_closed_grammar_denies_mutations_and_overrides_before_io(self):
        arguments = [["maintenance", name] for name in (
            "cycle", "scheduled", "install", "remove", "repair", "recover", "plan",
            "schedule-install", "schedule-remove", "schedule-recover", "schedule-plan",
            "unknown", "status;command", "../status")]
        arguments += [["maintenance"], ["maintenance", "--json", "status"],
            ["maintenance", "status", "--json", "--json"],
            ["maintenance", "status", "--root", "/tmp"],
            ["maintenance", "schedule-status", "--section", "current"],
            ["maintenance", "status", "--apply"], ["maintenance", "status", True],
            ["maintenance", "status", "schedule-status"]]
        for args in arguments:
            with self.subTest(args=args):
                self.assertEqual(A.main(args, adapter_factory=lambda: self.fail("unexpected IO"), emit=lambda _: None), 2)

    def test_maintenance_exec_failure_or_unexpected_return_is_not_success(self):
        for effect in (OSError("private launch error"), None):
            output = []
            with patch.object(Adapter, "maintenance", side_effect=effect, return_value=0):
                self.assertEqual(A.main(["maintenance", "status"], adapter_factory=Adapter, emit=output.append), 1)
            self.assertEqual(json.loads(output[0])["status"], "UNKNOWN")
            self.assertNotIn("private", "".join(output))

    def test_maintenance_help_distinguishes_latest_observation_from_schedule(self):
        self.assertIn("aid maintenance status [--json]", A.HELP)
        self.assertIn("aid maintenance schedule-status [--json]", A.HELP)
        self.assertIn("does not run a new capture", A.HELP)
        self.assertIn("does not prove a completed cycle", A.HELP)

    def test_inventory_is_explicit_declared_only_without_installed_or_acceptance_claim(self):
        adapter = Adapter()
        output = []
        self.assertEqual(A.main(["inventory", "--json"], adapter_factory=lambda: adapter, emit=output.append), 0)
        value = json.loads(output[0])
        self.assertEqual(value["scope"], "DECLARED_ONLY")
        self.assertFalse(value["freshObservation"] or value["installedStateChecked"] or value["sourceAcceptanceChecked"])
        self.assertFalse(value["catalog"]["complete"] or value["systemMutationsPerformed"])
        self.assertTrue(value["readOnly"])
        self.assertEqual(value["catalog"], fixture_catalog())
        self.assertEqual(adapter.calls, ["catalog"])
        self.assertNotIn("workflow", value)

    def test_plan_is_scoped_nonexecutable_routing_not_universal_root_workflow(self):
        value = fixture_catalog()
        value["items"][0]["lifecycle"] = "Metadata; no invocation"
        adapter = Adapter(raw(value))
        output = []
        self.assertEqual(A.main(["plan", "--json"], adapter_factory=lambda: adapter, emit=output.append), 0)
        report = json.loads(output[0])
        self.assertEqual(report["routingHelp"], {name: list(steps) for name, steps in A.ROUTES.items()})
        self.assertIsNone(report["selectedScope"])
        self.assertNotIn("workflow", report)
        self.assertFalse(report["executablePlan"] or report["freshObservation"])
        self.assertEqual(adapter.calls, ["catalog"])
        for scope in ("project", "workstation"):
            adapter = Adapter()
            output = []
            self.assertEqual(A.main(["plan", "--json", "--scope", scope],
                                   adapter_factory=lambda: adapter, emit=output.append), 0)
            scoped = json.loads(output[0])
            self.assertEqual(scoped["routingHelp"], {scope: list(A.ROUTES[scope])})
            self.assertEqual(scoped["selectedScope"], scope)
            text = " ".join(scoped["routingHelp"][scope])
            for forbidden in ("aid-admin", "acceptance-child", "independently accept", "Build the exact"):
                self.assertNotIn(forbidden, text)
            self.assertEqual(adapter.calls, ["catalog"])
        self.assertIn("typed aid-admin", " ".join(A.ROUTES["protected"]))
        self.assertIn("native", " ".join(A.ROUTES["protected"]).lower())

    def test_scope_help_rejects_mutation_and_unknown_scopes_without_io(self):
        for args in (["plan", "--scope", "root-apply"], ["plan", "--scope"],
                     ["inventory", "--scope", "project"], ["plan", "--scope", "project", "--json"],
                     ["plan", "--json", "--scope", "project", "--apply"]):
            self.assertEqual(A.main(args, adapter_factory=lambda: self.fail("unexpected IO"),
                                    emit=lambda _: None), 2)

    def test_human_inventory_and_plan_remain_explicit(self):
        for command in ("inventory", "plan"):
            output = []
            self.assertEqual(A.main([command], adapter_factory=Adapter, emit=output.append), 0)
            self.assertIn("not fresh state or acceptance", output[0])
            if command == "plan":
                self.assertIn("not an actual diff or executable plan", " ".join(output))

    def test_exact_catalog_schema_bounds_types_and_duplicate_rejection(self):
        changes = [lambda v: v.update(schema=True), lambda v: v.update(schema=2),
            lambda v: v.update(kind="OBSERVED_INVENTORY"), lambda v: v.update(complete=True),
            lambda v: v.update(complete=0), lambda v: v.update(extra="field"), lambda v: v.update(items={}),
            lambda v: v["items"].append(copy.deepcopy(v["items"][0])),
            lambda v: v["items"][0].update(extra="field"), lambda v: v["items"][0].pop("source"),
            lambda v: v["items"][0].update(id="not-a-valid id"),
            lambda v: v["items"][0].update(doctorSection="apply"),
            lambda v: v["items"][0].update(doctorSection=True)]
        for key in ("id", "owner", "versionPolicy", "source", "lifecycle"):
            for invalid in (None, 1, "", "x" * 257, "private\nnewline", "bad\x1b[0m", "$(command)", "back`tick", "pipe|command"):
                changes.append(lambda v, key=key, invalid=invalid: v["items"][0].update({key: invalid}))
        for mutate in changes:
            value = fixture_catalog()
            mutate(value)
            with self.assertRaises(A.AidError):
                A.catalog(raw(value))
        for content in (b"[]", b"null", b"{", b"\xff", b"x" * (A.MAX_CATALOG + 1),
                raw(fixture_catalog())[:-1] + b',"schema":1}', b"{" * 1100):
            with self.assertRaises(A.AidError):
                A.catalog(content)

    def test_catalog_nullable_doctor_and_bounded_plain_prose_are_data_only(self):
        value = fixture_catalog()
        value["items"][0].update(doctorSection=None, owner="Signed vendor lifecycle; local compatibility sentinel")
        self.assertEqual(A.catalog(raw(value)), value)

    def test_unavailable_catalog_and_exec_launch_errors_are_bounded_redacted(self):
        for error in (OSError("/private/secret-path"), A.AidError("private arbitrary source")):
            output = []
            with patch.object(Adapter, "read_catalog", side_effect=error):
                self.assertEqual(A.main(["inventory"], adapter_factory=Adapter, emit=output.append), 1)
            self.assertNotIn("private", "".join(output))
            self.assertEqual(json.loads(output[0])["status"], "UNKNOWN")
        output = []
        with patch.object(Adapter, "doctor", side_effect=OSError("private execve error")):
            self.assertEqual(A.main(["doctor"], adapter_factory=Adapter, emit=output.append), 1)
        self.assertNotIn("private", "".join(output))

    def test_unexpected_exec_return_does_not_claim_success(self):
        output = []
        with patch.object(Adapter, "doctor", return_value=0):
            self.assertEqual(A.main(["doctor"], adapter_factory=Adapter, emit=output.append), 1)
        self.assertEqual(json.loads(output[0])["status"], "UNKNOWN")

    def test_actual_catalog_references_are_real_repo_files(self):
        value = A.catalog((ROOT / "manifests/aid-catalog.json").read_bytes())
        for item in value["items"]:
            for key in ("source", "lifecycle"):
                reference = Path(item[key])
                self.assertFalse(reference.is_absolute())
                self.assertNotIn("..", reference.parts)
                self.assertTrue((ROOT / reference).is_file(), (item["id"], key))
            if item["doctorSection"] is not None:
                self.assertTrue((ROOT / A.DOCTORS[item["doctorSection"]][0]).is_file())


class NativeAidTests(unittest.TestCase):
    def test_maintenance_exact_vectors_preserve_context_and_only_known_operations(self):
        self.assertEqual(A.MAINTENANCE, {
            "status": ("bin/workstation-maintenance-cycle", "status"),
            "schedule-status": ("bin/workstation-maintenance-cycle", "schedule-status"),
        })
        native = A.Native.__new__(A.Native)
        native.root = "/fixture/AIDev/control"
        for operation in A.MAINTENANCE:
            for as_json in (False, True):
                with self.subTest(operation=operation, as_json=as_json):
                    context = {"TERM": "fixture", "PATH": "/fixture/bin"}
                    def execute(executable, argv):
                        self.assertEqual(dict(os.environ), context)
                        raise SystemExit(3)
                    with patch.dict(os.environ, context, clear=True), patch.object(A.os, "chdir") as chdir, \
                            patch.object(A.os, "execve", side_effect=AssertionError("no environment replacement")), \
                            patch.object(A.os, "execv", side_effect=execute) as call:
                        with self.assertRaises(SystemExit):
                            native.maintenance(operation, as_json)
                    chdir.assert_called_once_with(native.root)
                    call.assert_called_once_with("/usr/bin/python3", ("/usr/bin/python3",
                        native.root + "/bin/workstation-maintenance-cycle", operation, *(("--json",) if as_json else ())))
        for operation, as_json in (("cycle", False), ("schedule-install", True), ("status", 1), (None, False)):
            with patch.object(A.os, "chdir") as chdir, patch.object(A.os, "execv") as call:
                with self.assertRaises(A.AidError): native.maintenance(operation, as_json)
                chdir.assert_not_called(); call.assert_not_called()

    def test_real_process_replacement_preserves_native_text_json_and_nonzero_exit(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp") as directory:
            fixture = Path(directory)
            (fixture / "bin").mkdir()
            (fixture / "bin/workstation-maintenance-cycle").write_text(
                'import sys\nprint(\'{"status":"STALE","fixture":true}\' if "--json" in sys.argv else "Native fixture: STALE")\n'
                'raise SystemExit(3)\n')
            code = '''import importlib.machinery,sys
A=importlib.machinery.SourceFileLoader("fixture_aid",sys.argv[1]).load_module()
native=A.Native.__new__(A.Native); native.root=sys.argv[2]
raise SystemExit(A.main(sys.argv[3:],adapter_factory=lambda:native))
'''
            for operation in ("status", "schedule-status"):
                for options in ([], ["--json"]):
                    result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(ROOT / "bin/aid"),
                        str(fixture), "maintenance", operation, *options], stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                        env={"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp"})
                    self.assertEqual(result.returncode, 3, result.stderr)
                    self.assertEqual(result.stderr, b"")
                    self.assertEqual(result.stdout, b'{"status":"STALE","fixture":true}\n' if options
                        else b"Native fixture: STALE\n")

    def test_mac_launcher_uses_system_shell_without_metadata_repair(self):
        source = (ROOT / "darwin/aid.nix").read_text()
        self.assertIn('aidLauncher = pkgs.writeTextFile {', source)
        self.assertIn('destination = "/bin/aid";', source)
        self.assertIn('executable = true;', source)
        self.assertIn('#!/bin/sh\n', source)
        self.assertIn('exec /usr/bin/python3 ${lib.escapeShellArg', source)
        self.assertIn('}/AIDev/control/bin/aid"} "$@"', source)
        for forbidden in ('writeShellScriptBin', 'xattr -', 'chmod ', 'force = true', 'eval '):
            self.assertNotIn(forbidden, source)

    def test_native_rejects_worktree_before_catalog_or_exec(self):
        with patch.object(A.os, "open", side_effect=AssertionError("must not read catalog")), \
             patch.object(A.os, "execv", side_effect=AssertionError("must not execute")):
            with self.assertRaisesRegex(A.AidError, "noncanonical_source"):
                A.Native()

    def test_each_fixed_exec_vector_preserves_the_callers_environment(self):
        expected = {
            "current": ("bin/current-doctor", "--json"),
            "root": ("bin/root-runtime-doctor", "--json"),
            "revision": ("bin/system-revision-status", "--json"),
            "productivity": ("bin/productivity-doctor", "--manifest"),
            "tailscale": ("bin/tailscale-windows-host-doctor", "--installed"),
            "amnezia": ("bin/amnezia-desktop-doctor", "--manifest"),
            "windows-app": ("bin/windows-app-rdp-client-doctor",),
            "rustdesk": ("bin/rustdesk-mac-controller-doctor",),
        }
        native = A.Native.__new__(A.Native)
        native.root, native.home = "/fixture/AIDev/control", "/fixture"
        for section, (target, *options) in expected.items():
            with self.subTest(section=section):
                sentinel = SystemExit(82)
                context = {"TERM": "xterm-256color", "TMPDIR": "/fixture/tmp",
                    "PATH": "/fixture/bin", "AID_TEST_CONTEXT": "preserve"}
                def native_exec(executable, argv):
                    self.assertEqual(dict(os.environ), context)
                    raise sentinel
                with patch.dict(os.environ, context, clear=True), \
                     patch.object(A.os, "chdir") as chdir, \
                     patch.object(A.os, "execve", side_effect=AssertionError("no replacement environment")), \
                     patch.object(A.os, "execv", side_effect=native_exec) as execute:
                    with self.assertRaises(SystemExit) as stopped:
                        native.doctor(section)
                    self.assertEqual(dict(os.environ), context)
                self.assertIs(stopped.exception, sentinel)
                chdir.assert_called_once_with(native.root)
                execute.assert_called_once_with("/usr/bin/python3",
                    ("/usr/bin/python3", native.root + "/" + target, *options))

    def test_missing_terminal_context_is_not_fabricated(self):
        native = A.Native.__new__(A.Native)
        native.root = "/fixture/AIDev/control"
        def native_exec(executable, argv):
            self.assertEqual(dict(os.environ), {})
            raise SystemExit(82)
        with patch.dict(os.environ, {}, clear=True), patch.object(A.os, "chdir"), \
             patch.object(A.os, "execv", side_effect=native_exec):
            with self.assertRaises(SystemExit):
                native.doctor("tailscale")

    def test_native_unknown_section_cannot_change_cwd_or_exec(self):
        native = A.Native.__new__(A.Native)
        with patch.object(A.os, "chdir") as chdir, patch.object(A.os, "execv") as execute:
            with self.assertRaises(A.AidError):
                native.doctor("unknown")
        chdir.assert_not_called()
        execute.assert_not_called()

    def test_catalog_open_is_fixed_bounded_readonly_nofollow_and_closed(self):
        native = A.Native.__new__(A.Native)
        native.root, native.uid = "/fixture/control", 501
        content = raw(fixture_catalog())
        with patch.object(A.os.path, "realpath", side_effect=lambda p: p), \
             patch.object(A.os, "open", return_value=93) as opened, \
             patch.object(A.os, "fstat", return_value=SimpleNamespace(st_mode=0o100644, st_uid=501, st_size=len(content))), \
             patch.object(A.os, "read", side_effect=[content, b""]), patch.object(A.os, "close") as close:
            self.assertEqual(native.read_catalog(), content)
        path, flags = opened.call_args.args
        self.assertEqual(path, "/fixture/control/manifests/aid-catalog.json")
        self.assertTrue(flags & A.os.O_NOFOLLOW)
        self.assertTrue(flags & A.os.O_NONBLOCK)
        self.assertFalse(flags & (A.os.O_WRONLY | A.os.O_RDWR | A.os.O_CREAT | A.os.O_TRUNC))
        close.assert_called_once_with(93)

    def test_unsafe_catalog_file_never_read(self):
        native = A.Native.__new__(A.Native)
        native.root, native.uid = "/fixture/control", 501
        for facts in (SimpleNamespace(st_mode=0o040755, st_uid=501, st_size=2),
                SimpleNamespace(st_mode=0o100666, st_uid=501, st_size=2),
                SimpleNamespace(st_mode=0o100644, st_uid=0, st_size=2),
                SimpleNamespace(st_mode=0o100644, st_uid=501, st_size=A.MAX_CATALOG + 1)):
            with patch.object(A.os.path, "realpath", side_effect=lambda p: p), \
                 patch.object(A.os, "open", return_value=93), patch.object(A.os, "fstat", return_value=facts), \
                 patch.object(A.os, "read") as read, patch.object(A.os, "close") as close:
                with self.assertRaises(A.AidError):
                    native.read_catalog()
                read.assert_not_called()
                close.assert_called_once_with(93)


if __name__ == "__main__":
    unittest.main()
