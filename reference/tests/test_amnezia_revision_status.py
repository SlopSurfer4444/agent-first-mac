"""Connected Amnezia doctor fixtures; no live VPN, signature or network probes."""
import ast
import contextlib
import importlib.machinery
import inspect
import io
import json
from pathlib import Path, PurePosixPath
import plistlib
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
F = importlib.machinery.SourceFileLoader("amnezia_revision_fixture_support",
    str(ROOT / "tests/test_component_revision_status.py")).load_module()
A = F.load("amnezia-desktop-doctor")
MANIFEST = json.loads((ROOT / "manifests/amnezia-desktop.json").read_text())


class FixturePath(PurePosixPath):
    def is_file(self):
        return True

    def is_dir(self):
        return True

    def exists(self):
        return str(self) != MANIFEST["target"]["legacyBackupPath"]

    def rglob(self, pattern):
        assert pattern == "*.appex"
        return iter(())

    def stat(self):
        assert str(self) == MANIFEST["service"]["plist"]
        return SimpleNamespace(st_uid=0, st_gid=0, st_mode=0o100644)

    def read_text(self):
        assert str(self) == MANIFEST["target"]["marker"]
        return MANIFEST["application"]["bundleVersion"] + "|" + MANIFEST["source"]["sha256"]


class RevisionParserTests(unittest.TestCase):
    def observe(self, value, code=0):
        output = value if type(value) is str else json.dumps(value)
        with patch.object(A, "command", return_value=SimpleNamespace(returncode=code, stdout=output)) as call:
            observed = A.revision_observation()
        call.assert_called_once_with([A.sys.executable, str(A.ROOT / "bin/system-revision-status"), "--json"], timeout=200)
        return observed

    def test_parser_is_exact_same_algorithm_as_accepted_productivity_doctor(self):
        self.assertEqual(ast.dump(ast.parse(inspect.getsource(A.revision_observation))),
                         ast.dump(ast.parse(inspect.getsource(F.P.revision_observation))))

    def test_exact_and_accepted_successor_positive_and_distinct(self):
        for exact in (False, True):
            value = self.observe(F.report(exact))
            self.assertTrue(value["compatible"])
            self.assertIs(value["revisionExact"], exact)

    def test_current_state_admission_is_preserved_and_mislabeled_reports_rejected(self):
        for exact in (False, True):
            value = F.report(exact, admission="current-state")
            observed = self.observe(value)
            self.assertTrue(observed["compatible"])
            self.assertEqual(observed["sourceAdmissionMode"], "current-state")
            self.assertFalse(self.observe(dict(value, sourceAdmissionMode="historical-review"))["compatible"])
            value.pop("sourceAdmissionMode")
            self.assertFalse(self.observe(value)["compatible"])

    def test_false_malformed_inconsistent_and_nonzero_helper_fails_closed(self):
        changes = [{"schema": True}, {"compatible": 1}, {"sourceAccepted": False},
            {"installedCommitAccepted": False}, {"systemInputsEqual": False},
            {"childSettled": False}, {"sourceHandlesClosed": False}, {"readOnly": False},
            {"systemMutationsPerformed": True}, {"state": "CURRENT_REVISION"},
            {"revisionExact": True}, {"sourceRevision": "private-value"}, {"installedRevision": "0" * 40}]
        for change in changes:
            with self.subTest(change=change):
                value = self.observe(dict(F.report(), **change))
                self.assertFalse(value["compatible"])
                self.assertNotIn("private-value", json.dumps(value))
        for invalid in ("not JSON", "[]", '{"schema":1,"schema":1}', "x" * 16385):
            self.assertFalse(self.observe(invalid)["compatible"])
        self.assertFalse(self.observe(F.report(), code=1)["compatible"])

    def test_command_wrapper_uses_given_timeout_without_changing_other_parameters(self):
        with patch.object(A.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="")) as run:
            A.command(["/fixture"], timeout=200)
        run.assert_called_once_with(["/fixture"], text=True, stdout=A.subprocess.PIPE,
            stderr=A.subprocess.STDOUT, check=False, timeout=200)


class ConnectedAmneziaTests(unittest.TestCase):
    def test_unknown_initial_observation_stops_before_manifest_and_component_io_or_retry(self):
        output = io.StringIO()
        with patch.object(A, "command", return_value=SimpleNamespace(returncode=124, stdout="")) as command, \
             patch.object(A, "MANIFEST") as manifest, patch.object(A.sys, "argv", ["fixture-doctor"]), \
             patch.object(A, "Path", side_effect=AssertionError("must not access component paths")), \
             contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as stopped:
                A.main()
            manifest.read_text.assert_not_called()
        self.assertEqual(stopped.exception.code, 1)
        self.assertEqual(command.call_count, 1)
        value = json.loads(output.getvalue())
        self.assertFalse(value["componentChecksRun"] or value["systemMutationsPerformed"] or value["vpnConfigurationInspected"])
        self.assertEqual(value["configurationRevisionStatus"]["state"], "UNKNOWN")

    def run_doctor(self, *, fault=None, drift=False, manifest_race=False, final_unknown=False, admission="historical-review"):
        events, coordinate = [], {"source": "a" * 40}
        observations = [F.report(admission=admission), dict(F.report(admission=admission), sourceRevision=("c" if drift else "a") * 40)]
        def read_manifest():
            events.append("manifest")
            if manifest_race:
                coordinate["source"] = "c" * 40
            return json.dumps(MANIFEST)
        app, service = MANIFEST["application"], MANIFEST["service"]
        canonical = app["path"]
        def command(argv, timeout=None):
            text, code = "", 0
            if len(argv) > 1 and argv[1].endswith("/bin/system-revision-status"):
                events.append("revision")
                self.assertEqual(timeout, 200)
                observation = observations.pop(0)
                if manifest_race:
                    observation["sourceRevision"] = coordinate["source"]
                if final_unknown and not observations:
                    code = 1
                text = json.dumps(observation)
            else:
                events.append("component")
                self.assertIsNone(timeout)
                if argv == ["/usr/sbin/scutil", "--nc", "list"]:
                    text = "Disconnected" if fault == "vpn" else "Connected su.ffg.happ"
                elif argv == ["/usr/bin/dscacheutil", "-q", "host", "-a", "name", "example.com"]:
                    code = 1 if fault == "dns" else 0
                elif argv == ["/usr/bin/curl", "--silent", "--show-error", "--max-time", "10", "--output", "/dev/null", "https://example.com/"]:
                    code = 1 if fault == "https" else 0
                elif argv[0] == "/usr/bin/plutil":
                    self.assertEqual(argv[1:2] + argv[3:6], ["-extract", "raw", "-o", "-"])
                    key, path = argv[2], argv[6]
                    if path == canonical + "/Contents/Info.plist":
                        text = {"CFBundleIdentifier": app["bundleIdentifier"],
                            "CFBundleShortVersionString": app["bundleVersion"]}[key]
                        if fault == "version" and key == "CFBundleShortVersionString":
                            text = "0.0"
                    else:
                        self.assertEqual(path, service["plist"])
                        text = {"Label": service["label"], "ProgramArguments.0": service["program"],
                            "Sockets.Listeners.SockNodeName": service["socketAddress"],
                            "Sockets.Listeners.SockServiceName": str(service["socketPort"])}[key]
                elif argv == ["/usr/bin/codesign", "-d", "--verbose=4", canonical]:
                    text = "TeamIdentifier=" + app["teamIdentifier"]
                elif argv == ["/usr/bin/codesign", "--verify", "--deep", "--strict", canonical]:
                    code = 1 if fault == "signature" else 0
                elif argv == ["/usr/sbin/spctl", "--assess", "--type", "execute", canonical]:
                    code = 1 if fault == "gatekeeper" else 0
                elif argv == ["/usr/bin/file", canonical + "/Contents/MacOS/AmneziaVPN"]:
                    text = "Mach-O x86_64"
                elif argv[:3] == ["/usr/bin/shasum", "-a", "256"]:
                    values = {canonical + "/Contents/MacOS/AmneziaVPN-service": app["serviceSha256"],
                        canonical + "/Contents/Resources/AmneziaVPN.plist": app["resourcePlistSha256"]}
                    text = values[argv[3]] + " fixture-file"
                elif argv == ["/usr/bin/defaults", "export", "com.apple.dock", "-"]:
                    rows = [] if fault == "dock" else [{"tile-data": {"file-data": {"_CFURLString": "file:///Applications/AmneziaVPN.app/"}}}]
                    text = plistlib.dumps({"persistent-apps": rows}).decode()
                elif argv == ["/bin/launchctl", "print", "system/AmneziaVPN-service"]:
                    code = 1 if fault == "service" else 0
                elif argv == ["/usr/sbin/netstat", "-anv", "-p", "tcp"]:
                    address = "0.0.0.0" if fault == "listener" else "127.0.0.1"
                    text = "tcp4 0 0 " + address + ".5959 *.* LISTEN\n"
                else:
                    raise AssertionError("Unexpected fixture command " + repr(argv))
            return SimpleNamespace(returncode=code, stdout=text)
        output = io.StringIO()
        with patch.object(A, "command", side_effect=command), \
             patch.object(A, "MANIFEST", SimpleNamespace(read_text=read_manifest)), \
             patch.object(A, "Path", FixturePath), patch.object(A.sys, "argv", ["fixture-doctor", "--target"]), \
             contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as stopped:
                A.main()
        self.assertEqual(observations, [])
        self.assertEqual(events[0:2], ["revision", "manifest"])
        self.assertEqual(events[-1], "revision")
        return stopped.exception.code, json.loads(output.getvalue())

    def test_healthy_connected_component_accepts_control_only_successor(self):
        code, value = self.run_doctor()
        self.assertEqual((code, value["result"], value["problems"]), (0, "pass", []))
        self.assertEqual(value["configurationRevisionStatus"]["state"], "ACCEPTED_CONTROL_ONLY_SUCCESSOR")
        self.assertFalse(value["configurationRevisionStatus"]["revisionExact"] or value["vpnConfigurationInspected"])

    def test_current_state_admission_preserves_component_checks(self):
        for fault in (None, "signature"):
            code, value = self.run_doctor(fault=fault, admission="current-state")
            self.assertEqual(code, 0 if fault is None else 1)
            self.assertTrue(value["checks"]["configuration_revision"])
            self.assertEqual(value["configurationRevisionStatus"]["sourceAdmissionMode"], "current-state")
            self.assertEqual(value["configurationRevisionStatus"]["state"], "CURRENT_CONTROL_ONLY_SUCCESSOR")

    def test_vpn_signature_network_service_version_dock_and_listener_failures_stay_failed(self):
        expected = {"vpn": "fallback_vpn_connected", "dns": "dns", "https": "https", "signature": "desktop_codesign",
            "gatekeeper": "desktop_gatekeeper", "version": "desktop_version", "dock": "desktop_dock_tile",
            "service": "desktop_service_loaded", "listener": "desktop_listener_loopback_only"}
        for fault, problem in expected.items():
            with self.subTest(fault=fault):
                code, value = self.run_doctor(fault=fault)
                self.assertEqual(code, 1)
                self.assertIn(problem, value["problems"])
                self.assertTrue(value["checks"]["configuration_revision"])

    def test_changed_source_after_checks_is_not_stable(self):
        code, value = self.run_doctor(drift=True)
        self.assertEqual(code, 1)
        self.assertIn("configuration_revision_stable", value["problems"])

    def test_manifest_read_race_cannot_rebind_stale_values(self):
        code, value = self.run_doctor(manifest_race=True)
        self.assertEqual(code, 1)
        self.assertIn("configuration_revision_stable", value["problems"])

    def test_unknown_final_observation_rejects_without_retry(self):
        code, value = self.run_doctor(final_unknown=True)
        self.assertEqual(code, 1)
        self.assertIn("configuration_revision_final", value["problems"])
        self.assertEqual(value["configurationRevisionStatus"]["state"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
