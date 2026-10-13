"""Connected absent-state doctor fixtures; no live Amnezia or network reads."""
import contextlib
import importlib.machinery
import io
import json
from pathlib import Path, PurePosixPath
import plistlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
A = importlib.machinery.SourceFileLoader(
    "amnezia_absent_doctor", str(ROOT / "bin/amnezia-desktop-doctor")).load_module()
M = json.loads((ROOT / "manifests/amnezia-desktop.json").read_text())
RETIRED = M["absence"]["retiredPayloadPath"]


class FixturePath(PurePosixPath):
    fault = None

    def exists(self):
        return str(self).startswith(RETIRED)

    def is_symlink(self):
        return self.fault == "symlink" and str(self) == RETIRED

    def is_dir(self):
        return str(self) in (RETIRED, RETIRED + "/AmneziaVPN.app")

    def is_file(self):
        return str(self) in (RETIRED + "/AmneziaVPN.plist",
                             RETIRED + "/managed-version")

    def stat(self):
        assert str(self) == RETIRED
        return SimpleNamespace(st_uid=0, st_gid=0, st_mode=0o40755)

    def iterdir(self):
        assert str(self) == RETIRED
        names = ["AmneziaVPN.app", "AmneziaVPN.plist", "managed-version"]
        if self.fault == "extra":
            names.append("foreign")
        return iter(self / name for name in names)

    def read_text(self):
        assert str(self) == RETIRED + "/managed-version"
        return ("wrong" if self.fault == "marker" else
                M["application"]["bundleVersion"] + "|" + M["source"]["sha256"])


class AbsentDoctorTests(unittest.TestCase):
    def run_case(self, fault=None):
        FixturePath.fault = fault
        rev = {"state": "CURRENT_REVISION", "compatible": True,
               "revisionExact": True, "sourceRevision": "a" * 40,
               "installedRevision": "a" * 40, "sourceAdmissionMode": "historical-review",
               "reason": "exact_accepted_revision"}
        app = M["application"]
        service = M["service"]

        def command(argv, timeout=None):
            if len(argv) > 1 and argv[1].endswith("/bin/system-revision-status"):
                report = dict(schema=1, sourceAccepted=True,
                              installedCommitAccepted=True, systemInputsEqual=True,
                              childSettled=True, sourceHandlesClosed=True,
                              readOnly=True, systemMutationsPerformed=False, **rev)
                return SimpleNamespace(returncode=0, stdout=json.dumps(report))
            if argv == ["/usr/bin/defaults", "export", "com.apple.dock", "-"]:
                urls = ([{"tile-data": {"file-data": {
                    "_CFURLString": "file:///Applications/AmneziaVPN.app/"}}}]
                    if fault == "dock" else [])
                return SimpleNamespace(returncode=0,
                    stdout=plistlib.dumps({"persistent-apps": urls}).decode())
            if argv == ["/bin/launchctl", "print", "system/AmneziaVPN-service"]:
                return SimpleNamespace(returncode=0 if fault == "service" else 1,
                                       stdout="")
            if argv[:2] == ["/usr/bin/pgrep", "-f"]:
                return SimpleNamespace(returncode={"process": 0, "pgrep_error": 2}.get(fault, 1),
                                       stdout="")
            if argv == ["/usr/sbin/netstat", "-anv", "-p", "tcp"]:
                line = "tcp4 0 0 127.0.0.1.5959 *.* LISTEN\n" if fault == "listener" else ""
                return SimpleNamespace(returncode=1 if fault == "netstat_error" else 0,
                                       stdout=line)
            if argv[0] == "/usr/bin/plutil":
                key, path = argv[2], argv[6]
                if path.endswith("/Contents/Info.plist"):
                    value = {"CFBundleIdentifier": app["bundleIdentifier"],
                             "CFBundleShortVersionString": app["bundleVersion"]}[key]
                else:
                    assert path == RETIRED + "/AmneziaVPN.plist"
                    value = {"Label": service["label"],
                             "ProgramArguments.0": service["program"],
                             "Sockets.Listeners.SockNodeName": service["socketAddress"],
                             "Sockets.Listeners.SockServiceName": str(service["socketPort"])}[key]
                return SimpleNamespace(returncode=0, stdout=value)
            if argv[0] == "/usr/bin/codesign":
                if argv[1] == "-d":
                    return SimpleNamespace(returncode=0,
                        stdout="TeamIdentifier=" + app["teamIdentifier"])
                return SimpleNamespace(returncode=1 if fault == "signature" else 0, stdout="")
            if argv[:3] == ["/usr/bin/shasum", "-a", "256"]:
                suffix = str(argv[3]).removeprefix(RETIRED + "/")
                hash_value = {
                    "AmneziaVPN.app/Contents/MacOS/AmneziaVPN-service": app["serviceSha256"],
                    "AmneziaVPN.app/Contents/Resources/AmneziaVPN.plist": app["resourcePlistSha256"],
                    "AmneziaVPN.plist": M["absence"]["daemonSha256"],
                }[suffix]
                if fault == "daemon_hash" and suffix == "AmneziaVPN.plist":
                    hash_value = "0" * 64
                return SimpleNamespace(returncode=0, stdout=hash_value + "  fixture")
            raise AssertionError(repr(argv))

        out = io.StringIO()
        with patch.object(A, "command", side_effect=command), \
             patch.object(A, "Path", FixturePath), \
             patch.object(A, "MANIFEST", SimpleNamespace(read_text=lambda: json.dumps(M))), \
             patch.object(A.sys, "argv", ["fixture-doctor", "--absent"]), \
             contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as stopped:
                A.main()
        return stopped.exception.code, json.loads(out.getvalue())

    def test_absent_passes_without_rosetta_fallback_vpn_or_network_probe(self):
        code, value = self.run_case()
        self.assertEqual((code, value["result"], value["problems"]), (0, "pass", []))
        self.assertEqual(value["desiredState"], "absent")
        self.assertNotIn("rosetta", value["checks"])
        self.assertNotIn("fallback_vpn_connected", value["checks"])

    def test_residual_process_listener_and_check_errors_fail_closed(self):
        for fault, problem in (("process", "desktop_service_process_absent"),
                               ("pgrep_error", "desktop_service_process_absent"),
                               ("listener", "desktop_listener_absent"),
                               ("netstat_error", "desktop_listener_absent"),
                               ("service", "desktop_service_absent")):
            with self.subTest(fault=fault):
                code, value = self.run_case(fault)
                self.assertEqual(code, 1)
                self.assertIn(problem, value["problems"])

    def test_retired_foreign_or_drift_and_dock_fail_closed(self):
        for fault, problem in (("extra", "retired_directory"),
                               ("symlink", "retired_directory"),
                               ("marker", "retired_marker_identity"),
                               ("daemon_hash", "retired_daemon_identity"),
                               ("signature", "retired_app_identity"),
                               ("dock", "desktop_dock_tile_absent")):
            with self.subTest(fault=fault):
                code, value = self.run_case(fault)
                self.assertEqual(code, 1)
                self.assertIn(problem, value["problems"])


if __name__ == "__main__":
    unittest.main()
