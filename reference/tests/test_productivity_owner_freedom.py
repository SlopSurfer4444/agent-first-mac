"""Synthetic owner coexistence and released preference integration only."""
import copy
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
import contextlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
import productivity_ownership as O


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.manifest = json.loads((ROOT / "manifests/productivity-baseline.json").read_text())

    def brew(self, output="unrelated-app\n", code=0):
        return O.collect_homebrew_conflicts(self.manifest, lambda argv:
            subprocess.CompletedProcess(argv, code, output))

    def test_nonempty_unrelated_formula_cask_is_not_adopted(self):
        with patch("subprocess.Popen", side_effect=AssertionError("no machine")):
            self.assertEqual(self.brew()["status"], "clear")
        self.assertFalse(self.brew()["automaticAdoption"])
        self.assertNotIn("unrelated", json.dumps(self.brew()))

    def test_precise_cask_duplicate_and_formula_resolver_conflict(self):
        report = self.brew("other\niina\nraycast\n")
        self.assertEqual(report["caskConflicts"], ["iina", "raycast"])
        self.manifest["ownershipObservation"]["homebrewCollisions"]["formula"] = ["managed-cli"]
        report = self.brew("other\nmanaged-cli\n")
        self.assertEqual(report["formulaConflicts"], ["managed-cli"])
        self.assertEqual(report["status"], "conflict")

    def test_unknown_required_observation_never_clear(self):
        for output, code in (("", 1), ("private ERROR", 0), ("x" * 65537, 0)):
            self.assertEqual(self.brew(output, code)["status"], "unknown")

    def test_unknown_unrelated_kind_is_not_even_collected(self):
        calls = []
        def runner(argv):
            calls.append(argv)
            self.assertEqual(argv[-1], "--cask")
            return subprocess.CompletedProcess(argv, 0, "unrelated\n")
        self.assertEqual(O.collect_homebrew_conflicts(self.manifest, runner)["status"], "clear")
        self.assertEqual(len(calls), 1)

    def test_disabled_managed_app_profile_does_not_claim_external_owner_conflict(self):
        self.manifest["profileActive"] = False
        report = O.collect_homebrew_conflicts(self.manifest,
            lambda argv: self.fail("inactive managed set needs no Homebrew ownership probe"))
        self.assertEqual(report["status"], "clear")

    def test_external_targeted_app_collision_alias_absence_and_unknown(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            external = root / "external"
            managed = root / "managed"
            external.mkdir(); managed.mkdir()
            self.manifest["ownershipObservation"]["targetedExternalApplicationRoot"] = str(external)
            self.manifest["target"]["applicationRoot"] = str(managed)
            app = self.manifest["applications"][0]
            target = managed / app["bundleName"]
            candidate = external / app["bundleName"]
            target.mkdir()
            self.assertEqual(O.targeted_application_collision(self.manifest, app), "clear")
            candidate.mkdir()
            self.assertEqual(O.targeted_application_collision(self.manifest, app), "conflict")
            candidate.rmdir(); candidate.symlink_to(target)
            self.assertEqual(O.targeted_application_collision(self.manifest, app), "clear")
            with patch.object(O.os, "lstat", side_effect=PermissionError):
                self.assertEqual(O.targeted_application_collision(self.manifest, app,
                                 lstat=O.os.lstat), "unknown")

    def test_all_ten_owner_scenarios_do_not_create_execution_or_adoption_authority(self):
        scenarios = {
            "App Store install": ({"managed": False, "present": True}, "external-observed"),
            "Vendor auto-update": ({"managed": False, "present": True, "signature_valid": True}, "external-observed"),
            "DMG drag-and-drop": ({"managed": False, "present": True}, "external-observed"),
            "Owner uninstall preserving data": ({"managed": False, "present": False}, "external-observed"),
            "Install outside observed roots": ({"managed": False, "present": False, "observed": False}, "unknown"),
            "First scan after install": ({"managed": False, "present": True}, "external-observed"),
            "Install/remove between scans": ({"managed": False, "present": False}, "external-observed"),
            "Manual replacement of managed app": ({"managed": True, "present": True, "identity_matches": False}, "conflict"),
            "Unsigned or identity-changing update": ({"managed": False, "present": True, "authority_bearing": True, "signature_valid": False}, "conflict"),
            "Owner-confirmed expected change": ({"managed": False, "present": True}, "external-observed"),
        }
        for name, (args, expected) in scenarios.items():
            with self.subTest(name=name):
                report = O.classify_observation(**args)
                self.assertEqual(report["state"], expected)
                self.assertFalse(any(report[k] for k in ("automaticAdoption", "automaticRepair", "executionAuthorized", "completeInventory")))
        self.assertEqual(O.classify_observation(managed=True, present=False)["state"], "conflict")
        self.assertEqual(O.classify_observation(managed=True, present=True, identity_matches=True)["state"], "managed")

    def test_released_and_exact_opt_in_preferences_have_distinct_plans(self):
        self.assertEqual(O.preference_plan(self.manifest)["defaults"], [])
        self.assertEqual(O.preference_plan(self.manifest)["power"], {})
        self.assertIs(self.manifest["desiredState"]["batteryLowPowerMode"], True)
        self.assertIs(self.manifest["desiredState"]["acLowPowerMode"], False)
        self.manifest["preferenceOwnership"]["managedKeys"] = ["dockAutohide"]
        self.assertEqual(O.preference_plan(self.manifest)["defaults"], ["dockAutohide"])
        self.manifest["preferenceOwnership"]["managedKeys"] = ["batteryLowPowerMode"]
        self.assertEqual(O.preference_plan(self.manifest)["power"], {"batteryLowPowerMode": True})

    @unittest.skipUnless(shutil.which("nix-instantiate"), "local pure Nix evaluator unavailable")
    def test_actual_nix_evaluation_has_zero_released_writes_and_exact_targeted_key(self):
        # No nixpkgs resolution, store build, network, profile or machine query.
        # This evaluates the real module with inert package values and pure lib.
        prefix = r'''let
          lib = rec {
            optionals = condition: values: if condition then values else [];
            optionalString = condition: value: if condition then value else "";
            mkAfter = value: value;
            foldl' = builtins.foldl';
            recursiveUpdate = left: right: left // builtins.mapAttrs (key: value:
              if builtins.hasAttr key left && builtins.isAttrs value && builtins.isAttrs left.${key}
              then recursiveUpdate left.${key} value else value) right;
            setAttrByPath = path: value:
              if path == [] then value else { ${builtins.head path} = setAttrByPath (builtins.tail path) value; };
          };
          pkgs = { iina = "iina"; keka = "keka"; raycast = "raycast"; shottr = "shottr";
            localsend.overrideAttrs = _: "localsend"; };
          bootstrapIdentity = { homeDirectory = "/fixture-home"; userName = "fixture-owner"; };
          module = import '''
        suffix = r''' { inherit lib pkgs bootstrapIdentity; };
          in { defaults = module.system.defaults; power = module.system.activationScripts.power.text;
               apps = module.environment.systemPackages; }'''
        source = (ROOT / "darwin/productivity.nix").read_text()
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "productivity.nix"
            def evaluate(keys):
                selector = "managedPreferences = [ " + " ".join(json.dumps(key) for key in keys) + " ];"
                target.write_text(source.replace("managedPreferences = [ ];", selector))
                result = subprocess.run([shutil.which("nix-instantiate"), "--eval", "--strict", "--json", "--expr", prefix + str(target) + suffix], capture_output=True, text=True, timeout=20, check=True)
                return json.loads(result.stdout)
            ordinary = evaluate([])
            self.assertEqual(ordinary["defaults"], {"SoftwareUpdate": {"AutomaticallyInstallMacOSUpdates": True}})
            self.assertEqual(ordinary["power"].strip(), "")
            self.assertEqual(len(ordinary["apps"]), 5)
            targeted = evaluate(["dockAutohide"])
            self.assertEqual(targeted["defaults"]["dock"], {"autohide": False})
            self.assertEqual(targeted["power"].strip(), "")
            power = evaluate(["batteryLowPowerMode"])
            self.assertIn('/usr/bin/pmset -b lowpowermode', power["power"])
            self.assertNotIn('/usr/bin/pmset -c', power["power"])
            self.assertRegex(power["power"], r"lowpowermode\s+\\\s+1")

    def test_live_doctor_fixture_skips_all_released_defaults_and_power(self):
        doctor = load("owner_freedom_doctor", ROOT / "bin/productivity-doctor")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "manifest.json"
            manifest = copy.deepcopy(self.manifest)
            manifest["target"]["applicationRoot"] = str(Path(temp) / "managed")
            manifest["ownershipObservation"]["targetedExternalApplicationRoot"] = temp
            path.write_text(json.dumps(manifest))
            calls = []
            def command(argv, timeout=None):
                calls.append(argv)
                self.assertNotIn(argv[0], ("/usr/bin/defaults", "/usr/bin/pmset"))
                output = {"--getglobalstate": "Firewall is enabled", "--getblockall": "block all state set to disabled", "--getallowsigned": "built-in signed software ENABLED downloaded signed software ENABLED", "--getstealthmode": "stealth mode is off"}.get(argv[-1], "")
                if argv[0].endswith("fdesetup"): output = "FileVault is On"
                if argv[0].endswith("brew"): output = "unrelated\n"
                return subprocess.CompletedProcess(argv, 0, output)
            stream = io.StringIO()
            with patch.object(doctor, "MANIFEST", path), patch.object(doctor, "command", side_effect=command), patch.object(doctor, "revision_observation", return_value={"compatible": True}), patch.object(sys, "argv", ["doctor", "--prestate"]), contextlib.redirect_stdout(stream):
                with self.assertRaises(SystemExit) as exit:
                    doctor.main()
            self.assertEqual(exit.exception.code, 0)
            report = json.loads(stream.getvalue())
            self.assertTrue(report["checks"]["filevault_on"])
            self.assertTrue(report["checks"]["firewall_global"])
            self.assertFalse(report["completeInventory"])

    def test_target_doctor_connects_real_fixture_app_collisions_to_failed_gate(self):
        doctor = load("owner_freedom_target_doctor", ROOT / "bin/productivity-doctor")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            external = root / "external"
            managed = root / "managed"
            external.mkdir(); managed.mkdir()
            manifest = copy.deepcopy(self.manifest)
            manifest["target"]["applicationRoot"] = str(managed)
            manifest["ownershipObservation"]["targetedExternalApplicationRoot"] = str(external)
            for app in manifest["applications"]:
                (managed / app["bundleName"]).mkdir()
            path = root / "manifest.json"
            path.write_text(json.dumps(manifest))
            def command(argv, timeout=None):
                self.assertNotIn(argv[0], ("/usr/bin/defaults", "/usr/bin/pmset"))
                output = {"--getglobalstate": "Firewall is enabled", "--getblockall": "block all state set to disabled", "--getallowsigned": "built-in signed software ENABLED downloaded signed software ENABLED", "--getstealthmode": "stealth mode is on"}.get(argv[-1], "")
                if argv[0].endswith("fdesetup"): output = "FileVault is On"
                if argv[0].endswith("brew"): output = "unrelated-owner-app\n"
                return subprocess.CompletedProcess(argv, 0, output)
            by_name = {app["bundleName"]: app for app in manifest["applications"]}
            def plist(bundle, key):
                app = by_name[bundle.name]
                return app["bundleIdentifier" if key == "CFBundleIdentifier" else "version"]
            def execute():
                stream = io.StringIO()
                with patch.object(doctor, "MANIFEST", path), patch.object(doctor, "command", side_effect=command), patch.object(doctor, "plist_value", side_effect=plist), patch.object(doctor, "codesign_team", side_effect=lambda bundle: by_name[bundle.name]["teamIdentifier"]), patch.object(doctor, "revision_observation", return_value={"compatible": True}), patch.object(sys, "argv", ["doctor"]), contextlib.redirect_stdout(stream):
                    with self.assertRaises(SystemExit) as exit:
                        doctor.main()
                return exit.exception.code, json.loads(stream.getvalue())
            code, report = execute()
            self.assertEqual(code, 0)
            self.assertEqual(report["ownershipObservations"]["IINA"]["state"], "managed")
            (external / "IINA.app").mkdir()
            code, report = execute()
            self.assertEqual(code, 1)
            self.assertEqual(report["ownershipObservations"]["IINA"]["reason"], "competing_primary_owner")
            self.assertNotIn(temp, json.dumps(report))


if __name__ == "__main__":
    unittest.main()
