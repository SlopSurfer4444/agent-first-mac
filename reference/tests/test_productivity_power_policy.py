"""Run the static productivity validator on disposable source fixtures only."""

import contextlib
import copy
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "bin/check-productivity-baseline"
MANIFEST = "manifests/productivity-baseline.json"
MODULE = "darwin/productivity.nix"


class ProductivityPowerPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aid-productivity-power-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for path in (MANIFEST, MODULE, "flake.nix", "flake.lock", "darwin/homebrew.nix"):
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / path).read_bytes())
        self.manifest = json.loads((self.root / MANIFEST).read_text())
        self.module = (self.root / MODULE).read_text()
        loader = importlib.machinery.SourceFileLoader("productivity_power_fixture", str(CHECKER))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        self.checker = importlib.util.module_from_spec(spec)
        loader.exec_module(self.checker)

    def sources(self, *, battery=True):
        manifest = copy.deepcopy(self.manifest)
        manifest["desiredState"]["batteryLowPowerMode"] = battery
        manifest["ownerRuntimePreferences"]["lowPowerMode"] = "Only on Battery" if battery else "Never"
        module, count = re.subn(r"batteryLowPowerEnabled = (true|false);",
            "batteryLowPowerEnabled = " + str(battery).lower() + ";", self.module)
        self.assertEqual(count, 1)
        return manifest, module

    def validate(self, manifest, module):
        (self.root / MANIFEST).write_text(json.dumps(manifest))
        (self.root / MODULE).write_text(module)
        output = io.StringIO()
        with patch.object(self.checker, "ROOT", self.root), \
                patch.object(self.checker, "MANIFEST", self.root / MANIFEST), \
                patch.object(self.checker, "MODULE", self.root / MODULE), \
                patch.object(sys, "argv", [str(CHECKER)]), \
                patch("subprocess.Popen", side_effect=AssertionError("machine process forbidden")), \
                patch("os.system", side_effect=AssertionError("machine command forbidden")), \
                contextlib.redirect_stdout(output):
            self.checker.main()
        return json.loads(output.getvalue())

    def rejects(self, manifest, module, reason):
        with self.assertRaisesRegex(RuntimeError, "^" + reason + "$"):
            self.validate(manifest, module)

    def test_current_intent_preserves_battery_on_ac_off_and_charge_limit(self):
        self.assertIs(self.manifest["desiredState"]["batteryLowPowerMode"], True)
        self.assertIs(self.manifest["desiredState"]["acLowPowerMode"], False)
        self.assertIs(self.manifest["prestate"]["batteryLowPowerMode"], False)
        self.assertEqual(self.manifest["ownerRuntimePreferences"]["lowPowerMode"], "Only on Battery")
        self.assertEqual(self.manifest["ownerRuntimePreferences"]["chargeLimitPercent"], 90)
        self.assertEqual(self.manifest["ownerAuthorization"]["latestOwnerOverride"]["authorizedOn"],
                         "2026-09-09")
        self.assertIn("batteryLowPowerEnabled = true;", self.module)
        self.assertIn('/usr/bin/pmset -c lowpowermode 0', self.module)
        self.assertIs(self.validate(self.manifest, self.module)["batteryLowPowerMode"], True)

    def test_both_reviewed_exact_boolean_choices_pass_when_all_fields_agree(self):
        for battery in (False, True):
            with self.subTest(battery=battery):
                manifest, module = self.sources(battery=battery)
                report = self.validate(manifest, module)
                self.assertEqual(report["result"], "pass")
                self.assertIs(report["batteryLowPowerMode"], battery)
                self.assertEqual(report["applicationCount"], 5)

    def test_battery_value_rejects_non_boolean_types_including_numeric_aliases(self):
        for value in (0, 1, 0.0, 1.0, "false", "true", None, [], {}):
            with self.subTest(value=value):
                manifest, module = self.sources()
                manifest["desiredState"]["batteryLowPowerMode"] = value
                self.rejects(manifest, module, "battery_low_power_type")

    def test_module_manifest_mismatch_rejected_for_either_boolean(self):
        for battery in (False, True):
            with self.subTest(battery=battery):
                manifest, module = self.sources(battery=battery)
                module = module.replace("batteryLowPowerEnabled = " + str(battery).lower() + ";",
                                        "batteryLowPowerEnabled = " + str(not battery).lower() + ";")
                self.rejects(manifest, module, "battery_low_power_flag_manifest_drift")

    def test_runtime_label_must_match_each_boolean(self):
        for battery in (False, True):
            with self.subTest(battery=battery):
                manifest, module = self.sources(battery=battery)
                manifest["ownerRuntimePreferences"]["lowPowerMode"] = "Never" if battery else "Only on Battery"
                self.rejects(manifest, module, "battery_runtime_preferences")

    def test_runtime_label_rejects_other_enums_and_wrong_types(self):
        for value in ("Always", "Only on Power Adapter", "only on battery", "", True, 1, None, [], {}):
            with self.subTest(value=value):
                manifest, module = self.sources()
                manifest["ownerRuntimePreferences"]["lowPowerMode"] = value
                self.rejects(manifest, module, "battery_runtime_preferences")

    def test_ac_policy_stays_exact_false(self):
        for value in (True, 0, 1, "false", None):
            with self.subTest(value=value):
                manifest, module = self.sources()
                manifest["desiredState"]["acLowPowerMode"] = value
                self.rejects(manifest, module, "ac_low_power_drift")

    def test_charge_limit_is_not_changed_by_battery_boolean_support(self):
        manifest, module = self.sources()
        manifest["ownerRuntimePreferences"]["chargeLimitPercent"] = 80
        self.rejects(manifest, module, "battery_runtime_preferences")

    def test_application_version_pins_remain_unchanged(self):
        manifest, module = self.sources()
        manifest["applications"][0]["version"] = "9.9.9"
        self.rejects(manifest, module, "application_identity_drift")

    def test_profile_rollback_flag_does_not_disable_owner_battery_policy(self):
        manifest, module = self.sources()
        manifest["profileActive"] = False
        module = module.replace("productivityProfileEnabled = true;", "productivityProfileEnabled = false;")
        report = self.validate(manifest, module)
        self.assertIs(report["profileActive"], False)
        self.assertIs(report["batteryLowPowerMode"], True)

    def test_targeted_selector_matches_manifest_without_global_write_scope(self):
        manifest, module = self.sources()
        manifest["preferenceOwnership"]["managedKeys"] = ["dockAutohide"]
        module = module.replace("managedPreferences = [ ];", 'managedPreferences = [ "dockAutohide" ];')
        self.assertEqual(self.validate(manifest, module)["preferencePlan"]["defaults"], ["dockAutohide"])
        self.rejects(manifest, self.module, "preference_selector_manifest_drift")

    def test_targeted_declaration_value_or_path_drift_fails_closed(self):
        manifest, module = self.sources()
        self.rejects(manifest, module.replace('"dock" "autohide" ]; value = false;',
                                            '"dock" "autohide" ]; value = true;'), "managed_preference_value_drift")
        self.rejects(manifest, module.replace('"dock" "autohide" ];',
                                            '"dock" "show-recents" ];'), "managed_preference_path_drift")

    def test_unconditional_released_writer_cannot_be_reintroduced(self):
        manifest, module = self.sources()
        self.rejects(manifest, module.replace("SoftwareUpdate.AutomaticallyInstallMacOSUpdates = true;",
                     "SoftwareUpdate.AutomaticallyInstallMacOSUpdates = true;\n    dock.autohide = false;"),
                     "released_preference_write")


if __name__ == "__main__":
    unittest.main()
