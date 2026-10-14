"""Focused, process-free tests for the Phase 5 signed application floor."""

from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace
import copy
import os
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
PREFLIGHT = SourceFileLoader(
    "phase5_vendor_floor_preflight", str(ROOT / "bin/phase5-preflight")
).load_module()

DESIGNATED = (
    'designated => identifier "com.openai.codex" and anchor apple generic '
    'and certificate leaf[subject.OU] = "2DC432GLL2"'
)


def manifest():
    return {
        "runtime": {
            "appMinimumVersion": "26.721.41059",
            "appVersionPolicy": "signed-vendor-floor",
            "cliVersionPolicy": "signed-vendor-floor",
            "observedAppBuild": "5848",
            "observedAppVersion": "26.721.41059",
            "bundleId": "com.openai.codex",
            "teamId": "2DC432GLL2",
            "designatedRequirement": DESIGNATED,
        }
    }


def plist(*, version="27.0.0", build="1", bundle="com.openai.codex"):
    return {
        "CFBundleShortVersionString": version,
        "CFBundleVersion": build,
        "CFBundleIdentifier": bundle,
    }


def completed(returncode=0, stdout=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout)


def runner(*, identity_rc=0, identity_team="2DC432GLL2", designated_rc=0,
           designated=DESIGNATED, verify_rc=0, gatekeeper_rc=0):
    def fake(arguments, environment=None):
        del environment
        command = tuple(str(item) for item in arguments)
        if command[:2] == ("/usr/bin/codesign", "-dvv"):
            return completed(identity_rc, "TeamIdentifier=" + identity_team + "\n")
        if command[:3] == ("/usr/bin/codesign", "-dr", "-"):
            return completed(designated_rc, designated + "\n")
        if command[:3] == ("/usr/bin/codesign", "--verify", "--deep"):
            return completed(verify_rc)
        if command[:3] == ("/usr/sbin/spctl", "--assess", "--type"):
            return completed(gatekeeper_rc)
        raise AssertionError("unexpected process contract: " + repr(command))
    return fake


class NumericVersionTests(unittest.TestCase):
    def test_unsigned_numeric_floor(self):
        compare = PREFLIGHT.numeric_version_at_or_above
        self.assertTrue(compare("26.721.41059", "26.721.41059", minimum_components=2))
        self.assertTrue(compare("26.722.0", "26.721.41059", minimum_components=2))
        self.assertFalse(compare("26.720.99999", "26.721.41059", minimum_components=2))

    def test_malformed_equal_strings_never_pass(self):
        compare = PREFLIGHT.numeric_version_at_or_above
        for value in (
            "release-current", "26.721.41059-alpha.1", "26..721", "+5848",
            " 5848", "1" * 21, ".".join(["1"] * 17),
        ):
            with self.subTest(value=value):
                self.assertFalse(compare(value, value))
        self.assertFalse(compare("26", "26", minimum_components=2))

    def test_existing_opaque_plugin_policy_remains_exact(self):
        self.assertTrue(PREFLIGHT.version_at_or_above("opaque-revision", "opaque-revision"))
        self.assertFalse(PREFLIGHT.version_at_or_above("new-opaque", "opaque-revision"))

    def test_malformed_cli_suffix_cannot_win_numeric_comparison(self):
        for value in ("0.146.0-alpha..18", "1.0.0-.", "1.0.0-alpha.",
                      "1.0.0-.alpha", "9" * 21 + ".0", ".".join(["1"] * 17)):
            for prefix in ("", "codex-cli "):
                with self.subTest(value=value, prefix=prefix):
                    self.assertFalse(PREFLIGHT.version_at_or_above(prefix + value, "0.1.0"))
                    self.assertFalse(PREFLIGHT.version_at_or_above(prefix + value, prefix + value))

    def test_valid_prerelease_order_preserved(self):
        compare = PREFLIGHT.version_at_or_above
        self.assertTrue(compare("codex-cli 0.146.0-alpha.18", "codex-cli 0.145.0"))
        self.assertFalse(compare("codex-cli 1.0.0-alpha.18", "codex-cli 1.0.0"))
        self.assertTrue(compare("codex-cli 1.0.0", "codex-cli 1.0.0-alpha.18"))


class AppAttestationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="phase5-vendor-floor-",
            dir="/private/tmp",
        )
        self.addCleanup(self.temporary.cleanup)
        self.fixture_root = Path(self.temporary.name)
        self.bundle = self.fixture_root / "ChatGPT.app"
        self.info_path = self.bundle / "Contents/Info.plist"
        self.write_info(plist())

    def write_info(self, info):
        self.info_path.parent.mkdir(parents=True, exist_ok=True)
        self.info_path.write_bytes(plistlib.dumps(info))

    def attest(self, run=None, value=None, bundle=None):
        run = runner() if run is None else run
        value = manifest() if value is None else value
        bundle = self.bundle if bundle is None else bundle
        with patch.object(PREFLIGHT, "APP_BUNDLE", bundle), \
                patch.object(PREFLIGHT, "run", side_effect=run):
            return PREFLIGHT.app_attestation(value)

    def test_newer_signed_version_with_reset_numeric_build_passes(self):
        self.assertEqual(self.attest(), "27.0.0")

    def test_matching_floor_relationships_pass(self):
        self.write_info(plist(version="26.721.41059", build="5848"))
        self.assertEqual(
            self.attest(),
            "26.721.41059",
        )

    def test_malformed_build_or_malformed_and_downgraded_version_fail(self):
        cases = (
            plist(version="26.721.41059-alpha.1"),
            plist(version="26.720.99999"),
            plist(build="build-5848"),
        )
        for info in cases:
            with self.subTest(info=info):
                self.write_info(info)
                self.assertIsNone(self.attest())

    def test_bundle_identity_denial(self):
        self.write_info(plist(bundle="com.example.substitute"))
        self.assertIsNone(self.attest())

    def test_team_identity_denial(self):
        self.assertIsNone(self.attest(run=runner(identity_team="WRONGTEAM")))

    def test_team_identity_requires_exact_field(self):
        def misleading_identity(arguments, environment=None):
            result = runner()(arguments, environment)
            if tuple(str(item) for item in arguments)[:2] == ("/usr/bin/codesign", "-dvv"):
                return completed(0, "OtherTeamIdentifier=2DC432GLL2\n")
            return result
        self.assertIsNone(self.attest(run=misleading_identity))

    def test_identity_command_denial(self):
        self.assertIsNone(self.attest(run=runner(identity_rc=1)))

    def test_designated_requirement_denials(self):
        for run in (
            runner(designated="designated => identifier substitution"),
            runner(designated_rc=1),
        ):
            with self.subTest(run=run):
                self.assertIsNone(self.attest(run=run))

    def test_strict_signature_denial(self):
        self.assertIsNone(self.attest(run=runner(verify_rc=1)))

    def test_gatekeeper_denial(self):
        self.assertIsNone(self.attest(run=runner(gatekeeper_rc=1)))

    def test_policy_denial(self):
        value = copy.deepcopy(manifest())
        value["runtime"]["appVersionPolicy"] = "exact"
        self.assertIsNone(self.attest(value=value))

    def test_bundle_symlink_is_denied_before_signing(self):
        link = self.fixture_root / "Substitute.app"
        link.symlink_to(self.bundle, target_is_directory=True)
        invoked = Mock(side_effect=AssertionError("signing must not run"))
        self.assertIsNone(self.attest(run=invoked, bundle=link))
        invoked.assert_not_called()

    def test_plist_drift_between_signing_commands_is_denied(self):
        accepted = runner()
        changed = False
        def mutate(arguments, environment=None):
            nonlocal changed
            result = accepted(arguments, environment)
            if not changed:
                changed = True
                self.write_info(plist(version="28.0.0", build="2"))
            return result
        self.assertIsNone(self.attest(run=mutate))

    def test_plist_metadata_drift_between_signing_commands_is_denied(self):
        accepted = runner()
        changed = False
        def mutate(arguments, environment=None):
            nonlocal changed
            result = accepted(arguments, environment)
            if not changed:
                changed = True
                self.info_path.chmod(0o600)
            return result
        self.assertIsNone(self.attest(run=mutate))

    def test_bundle_replacement_between_signing_commands_is_denied(self):
        accepted = runner()
        replaced = False
        def replace(arguments, environment=None):
            nonlocal replaced
            result = accepted(arguments, environment)
            if not replaced:
                replaced = True
                previous = self.fixture_root / "Previous.app"
                self.bundle.rename(previous)
                self.write_info(plist())
            return result
        self.assertIsNone(self.attest(run=replace))

    def test_plist_root_and_scalar_field_shapes_are_denied(self):
        for value in (["not", "a", "map"], plist(version=27)):
            with self.subTest(value=value):
                self.write_info(value)
                self.assertIsNone(self.attest())

    def test_ordinary_process_failures_are_redacted_to_none(self):
        failures = (
            OSError("private signing path"),
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "private output"),
            subprocess.TimeoutExpired(["private-command"], 1),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                def fail(*_args, **_kwargs):
                    raise failure
                self.assertIsNone(self.attest(run=fail))

    def test_base_exception_interruption_is_not_swallowed(self):
        def interrupt(*_args, **_kwargs):
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.attest(run=interrupt)

    def test_fifo_metadata_is_rejected_without_blocking_open(self):
        self.info_path.unlink()
        os.mkfifo(self.info_path, 0o600)
        native_open = os.open
        def nonblocking_open(path, flags, *args, **kwargs):
            if path == "Info.plist":
                # Fail before native open if the safety flag regresses.
                self.assertTrue(flags & os.O_NONBLOCK)
            return native_open(path, flags, *args, **kwargs)
        with patch.object(PREFLIGHT.os, "open", side_effect=nonblocking_open):
            with self.assertRaisesRegex(OSError, "^unsafe app metadata$"):
                PREFLIGHT._AppBundleObservation(self.bundle)

    def test_constructor_interrupt_closes_all_acquired_descriptors(self):
        native_open, native_fstat = os.open, os.fstat
        for seam in ("open", "fstat"):
            for step in range(1, 5):
                with self.subTest(seam=seam, step=step):
                    opened, calls = [], {"open": 0, "fstat": 0}
                    def observed_open(*args, **kwargs):
                        calls["open"] += 1
                        if seam == "open" and calls["open"] == step:
                            raise KeyboardInterrupt()
                        descriptor = native_open(*args, **kwargs)
                        opened.append(descriptor)
                        return descriptor
                    def observed_fstat(*args, **kwargs):
                        calls["fstat"] += 1
                        if seam == "fstat" and calls["fstat"] == step:
                            raise KeyboardInterrupt()
                        return native_fstat(*args, **kwargs)
                    try:
                        with patch.object(PREFLIGHT.os, "open", side_effect=observed_open), \
                                patch.object(PREFLIGHT.os, "fstat", side_effect=observed_fstat):
                            with self.assertRaises(KeyboardInterrupt):
                                PREFLIGHT._AppBundleObservation(self.bundle)
                        for descriptor in opened:
                            with self.assertRaises(OSError):
                                native_fstat(descriptor)
                    finally:
                        # Keep a failing old-behavior regression fixture clean.
                        for descriptor in opened:
                            try:
                                os.close(descriptor)
                            except OSError:
                                pass


class McpAppVersionRelationshipTests(unittest.TestCase):
    @staticmethod
    def rows(version):
        return [{
            "name": "node_repl",
            "transport": {"env": {"BROWSER_USE_CODEX_APP_VERSION": version}},
        }]

    def test_exact_fresh_attestation_relationship(self):
        self.assertTrue(PREFLIGHT.mcp_app_version_matches_attestation(
            self.rows("27.0.0"), "27.0.0"
        ))

    def test_stale_malformed_missing_and_duplicate_relationships_fail(self):
        cases = (
            (self.rows("26.721.41059"), "27.0.0"),
            (self.rows("27.0.0-alpha"), "27.0.0-alpha"),
            ([], "27.0.0"),
            (self.rows("27.0.0") * 2, "27.0.0"),
        )
        for rows, version in cases:
            with self.subTest(rows=rows, version=version):
                self.assertFalse(PREFLIGHT.mcp_app_version_matches_attestation(rows, version))


if __name__ == "__main__":
    unittest.main()
