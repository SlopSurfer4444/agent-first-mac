#!/usr/bin/env python3
"""Source-only and mocked bundle checks; never compile, invoke sudo or install."""

import contextlib
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True


def load_builder(name):
    path = ROOT / "bin" / name
    loader = importlib.machinery.SourceFileLoader(name.replace("-", "_"), str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class RootBundleSuccessorTests(unittest.TestCase):
    def builders(self):
        return [load_builder("build-phase4-install-bundle"),
                load_builder("build-phase4-emergency-bundle")]

    def test_parser_requires_explicit_new_successor_output(self):
        for builder in self.builders():
            with self.subTest(builder=builder.__name__), tempfile.TemporaryDirectory() as raw:
                base = Path(raw).resolve()
                historical = base / "historical"
                new = base / "candidate"
                with patch.object(builder, "DEFAULT_OUTPUT", historical):
                    self.assertEqual(builder.parse_args([]), (False, historical))
                    self.assertEqual(builder.parse_args(["--output", str(new)]), (False, new))
                    self.assertEqual(builder.parse_args(["--successor", "--output", str(new)]), (True, new))
                    for args in [["--successor"], ["--successor", str(new)],
                                 ["--successor", "--output"], ["--successor", "--output", ""],
                                 ["--successor", "--output", str(new), "extra"],
                                 ["--successor", "--output", "--other"],
                                 ["--output", "--other"],
                                 ["--output", str(new), "--successor"],
                                 ["--successor", "--output", str(historical)]]:
                        with self.subTest(args=args), self.assertRaises(RuntimeError):
                            builder.parse_args(args)
                    new.mkdir()
                    with self.assertRaises(RuntimeError):
                        builder.parse_args(["--successor", "--output", str(new)])
                    dangling = base / "dangling"
                    dangling.symlink_to(base / "absent")
                    with self.assertRaises(RuntimeError):
                        builder.parse_args(["--successor", "--output", str(dangling)])

    def test_successor_manifest_cannot_claim_historical_acceptance(self):
        for builder in self.builders():
            historical = {
                "schema": 1, "acceptedBases": {"controlMain": "old", "taskParent": "old-parent"},
                "buildProvenance": {"sourceBase": "old-base", "sourceFileSHA256": {}},
                "gates": {"applyGateAccepted": True, "preparationOnly": False},
                "futureLauncher": {"standardSudoOnly": True},
                "installedContract": {"receipt": {"sha256": "historical-only"}},
                "reviewMarker": "OLD_REVIEW", "verdict": "OLD_PREPARED",
            }
            before = json.dumps(historical, sort_keys=True)
            candidate = {"gitHEAD": "a" * 40, "sourceFileSHA256": {"candidate.swift": "b" * 64},
                         "isAcceptance": False}
            value = builder.successor_manifest(historical, candidate)
            with self.subTest(builder=builder.__name__):
                self.assertEqual(json.dumps(historical, sort_keys=True), before)
                self.assertEqual(value["schema"], 2)
                self.assertEqual(value["candidateSource"], candidate)
                self.assertNotIn("acceptedBases", value)
                self.assertNotIn("sourceBase", value["buildProvenance"])
                self.assertEqual(value["historicalPredecessor"]["role"], "predecessor-only")
                self.assertTrue(value["gates"]["preparationOnly"])
                for key in ["applyGateAccepted", "accepted", "installed", "compiledBindingsAccepted"]:
                    self.assertFalse(value["gates"][key])
                self.assertEqual(value["acceptanceState"], "not-accepted")
                self.assertEqual(value["installationState"], "not-installed")
                if "emergency" in builder.__name__:
                    self.assertNotIn("installedContract", value)
                    self.assertEqual(value["historicalPredecessor"]["receipt"],
                                     {"sha256": "historical-only"})
                    self.assertNotIn("receipt", value["compiledExpectedContract"])
                    self.assertEqual(value["compiledExpectedContract"]["role"],
                                     "compiled-expectations-not-installed-proof")

    def test_build_commands_and_environment_are_scratch_local(self):
        for builder in self.builders():
            with self.subTest(builder=builder.__name__), tempfile.TemporaryDirectory() as raw:
                scratch = Path(raw).resolve()
                binary_dir = scratch / "mock-bin"
                binary_dir.mkdir()
                for name in ["aid-admin-apply", "aid-admin-bootstrap"]:
                    (binary_dir / name).write_bytes(b"fixture-not-executable")
                calls = []

                def command(argv, **kwargs):
                    calls.append((argv, kwargs))
                    if "-o" in argv:
                        Path(argv[argv.index("-o") + 1]).write_bytes(b"fixture-not-executable")
                    return SimpleNamespace(returncode=0,
                        stdout=str(binary_dir) + "\n" if "--show-bin-path" in argv else "")

                with patch.object(builder.subprocess, "run", side_effect=command):
                    if "emergency" in builder.__name__:
                        builder.build(scratch / "candidate", scratch / "cache")
                    else:
                        builder.clean_build(scratch)
                self.assertTrue(calls)
                if "install" in builder.__name__:
                    build_calls = [argv for argv, _ in calls if "--show-bin-path" not in argv]
                    self.assertEqual([argv[argv.index("--product") + 1] for argv in build_calls],
                                     ["aid-admin-apply", "aid-admin-bootstrap"])
                    self.assertFalse(any("Emergency" in path for path in builder.SOURCE_FILES))
                    self.assertNotIn("Sources/AidAdmin/main.swift", builder.SOURCE_FILES)
                for argv, kwargs in calls:
                    self.assertIn("-module-cache-path", argv)
                    if argv[0].endswith("/swift"):
                        self.assertIn("--disable-sandbox", argv)
                    for key in ["HOME", "TMPDIR", "XDG_CACHE_HOME", "CLANG_MODULE_CACHE_PATH",
                                "SWIFT_MODULECACHE_PATH", "SWIFTPM_MODULECACHE_OVERRIDE",
                                "SWIFTPM_CUSTOM_CACHE_PATH"]:
                        self.assertTrue(Path(kwargs["env"][key]).is_relative_to(scratch), key)

    def test_mocked_successor_bundle_records_actual_candidate_and_output(self):
        for builder in self.builders():
            with self.subTest(builder=builder.__name__), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                source = root / "candidate.swift"
                source.write_text("fixture source\n")
                expected_source_hash = builder.digest(source)
                policy = root / "policy.json"
                policy.write_text("{}\n")
                template = root / "sudoers-template"
                template.write_text("@@AGENT_OWNER@@ ALL=(root) NOPASSWD: /fixed/broker\n")
                output = root / "new-successor"

                def run(argv, **kwargs):
                    if "rev-parse" in argv:
                        return "c" * 40 + "\n"
                    if "--version" in argv:
                        return "fixture Swift version\n"
                    raise AssertionError("unexpected command: " + str(argv))

                def clean_build(scratch):
                    scratch = Path(scratch)
                    a, b = scratch / "broker", scratch / "bootstrap"
                    a.write_bytes(b"mock-broker-not-executable")
                    b.write_bytes(b"mock-bootstrap-not-executable")
                    return a, b

                def build(path, cache_root):
                    Path(path).write_bytes(b"mock-emergency-not-executable")

                with contextlib.ExitStack() as stack:
                    for name, value in [("ROOT", root), ("run", run), ("behavior", lambda *a: []),
                                        ("architecture", lambda *a: "arm64-darwin")]:
                        stack.enter_context(patch.object(builder, name, value))
                    stack.enter_context(patch.object(builder.sys, "argv", ["builder", "--successor", "--output", str(output)]))
                    stack.enter_context(patch.object(builder.subprocess, "run", side_effect=AssertionError("native execution forbidden")))
                    if "emergency" in builder.__name__:
                        stack.enter_context(patch.object(builder, "SOURCES", ("candidate.swift",)))
                        stack.enter_context(patch.object(builder, "build", build))
                    else:
                        stack.enter_context(patch.object(builder, "SOURCE_FILES", ("candidate.swift",)))
                        stack.enter_context(patch.object(builder, "APPLY_POLICY", policy))
                        stack.enter_context(patch.object(builder, "TEMPLATE", template))
                        stack.enter_context(patch.object(builder, "clean_build", clean_build))
                        stack.enter_context(patch.object(builder.pwd, "getpwuid", return_value=SimpleNamespace(pw_name="fixtureowner")))
                    stdout = io.StringIO()
                    with contextlib.redirect_stdout(stdout):
                        builder.main()
                    drift_output = root / "refused-source-drift"

                    def drift_build(*args):
                        result = build(*args) if "emergency" in builder.__name__ else clean_build(*args)
                        source.write_text("changed during mocked build\n")
                        return result

                    build_name = "build" if "emergency" in builder.__name__ else "clean_build"
                    with patch.object(builder, build_name, drift_build), patch.object(
                            builder.sys, "argv", ["builder", "--successor", "--output", str(drift_output)]):
                        with self.assertRaisesRegex(RuntimeError, "candidate_source_"):
                            builder.main()
                    self.assertFalse(drift_output.exists(), "source drift published an output")
                report = json.loads(stdout.getvalue())
                self.assertEqual(report["output"], str(output))
                review = json.loads((output / "review-manifest.json").read_text())
                self.assertEqual(review["candidateSource"]["gitHEAD"], "c" * 40)
                self.assertEqual(review["candidateSource"]["sourceFileSHA256"]["candidate.swift"], expected_source_hash)
                self.assertFalse(review["gates"]["applyGateAccepted"])
                if "install" in builder.__name__:
                    inputs = json.loads((output / "install-inputs.json").read_text())
                    self.assertEqual(inputs["schema"], 1)
                    self.assertEqual(inputs["artifactSet"], "phase4-aid-admin-install-bundle-v1")
                    launcher = (output / "launch-owner-authenticated-install.zsh").read_text()
                    self.assertIn("exec /usr/bin/sudo -k", launcher)
                    self.assertFalse(review["futureLauncher"]["executionAuthorized"])


if __name__ == "__main__":
    unittest.main()
