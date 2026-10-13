"""Fake-only installed-launcher root wiring; no native process, model or filesystem."""

import ast
from contextlib import ExitStack, redirect_stdout
import hashlib
import importlib.machinery
import io
import json
import os
from pathlib import Path
import pwd
import secrets
import signal
import sys
from types import SimpleNamespace as N
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import phase5_current_probe as P
from lib import phase5_current_quarantine as Q

SOURCE = (ROOT / "evidence/phase-5/current-quarantine-launcher-root-adapter.txt").read_text()
TREE = ast.parse(SOURCE)
BINDINGS = next(ast.literal_eval(node.value) for node in TREE.body
                if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "bindings")
CLOSURE = next(tuple(ast.literal_eval(node.value.args[0])) for node in TREE.body
               if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
               and node.targets[0].id == "source_closure")
HOME = "/Users/synthetic-owner"
WORKSPACE = HOME + "/AIDev/quarantine/phase5-quarantine-task." + "a" * 12
PROFILE = (ROOT / "codex/quarantine.config.toml").read_bytes()
LAUNCHER = (ROOT / "bin/codex-quarantine").read_bytes()
GOOD = json.dumps({"schema": 1, "userMcpToolsVisible": False,
                   "userPluginToolsVisible": False,
                   "userAppToolsVisible": False}).encode()


class ExitBoundary(BaseException):
    pass


class OuterTests(unittest.TestCase):
    def run_case(self, case):
        calls = {key: 0 for key in ("hash", "load", "command", "model", "exit", "verify", "close")}
        namespace, stream, pins, scopes, errors = {}, io.StringIO(), [], [], []
        fixtures = []
        real_digest = hashlib.sha256

        def require(value):
            if value is not True:
                raise ValueError("private requirement")

        class Budget:
            def __init__(self, seconds):
                require(seconds == 300)
            def check(self):
                return None

        class Pin:
            def __init__(self, path, home, uid, budget, keep):
                require((home, uid, keep) == (HOME, 501, False))
                if case == "acquisition":
                    raise ValueError("private acquisition")
                self.digest = BINDINGS[str(path.relative_to(ROOT))]
                self.closed = False
                pins.append(self)
            def verify(self):
                calls["verify"] += 1
                require(not self.closed)
                if case == "guard" and namespace.get("invoked") and not errors:
                    error = ValueError("private guard")
                    errors.append(error)
                    raise error
                return True
            def close(self):
                require(not self.closed)
                self.closed = True
                calls["close"] += 1
                if case == "close" and calls["close"] == 1:
                    raise ValueError("private close")

        class Held:
            def __init__(self, *args):
                self.closed = False
                self.pending_owner = None
                profile = PROFILE + (b"drift" if case == "profile-image-drift" else b"")
                launcher = LAUNCHER + (b"drift" if case == "launcher-image-drift" else b"")
                self.images = {"quarantine-profile": N(data=profile),
                               "quarantine-launcher": N(data=launcher)}
                self.bindings = {}
                self.receipt = self.physical_before = self.physical_after = {}
                self.metadata_empty = {}
                scopes.append(self)
            def collect(self):
                return None
            def verify(self):
                require(not self.closed)
                return True
            def final_attest(self):
                return self.verify()
            def close(self):
                require(not self.closed)
                self.closed = True

        def ready(*args, **kwargs):
            require(kwargs["recheck_dependencies"]() is True)
            require(kwargs["admit_current"]({}) is True)
            return {"verdict": "ready"}

        catalog = N(subprocess=N(Popen=object()))
        R = N(Budget=Budget, SourceFile=Pin, NativeRuntime=Held,
              targets=N(observe=Held), legacy=N(observe=Held), catalog=catalog,
              SOURCE_CLOSURE=("bin/phase5-current-readiness",), require=require,
              capture=N(readiness=ready), admit_current_round=lambda *a, **k: k["recheck_dependencies"]())
        def earliest(first, later):
            if isinstance(first, (KeyboardInterrupt, SystemExit)):
                return first
            return later if first is None or isinstance(later, (KeyboardInterrupt, SystemExit)) else first
        R.earliest = earliest

        class Fixture:
            workspace = WORKSPACE
            def __init__(self):
                self.closed = False
            def verify(self):
                require(not self.closed)
                if case == "fixture-verify" and calls["command"]:
                    raise ValueError("private fixture drift")
                return True
            def close(self):
                require(not self.closed)
                self.closed = True
                if case == "fixture-close":
                    raise ValueError("private fixture close")
                if case == "fixture-close-interrupt":
                    error = KeyboardInterrupt("private fixture close interruption")
                    errors.append(error)
                    raise error
        paths, backend = N(DarwinEnvelope=lambda: "envelope"), N()
        def allocate(home, uid, leaf, profile, **kwargs):
            require((home, uid, leaf) == (HOME, 501, "phase5-quarantine-task." + "a" * 12))
            require(profile == PROFILE or case == "profile-image-drift")
            require(kwargs["admit_sources"]() is True and kwargs["paths"] is paths
                    and kwargs["backend"] is backend and kwargs["syscalls"] is os
                    and kwargs["platform"] == "envelope")
            owner = Fixture()
            fixtures.append(owner)
            if case == "fixture-allocation":
                error = ValueError("private allocation")
                error.private_owner = owner
                errors.append(error)
                raise error
            return owner
        F = N(allocate=allocate)

        def command(value, budget, maximum, **kwargs):
            calls["command"] += 1
            require(kwargs["catalog"] is catalog and kwargs["process_factory"] is catalog.subprocess.Popen)
            require(kwargs["admit_launch"](value) is True)
            if value.name == "git-precondition":
                require(maximum == 8 and calls["model"] == 0)
                require(value.argv == ("/usr/bin/git", "-c", "core.hooksPath=/dev/null",
                    "-C", WORKSPACE, "rev-parse", "--is-inside-work-tree", "--show-toplevel"))
                if case == "transport-git":
                    error = ValueError("private git transport")
                    error.private_owner = object()
                    errors.append(error)
                    raise error
                stdout = (("false" if case == "git-invalid" else "true") + "\n" + WORKSPACE + "\n").encode()
                stderr = b"private git diagnostic\n" if case == "git-stderr" else b""
                return N(returncode=0, stdout=stdout, stderr=stderr)
            calls["model"] += 1
            require(calls["model"] == 1 and maximum == 180 and value.name == "model-visibility")
            require(value.argv == (HOME + "/AIDev/bin/codex-quarantine", "--root", WORKSPACE,
                                   "--", Q.MODEL_PROMPT))
            require(value.cwd == WORKSPACE and value.environment == ())
            if case in ("transport-model", "interrupt-model", "transport-settled-model"):
                error = KeyboardInterrupt("private interrupted") if case == "interrupt-model" else ValueError("private model transport")
                error.private_owner = object() if case != "transport-settled-model" else None
                error.child_settled = True if case == "transport-settled-model" else None
                errors.append(error)
                raise error
            output = b"{}" if case == "invalid-output" else GOOD
            if case == "visible-integration":
                visible = json.loads(GOOD)
                visible["userMcpToolsVisible"] = True
                output = json.dumps(visible).encode()
            stderr = (b"ERROR mcp server failed to initialize private-name\n"
                      if case == "startup-contradiction" else b"private progress\n")
            return N(returncode=1 if case == "model-nonzero" else 0,
                     stdout=output, stderr=stderr)
        O = N(command=command, MAX_BYTES=4 * 1024 * 1024)
        fake_lib = N(phase5_current_probe=P, phase5_probe_process=O,
                     phase5_current_quarantine=Q, phase5_quarantine_fixture=F,
                     phase5_runtime_paths=paths, phase5_runtime_backend=backend)

        def bootstrap(loader, fullname=None):
            calls["load"] += 1
            if case == "loader":
                raise ValueError("private loader")
            require(loader.name == "root_quarantine_launcher_readiness" and not pins)
            return R
        def digest(data):
            try:
                path = Path(data.decode())
                relative = str(path.relative_to(ROOT))
            except (ValueError, UnicodeError):
                return real_digest(data)
            if relative not in BINDINGS:
                return real_digest(data)
            calls["hash"] += 1
            wrong = (case == "pre-drift" and calls["hash"] == 1 or
                     case == "post-drift" and calls["hash"] == len(BINDINGS) + 1)
            return N(hexdigest=lambda: "f" * 64 if wrong else BINDINGS[relative])
        def exit0(code):
            require(code == 0)
            calls["exit"] += 1
            raise ExitBoundary()

        with ExitStack() as stack:
            stack.enter_context(patch.object(Path, "cwd", return_value=ROOT))
            stack.enter_context(patch.object(Path, "read_bytes", lambda path: str(path).encode()))
            stack.enter_context(patch.object(hashlib, "sha256", side_effect=digest))
            stack.enter_context(patch.object(importlib.machinery.SourceFileLoader, "load_module", bootstrap))
            stack.enter_context(patch.dict(sys.modules, {"lib": fake_lib}))
            stack.enter_context(patch.object(os, "getuid", return_value=501))
            stack.enter_context(patch.object(pwd, "getpwuid", return_value=N(pw_dir=HOME)))
            stack.enter_context(patch.object(secrets, "token_hex", return_value="a" * 12))
            stack.enter_context(patch.object(signal, "signal"))
            stack.enter_context(patch.object(signal, "setitimer"))
            stack.enter_context(patch.object(os, "_exit", side_effect=exit0))
            stack.enter_context(redirect_stdout(stream))
            try:
                exec(compile(SOURCE, "root-quarantine-launcher-adapter-pure", "exec"), namespace)
            except ExitBoundary:
                pass
        result = json.loads(stream.getvalue())
        self.assertEqual(len(BINDINGS), 31)
        self.assertEqual(len(CLOSURE), 23)
        self.assertNotIn("lib/phase5_loopback_probe.py", CLOSURE)
        self.assertEqual(calls["exit"], 0)
        self.assertIs(result["outerSessionRetained"], True)
        self.assertIs(result["startupReviewRequired"], True)
        self.assertIs(result["startupProgressInspected"], False)
        self.assertIsNone(result["startupContradictionDetected"])
        self.assertTrue(all(held.closed for held in pins + scopes))
        self.assertEqual(calls["close"], len(pins))
        self.assertLessEqual(calls["model"], 1)
        self.assertEqual(result["logicalTaskLaunchAttempts"], calls["model"])
        self.assertEqual(result["maximumLogicalTaskLaunches"], 1)
        self.assertIsNone(result["providerRequestCount"])
        for secret in ("private progress", "private git diagnostic", "private-name",
                       "private acquisition", "private guard"):
            self.assertNotIn(secret, stream.getvalue())
        self.assertNotIn(HOME, stream.getvalue())
        self.assertIs(result["supportingEvidenceOnly"], True)
        self.assertIs(result["integrationAbsenceProven"], False)
        self.assertIs(result["authMaterialCopied"], False)
        self.assertIs(result["launcherParentEnvironmentEmpty"], True)
        self.assertIs(result["phase5Accepted"], False)
        self.assertIs(result["phase6Allowed"], False)
        if case == "pass":
            self.assertEqual(result["outcome"]["verdict"], "completed")
            self.assertEqual((calls["command"], calls["model"]), (2, 1))
            self.assertTrue(result["gitFixtureValidated"] and result["modelOutputValidated"])
            self.assertIs(result["modelSupportObserved"], True)
            self.assertTrue(fixtures[0].closed)
        if case in ("transport-git", "transport-model", "interrupt-model"):
            self.assertEqual(result["processSettlement"], "unknown")
        if case in ("interrupt-model", "fixture-close-interrupt"):
            self.assertIs(namespace["caught"], errors[0])
        if case in ("transport-settled-model", "git-invalid", "git-stderr", "invalid-output",
                    "model-nonzero", "visible-integration", "launcher-image-drift",
                    "profile-image-drift"):
            self.assertEqual(result["processSettlement"], "confirmed")
            self.assertIsNotNone(namespace["work_error"])
            self.assertTrue(fixtures[0].closed)
        if case == "startup-contradiction":
            self.assertTrue(result["modelOutputValidated"])
            self.assertIs(result["privateContextRetainedInRAM"], True)
            self.assertIn(b"ERROR mcp server", namespace["private_model"].stderr)
            self.assertIs(result["startupReviewRequired"], True)
        if case in ("acquisition", "close"):
            self.assertIs(result["sourceHandlesClosed"], False)
        if case == "fixture-allocation":
            self.assertIs(namespace["work_error"], errors[0])
            self.assertIs(errors[0].private_owner, fixtures[0])
            self.assertIsNone(result["benignFixturesRetained"])
        elif fixtures:
            self.assertIs(result["benignFixturesRetained"], True)
        else:
            self.assertIs(result["benignFixturesRetained"], False)

    def test_outer_boundaries_with_actual_scope_caller(self):
        for case in ("pass", "pre-drift", "post-drift", "acquisition", "loader", "guard",
                     "close", "fixture-allocation", "fixture-verify", "fixture-close", "fixture-close-interrupt",
                     "git-invalid", "git-stderr", "transport-git", "transport-model",
                     "interrupt-model", "transport-settled-model", "invalid-output",
                     "model-nonzero", "visible-integration", "startup-contradiction", "launcher-image-drift",
                     "profile-image-drift"):
            with self.subTest(case=case):
                self.run_case(case)


if __name__ == "__main__":
    unittest.main()
