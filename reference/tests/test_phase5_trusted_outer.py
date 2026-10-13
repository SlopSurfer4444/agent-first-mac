"""Actual held-scope caller and trusted wiring; fake filesystem/runtime/transport.

Never executes the text with native sources or dependencies. Leaf contracts and
catalog pipe ownership have their own connected tests; this tests composition,
bootstrap ordering, redacted publication and retention at the outer boundary.
"""

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

SOURCE = (ROOT / "evidence/phase-5/current-trusted-root-adapter.txt").read_text()
BINDINGS = next(ast.literal_eval(n.value) for n in ast.parse(SOURCE).body
                if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                and n.targets[0].id == "bindings")
HOME = "/Users/synthetic-owner"
IDS = ("hooks-definition", "hook-router", "skill-definition", "skill-metadata")


class ExitBoundary(BaseException):
    pass


class OuterTests(unittest.TestCase):
    def run_case(self, case):
        calls = {key: 0 for key in ("hash", "load", "work", "exit", "verify", "close")}
        namespace, stream, pins, scopes, errors = {}, io.StringIO(), [], [], []
        file_owners = []
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
                self.hook_records = {"slot": "digest"}
                self.images = {key: N(data=b"source") for key in IDS}
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
            def data(self, path):
                return b"source"

        def ready(*args, **kwargs):
            require(kwargs["recheck_dependencies"]() is True)
            require(kwargs["admit_current"]({}) is True)
            return {"verdict": "ready"}

        catalog = N(subprocess=N(Popen=object()))
        R = N(Budget=Budget, SourceFile=Pin, NativeRuntime=Held,
              targets=N(observe=Held), legacy=N(observe=Held), catalog=catalog,
              SOURCE_CLOSURE=("bin/phase5-current-readiness",),
              MANAGED={key: key for key in IDS}, require=require,
              capture=N(readiness=ready), admit_current_round=lambda *a, **k: k["recheck_dependencies"]())
        def earliest(first, later):
            if isinstance(first, (KeyboardInterrupt, SystemExit)):
                return first
            return later if first is None or isinstance(later, (KeyboardInterrupt, SystemExit)) else first
        R.earliest = earliest

        launch = N(argv=("fixed", "exec"), cwd=HOME + "/AIDev/control", environment={})
        def validation(*args, **kwargs):
            require(args[-1] == b"private result bytes")
            if case == "validation":
                raise ValueError("private response")
            return {"verdict": "schema-valid"}
        T = N(task_material=lambda *a: {"schema": {"type": "object"}},
              exec_launch=lambda *a, **k: launch,
              exec_command_contract=lambda definitions, value, **k: value is launch,
              validate_task_output=validation)
        def command(value, budget, maximum, **kwargs):
            calls["work"] += 1
            require(maximum == 180 and value is launch and kwargs["admit_launch"](value) is True)
            require(kwargs["catalog"] is catalog and kwargs["process_factory"] is catalog.subprocess.Popen)
            if case in ("transport", "interrupt", "transport-settled"):
                error = KeyboardInterrupt("private interrupted") if case == "interrupt" else ValueError("private transport")
                error.private_owner = object() if case != "transport-settled" else None
                error.child_settled = True if case == "transport-settled" else None
                errors.append(error)
                raise error
            return N(returncode=1 if case == "nonzero" else 0, stdout=b"private events", stderr=b"")
        O = N(command=command)
        class Files:
            def __init__(self):
                self.schema_path, self.result_path = HOME + "/private/schema.json", HOME + "/private/result.json"
                self.closed = self.removed = False
            def verify_initial(self):
                require(not self.closed and calls["work"] == 0)
                return True
            def result(self, *, child_settled):
                require(child_settled is True and calls["work"] == 1)
                if case == "result":
                    raise ValueError("private result drift")
                return N(data=b"private result bytes")
            def cleanup(self, result, *, child_settled):
                require(child_settled is True and result.data == b"private result bytes" and not self.removed)
                if case == "cleanup":
                    raise ValueError("private cleanup")
                self.removed = True
                self.close()
                return {"filesRemoved": 2, "directoryRemoved": True, "handlesClosed": True}
            def close(self):
                require(not self.closed and self.removed)
                self.closed = True
                if case == "files-close":
                    raise ValueError("private file close")
        paths, backend = N(DarwinEnvelope=lambda: "envelope"), N()
        def allocate(home, uid, leaf, schema, **kwargs):
            require(home == HOME and uid == 501 and leaf == "phase5-trusted-task." + "a" * 12)
            require(json.loads(schema) == {"type": "object"} and kwargs["admit_sources"]() is True)
            require(kwargs["paths"] is paths and kwargs["backend"] is backend
                    and kwargs["syscalls"] is os and kwargs["platform"] == "envelope")
            owner = Files()
            file_owners.append(owner)
            if case == "files-allocation":
                error = ValueError("private allocation")
                error.private_owner = owner
                errors.append(error)
                raise error
            return owner
        F = N(allocate=allocate)
        fake_lib = N(phase5_current_probe=P, phase5_current_trusted=T, phase5_probe_process=O,
                     phase5_trusted_files=F, phase5_runtime_paths=paths, phase5_runtime_backend=backend)

        def bootstrap(loader, fullname=None):
            calls["load"] += 1
            if case == "loader":
                raise ValueError("private loader")
            if loader.name == "root_trusted_readiness":
                require(not pins)
                return R
            require(loader.name == "root_trusted_legacy_definitions")
            require(len(pins) == len(BINDINGS) and calls["verify"] >= len(BINDINGS))
            return N()
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
            stack.enter_context(patch.object(secrets, "token_hex", return_value="a" * 12))
            stack.enter_context(patch.object(pwd, "getpwuid", return_value=N(pw_dir=HOME)))
            stack.enter_context(patch.object(signal, "signal"))
            stack.enter_context(patch.object(signal, "setitimer"))
            stack.enter_context(patch.object(os, "_exit", side_effect=exit0))
            stack.enter_context(redirect_stdout(stream))
            try:
                exec(compile(SOURCE, "root-trusted-adapter-pure", "exec"), namespace)
            except ExitBoundary:
                pass
        result = json.loads(stream.getvalue())
        self.assertEqual(calls["exit"], int(case == "pass"))
        self.assertEqual(result["outerSessionRetained"], case != "pass")
        launched = case in ("pass", "post-drift", "close", "validation", "nonzero", "transport",
                            "interrupt", "transport-settled", "result", "cleanup", "files-close")
        self.assertEqual(calls["work"], int(launched))
        self.assertIs(result["logicalTaskLaunchAttempted"], launched)
        self.assertEqual(result["maximumLogicalTaskLaunches"], 1)
        removed = case in ("pass", "post-drift", "close")
        self.assertIs(result["taskFilesRemoved"], removed)
        self.assertEqual(sum(owner.removed for owner in file_owners), int(removed or case == "files-close"))
        if case in ("validation", "nonzero", "result", "cleanup", "transport-settled"):
            self.assertEqual(result["processSettlement"], "confirmed")
            self.assertFalse(file_owners[0].closed)
        if case == "files-allocation":
            self.assertIs(namespace["task_error"], errors[0])
            self.assertIs(namespace["task_error"].private_owner, file_owners[0])
        self.assertTrue(all(held.closed for held in pins + scopes))
        self.assertEqual(calls["close"], len(pins))
        self.assertNotIn("private response", stream.getvalue())
        self.assertNotIn(HOME, stream.getvalue())
        self.assertIs(result["hookExecutionProven"], False)
        self.assertIs(result["skillUseProven"], False)
        self.assertIs(result["phase5Accepted"], False)
        self.assertIs(result["phase6Allowed"], False)
        if case == "pass":
            self.assertEqual(result["outcome"]["verdict"], "completed")
        if case in ("transport", "interrupt"):
            self.assertEqual(result["processSettlement"], "unknown")
        if case == "interrupt":
            self.assertIs(namespace["caught"], errors[0])
        if case == "validation":
            self.assertIsNotNone(namespace["task_error"])
            self.assertEqual(result["processSettlement"], "confirmed")
        if case in ("acquisition", "close"):
            self.assertIs(result["sourceHandlesClosed"], False)

    def test_outer_boundaries_with_actual_scope_caller(self):
        for case in ("pass", "pre-drift", "post-drift", "acquisition", "loader", "guard",
                     "close", "validation", "nonzero", "transport", "interrupt",
                     "transport-settled", "files-allocation", "result", "cleanup", "files-close"):
            with self.subTest(case=case):
                self.run_case(case)


if __name__ == "__main__":
    unittest.main()
