"""Actual held-scope caller and root wiring; fake filesystem/runtime/transport.

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
import socket
import threading
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

SOURCE = (ROOT / "evidence/phase-5/current-quarantine-capability-root-adapter.txt").read_text()
BINDINGS = next(ast.literal_eval(n.value) for n in ast.parse(SOURCE).body
                if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                and n.targets[0].id == "bindings")
HOME = "/Users/synthetic-owner"
IDS = ("quarantine-profile",)
PROFILE = (ROOT / "codex/quarantine.config.toml").read_bytes()
WORKSPACE = HOME + "/AIDev/quarantine/phase5-quarantine-task." + "a" * 12


class ExitBoundary(BaseException):
    pass


class OuterTests(unittest.TestCase):
    def run_case(self, case):
        calls = {key: 0 for key in ("hash", "load", "work", "exit", "verify", "close")}
        namespace, stream, pins, scopes, errors = {}, io.StringIO(), [], [], []
        fixtures, listeners = [], []
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
                self.images = {"quarantine-profile": N(data=PROFILE)}
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

        class Fixture:
            workspace, profile_home = WORKSPACE, WORKSPACE + "/profile-home"
            fixture_paths = {leaf: WORKSPACE + "/" + leaf for leaf in Q.SECRET_LEAVES}
            fixture_paths.update(visible=WORKSPACE + "/visible.txt", outside=HOME + "/AIDev/scratch/outside.txt")
            def __init__(self):
                self.closed = False
            def verify(self):
                require(not self.closed)
                if case == "fixture-verify" and calls["work"] >= 1:
                    raise ValueError("private fixture drift")
                return True
            def close(self):
                require(not self.closed)
                self.closed = True
                if case == "fixture-close":
                    raise ValueError("private fixture close")
        paths, backend = N(DarwinEnvelope=lambda: "envelope"), N()
        def allocate(home, uid, leaf, profile, **kwargs):
            require((home, uid, leaf, profile) ==
                    (HOME, 501, "phase5-quarantine-task." + "a" * 12, PROFILE))
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
        class Listener:
            def __init__(self, **kwargs):
                require(kwargs == dict(socket_api=socket, thread_factory=threading.Thread, clock=__import__("time").monotonic))
                self.count = 0
                self.settled = False
                self.stop_count = 0
                listeners.append(self)
            def start(self):
                if case == "listener-start":
                    raise ValueError("private start")
                return 43123
            def health(self):
                require(not self.settled)
                return self.count
            def stop(self):
                self.stop_count += 1
                require(self.stop_count == 1)
                if case == "listener-unknown":
                    error = ValueError("private settlement")
                    error.settlement_failed = True
                    raise error
                self.settled = True
                if case == "listener-start":
                    raise ValueError("private earlier start")
                return True
        L = N(LoopbackProbe=Listener)
        def command(value, budget, maximum, **kwargs):
            calls["work"] += 1
            require(maximum == 8 and kwargs["admit_launch"](value) is True)
            require(kwargs["catalog"] is catalog and kwargs["process_factory"] is catalog.subprocess.Popen)
            if value.name == "git-precondition":
                require(value.argv == ("/usr/bin/git", "-c", "core.hooksPath=/dev/null",
                    "-C", WORKSPACE, "rev-parse", "--is-inside-work-tree", "--show-toplevel"))
                return N(returncode=0, stdout=(("false" if case == "git-invalid" else "true") +
                         "\n" + WORKSPACE + "\n").encode(), stderr=b"")
            if case in ("transport", "interrupt", "transport-settled"):
                error = KeyboardInterrupt("private interrupted") if case == "interrupt" else ValueError("private transport")
                error.private_owner = object() if case != "transport-settled" else None
                error.child_settled = True if case == "transport-settled" else None
                errors.append(error)
                raise error
            rc, out, err = 0, b"", b""
            if value.name == "workspace-read":
                out = b"visible\n"
                if case == "cli-error":
                    rc, out, err = 2, b"", b"private CLI error"
            elif value.name == "outside-read" or value.name.startswith("secret-"):
                rc, err = 1, ("cat: " + value.argv[-1] + ": Operation not permitted\n").encode()
                if case == "missing-file":
                    err = ("cat: " + value.argv[-1] + ": No such file or directory\n").encode()
            elif value.name == "environment":
                out = b"PATH=/usr/bin:/bin:/usr/sbin:/sbin\n"
            elif value.name == "aid-admin":
                rc = 1
            elif value.name == "loopback-direct":
                listeners[0].count += 1
                out = b"phase5-loopback\n"
                if case == "final-loopback-failure" and listeners[0].count == 2:
                    rc, out, err = 7, b"", b"curl: (7) Failed to connect\n"
            else:
                require(value.name == "loopback-sandbox")
                rc, err = 7, (b"* Immediate connect fail for 127.0.0.1: Operation not permitted\n"
                              b"curl: (7) Failed to connect to 127.0.0.1 port 43123 after 0 ms: Couldn't connect to server\n")
                if case == "network-leak":
                    listeners[0].count += 1
                    rc, out, err = 0, b"phase5-loopback\n", b""
            return N(returncode=rc, stdout=out, stderr=err)
        O = N(command=command)
        fake_lib = N(phase5_current_probe=P, phase5_current_quarantine=Q,
                     phase5_quarantine_fixture=F, phase5_loopback_probe=L,
                     phase5_probe_process=O, phase5_runtime_paths=paths, phase5_runtime_backend=backend)

        def bootstrap(loader, fullname=None):
            calls["load"] += 1
            if case == "loader":
                raise ValueError("private loader")
            if loader.name == "root_quarantine_readiness":
                require(not pins)
                return R
            raise AssertionError("unexpected loader")
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
                exec(compile(SOURCE, "root-quarantine-adapter-pure", "exec"), namespace)
            except ExitBoundary:
                pass
        result = json.loads(stream.getvalue())
        self.assertEqual(calls["exit"], int(case == "pass"))
        self.assertEqual(result["outerSessionRetained"], case != "pass")
        self.assertTrue(all(held.closed for held in pins + scopes))
        self.assertEqual(calls["close"], len(pins))
        self.assertEqual(result["nativeLaunchAttempts"], calls["work"])
        self.assertTrue(all(owner.stop_count == 1 for owner in listeners))
        self.assertNotIn("private response", stream.getvalue())
        self.assertNotIn(HOME, stream.getvalue())
        self.assertEqual(result["modelRequests"], 0)
        self.assertIs(result["phase5Accepted"], False)
        self.assertIs(result["phase6Allowed"], False)
        self.assertIs(result["integrationAbsenceProven"], False)
        if case == "pass":
            self.assertEqual(result["outcome"]["verdict"], "completed")
            self.assertEqual((result["casesPassed"], calls["work"]), (12, 14))
            self.assertEqual(listeners[0].count, 2)
            self.assertTrue(fixtures[0].closed and listeners[0].settled)
        if case in ("transport", "interrupt", "listener-unknown"):
            self.assertEqual(result["processSettlement"], "unknown")
        if case == "interrupt":
            self.assertIs(namespace["caught"], errors[0])
        if case in ("transport-settled", "missing-file", "cli-error", "network-leak", "git-invalid"):
            self.assertEqual(result["processSettlement"], "confirmed")
            self.assertIsNotNone(namespace["work_error"])
            self.assertTrue(fixtures[0].closed)
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
        if case in ("missing-file", "cli-error", "network-leak", "final-loopback-failure"):
            self.assertIsNotNone(result["failureCase"])

    def test_outer_boundaries_with_actual_scope_caller(self):
        for case in ("pass", "pre-drift", "post-drift", "acquisition", "loader", "guard",
                     "close", "transport", "interrupt", "transport-settled", "git-invalid",
                     "fixture-allocation", "fixture-verify", "fixture-close", "listener-start",
                     "listener-unknown", "cli-error", "missing-file", "network-leak",
                     "final-loopback-failure"):
            with self.subTest(case=case):
                self.run_case(case)


if __name__ == "__main__":
    unittest.main()
