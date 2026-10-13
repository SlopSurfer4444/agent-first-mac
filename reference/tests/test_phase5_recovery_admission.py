"""Pure fake syscalls with actual SourceFile and a connected fake recovery seam."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import traceback
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import phase5_recovery_admission as admission


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


F = load("admission_recovery_fakes", "tests/test_phase5_current_recovery.py")
C, R, HOME = F.C, F.C.R, F.A.HOME


class Fixture:
    def __init__(self):
        self.fs, _ = F.A.SourceFileTests().fixture()
        self.root = HOME + "/source"
        self.closure, self.managed = C.SOURCE_CLOSURE, tuple(R.MANAGED.values())
        self.hashes, self.held, self.events = {}, [], []
        self.budget = R.Budget(clock=lambda: 0)
        for relative in sorted(set(self.closure) | set(self.managed) | {admission.SELF, admission.CONTRACT}):
            path = self.root + "/" + relative
            parts = path.split("/")
            for index in range(2, len(parts)):
                parent = "/".join(parts[:index])
                if parent not in self.fs.nodes:
                    self.fs.add(parent, directory=True, mode=0o755)
            raw = ("public fake source: " + relative).encode()
            self.fs.add(path, raw)
            self.hashes[relative] = hashlib.sha256(raw).hexdigest()
        self.report = C.public("completed", stage="final-recheck", state="current", captured=True)
        self.caller = SimpleNamespace(SOURCE_CLOSURE=self.closure,
            R=SimpleNamespace(MANAGED=R.MANAGED), RecoveryError=C.RecoveryError, connected=self.connected)
        self.effect = self.load_effect = None

    def source(self, relative):
        self.events.append(("source", relative))
        value = R.SourceFile(self.root + "/" + relative, HOME, 501, self.budget, syscalls=self.fs)
        self.held.append(value)
        return value

    def loader(self):
        self.events.append(("load", None))
        if self.load_effect:
            self.load_effect()
        return self.caller

    def connected(self, home, uid, **kwargs):
        self.events.append(("operation", None))
        assert (home, uid, kwargs["operation"], kwargs["run_id"]) == (HOME, 501, "capture-noop", F.RUN)
        assert kwargs["recheck_source_closure"](self.closure) is True
        if self.effect:
            self.effect(kwargs)
        return self.report

    def invoke(self, **overrides):
        kwargs = dict(source_hashes=self.hashes, source_closure=self.closure, managed_sources=self.managed,
            source_factory=self.source, caller_loader=self.loader, home=HOME, uid=501,
            operation="capture-noop", run_id=F.RUN, runtime_factory=lambda *_: None, budget=self.budget)
        kwargs.update(overrides)
        with patch.object(R.catalog.subprocess, "Popen", side_effect=AssertionError("no native process")):
            return admission.run(**kwargs)


class AdmissionTests(unittest.TestCase):
    def error(self, fixture, **kwargs):
        with self.assertRaises(admission.AdmissionError) as raised:
            fixture.invoke(**kwargs)
        self.assertEqual(str(raised.exception), "recovery_admission_required")
        return raised.exception.admission_outcome

    def test_sourcefile_all_31_held_before_loader_and_safe_pass(self):
        f = Fixture()
        original = copy.deepcopy(f.fs.nodes)
        f.load_effect = lambda: self.assertEqual(len(f.fs.handles), 31)
        result = f.invoke()
        self.assertEqual(result.public["verdict"], "completed")
        self.assertTrue(result.public["sourcesUnchanged"] and result.public["sourceHandlesClosed"])
        self.assertTrue(result.public["nativeChildrenSettled"])
        self.assertEqual(f.fs.handles, {})
        self.assertEqual(f.fs.nodes, original)
        self.assertEqual([kind for kind, _ in f.events], ["source"] * 31 + ["load", "operation"])
        self.assertNotIn(HOME, json.dumps(result.public))
        self.assertTrue(all(result.public[key] is False for key in admission.AUTHORITY))

    def test_hash_mismatch_blocks_import_and_closes_acquired_source(self):
        f = Fixture()
        f.hashes[sorted(f.hashes)[1]] = "0" * 64
        result = self.error(f)
        self.assertEqual(len(f.held), 2)
        self.assertFalse(any(kind == "load" for kind, _ in f.events))
        self.assertEqual(f.fs.handles, {})
        self.assertFalse(result.public["operationStarted"])

    def test_missing_extra_or_traversal_source_map_denied_without_factory(self):
        for kind in ("missing", "extra", "traversal"):
            f = Fixture()
            if kind == "missing": f.hashes.pop(admission.SELF)
            elif kind == "extra": f.hashes["secret.txt"] = "0" * 64
            else: f.closure = f.closure + ("../private",)
            self.error(f)
            self.assertEqual(f.events, [])

    def test_no_implicit_factories_or_operation(self):
        for kwargs in ({"source_factory": None}, {"caller_loader": None}, {"runtime_factory": None},
                       {"operation": "resume"}, {"run_id": True}, {"uid": True}):
            f = Fixture()
            self.error(f, **kwargs)
            self.assertEqual(f.events, [])

    def test_same_bytes_new_identity_before_import_denied(self):
        f = Fixture()
        source = f.source
        def changed(relative):
            value = source(relative)
            if len(f.held) == 31:
                path = f.held[0].path
                replacement = dict(f.fs.nodes[path])
                replacement["st_ino"] += 10000
                f.fs.nodes[path] = replacement
            return value
        self.error(f, source_factory=changed)
        self.assertFalse(any(kind == "load" for kind, _ in f.events))
        self.assertEqual(f.fs.handles, {})

    def test_caller_manifest_mismatch_or_loader_drift_prevents_operation(self):
        for kind in ("closure", "managed", "drift"):
            f = Fixture()
            if kind == "closure": f.caller.SOURCE_CLOSURE = f.closure[:-1]
            elif kind == "managed": f.caller.R = SimpleNamespace(MANAGED={})
            else: f.load_effect = lambda: f.fs.nodes[f.held[0].path].update(st_ino=999999)
            self.error(f)
            self.assertFalse(any(kind == "operation" for kind, _ in f.events))
            self.assertEqual(f.fs.handles, {})

    def test_physical_callback_and_final_postcheck_keep_source_identity(self):
        for boundary in ("callback", "postcheck"):
            f = Fixture()
            def effect(kwargs):
                f.fs.nodes[f.held[0].path]["st_ctime_ns"] += 1
                if boundary == "callback": kwargs["recheck_source_closure"](f.closure)
            f.effect = effect
            result = self.error(f)
            self.assertFalse(result.public["sourcesUnchanged"])
            self.assertEqual(result.public["verdict"], "needs-review")
            self.assertEqual(f.fs.handles, {})

    def test_unexpected_operation_failure_without_owner_is_unconfirmed(self):
        f = Fixture()
        original = RuntimeError("private original operation failure")
        def effect(_): raise original
        f.effect = effect
        result = self.error(f)
        self.assertIs(result.primary, original)
        self.assertIs(result.caller_exception, original)
        self.assertIsNone(result.private_owner)
        self.assertFalse(result.public["nativeChildrenSettled"])

    def test_false_settlement_with_no_owner_and_private_context_preserved(self):
        f = Fixture()
        context = C.PrivateSession(F.RUN)
        context.settlement_confirmed = False
        original = C.RecoveryError(C.public("recovery-required", settled=True), context)
        def effect(_): raise original
        f.effect = effect
        result = self.error(f)
        self.assertIs(result.caller_exception, original)
        self.assertIs(result.private_session, context)
        self.assertFalse(result.public["nativeChildrenSettled"])

    def test_known_caller_nonprocess_failure_keeps_confirmed_settlement(self):
        f = Fixture()
        context = C.PrivateSession(F.RUN)
        original = C.RecoveryError(C.public("recovery-required", settled=True), context)
        def effect(_): raise original
        f.effect = effect
        self.assertTrue(self.error(f).public["nativeChildrenSettled"])

    def test_malformed_error_report_does_not_lose_original_or_owner(self):
        f = Fixture()
        context = C.PrivateSession(F.RUN)
        context.pending_owner, context.settlement_confirmed = object(), False
        original = C.RecoveryError({"private": "not public"}, context)
        def effect(_): raise original
        f.effect = effect
        result = self.error(f)
        self.assertIs(result.primary, original)
        self.assertIs(result.private_owner, context.pending_owner)
        self.assertIsNone(result.public["callerReport"])

    def test_report_extra_field_type_or_authority_never_public(self):
        for key, value in (("private", "path"), ("phase6Allowed", True), ("completedStages", True),
                           ("stage", "private path"), ("state", ["private"])):
            f = Fixture()
            f.report[key] = value
            result = self.error(f)
            self.assertIsNone(result.public["callerReport"])
            self.assertFalse(result.public["nativeChildrenSettled"])

    def test_original_interrupt_wins_later_postcheck_and_close_interrupt(self):
        for first, later in ((KeyboardInterrupt("private first"), SystemExit("private later")),
                             (SystemExit("private first"), KeyboardInterrupt("private later"))):
            f = Fixture()
            def effect(_):
                source = f.held[0]
                source.verify = lambda: (_ for _ in ()).throw(later)
                close = source.close
                def interrupted_close(): close(); raise later
                source.close = interrupted_close
                raise first
            f.effect = effect
            with self.assertRaises(type(first)) as raised: f.invoke()
            self.assertIs(raised.exception, first)
            result = first.admission_outcome
            self.assertIs(result.primary, first)
            self.assertIs(result.caller_exception, first)
            self.assertFalse(result.public["nativeChildrenSettled"])
            self.assertFalse(result.public["sourceHandlesClosed"])
            self.assertEqual(f.fs.handles, {})

    def test_source_handle_close_error_attempts_every_owner_once(self):
        f = Fixture()
        closed = []
        def effect(_):
            for source in f.held:
                original = source.close
                def close(source=source, original=original):
                    closed.append(source); original()
                    if source is f.held[-1]: raise OSError("private close")
                source.close = close
        f.effect = effect
        result = self.error(f)
        self.assertEqual(len(closed), 31)
        self.assertEqual(len({id(value) for value in closed}), 31)
        self.assertEqual(f.fs.handles, {})
        self.assertFalse(result.public["sourceHandlesClosed"])
        self.assertEqual(result.public["stage"], "source-close")

    def test_ordinary_caller_error_then_cleanup_interrupt_retains_both(self):
        f = Fixture()
        original, interrupted = RuntimeError("private caller"), KeyboardInterrupt("private close")
        def effect(_):
            close = f.held[0].close
            def failed(): close(); raise interrupted
            f.held[0].close = failed
            raise original
        f.effect = effect
        with self.assertRaises(KeyboardInterrupt) as raised: f.invoke()
        self.assertIs(raised.exception, interrupted)
        self.assertIs(interrupted.admission_outcome.caller_exception, original)
        self.assertIs(interrupted.admission_outcome.primary, interrupted)
        self.assertTrue(interrupted.settlement_failed)
        self.assertEqual(f.fs.handles, {})

    def test_actual_sourcefile_constructor_cleanup_interrupt_is_unconfirmed(self):
        f = Fixture()
        path = f.root + "/" + sorted(f.hashes)[0]
        f.fs.effects[("read", path)] = OSError("private read failure")
        native_close = f.fs.close
        interrupted = KeyboardInterrupt("private constructor close")
        def close(fd):
            selected = f.fs.handles[fd][0] == path
            native_close(fd)
            if selected: raise interrupted
        f.fs.close = close
        with self.assertRaises(KeyboardInterrupt) as raised: f.invoke()
        self.assertIs(raised.exception, interrupted)
        self.assertFalse(interrupted.admission_outcome.public["sourceHandlesClosed"])
        self.assertIsNotNone(interrupted.admission_outcome.pending_source)
        self.assertFalse(any(kind == "load" for kind, _ in f.events))
        self.assertEqual(f.fs.handles, {})

    def test_failed_source_check_cannot_be_rehabilitated_by_later_success(self):
        f = Fixture()
        def effect(kwargs):
            original = f.held[0].verify
            def once():
                f.held[0].verify = original
                return False
            f.held[0].verify = once
            kwargs["recheck_source_closure"](f.closure)
        f.effect = effect
        result = self.error(f)
        self.assertFalse(result.public["sourcesUnchanged"])
        self.assertEqual(f.fs.handles, {})

    def test_factory_failure_without_returned_owner_is_not_closed_claim(self):
        for error in (OSError("private factory"), KeyboardInterrupt("private factory")):
            f = Fixture()
            def source(relative):
                f.source(relative)
                raise error  # Deliberately ambiguous factory; no owner handed off.
            try:
                if isinstance(error, KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt) as raised: f.invoke(source_factory=source)
                    result = raised.exception.admission_outcome
                    self.assertIs(raised.exception, error)
                else: result = self.error(f, source_factory=source)
                self.assertFalse(result.public["sourceHandlesClosed"])
                self.assertIsNotNone(result.pending_source)
                self.assertFalse(any(kind == "load" for kind, _ in f.events))
            finally:
                # Test-owned fake handle only; adapter must not invent this owner.
                for held in f.held: held.close()

    def test_ordinary_public_exception_traceback_is_redacted(self):
        f = Fixture()
        def effect(_): raise OSError("private native output")
        f.effect = effect
        with self.assertRaises(admission.AdmissionError) as raised: f.invoke()
        error = raised.exception
        self.assertNotIn("private native output", "".join(traceback.format_exception(type(error), error, error.__traceback__)))
        self.assertNotIn("private native output", json.dumps(error.admission_outcome.public))

    def test_actual_connected_capture_noop_with_original_source_callback(self):
        f, recovery = Fixture(), F.Fixture()
        f.budget = recovery.budget
        original = copy.deepcopy(F.F.fakes.images(recovery.backends))
        def connected(home, uid, **kwargs):
            self.assertEqual((home, uid), (HOME, 501))
            return recovery.invoke(**kwargs)
        f.caller.connected = connected
        outcome = f.invoke(runtime_factory=lambda *_: recovery.runtime)
        self.assertEqual(outcome.public["verdict"], "completed")
        self.assertTrue(outcome.public["callerReport"]["captureConfirmed"])
        self.assertEqual(F.F.fakes.images(recovery.backends), original)
        self.assertFalse(outcome.public["callerReport"]["targetMutationAttempted"])
        self.assertEqual(f.fs.handles, {})


if __name__ == "__main__":
    unittest.main()
