"""Connected actual readiness predicates with fake held targets/runtime only."""

import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import phase5_current_probe as P

spec = importlib.util.spec_from_file_location("probe_recovery_fixtures", ROOT / "tests/test_phase5_current_recovery.py")
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)
R = F.C.R
CLOSURE = R.SOURCE_CLOSURE + (P.SELF,)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.f = F.Fixture()
        self.calls, self.guards = [], []
        self.work_effect = None
        self.source_effect = None
        self.accept = lambda value: value == {"private": "private test response"}
        self.f.runtime.final_attest = self.attest

    def attest(self):
        self.calls.append("attest")
        return self.f.runtime.verify()

    def sources(self, closure):
        self.assertEqual(closure, CLOSURE)
        if self.source_effect:
            return self.source_effect()
        return True

    def work(self, context, guard):
        self.calls.append("work")
        self.guards.append(guard)
        self.assertIs(context.targets, self.f.targets)
        self.assertIs(context.legacy, self.f.legacy)
        self.assertIs(context.runtime, self.f.runtime)
        self.assertFalse(self.f.targets.closed)
        self.assertFalse(self.f.legacy.closed)
        self.assertTrue(guard())
        if self.work_effect:
            self.work_effect(context, guard)
        return {"private": "private test response"}

    def invoke(self, **overrides):
        options = dict(operation="discovery", source_closure=CLOSURE,
            recheck_sources=self.sources, runtime_factory=lambda *_: self.f.runtime,
            target_observer=lambda *_: self.f.targets, legacy_observer=lambda *_: self.f.legacy,
            work=self.work, accept_work=self.accept, budget=self.f.budget)
        options.update(overrides)
        with patch.object(R.catalog.subprocess, "Popen", side_effect=AssertionError("no native process")):
            return P.connected(R, F.A.HOME, 501, **options)

    def failed(self, **options):
        with self.assertRaises(P.ProbeError) as raised:
            self.invoke(**options)
        error = raised.exception
        self.assertEqual(str(error), "current_probe_required")
        self.assertEqual(error.report["verdict"], "needs-review")
        self.assertNotIn("private", json.dumps(error.report))
        self.assertNotIn(F.A.HOME, json.dumps(error.report))
        return error

    def test_default_and_unknown_calls_have_no_effect(self):
        self.assertEqual(P.connected(None, None, None)["verdict"], "closed")
        for options in ({"operation": "recovery"}, {"operation": True}, {"work": None},
                        {"source_closure": ()}, {"source_closure": (P.SELF, P.SELF)},
                        {"source_closure": (P.SELF, 1)}, {"budget": None}):
            self.assertEqual(self.invoke(**options)["verdict"], "closed")
        self.assertEqual(self.calls, [])

    def test_success_same_held_generation_one_work_no_capture(self):
        result = self.invoke()
        self.assertEqual(self.calls, ["attest", "work", "attest"])
        self.assertEqual(result["verdict"], "completed")
        for key in ("currentStateUnchanged", "nativeChildrenSettled", "handlesClosed", "workInvoked"):
            self.assertIs(result[key], True)
        for key in ("targetMutationAttempted", "executionAdmission", "phase5Accepted", "phase6Allowed"):
            self.assertIs(result[key], False)
        self.assertTrue(self.f.targets.closed and self.f.legacy.closed)
        self.assertEqual((self.f.allocations, self.f.stores, self.f.targets.handoffs), (0, 0, 0))
        self.assertNotIn("private", json.dumps(result))

    def test_guard_cannot_be_reused_after_owner_lifetime(self):
        self.invoke()
        with self.assertRaises(R.ReadinessError):
            self.guards[0]()

    def test_all_named_operations_use_same_closed_scope(self):
        for operation in ("trusted-task", "quarantine"):
            self.setUp()
            self.assertEqual(self.invoke(operation=operation)["operation"], operation)
            self.assertEqual(self.calls.count("work"), 1)

    def test_source_mismatch_blocks_work_even_if_later_recheck_passes(self):
        def once():
            self.source_effect = None
            return False
        self.source_effect = once
        error = self.failed()
        self.assertFalse(error.report["currentStateUnchanged"])
        self.assertFalse(error.report["workInvoked"])

    def test_acquisition_failure_does_not_claim_closed_or_unchanged(self):
        def failed(*_):
            raise OSError("private acquisition")
        error = self.failed(target_observer=failed)
        self.assertFalse(error.report["handlesClosed"])
        self.assertFalse(error.report["currentStateUnchanged"])
        self.assertEqual(error.private_context.pending_acquisition, "targets")

    def test_duplicate_owner_is_rejected_and_closed_once(self):
        calls = []
        original = self.f.targets.close
        def close():
            calls.append("close")
            original()
        self.f.targets.close = close
        error = self.failed(legacy_observer=lambda *_: self.f.targets)
        self.assertEqual(calls, ["close"])
        self.assertFalse(error.report["workInvoked"])

    def test_collect_exception_without_returned_child_stays_unknown(self):
        def collect():
            raise OSError("private spawn error")
        self.f.runtime.collect = collect
        error = self.failed()
        self.assertFalse(error.report["nativeChildrenSettled"])
        self.assertEqual(error.private_context.pending_native, "collect")

    def test_work_failure_retains_original_context_without_retry(self):
        original = OSError("private work error")
        def work(*_):
            raise original
        self.work_effect = work
        error = self.failed()
        self.assertIs(error.private_context.primary, original)
        self.assertFalse(error.report["nativeChildrenSettled"])
        self.assertEqual(self.calls.count("work"), 1)

    def test_pending_child_handle_is_retained(self):
        owner = object()
        def work(*_):
            error = OSError("private child")
            error.private_owner = owner
            raise error
        self.work_effect = work
        error = self.failed()
        self.assertIs(error.private_owner, owner)

    def test_changed_target_during_work_is_not_admitted(self):
        def work(*_):
            backend, name = self.f.backends[F.IDS[0]]
            old = backend.files[name]
            backend.files[name] = F.Image(old.data + b"\n", old.identity, old.mode, old.seal)
        self.work_effect = work
        error = self.failed()
        self.assertFalse(error.report["currentStateUnchanged"])
        self.assertEqual(self.calls.count("attest"), 1)

    def test_non_boolean_acceptance_fails_after_settled_work(self):
        error = self.failed(accept_work=lambda _: 1)
        self.assertTrue(error.report["nativeChildrenSettled"])
        self.assertIsNotNone(error.private_context.work_result)

    def test_callback_cannot_erase_caught_source_guard_failure(self):
        def work(context, guard):
            def once():
                self.source_effect = None
                return False
            self.source_effect = once
            try:
                guard()
            except R.ReadinessError:
                pass
        self.work_effect = work
        error = self.failed()
        self.assertFalse(error.report["currentStateUnchanged"])
        self.assertEqual(self.calls.count("attest"), 1)
        self.assertIsInstance(error.private_context.primary, R.ReadinessError)

    def test_callback_cannot_erase_caught_guard_interrupt_and_owner(self):
        for kind in (KeyboardInterrupt, SystemExit):
            self.setUp()
            original, owner = kind("private interrupt"), object()
            original.private_owner = owner
            def work(context, guard):
                def once():
                    self.source_effect = None
                    raise original
                self.source_effect = once
                try:
                    guard()
                except kind:
                    pass
            self.work_effect = work
            with self.assertRaises(kind) as raised:
                self.invoke()
            self.assertIs(raised.exception, original)
            self.assertIs(original.private_owner, owner)
            self.assertFalse(original.probe_report["nativeChildrenSettled"])
            self.assertFalse(original.probe_report["currentStateUnchanged"])
            self.assertEqual(self.calls.count("attest"), 1)

    def test_budget_expiry_during_work_blocks_acceptance(self):
        self.work_effect = lambda *_: self.f.clock.__setitem__(0, 100.0)
        error = self.failed()
        self.assertFalse(error.report["currentStateUnchanged"])

    def test_first_interrupt_survives_later_close_interrupt(self):
        original = KeyboardInterrupt("private first")
        def work(*_):
            raise original
        def close():
            raise SystemExit("private second")
        self.work_effect, self.f.runtime.close = work, close
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.invoke()
        self.assertIs(raised.exception, original)
        self.assertIs(original.private_context.primary, original)
        self.assertFalse(original.probe_report["handlesClosed"])
        self.assertTrue(self.f.targets.closed and self.f.legacy.closed)

    def test_close_interrupt_overrides_ordinary_work_failure(self):
        original = SystemExit(77)
        def work(*_):
            raise OSError("private earlier")
        def close():
            raise original
        self.work_effect, self.f.runtime.close = work, close
        with self.assertRaises(SystemExit) as raised:
            self.invoke()
        self.assertIs(raised.exception, original)
        self.assertEqual(len(original.private_context.failures), 2)

    def test_every_owner_gets_one_close_after_close_failure(self):
        calls = []
        for name in ("runtime", "legacy", "targets"):
            original = getattr(self.f, name).close
            def close(name=name, original=original):
                calls.append(name)
                original()
                if name == "runtime":
                    raise OSError("private close")
            getattr(self.f, name).close = close
        error = self.failed()
        self.assertEqual(calls, ["runtime", "legacy", "targets"])
        self.assertFalse(error.report["handlesClosed"])


if __name__ == "__main__":
    unittest.main()
