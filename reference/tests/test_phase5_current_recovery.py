"""Fake-only connected lifecycle. No native observer, syscall, CLI or model."""

import copy
from collections import Counter
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
C = importlib.machinery.SourceFileLoader("recovery_test_caller", str(ROOT / "bin/phase5-current-recovery")).load_module()


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


A = load("recovery_readiness_fakes", "tests/test_phase5_current_readiness.py")
F = load("recovery_capture_fakes", "tests/test_phase5_runtime_capture.py")
D = load("recovery_directory_fakes", "tests/test_phase5_runtime_directory.py")
Image, ABSENT = F.Image, F.ABSENT
IDS = C.R.capture.TARGET_IDS
RUN = "p5-" + "c" * 32
THIRD = F.fakes.THIRD


def fail(*_):
    raise OSError("private failure detail")


class Owner:
    def __init__(self):
        self.closed, self.calls, self.effect = False, 0, None

    def verify(self):
        self.calls += 1
        if self.effect is not None:
            effect, self.effect = self.effect, None
            effect()
        C.R.require(not self.closed)
        return True

    def close(self):
        C.R.require(not self.closed)
        self.closed = True


class TargetOwner(Owner):
    def __init__(self, backends):
        super().__init__()
        self.original, self.backends = F.fakes.images(backends), backends
        self.metadata_empty = dict.fromkeys(IDS, True)
        self.handoffs, self.handoff_effect = 0, None

    @property
    def bindings(self):
        held = self
        class Read:
            def __init__(self, key): self.key = key
            def verify(self): return held.verify()
            def snapshot(self, name):
                held.verify()
                C.R.require(name == self.key)
                return held.backends[self.key][0].snapshot(name)
        return {key: (Read(key), key) for key in IDS}

    def verify(self):
        super().verify()
        C.R.require(F.fakes.images(self.backends) == self.original)
        return True

    def transition_bindings(self, run_id):
        self.verify()
        C.R.require(run_id == RUN and self.handoffs == 0 and all(self.metadata_empty.values()))
        self.handoffs += 1
        if self.handoff_effect:
            self.handoff_effect()
        held = self
        class Adapter:
            def __init__(self, backend): self.backend = backend
            def verify(self):
                Owner.verify(held)  # same held parent lifetime, not old images
                self.backend.verify()
                return True
            def snapshot(self, name):
                self.verify()
                return self.backend.snapshot(name)
            def sync(self): return self.backend.sync()
            def create_exclusive(self, *args): return self.backend.create_exclusive(*args)
            def swap(self, *args): return self.backend.swap(*args)
            def move_exclusive(self, *args): return self.backend.move_exclusive(*args)
        return {key: (Adapter(backend), name) for key, (backend, name) in self.backends.items()}


class Fixture:
    def __init__(self):
        self.backends, self.store, receipt, before, after, self.events = F.fixture()
        fs, _, _ = A.T.fixture()
        self.runtime = A.runtime_fixture(fs)  # actual source matcher predicates, fake source pins
        for i, key in enumerate(IDS):
            image = self.backends[key][0].files[key]
            mode = 0o644 if key == "global-agents" else image.mode
            self.backends[key][0].files[key] = Image(fs.nodes[A.T.path(i)]["data"], image.identity, mode, image.seal)
        self.targets, self.legacy, self.parent = TargetOwner(self.backends), Owner(), Owner()
        self.legacy.receipt, self.legacy.physical_before, self.legacy.physical_after = receipt, before, after
        self.clock, self.budget_calls = [0.0], 0
        self.budget = C.R.Budget(clock=lambda: self.clock[0])
        check = self.budget.check
        def counted():
            self.budget_calls += 1
            check()
        self.budget.check = counted
        self.runtime.budget = self.budget
        self.source_calls, self.allocations, self.stores = 0, 0, 0
        self.source_effect = self.allocate_effect = self.store_effect = None
        self.popen_effect = AssertionError("no native process")

    def sources(self, closure):
        self.source_calls += 1
        C.R.require(closure == C.SOURCE_CLOSURE)
        if self.source_effect:
            return self.source_effect()
        return True

    def allocate(self, home, uid, run):
        self.allocations += 1
        self.events.append(("allocation", run))
        C.R.require((home, uid, run) == (A.HOME, 501, RUN))
        if self.allocate_effect:
            self.allocate_effect()
        return self.parent

    def make_store(self, parent):
        self.stores += 1
        C.R.require(parent is self.parent)
        if self.store_effect:
            self.store_effect()
        return self.store

    def invoke(self, operation="rollback-return", **overrides):
        kwargs = dict(operation=operation, run_id=RUN, runtime_factory=lambda *_: self.runtime,
            recheck_source_closure=self.sources, target_observer=lambda *_: self.targets,
            legacy_observer=lambda *_: self.legacy, allocator=self.allocate,
            store_factory=self.make_store, budget=self.budget)
        kwargs.update(overrides)
        with patch.object(C.R.catalog.subprocess, "Popen", side_effect=self.popen_effect):
            return C.connected(A.HOME, 501, **kwargs)


class RecoveryTests(unittest.TestCase):
    def nonpass(self, fixture, **kwargs):
        with self.assertRaises(C.RecoveryError) as raised:
            fixture.invoke(**kwargs)
        value = raised.exception
        self.assertEqual(str(value), "current_recovery_required")
        self.assertEqual(value.report["verdict"], "recovery-required")
        self.assertNotIn("private", json.dumps(value.report))
        self.assertNotIn(RUN, json.dumps(value.report))
        self.assertIs(value.private_session.runtime, fixture.runtime)
        return value

    def test_cli_and_default_connected_closed_without_effects(self):
        with patch.object(C.R, "Budget", side_effect=AssertionError("closed")):
            self.assertEqual(C.connected("unused", 0)["verdict"], "closed")
            with patch("sys.stdout", new=io.StringIO()) as stream:
                self.assertEqual(C.main(), 2)
            self.assertEqual(json.loads(stream.getvalue())["verdict"], "closed")

    def test_invalid_operation_id_and_missing_closure_are_closed(self):
        for overrides in ({"operation": True}, {"operation": "resume"}, {"run_id": RUN.upper()},
                          {"run_id": C.directory.LEGACY_LEAF}, {"recheck_source_closure": None},
                          {"runtime_factory": None}):
            fixture = Fixture()
            self.assertEqual(fixture.invoke(**overrides)["verdict"], "closed")
            self.assertEqual(fixture.source_calls, 0)
            self.assertEqual(fixture.events, [])

    def test_full_real_session_cycle_preserves_current_and_history(self):
        fixture = Fixture()
        original = F.fakes.images(fixture.backends)
        history = copy.deepcopy((fixture.legacy.receipt, fixture.legacy.physical_before, fixture.legacy.physical_after))
        result = fixture.invoke()
        self.assertEqual(result["verdict"], "completed")
        self.assertEqual(result["state"], "current")
        self.assertTrue(result["captureConfirmed"] and result["returnConfirmed"])
        self.assertEqual(fixture.targets.handoffs, 1)
        self.assertEqual(fixture.allocations, 1)
        self.assertEqual([(i.data, i.mode) for i in F.fakes.images(fixture.backends)],
                         [(i.data, i.mode) for i in original])
        self.assertEqual(F.fakes.images(fixture.backends)[1], original[1])
        self.assertEqual(history, (fixture.legacy.receipt, fixture.legacy.physical_before, fixture.legacy.physical_after))
        self.assertEqual([i for event, i in fixture.events if event == "rename"], list(range(0, 1)) + list(range(2, 8)) + list(range(0, 1)) + list(range(2, 8)))
        self.assertTrue(all(held.closed for held in (fixture.targets, fixture.legacy, fixture.parent)))
        self.assertTrue(all(pin.closed for pin in fixture.runtime.pins.values()))
        for key in ("executionAdmission", "liveAdmission", "phase5Accepted", "phase6Allowed", "cleanupPerformed"):
            self.assertIs(result[key], False)

    def test_capture_noop_has_no_target_writes(self):
        fixture = Fixture()
        original = F.fakes.images(fixture.backends)
        result = fixture.invoke("capture-noop")
        self.assertEqual(result["verdict"], "completed")
        self.assertIs(result["targetMutationAttempted"], False)
        self.assertIs(result["returnConfirmed"], False)
        self.assertEqual(F.fakes.images(fixture.backends), original)
        self.assertEqual(set(fixture.store.records), {"capture"})
        self.assertFalse(any(event in ("create", "rename") for event, _ in fixture.events))

    def test_required_source_closure_is_unique_and_complete(self):
        self.assertEqual(len(C.SOURCE_CLOSURE), len(set(C.SOURCE_CLOSURE)))
        self.assertTrue(set(C.R.SOURCE_CLOSURE) <= set(C.SOURCE_CLOSURE))
        for member in ("bin/phase5-current-recovery", "lib/phase5_runtime_store.py", "lib/phase5_runtime_directory.py"):
            self.assertIn(member, C.SOURCE_CLOSURE)

    def test_all_three_admission_rounds_share_two_full_source_brackets(self):
        fixture, counts, active = Fixture(), [], [None]
        original_verify, original_round = fixture.runtime.verify, C.R.admit_current_round
        def verify():
            if active[0] is not None: counts[active[0]] += 1
            return original_verify()
        fixture.runtime.verify = verify
        def checked_round(*args, **kwargs):
            counts.append(0)
            active[0] = len(counts) - 1
            try:
                return original_round(*args, **kwargs)
            finally:
                active[0] = None
        with patch.object(C.R, "admit_current_round", side_effect=checked_round):
            self.assertEqual(fixture.invoke("capture-noop")["verdict"], "completed")
        self.assertEqual(counts, [2, 2, 2])

    def test_source_drift_in_each_pure_admission_round_retains_exact_progress(self):
        for selected in (1, 2, 3):
            fixture, calls = Fixture(), []
            original = C.R.classify
            def classify(*args, **kwargs):
                result = original(*args, **kwargs)
                calls.append(True)
                if len(calls) == selected:
                    next(iter(fixture.runtime.pins.values())).data += b"private changed source"
                return result
            with patch.object(C.R, "classify", side_effect=classify):
                error = self.nonpass(fixture, operation="capture-noop")
            self.assertEqual(fixture.allocations, 0 if selected == 1 else 1)
            self.assertEqual("capture" in fixture.store.records, selected == 3)
            self.assertEqual(error.report["captureConfirmed"], selected == 3)
            self.assertFalse(error.report["targetMutationAttempted"])

    def test_source_callback_false_integer_and_exception_deny_before_observation(self):
        for response in (False, 1, None, fail):
            fixture = Fixture()
            fixture.source_effect = response if callable(response) else lambda: response
            with self.assertRaises(C.RecoveryError) as raised:
                fixture.invoke()
            self.assertEqual(fixture.targets.calls, 0)
            self.assertEqual(fixture.events, [])
            self.assertEqual(raised.exception.report["stage"], "source-bind")

    def test_real_classifier_and_matcher_reject_unknown_integration(self):
        fixture = Fixture()
        old = fixture.backends["config"][0].files["config"]
        changed = Image(old.data + b'\n[plugins.unadmitted]\nenabled=true\n', old.identity, old.mode, old.seal)
        fixture.backends["config"][0].files["config"] = changed
        fixture.targets.original = F.fakes.images(fixture.backends)
        value = self.nonpass(fixture)
        self.assertEqual(value.report["stage"], "admission")
        self.assertEqual(fixture.allocations, 0)

    def test_metadata_denial_and_source_guidance_drift_before_allocation(self):
        for kind in ("metadata", "guidance"):
            fixture = Fixture()
            if kind == "metadata":
                fixture.targets.metadata_empty["global-agents"] = False
            else:
                fixture.runtime.pins[str(ROOT / C.R.MANAGED["global-agents"])].data += b"changed"
            self.nonpass(fixture)
            self.assertEqual(fixture.allocations, 0)

    def test_admission_to_capture_drift_keeps_new_directory_no_capture(self):
        fixture = Fixture()
        fixture.allocate_effect = lambda: fixture.backends["config"][0].files.update(config=THIRD)
        value = self.nonpass(fixture)
        self.assertTrue(value.report["allocationAttempted"])
        self.assertFalse(value.report["captureConfirmed"])
        self.assertEqual(value.report["state"], "unknown")
        self.assertEqual(fixture.store.records, {})
        self.assertEqual(fixture.allocations, 1)

    def test_uncertain_allocation_and_store_failure_retained_without_retry(self):
        for boundary in ("allocate", "store"):
            fixture = Fixture()
            setattr(fixture, boundary + "_effect", fail)
            value = self.nonpass(fixture)
            self.assertTrue(value.report["allocationAttempted"])
            self.assertFalse(value.report["targetMutationAttempted"])
            self.assertEqual(fixture.allocations, 1)
            self.assertEqual(fixture.store.records, {})

    def test_capture_publication_failure_retains_record_not_confirmed(self):
        fixture = Fixture()
        fixture.store.hooks["after:capture"] = fail
        value = self.nonpass(fixture)
        self.assertIn("capture", fixture.store.records)
        self.assertFalse(value.report["captureConfirmed"])
        self.assertFalse(any(event == "rename" for event, _ in fixture.events))

    def test_noop_failure_never_dispatches_rollback(self):
        fixture = Fixture()
        fixture.backends["config"][0].hooks["sync"] = fail
        value = self.nonpass(fixture)
        self.assertEqual(value.report["stage"], "current-noop")
        self.assertFalse(value.report["targetMutationAttempted"])
        self.assertNotIn("rollback.initial.intent", fixture.store.records)

    def test_ticket_store_failure_prevents_first_rename_and_keeps_stage(self):
        fixture = Fixture()
        fixture.store.hooks["volatile:rollback.ticket.0"] = fail
        value = self.nonpass(fixture)
        self.assertTrue(value.report["targetMutationAttempted"])
        self.assertEqual(value.report["state"], "unknown")
        self.assertIn("rollback.ticket.0", fixture.store.records)
        self.assertTrue(any(event == "create" for event, _ in fixture.events))
        self.assertFalse(any(event == "rename" for event, _ in fixture.events))
        self.assertNotIn("return.initial.intent", fixture.store.records)

    def test_midrollback_unknown_target_stops_without_return(self):
        fixture = Fixture()
        fixture.backends["config"][0].hooks["after-rename"] = lambda _: fixture.backends[IDS[4]][0].files.update({IDS[4]: THIRD})
        value = self.nonpass(fixture)
        self.assertEqual(value.report["state"], "unknown")
        self.assertEqual(fixture.backends[IDS[4]][0].files[IDS[4]], THIRD)
        self.assertNotIn("return.initial.intent", fixture.store.records)

    def test_noop_at_rollback_does_not_classify_historical_managed_scalars(self):
        fixture = Fixture()
        actual, seen = C.R.classify, []
        def observed(raw, **kwargs):
            seen.append(raw)
            self.assertIn(b"danger-full-access", raw)
            return actual(raw, **kwargs)
        with patch.object(C.R, "classify", side_effect=observed):
            self.assertEqual(fixture.invoke()["verdict"], "completed")
        self.assertGreaterEqual(len(seen), 3)

    def test_final_terminal_drift_retains_terminal_and_failure(self):
        for action in ("rollback", "return"):
            fixture = Fixture()
            fixture.store.hooks["after:" + action + ".initial.terminal"] = lambda _: fixture.backends["config"][0].files.update(config=THIRD)
            value = self.nonpass(fixture)
            self.assertEqual(value.report["state"], "unknown")
            self.assertIn(action + ".initial.terminal", fixture.store.records)
            self.assertIn(action + ".initial.failure", fixture.store.records)

    def test_budget_expiry_after_rename_is_unknown_and_never_auto_return(self):
        fixture = Fixture()
        fixture.backends["config"][0].hooks["after-rename"] = lambda _: fixture.clock.__setitem__(0, 91.0)
        value = self.nonpass(fixture)
        self.assertEqual(value.report["state"], "unknown")
        self.assertNotIn("return.initial.intent", fixture.store.records)
        self.assertTrue(value.report["targetMutationAttempted"])

    def test_interrupt_after_rename_preserves_original_exception_and_run(self):
        for error in (KeyboardInterrupt(), SystemExit("private exit payload")):
            fixture = Fixture()
            def stop(_): raise error
            fixture.backends["config"][0].hooks["after-rename"] = stop
            with self.assertRaises(type(error)) as raised:
                fixture.invoke()
            self.assertIs(raised.exception, error)
            self.assertEqual(error.private_session.run_id, RUN)
            self.assertTrue(error.recovery_report["targetMutationAttempted"])
            self.assertEqual(error.recovery_report["state"], "unknown")
            self.assertTrue(fixture.parent.closed and fixture.targets.closed and fixture.legacy.closed)
            self.assertFalse(error.recovery_report["nativeChildrenSettled"])
            self.assertTrue(error.settlement_failed)

    def test_actual_session_creation_interrupt_without_returned_handle_is_unconfirmed(self):
        for interrupted in (KeyboardInterrupt(), SystemExit(17)):
            fixture, created = Fixture(), []
            def ambiguous_popen(*_args, **_kwargs):
                created.append(object())  # fake child exists; no handle returns
                raise interrupted
            fixture.popen_effect = ambiguous_popen
            fixture.runtime.collect = lambda: fixture.runtime._run([A.R.CLI, "--version"])
            with self.assertRaises(type(interrupted)) as raised:
                fixture.invoke()
            error = raised.exception
            self.assertIs(error, interrupted)
            self.assertEqual(len(created), 1)
            self.assertIsNone(error.private_owner)
            self.assertTrue(error.settlement_failed)
            self.assertFalse(error.recovery_report["nativeChildrenSettled"])
            self.assertEqual(error.private_session.pending_native_operation, "collect")
            self.assertIs(error.private_session.primary, interrupted)
            self.assertEqual(fixture.allocations, 0)
            self.assertTrue(fixture.targets.closed and fixture.legacy.closed)

    def test_ordinary_ambiguous_creation_retains_unknown_even_without_handle(self):
        fixture, created = Fixture(), []
        def ambiguous_popen(*_args, **_kwargs):
            created.append(object())
            raise RuntimeError("private ambiguous creation")
        fixture.popen_effect = ambiguous_popen
        fixture.runtime.collect = lambda: fixture.runtime._run([A.R.CLI, "--version"])
        error = self.nonpass(fixture)
        self.assertEqual(len(created), 1)
        self.assertIsNone(error.private_owner)
        self.assertTrue(error.settlement_failed)
        self.assertFalse(error.report["nativeChildrenSettled"])
        self.assertFalse(error.private_session.settlement_confirmed)
        self.assertEqual(error.private_session.pending_native_operation, "collect")

    def test_attestation_interruption_does_not_lose_settlement_uncertainty(self):
        for which in (1, 2):
            fixture, calls = Fixture(), []
            interrupted = KeyboardInterrupt()
            def attest():
                calls.append(True)
                if len(calls) == which:
                    raise interrupted
                return True
            fixture.runtime.final_attest = attest
            with self.assertRaises(KeyboardInterrupt) as raised:
                fixture.invoke()
            self.assertIs(raised.exception, interrupted)
            self.assertFalse(interrupted.recovery_report["nativeChildrenSettled"])
            self.assertTrue(interrupted.settlement_failed)
            self.assertEqual(interrupted.private_session.pending_native_operation, "attestation")
            self.assertEqual(fixture.allocations, 0 if which == 1 else 1)

    def test_explicit_unconfirmed_flag_without_owner_is_retained(self):
        fixture = Fixture()
        error = OSError("private uncertain operation")
        error.settlement_failed = True
        def source(): raise error
        fixture.source_effect = source
        with self.assertRaises(C.RecoveryError) as raised:
            fixture.invoke()
        value = raised.exception
        self.assertIsNone(value.private_owner)
        self.assertTrue(value.settlement_failed)
        self.assertFalse(value.report["nativeChildrenSettled"])
        self.assertIs(value.private_session.primary, error)

    def test_successful_observation_then_known_nonprocess_failure_keeps_settlement(self):
        fixture = Fixture()
        fixture.store.hooks["after:capture"] = fail
        error = self.nonpass(fixture)
        self.assertTrue(error.report["nativeChildrenSettled"])
        self.assertFalse(error.settlement_failed)
        self.assertIsNone(error.private_session.pending_native_operation)

    def test_pending_native_owner_retained_despite_final_and_close_failures(self):
        fixture = Fixture()
        owner, first = object(), C.R.ReadinessError(private_owner=object())
        first.private_owner = owner
        def collect():
            fixture.runtime.pending_owner = owner
            raise first
        fixture.runtime.collect = collect
        fixture.runtime.close = fail
        value = self.nonpass(fixture)
        self.assertIs(value.private_owner, owner)
        self.assertIs(value.private_session.primary, first)
        self.assertFalse(value.report["nativeChildrenSettled"])
        self.assertTrue(fixture.targets.closed and fixture.legacy.closed)
        self.assertEqual(fixture.allocations, 0)

    def test_postphase_history_and_source_drift_stop_following_action(self):
        for kind in ("history", "source"):
            fixture = Fixture()
            def changed(_):
                if kind == "history": fixture.legacy.closed = True
                else: fixture.source_effect = lambda: False
            fixture.store.hooks["after:rollback.initial.terminal"] = changed
            value = self.nonpass(fixture)
            self.assertEqual(value.report["state"], "unknown")
            self.assertNotIn("return.initial.intent", fixture.store.records)

    def test_full_cycle_bounded_operation_counts(self):
        fixture = Fixture()
        started = time.monotonic()
        self.assertEqual(fixture.invoke()["verdict"], "completed")
        elapsed = time.monotonic() - started
        self.assertLess(fixture.budget_calls, 20000)
        self.assertLess(len(fixture.store.sync_calls), 10000)
        print("fake recovery cycle: %.3fs; budgetChecks=%d; sourceChecks=%d; recordBarriers=%d; renames=%d" % (
            elapsed, fixture.budget_calls, fixture.source_calls, len(fixture.store.sync_calls),
            sum(event == "rename" for event, _ in fixture.events)))

    def test_actual_targets_directory_store_legacy_and_session_over_fake_syscalls(self):
        base, _, _ = A.T.fixture()
        target_fs = A.T.TransitionOS()
        target_fs.nodes, target_fs.sequence = copy.deepcopy(base.nodes), base.sequence
        target_fs.nodes[A.T.path(1)]["st_mode"] = A.stat.S_IFREG | 0o644
        metadata = A.T.Metadata(target_fs)
        runtime = A.runtime_fixture(target_fs)
        history_fs, history_pins = A.L.fixture()
        state_fs, state_metadata = D.fixture()
        original, held = copy.deepcopy(target_fs.nodes), []
        def observe(home, uid):
            value = C.R.targets.observe(home, uid, syscalls=target_fs, platform=metadata,
                backend_factory=lambda parent, **kw: A.T.DescriptorBackend(parent, rename=target_fs.rename, **kw))
            held.append(value)
            return value
        started = time.monotonic()
        with patch.multiple(C.R.legacy, **history_pins), \
                patch.object(C.R.catalog.subprocess, "Popen", side_effect=AssertionError("no native process")):
            value = C.connected(A.HOME, 501, operation="rollback-return", run_id=D.RUN_ID,
                runtime_factory=lambda *_: runtime, budget=runtime.budget,
                recheck_source_closure=lambda paths: paths == C.SOURCE_CLOSURE,
                target_observer=observe,
                legacy_observer=lambda home, uid: C.R.legacy.observe(home, uid, syscalls=history_fs),
                allocator=lambda home, uid, run: C.directory.allocate(home, uid, run, syscalls=state_fs, platform=state_metadata),
                store_factory=lambda parent: C.DurableStore(parent, syscalls=state_fs))
        self.assertEqual(value["verdict"], "completed")
        self.assertEqual(len(held), 1)
        self.assertEqual(target_fs.nodes[A.T.path(1)], original[A.T.path(1)])
        for i in range(8):
            for field in ("data", "st_mode"):
                self.assertEqual(target_fs.nodes[A.T.path(i)][field], original[A.T.path(i)][field])
        self.assertEqual(target_fs.handles, {})
        self.assertEqual(state_fs.handles, {})
        self.assertEqual(history_fs.handles, {})
        counts = Counter(op for fs in (target_fs, state_fs, history_fs) for op, _ in fs.calls)
        self.assertEqual(counts["mkdir"], 1)
        self.assertEqual(counts["rename"], 14)
        self.assertEqual(counts["unlink"], 0)
        print("actual classes/fake syscalls: %.3fs; target=%d; state=%d; history=%d; fsync=%d; rename=%d" % (
            time.monotonic() - started, len(target_fs.calls), len(state_fs.calls), len(history_fs.calls),
            counts["fsync"], counts["rename"]))


if __name__ == "__main__":
    unittest.main()
