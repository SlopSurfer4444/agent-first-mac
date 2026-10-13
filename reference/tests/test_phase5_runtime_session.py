"""Pure in-memory lifecycle/syscall/store fixtures; no live paths or execution."""

import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.phase5_runtime_session import (  # noqa: E402
    MAX_RECORD_BYTES, TARGET_IDS, capture, noop, return_current, rollback, verify,
)
from lib.phase5_runtime_transition import ABSENT, Image  # noqa: E402


SESSION = "p5-" + "a" * 32
THIRD = Image(b"private unknown owner state", (1, 999999), 0o600, b"owner")
BEFORE = b'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n[projects.old]\nx=1\n'
AFTER = BEFORE.replace(b"on-request", b"never").replace(b"workspace-write", b"danger-full-access")
CURRENT = (b'# current owner comment\napproval_policy = "never" # keep\n'
           b'sandbox_mode = "danger-full-access"\n[projects.new]\nx=2\n[plugins.new]\nenabled=true\n')


def failure(*_args):
    raise OSError("private/path/error must not escape")


class Hooks:
    def __init__(self):
        self.hooks = {}

    def fire(self, event):
        callback = self.hooks.pop(event, None)
        if callback is not None:
            callback(self)


class Backend(Hooks):
    def __init__(self, index, current, events):
        super().__init__()
        self.files, self.events = {TARGET_IDS[index]: current}, events
        self.index, self.sequence, self.syncs = index, 1000, 0

    def verify(self):
        self.fire("verify")

    def snapshot(self, name):
        self.fire("snapshot")
        return self.files.get(name, ABSENT)

    def create_exclusive(self, name, data, mode):
        self.fire("before-create")
        if name in self.files:
            raise FileExistsError()
        self.sequence += 1
        result = Image(data, (self.index + 100, self.sequence), mode, b"owner")
        self.files[name] = result
        self.events.append(("create", self.index))
        self.fire("after-create")
        return result

    def swap(self, first, second):
        self.fire("before-rename")
        self.files[first], self.files[second] = self.files[second], self.files[first]
        self.events.append(("rename", self.index))
        self.fire("after-rename")

    def move_exclusive(self, first, second):
        self.fire("before-rename")
        if second in self.files:
            raise FileExistsError()
        self.files[second] = self.files.pop(first)
        self.events.append(("rename", self.index))
        self.fire("after-rename")

    def sync(self):
        self.syncs += 1
        self.fire("sync")


class Store(Hooks):
    def __init__(self, events):
        super().__init__()
        self.records, self.events = {}, events
        self.durable, self.volatile, self.sync_calls = set(), set(), []
        self.identities, self.bound = {}, {}

    def verify(self):
        self.fire("verify")

    def read(self, name):
        self.fire("read:" + name)
        if name in self.records:
            identity = self.identities.setdefault(name, object())
            if self.bound.setdefault(name, identity) is not identity:
                raise OSError("private record identity changed")
        return self.records.get(name)

    def sync_record(self, name, expected_raw):
        self.sync_calls.append(name)
        self.fire("before-sync:" + name)

        def exact():
            if (self.records.get(name) != expected_raw
                    or self.identities.get(name) is not self.bound.get(name)):
                raise OSError("private record replaced")

        exact()
        self.fire("sync:" + name)
        self.durable.add(name)
        self.volatile.discard(name)
        self.fire("after-sync:" + name)
        exact()

    def substitute(self, name, raw):
        self.records[name] = raw
        self.identities[name] = object()
        self.durable.discard(name)
        self.volatile.add(name)

    def put_exclusive(self, name, raw):
        self.fire("before:" + name)
        if name in self.records:
            raise FileExistsError()
        self.records[name] = raw
        self.identities[name] = object()
        self.bound[name] = self.identities[name]
        self.volatile.add(name)
        self.events.append(("persist", name))
        self.fire("volatile:" + name)
        self.durable.add(name)
        self.volatile.discard(name)
        self.fire("after:" + name)


def fixture():
    events, before, after, backends = [], {}, {}, {}
    for index, identifier in enumerate(TARGET_IDS):
        mode = 0o755 if index in (4, 7) else 0o600
        if index == 0:
            old, applied, live = BEFORE, AFTER, CURRENT
        elif index == 1:
            old, applied, live = b"private old guidance", b"private historical guidance", b"private current guidance"
        else:
            old = None if index % 2 == 0 else ("private before " + identifier).encode()
            applied = live = ("private applied " + identifier).encode()
        before[identifier] = ABSENT if old is None else Image(old, (2, index), mode, b"legacy")
        after[identifier] = Image(applied, (3, index), mode, b"legacy")
        backend = Backend(index, Image(live, (1, index), mode, b"owner"), events)
        backends[identifier] = (backend, identifier)
    return backends, Store(events), before, after, events


def captured():
    backends, store, before, after, events = fixture()
    result = capture(backends, store, before, after, session_id=SESSION)
    assert result["verdict"] == "captured"
    return backends, store, before, after, events


def images(backends):
    return tuple(backends[k][0].files.get(k, ABSENT) for k in TARGET_IDS)


class RuntimeSessionTests(unittest.TestCase):
    def assert_public(self, result, verdict):
        self.assertEqual(result["verdict"], verdict)
        self.assertEqual(set(result), {"schema", "verdict", "reason", "completedTargets",
                                     "executionAdmission", "liveAdmission", "phase5Accepted",
                                     "phase6Allowed", "cleanupPerformed"})
        for key in ("executionAdmission", "liveAdmission", "phase5Accepted", "phase6Allowed", "cleanupPerformed"):
            self.assertIs(result[key], False)
        self.assertNotIn("private", json.dumps(result))
        self.assertNotIn("p5-", json.dumps(result))

    def test_capture_verify_noop_zero_target_writes(self):
        backends, store, before, after, events = fixture()
        original = images(backends)
        self.assert_public(capture(backends, store, before, after, session_id=SESSION), "captured")
        stored = dict(store.records)
        self.assert_public(verify(backends, store), "verified")
        self.assert_public(noop(backends, store), "noop")
        self.assertEqual(images(backends), original)
        self.assertEqual(store.records, stored)
        self.assertEqual(events, [("persist", "capture")])
        self.assertTrue(all(b.syncs == 1 for b, _ in backends.values()))

    def test_rollback_then_return_preserves_current_owner_bytes_and_history(self):
        backends, store, before, after, events = captured()
        original, history, capture_raw = images(backends), (dict(before), dict(after)), store.records["capture"]
        self.assert_public(rollback(backends, store), "completed")
        rolled = images(backends)
        self.assertEqual(rolled[0].data, CURRENT.replace(b"never", b"on-request").replace(b"danger-full-access", b"workspace-write"))
        self.assertEqual(rolled[1], original[1])
        for index in range(2, 8):
            self.assertEqual((rolled[index].data, rolled[index].mode),
                             (before[TARGET_IDS[index]].data, before[TARGET_IDS[index]].mode))
        self.assert_public(verify(backends, store, state="rollback"), "verified")
        self.assert_public(noop(backends, store, state="rollback"), "noop")
        self.assert_public(return_current(backends, store), "completed")
        returned = images(backends)
        self.assertEqual([(i.data, i.mode) for i in returned], [(i.data, i.mode) for i in original])
        self.assertEqual(returned[1], original[1])
        self.assertEqual((before, after), history)
        self.assertEqual(store.records["capture"], capture_raw)
        self.assert_public(verify(backends, store, state="return"), "verified")
        renames = [i for event, i in events if event == "rename"]
        self.assertEqual(renames, [0, 2, 3, 4, 5, 6, 7] * 2)

    def test_each_ticket_is_durable_before_any_target_rename(self):
        backends, store, _, _, events = captured()
        self.assert_public(rollback(backends, store), "completed")
        for position, event in enumerate(events):
            if event[0] == "rename":
                self.assertIn(("persist", "rollback.ticket." + str(event[1])), events[:position])
                self.assertIn(("persist", "rollback.initial.intent"), events[:position])

    def test_capture_requires_all_six_after_bytes_and_mode(self):
        for field in ("data", "mode"):
            backends, store, before, after, events = fixture()
            backend, name = backends[TARGET_IDS[5]]
            old = backend.files[name]
            backend.files[name] = Image(b"changed" if field == "data" else old.data, old.identity,
                                       0o644 if field == "mode" else old.mode, old.seal)
            self.assert_public(capture(backends, store, before, after, session_id=SESSION), "recovery-required")
            self.assertEqual(events, [])

    def test_capture_rejects_missing_targets_aliases_and_partial_images(self):
        for defect in ("missing", "alias", "partial", "session"):
            backends, store, before, after, events = fixture()
            if defect == "missing":
                del before[TARGET_IDS[-1]]
            elif defect == "alias":
                backends[TARGET_IDS[1]][0].files[TARGET_IDS[1]] = images(backends)[0]
            elif defect == "partial":
                before[TARGET_IDS[1]] = object.__new__(Image)
            self.assert_public(capture(backends, store, before, after, session_id=True if defect == "session" else SESSION),
                               "recovery-required")
            self.assertEqual(events, [])

    def test_capture_drift_during_publication_never_changes_target(self):
        backends, store, before, after, events = fixture()
        store.hooks["after:capture"] = lambda _: backends["config"][0].files.update(config=THIRD)
        self.assert_public(capture(backends, store, before, after, session_id=SESSION), "recovery-required")
        self.assertEqual(images(backends)[0], THIRD)
        self.assertEqual(events, [("persist", "capture")])
        self.assert_public(verify(backends, store), "recovery-required")

    def test_repeated_capture_and_initial_action_never_overwrite(self):
        backends, store, before, after, events = captured()
        self.assert_public(capture(backends, store, before, after, session_id=SESSION), "recovery-required")
        self.assert_public(rollback(backends, store), "completed")
        saved, original_events = dict(store.records), list(events)
        self.assert_public(rollback(backends, store), "recovery-required")
        self.assertEqual(store.records, saved)
        self.assertEqual(events, original_events)

    def test_noop_sync_failure_and_drift_are_not_success(self):
        for drift in (False, True):
            backends, store, _, _, events = captured()
            backend = backends["config"][0]
            backend.hooks["sync"] = (lambda b: b.files.update(config=THIRD)) if drift else failure
            self.assert_public(noop(backends, store), "recovery-required")
            self.assertFalse(any(e[0] in ("rename", "create") for e in events))

    def test_whole_prestate_unknown_blocks_before_first_mutation(self):
        backends, store, _, _, events = captured()
        backends[TARGET_IDS[-1]][0].files[TARGET_IDS[-1]] = THIRD
        self.assert_public(rollback(backends, store), "recovery-required")
        self.assertEqual(events, [("persist", "capture")])

    def test_intent_failure_before_and_after_durable_write_zero_target_writes(self):
        for timing in ("before", "after"):
            backends, store, _, _, events = captured()
            store.hooks[timing + ":rollback.initial.intent"] = failure
            self.assert_public(rollback(backends, store), "recovery-required")
            self.assertIn("rollback.initial.failure", store.records)
            self.assertFalse(any(e[0] in ("rename", "create") for e in events))

    def test_ticket_failure_before_persistence_retains_staging_and_cannot_rebase(self):
        backends, store, _, _, events = captured()
        store.hooks["before:rollback.ticket.0"] = failure
        original = images(backends)
        self.assert_public(rollback(backends, store), "recovery-required")
        self.assertEqual(images(backends), original)
        self.assertIn(SESSION + "-rollback-0-tmp", backends["config"][0].files)
        self.assertNotIn("rollback.ticket.0", store.records)
        self.assert_public(rollback(backends, store, resume=True), "recovery-required")
        self.assertFalse(any(e[0] == "rename" for e in events))

    def test_ticket_failure_after_durable_write_resumes_exact_ticket(self):
        backends, store, _, _, events = captured()
        store.hooks["after:rollback.ticket.0"] = failure
        self.assert_public(rollback(backends, store), "recovery-required")
        ticket = store.records["rollback.ticket.0"]
        failure_record = store.records["rollback.initial.failure"]
        self.assert_public(rollback(backends, store, resume=True), "completed")
        self.assertEqual(store.records["rollback.ticket.0"], ticket)
        self.assertEqual(store.records["rollback.initial.failure"], failure_record)
        self.assertEqual(events.count(("create", 0)), 1)

    def test_midtargets_failure_stops_and_retains_per_target_failure_on_resume(self):
        backends, store, _, _, events = captured()
        backends[TARGET_IDS[3]][0].hooks["before-rename"] = failure
        self.assert_public(rollback(backends, store), "recovery-required")
        self.assertEqual([i for e, i in events if e == "rename"], [0, 2])
        saved = store.records["rollback.initial.result.3"]
        self.assertIs(json.loads(saved)["succeeded"], False)
        self.assert_public(rollback(backends, store, resume=True), "completed")
        self.assertEqual(store.records["rollback.initial.result.3"], saved)
        self.assertIs(json.loads(store.records["rollback.resume.result.3"])["succeeded"], True)

    def test_postrename_interruption_explicit_resume_syncs_without_second_rename(self):
        backends, store, _, _, events = captured()
        backends["config"][0].hooks["after-rename"] = failure
        self.assert_public(rollback(backends, store), "recovery-required")
        self.assert_public(rollback(backends, store, resume=True), "completed")
        self.assertEqual(events.count(("rename", 0)), 1)

    def test_result_persistence_failure_after_rename_has_distinct_resume_outcome(self):
        for timing in ("before", "after"):
            backends, store, _, _, events = captured()
            store.hooks[timing + ":rollback.initial.result.0"] = failure
            self.assert_public(rollback(backends, store), "recovery-required")
            self.assert_public(rollback(backends, store, resume=True), "completed")
            self.assertEqual(events.count(("rename", 0)), 1)
            self.assertIn("rollback.initial.failure", store.records)

    def test_unknown_state_during_target_and_resume_is_preserved(self):
        backends, store, _, _, events = captured()
        backends["config"][0].hooks["after-rename"] = lambda b: b.files.update(config=THIRD)
        self.assert_public(rollback(backends, store), "recovery-required")
        before_resume = list(events)
        self.assert_public(rollback(backends, store, resume=True), "recovery-required")
        self.assertEqual(events, before_resume)
        self.assertEqual(images(backends)[0], THIRD)
        self.assertIn(SESSION + "-rollback-0-tmp", backends["config"][0].files)

    def test_other_target_drift_stops_before_next_mutation(self):
        backends, store, _, _, events = captured()
        backends["config"][0].hooks["after-rename"] = lambda _: backends[TARGET_IDS[-1]][0].files.update({TARGET_IDS[-1]: THIRD})
        self.assert_public(rollback(backends, store), "recovery-required")
        self.assertEqual([i for e, i in events if e == "rename"], [0])
        self.assertEqual(images(backends)[-1], THIRD)

    def test_successful_target_cannot_regress_to_origin_on_resume(self):
        backends, store, _, _, events = captured()
        original = images(backends)[0]
        backends[TARGET_IDS[2]][0].hooks["before-rename"] = failure
        self.assert_public(rollback(backends, store), "recovery-required")
        backend = backends["config"][0]
        backend.files[SESSION + "-rollback-0-tmp"], backend.files["config"] = backend.files["config"], original
        saved = list(events)
        self.assert_public(rollback(backends, store, resume=True), "recovery-required")
        self.assertEqual(events, saved)

    def test_return_requires_completed_rollback_and_preserved_displaced_evidence(self):
        backends, store, _, _, events = captured()
        self.assert_public(return_current(backends, store), "recovery-required")
        self.assert_public(rollback(backends, store), "completed")
        backends["config"][0].files[SESSION + "-rollback-0-tmp"] = THIRD
        saved = list(events)
        self.assert_public(return_current(backends, store), "recovery-required")
        self.assertEqual(events, saved)

    def test_return_interruption_resumes_without_restoring_old_guidance(self):
        backends, store, _, _, events = captured()
        original = images(backends)
        self.assert_public(rollback(backends, store), "completed")
        backends[TARGET_IDS[2]][0].hooks["after-rename"] = failure
        self.assert_public(return_current(backends, store), "recovery-required")
        self.assert_public(return_current(backends, store, resume=True), "completed")
        self.assertEqual([i.data for i in images(backends)], [i.data for i in original])
        self.assertEqual(images(backends)[1], original[1])

    def test_resume_is_bounded_and_never_overwrites_prior_completion(self):
        backends, store, _, _, events = captured()
        backends["config"][0].hooks["after-rename"] = failure
        rollback(backends, store)
        self.assert_public(rollback(backends, store, resume=True), "completed")
        saved, saved_events = dict(store.records), list(events)
        self.assert_public(rollback(backends, store, resume=True), "recovery-required")
        self.assertEqual(store.records, saved)
        self.assertEqual(events, saved_events)

    def test_failed_terminal_publication_retained_and_requires_resume(self):
        backends, store, _, _, events = captured()
        store.hooks["after:rollback.initial.terminal"] = failure
        self.assert_public(rollback(backends, store), "recovery-required")
        self.assertIn("rollback.initial.failure", store.records)
        self.assert_public(return_current(backends, store), "recovery-required")
        self.assert_public(rollback(backends, store, resume=True), "completed")
        self.assert_public(return_current(backends, store), "completed")

    def test_strict_private_records_bool_extra_duplicate_noncanonical_and_size(self):
        for defect in ("bool", "extra", "duplicate", "space", "oversize"):
            backends, store, _, _, events = captured()
            raw = store.records["capture"]
            if defect in ("bool", "extra"):
                value = json.loads(raw)
                value["schema" if defect == "bool" else "unexpected"] = True
                raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
            elif defect == "duplicate":
                raw = b'{"schema":1,' + raw[1:]
            elif defect == "space":
                raw = b" " + raw
            else:
                raw = b" " * (MAX_RECORD_BYTES + 1)
            store.records["capture"] = raw
            self.assert_public(rollback(backends, store), "recovery-required")
            self.assertEqual(events, [("persist", "capture")])

    def test_private_intent_schema_bool_is_not_integer(self):
        backends, store, _, _, events = captured()
        backends["config"][0].hooks["after-rename"] = failure
        rollback(backends, store)
        value = json.loads(store.records["rollback.initial.intent"])
        value["schema"] = True
        store.records["rollback.initial.intent"] = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        saved = list(events)
        self.assert_public(rollback(backends, store, resume=True), "recovery-required")
        self.assertEqual(events, saved)

    def test_store_drift_after_ticket_publication_blocks_rename(self):
        backends, store, _, _, events = captured()
        store.hooks["after:rollback.ticket.0"] = lambda s: s.records.update(capture=b"{}\n")
        self.assert_public(rollback(backends, store), "recovery-required")
        self.assertFalse(any(e[0] == "rename" for e in events))

    def test_partial_backend_image_and_owner_check_failure_are_redacted(self):
        for partial in (False, True):
            backends, store, _, _, events = captured()
            backend = backends["config"][0]
            if partial:
                backend.files["config"] = object.__new__(Image)
            else:
                backend.hooks["verify"] = failure
            self.assert_public(rollback(backends, store), "recovery-required")
            self.assertFalse(any(e[0] in ("rename", "create") for e in events))

    def test_capture_record_above_image_limit_uses_separate_bounded_store_channel(self):
        backends, store, before, after, events = fixture()
        large = b"x" * (900 * 1024)
        before["global-agents"] = Image(large, (2, 1), 0o600)
        after["global-agents"] = Image(large, (3, 1), 0o600)
        backends["global-agents"][0].files["global-agents"] = Image(large, (1, 1), 0o600)
        self.assert_public(capture(backends, store, before, after, session_id=SESSION), "captured")
        self.assertGreater(len(store.records["capture"]), 1024 * 1024)
        self.assertLess(len(store.records["capture"]), MAX_RECORD_BYTES)
        self.assert_public(verify(backends, store), "verified")
        self.assertEqual(events, [("persist", "capture")])

    def test_orphan_future_result_blocks_before_first_target_write(self):
        backends, store, _, _, events = captured()
        store.records["rollback.initial.result.7"] = b'{"schema":1,"succeeded":false}\n'
        self.assert_public(rollback(backends, store), "recovery-required")
        self.assertFalse(any(e[0] in ("rename", "create") for e in events))

    def test_final_whole_target_drift_prevents_completion(self):
        backends, store, _, _, events = captured()
        backends[TARGET_IDS[-1]][0].hooks["after-rename"] = lambda _: backends["config"][0].files.update(config=THIRD)
        self.assert_public(rollback(backends, store), "recovery-required")
        self.assertIs(json.loads(store.records["rollback.initial.terminal"])["completed"], False)
        self.assertEqual(images(backends)[0], THIRD)

    def test_failed_resume_is_retained_and_cannot_be_repeated(self):
        backends, store, _, _, events = captured()
        backends["config"][0].hooks["after-rename"] = failure
        rollback(backends, store)
        backends["config"][0].hooks["sync"] = failure
        self.assert_public(rollback(backends, store, resume=True), "recovery-required")
        saved, saved_events = dict(store.records), list(events)
        self.assert_public(rollback(backends, store, resume=True), "recovery-required")
        self.assertEqual(store.records, saved)
        self.assertEqual(events, saved_events)

    def test_pending_return_cannot_be_closed_by_rollback_noop(self):
        backends, store, _, _, events = captured()
        rollback(backends, store)
        store.hooks["before:return.ticket.0"] = failure
        self.assert_public(return_current(backends, store), "recovery-required")
        saved = list(events)
        self.assert_public(noop(backends, store, state="rollback"), "recovery-required")
        self.assertEqual(events, saved)

    def test_terminal_publication_target_store_and_aux_drift_both_actions(self):
        for action in ("rollback", "return"):
            for defect in ("target", "capture", "auxiliary", "rollback-auxiliary"):
                backends, store, _, _, events = captured()
                if action == "return":
                    self.assert_public(rollback(backends, store), "completed")
                name = action + ".initial.terminal"
                published = []

                def drift(s):
                    published.append(s.records[name])
                    if defect == "capture":
                        s.records["capture"] = b"{}\n"
                    elif defect == "target":
                        backends["config"][0].files["config"] = THIRD
                    else:
                        affected = "rollback" if defect == "rollback-auxiliary" else action
                        backends["config"][0].files[SESSION + "-" + affected + "-0-tmp"] = THIRD

                store.hooks["after:" + name] = drift
                operation = rollback if action == "rollback" else return_current
                self.assert_public(operation(backends, store), "recovery-required")
                self.assertEqual(store.records[name], published[0])
                self.assertIs(json.loads(store.records[name])["completed"], True)
                self.assertIn(action + ".initial.failure", store.records)
                self.assert_public(verify(backends, store, state=action), "recovery-required")
                if defect == "target":
                    self.assertEqual(images(backends)[0], THIRD)
                elif defect != "capture":
                    self.assertIn(THIRD, backends["config"][0].files.values())

    def test_postterminal_pinned_terminal_substitution_is_not_completed(self):
        for action in ("rollback", "return"):
            backends, store, _, _, events = captured()
            if action == "return":
                rollback(backends, store)
            name = action + ".initial.terminal"
            store.hooks["after:" + name] = lambda s: s.substitute(name, s.records[name])
            operation = rollback if action == "rollback" else return_current
            self.assert_public(operation(backends, store), "recovery-required")
            self.assertIn(action + ".initial.failure", store.records)

    def test_uncertain_capture_requires_connected_durability_barrier(self):
        backends, store, before, after, events = fixture()
        store.hooks["volatile:capture"] = failure
        self.assert_public(capture(backends, store, before, after, session_id=SESSION), "recovery-required")
        original_capture = store.records["capture"]
        self.assertIn("capture", store.volatile)
        self.assertNotIn("capture", store.durable)
        for operation in (verify, noop, rollback):
            store.hooks["sync:capture"] = failure
            self.assert_public(operation(backends, store), "recovery-required")
            self.assertIn("capture", store.volatile)
        self.assertEqual(events, [("persist", "capture")])
        self.assert_public(verify(backends, store), "verified")
        self.assertIn("capture", store.durable)
        self.assertNotIn("capture", store.volatile)
        self.assertEqual(store.records["capture"], original_capture)
        self.assertGreaterEqual(store.sync_calls.count("capture"), 4)

    def test_volatile_ticket_resume_blocks_until_same_record_is_synced(self):
        for action in ("rollback", "return"):
            backends, store, _, _, events = captured()
            if action == "return":
                rollback(backends, store)
            name = action + ".ticket.0"
            operation = rollback if action == "rollback" else return_current
            store.hooks["volatile:" + name] = failure
            self.assert_public(operation(backends, store), "recovery-required")
            ticket, initial_failure = store.records[name], store.records[action + ".initial.failure"]
            self.assertIn(name, store.volatile)
            saved_events = list(events)
            store.hooks["sync:" + name] = failure
            self.assert_public(operation(backends, store, resume=True), "recovery-required")
            self.assertEqual(events, saved_events)
            self.assertNotIn(action + ".resume.intent", store.records)
            self.assertIn(name, store.volatile)
            self.assert_public(operation(backends, store, resume=True), "completed")
            self.assertIn(name, store.durable)
            self.assertNotIn(name, store.volatile)
            self.assertEqual(store.records[name], ticket)
            self.assertEqual(store.records[action + ".initial.failure"], initial_failure)
            self.assertEqual(events.count(("create", 0)), 1 if action == "rollback" else 2)

    def test_present_record_substitution_around_barrier_blocks_consumption(self):
        for moment in ("before-sync:", "after-sync:"):
            for same_bytes in (False, True):
                backends, store, _, _, events = captured()
                store.hooks[moment + "capture"] = lambda s: s.substitute(
                    "capture", s.records["capture"] if same_bytes else b"{}\n")
                self.assert_public(rollback(backends, store), "recovery-required")
                self.assertEqual(events, [("persist", "capture")])

    def test_paired_read_after_barrier_catches_late_byte_and_identity_drift(self):
        for same_bytes in (False, True):
            backends, store, _, _, events = captured()

            def after_barrier(s):
                s.hooks["read:capture"] = lambda current: current.substitute(
                    "capture", current.records["capture"] if same_bytes else b"{}\n")

            store.hooks["after-sync:capture"] = after_barrier
            self.assert_public(verify(backends, store), "recovery-required")
            self.assertEqual(events, [("persist", "capture")])

    def test_uncertain_ticket_identity_substitution_never_resumes_rename(self):
        backends, store, _, _, events = captured()
        name = "rollback.ticket.0"
        store.hooks["volatile:" + name] = failure
        rollback(backends, store)
        saved_events = list(events)
        store.hooks["before-sync:" + name] = lambda s: s.substitute(name, s.records[name])
        self.assert_public(rollback(backends, store, resume=True), "recovery-required")
        self.assertEqual(events, saved_events)
        self.assertIn(name, store.volatile)

    def test_no_store_barrier_method_cannot_accept_readable_capture(self):
        backends, store, _, _, events = captured()
        store.sync_record = None
        self.assert_public(verify(backends, store), "recovery-required")
        self.assert_public(rollback(backends, store), "recovery-required")
        self.assertEqual(events, [("persist", "capture")])

    def test_noop_rechecks_completed_auxiliaries_after_target_sync(self):
        for state, affected in (("rollback", "rollback"), ("return", "return"),
                                 ("return", "rollback")):
            backends, store, _, _, events = captured()
            self.assert_public(rollback(backends, store), "completed")
            if state == "return":
                self.assert_public(return_current(backends, store), "completed")
            original, saved, saved_events = images(backends), dict(store.records), list(events)
            name = SESSION + "-" + affected + "-0-tmp"
            backend = backends["config"][0]
            backend.hooks["sync"] = lambda b: b.files.update({name: THIRD})
            self.assert_public(noop(backends, store, state=state), "recovery-required")
            self.assertEqual(backend.files[name], THIRD)
            self.assertEqual(images(backends), original)
            self.assertEqual(store.records, saved)
            self.assertEqual(events, saved_events)

    def test_verify_rechecks_completed_auxiliaries_after_record_barrier(self):
        for state, affected in (("rollback", "rollback"), ("return", "return"),
                                 ("return", "rollback")):
            backends, store, _, _, events = captured()
            self.assert_public(rollback(backends, store), "completed")
            if state == "return":
                self.assert_public(return_current(backends, store), "completed")
            original, saved, saved_events = images(backends), dict(store.records), list(events)
            name = SESSION + "-" + affected + "-0-tmp"
            backend = backends["config"][0]

            def arm_final_barrier(s):
                # First capture barrier is its load; second is records.check(),
                # after the initial completed-action auxiliary observations.
                s.hooks["after-sync:capture"] = lambda _: backend.files.update({name: THIRD})

            store.hooks["after-sync:capture"] = arm_final_barrier
            self.assert_public(verify(backends, store, state=state), "recovery-required")
            self.assertEqual(backend.files[name], THIRD)
            self.assertEqual(images(backends), original)
            self.assertEqual(store.records, saved)
            self.assertEqual(events, saved_events)


if __name__ == "__main__":
    unittest.main()
