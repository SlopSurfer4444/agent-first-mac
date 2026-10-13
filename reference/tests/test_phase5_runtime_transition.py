"""Fake-syscall tests only; no production paths, imports or native execution."""

from pathlib import Path
import json
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.phase5_runtime_transition import (  # noqa: E402
    ABSENT, Image, Ticket, TransitionError, classify, prepare, recover, transition,
)


OLD = Image(b"private-old", (1, 10), 0o600, b"owner-envelope")
THIRD = Image(b"private-third-state", (1, 30), 0o600, b"owner-envelope")


class FakeBackend:
    """One held directory, atomic dictionary renames, injected boundary races."""
    def __init__(self, source=OLD):
        self.files = {} if source == ABSENT else {"target": source}
        self.events, self.hooks = [], {}
        self.next_inode = 100
        self.sync_count = 0

    def on(self, event, action):
        self.hooks[event] = action

    def fire(self, event):
        action = self.hooks.pop(event, None)
        if action:
            action(self)

    def verify(self):
        self.fire("verify")

    def snapshot(self, name):
        self.fire("snapshot:" + name)
        return self.files.get(name, ABSENT)

    def create_exclusive(self, name, data, mode):
        self.fire("before-create")
        if name in self.files:
            raise FileExistsError("private collision")
        image = Image(data, (1, self.next_inode), mode, b"owner-envelope")
        self.next_inode += 1
        self.files[name] = image
        self.events.append(("create", name))
        self.fire("after-create")
        return image

    def swap(self, a, b):
        self.fire("before-swap")
        if a not in self.files or b not in self.files:
            raise FileNotFoundError("private missing name")
        self.files[a], self.files[b] = self.files[b], self.files[a]
        self.events.append(("swap", a, b))
        self.fire("after-swap")

    def move_exclusive(self, a, b):
        self.fire("before-move")
        if b in self.files:
            raise FileExistsError("private collision")
        self.files[b] = self.files.pop(a)
        self.events.append(("move", a, b))
        self.fire("after-move")

    def sync(self):
        self.sync_count += 1
        self.fire("sync")


def stage(backend, source=OLD, data=b"private-new", mode=0o600):
    return prepare(backend, target="target", temporary="owned-temp", recovery="owned-recovery",
                   source=source, destination_bytes=data, mode=mode)


def fail(_backend):
    raise OSError("private error path must not escape")


class RuntimeTransitionTests(unittest.TestCase):
    def assert_public(self, value, verdict):
        self.assertEqual(value["verdict"], verdict)
        self.assertIs(value["executionAdmission"], False)
        self.assertIs(value["cleanupPerformed"], False)
        self.assertNotIn("private", json.dumps(value))
        self.assertNotIn("owned-temp", json.dumps(value))
        return value

    def test_replace_compensate_return_retains_both_images(self):
        backend = FakeBackend()
        ticket = stage(backend)
        self.assertEqual(backend.files["target"], OLD)
        self.assert_public(classify(backend, ticket), "origin")
        self.assert_public(transition(backend, ticket), "completed")
        self.assertEqual(backend.files["owned-temp"], OLD)
        self.assertEqual(backend.files["target"], ticket.destination)
        self.assert_public(recover(backend, ticket), "recovered")
        self.assertEqual(backend.files["target"], OLD)
        self.assertEqual(backend.files["owned-temp"], ticket.destination)
        self.assert_public(transition(backend, ticket), "completed")
        self.assertEqual(sum(e[0] == "swap" for e in backend.events), 3)

    def test_absent_create_and_compensate_never_unlinks(self):
        backend = FakeBackend(ABSENT)
        ticket = stage(backend, source=ABSENT)
        self.assert_public(transition(backend, ticket), "completed")
        self.assert_public(recover(backend, ticket), "recovered")
        self.assertNotIn("target", backend.files)
        self.assertEqual(backend.files["owned-recovery"], ticket.destination)
        self.assert_public(classify(backend, ticket), "recovered")
        self.assert_public(transition(backend, ticket), "recovery-required")

    def test_existing_to_absent_and_return(self):
        backend = FakeBackend()
        ticket = stage(backend, data=None, mode=None)
        self.assertEqual(backend.events, [])
        self.assert_public(transition(backend, ticket), "completed")
        self.assertEqual(backend.files, {"owned-temp": OLD})
        self.assert_public(recover(backend, ticket), "recovered")
        self.assertEqual(backend.files, {"target": OLD})

    def test_present_and_absent_noops_create_nothing(self):
        for source in (OLD, ABSENT):
            backend = FakeBackend(source)
            ticket = stage(backend, source=source, data=source.data, mode=source.mode)
            self.assertTrue(ticket.noop)
            self.assert_public(transition(backend, ticket), "noop")
            self.assert_public(recover(backend, ticket), "noop")
            self.assertEqual(backend.events, [])

    def test_mode_change_not_a_noop(self):
        backend = FakeBackend()
        ticket = stage(backend, data=OLD.data, mode=0o644)
        self.assertFalse(ticket.noop)
        self.assert_public(transition(backend, ticket), "completed")
        self.assertEqual(backend.files["target"].mode, 0o644)

    def test_already_destination_is_read_only_noop(self):
        backend = FakeBackend()
        ticket = stage(backend)
        transition(backend, ticket)
        events = list(backend.events)
        self.assert_public(transition(backend, ticket), "noop")
        self.assertEqual(backend.events, events)

    def test_third_state_before_staging_zero_creates(self):
        backend = FakeBackend(THIRD)
        with self.assertRaisesRegex(TransitionError, "^transition_preparation_recovery_required$"):
            stage(backend)
        self.assertEqual(backend.files, {"target": THIRD})
        self.assertEqual(backend.events, [])

    def test_third_state_during_create_is_retained_with_staging(self):
        backend = FakeBackend()
        backend.on("before-create", lambda b: b.files.update(target=THIRD))
        with self.assertRaises(TransitionError):
            stage(backend)
        self.assertEqual(backend.files["target"], THIRD)
        self.assertIn("owned-temp", backend.files)
        self.assertEqual([e[0] for e in backend.events], ["create"])

    def test_partial_create_failure_never_cleans_up(self):
        backend = FakeBackend()
        backend.on("after-create", fail)
        with self.assertRaisesRegex(TransitionError, "^transition_preparation_recovery_required$"):
            stage(backend)
        self.assertIn("owned-temp", backend.files)
        self.assertEqual(backend.files["target"], OLD)

    def test_create_collision_preserves_unknown_owned_name(self):
        backend = FakeBackend()
        backend.on("before-create", lambda b: b.files.update({"owned-temp": THIRD}))
        with self.assertRaises(TransitionError):
            stage(backend)
        self.assertEqual(backend.files, {"target": OLD, "owned-temp": THIRD})

    def test_observed_third_state_before_forward_no_rename(self):
        backend = FakeBackend()
        ticket = stage(backend)
        backend.files["target"] = THIRD
        before = dict(backend.files)
        self.assert_public(transition(backend, ticket), "recovery-required")
        self.assertEqual(backend.files, before)
        self.assertEqual(len(backend.events), 1)

    def test_inode_only_substitution_and_metadata_seal_are_unknown(self):
        for substitute in (Image(OLD.data, (1, 99), OLD.mode, OLD.seal),
                           Image(OLD.data, OLD.identity, OLD.mode, b"changed-metadata")):
            backend = FakeBackend()
            ticket = stage(backend)
            backend.files["target"] = substitute
            self.assert_public(transition(backend, ticket), "recovery-required")
            self.assertEqual(backend.files["target"], substitute)

    def test_backend_owner_or_parent_failure_blocks(self):
        for event in ("verify", "snapshot:target"):
            backend = FakeBackend()
            ticket = stage(backend)
            backend.on(event, fail)
            self.assert_public(transition(backend, ticket), "recovery-required")
            self.assertEqual(backend.files["target"], OLD)
            self.assertEqual(len(backend.events), 1)

    def test_pair_observation_drift_blocks_before_rename(self):
        backend = FakeBackend()
        ticket = stage(backend)
        backend.on("snapshot:owned-recovery", lambda b: b.files.update(target=THIRD))
        self.assert_public(transition(backend, ticket), "recovery-required")
        self.assertEqual(backend.files["target"], THIRD)
        self.assertEqual(len(backend.events), 1)

    def test_unobserved_staging_name_race_retains_both_displaced_images(self):
        backend = FakeBackend()
        ticket = stage(backend)
        backend.on("before-swap", lambda b: b.files.update({"owned-temp": THIRD}))
        self.assert_public(transition(backend, ticket), "recovery-required")
        self.assertEqual(backend.files, {"target": THIRD, "owned-temp": OLD})

    def test_unobserved_preswap_race_retains_displaced_third_not_cas(self):
        backend = FakeBackend()
        ticket = stage(backend)
        backend.on("before-swap", lambda b: b.files.update(target=THIRD))
        self.assert_public(transition(backend, ticket), "recovery-required")
        self.assertEqual(backend.files["owned-temp"], THIRD)
        self.assertEqual(backend.files["target"], ticket.destination)
        events = list(backend.events)
        self.assert_public(recover(backend, ticket), "recovery-required")
        self.assertEqual(backend.events, events)

    def test_postswap_third_current_and_displaced_source_both_preserved(self):
        backend = FakeBackend()
        ticket = stage(backend)
        backend.on("after-swap", lambda b: b.files.update(target=THIRD))
        self.assert_public(transition(backend, ticket), "recovery-required")
        self.assertEqual(backend.files, {"target": THIRD, "owned-temp": OLD})
        self.assert_public(recover(backend, ticket), "recovery-required")
        self.assertEqual(backend.files, {"target": THIRD, "owned-temp": OLD})

    def test_third_observed_before_compensation_is_not_swapped(self):
        for name in ("target", "owned-temp", "owned-recovery"):
            backend = FakeBackend()
            ticket = stage(backend)
            transition(backend, ticket)
            backend.files[name] = THIRD
            before, events = dict(backend.files), list(backend.events)
            self.assert_public(recover(backend, ticket), "recovery-required")
            self.assertEqual(backend.files, before)
            self.assertEqual(backend.events, events)

    def test_unobserved_race_during_compensation_retains_third(self):
        backend = FakeBackend()
        ticket = stage(backend)
        transition(backend, ticket)
        backend.on("before-swap", lambda b: b.files.update(target=THIRD))
        self.assert_public(recover(backend, ticket), "recovery-required")
        self.assertEqual(backend.files, {"target": OLD, "owned-temp": THIRD})
        self.assertEqual(sum(e[0] == "swap" for e in backend.events), 2)

    def test_postcompensation_third_state_never_triggers_second_compensation(self):
        backend = FakeBackend()
        ticket = stage(backend)
        transition(backend, ticket)
        backend.on("after-swap", lambda b: b.files.update(target=THIRD))
        self.assert_public(recover(backend, ticket), "recovery-required")
        self.assertEqual(backend.files, {"target": THIRD, "owned-temp": ticket.destination})
        events = list(backend.events)
        self.assert_public(recover(backend, ticket), "recovery-required")
        self.assertEqual(backend.events, events)

    def test_absent_to_present_race_exclusive_does_not_overwrite(self):
        backend = FakeBackend(ABSENT)
        ticket = stage(backend, source=ABSENT)
        backend.on("before-move", lambda b: b.files.update(target=THIRD))
        self.assert_public(transition(backend, ticket), "recovery-required")
        self.assertEqual(backend.files["target"], THIRD)
        self.assertEqual(backend.files["owned-temp"], ticket.destination)
        self.assertFalse(any(e[0] == "move" for e in backend.events))

    def test_remove_race_retains_unknown_in_temporary(self):
        backend = FakeBackend()
        ticket = stage(backend, data=None, mode=None)
        backend.on("before-move", lambda b: b.files.update(target=THIRD))
        self.assert_public(transition(backend, ticket), "recovery-required")
        self.assertEqual(backend.files, {"owned-temp": THIRD})
        self.assert_public(recover(backend, ticket), "recovery-required")
        self.assertEqual(backend.files, {"owned-temp": THIRD})

    def test_remove_compensation_collision_preserves_new_target(self):
        backend = FakeBackend()
        ticket = stage(backend, data=None, mode=None)
        transition(backend, ticket)
        backend.on("before-move", lambda b: b.files.update(target=THIRD))
        self.assert_public(recover(backend, ticket), "recovery-required")
        self.assertEqual(backend.files, {"target": THIRD, "owned-temp": OLD})

    def test_create_compensation_recovery_name_collision_preserves_both(self):
        backend = FakeBackend(ABSENT)
        ticket = stage(backend, source=ABSENT)
        transition(backend, ticket)
        backend.on("before-move", lambda b: b.files.update({"owned-recovery": THIRD}))
        self.assert_public(recover(backend, ticket), "recovery-required")
        self.assertEqual(backend.files, {"target": ticket.destination, "owned-recovery": THIRD})

    def test_rename_interruption_classify_then_explicit_recover(self):
        backend = FakeBackend()
        ticket = stage(backend)
        backend.on("after-swap", fail)
        self.assert_public(transition(backend, ticket), "recovery-required")
        self.assert_public(classify(backend, ticket), "destination")
        self.assert_public(recover(backend, ticket), "recovered")
        self.assertEqual(backend.files["target"], OLD)

    def test_postrename_fsync_failure_retains_evidence(self):
        backend = FakeBackend()
        ticket = stage(backend)
        backend.on("sync", fail)
        self.assert_public(transition(backend, ticket), "recovery-required")
        self.assertEqual(backend.files["owned-temp"], OLD)
        self.assertEqual(backend.files["target"], ticket.destination)

    def test_forward_failure_before_rename_can_be_observed_as_origin(self):
        backend = FakeBackend()
        ticket = stage(backend)
        backend.on("before-swap", fail)
        self.assert_public(transition(backend, ticket), "recovery-required")
        self.assert_public(classify(backend, ticket), "origin")
        self.assert_public(recover(backend, ticket), "noop")

    def test_input_names_types_and_private_repr(self):
        backend = FakeBackend()
        for name in ("../target", "/private/target", ".", "..", "a/b", ""):
            with self.assertRaisesRegex(TransitionError, "^transition_input_invalid$"):
                prepare(backend, target=name, temporary="tmp", recovery="rec", source=OLD,
                        destination_bytes=b"new", mode=0o600)
        for values in ((b"x", (True, 1), 0o600), (b"x", (1, 1), True),
                       (None, (1, 1), None), (bytearray(b"x"), (1, 1), 0o600)):
            with self.assertRaises(TransitionError):
                Image(*values)
        ticket = stage(backend)
        self.assertNotIn("private-old", repr(OLD))
        self.assertNotIn("target", repr(ticket))
        self.assert_public(transition(backend, None), "recovery-required")
        self.assertEqual(len(backend.events), 1)

    def test_inconsistent_private_ticket_is_not_a_transition(self):
        backend = FakeBackend()
        for destination, noop in ((OLD, False), (ABSENT, True),
                                  (Image(b"new", OLD.identity, OLD.mode), False)):
            ticket = Ticket("target", "owned-temp", "owned-recovery", OLD, destination, noop)
            self.assert_public(transition(backend, ticket), "recovery-required")
        self.assertEqual(backend.events, [])

    def test_partial_and_corrupted_tickets_fail_before_backend_calls(self):
        fields = dict(target="target", temporary="owned-temp", recovery="owned-recovery",
                      source=OLD, destination=ABSENT, noop=False)
        cases = [dict((k, v) for k, v in fields.items() if k != missing) for missing in fields]
        for key, value in (("target", 1), ("temporary", None), ("recovery", []),
                           ("source", object.__new__(Image)), ("destination", None),
                           ("noop", 1), ("extra", True)):
            cases.append(dict(fields, **{key: value}))
        for values in cases:
            ticket = object.__new__(Ticket)
            vars(ticket).update(values)
            backend = FakeBackend()
            backend.verify = lambda: backend.events.append(("unexpected-verify",))
            for operation in (classify, transition, recover):
                result = self.assert_public(operation(backend, ticket), "recovery-required")
                self.assertEqual(result["reason"], "ticket-invalid")
            self.assertEqual(backend.events, [])

    def test_restored_images_validate_all_fields_without_private_object_methods(self):
        class Poison:
            def __repr__(self):
                raise AssertionError("repr must not run")

            def __eq__(self, other):
                raise AssertionError("equality must not run")

        fields = vars(OLD)
        cases = [dict((k, v) for k, v in fields.items() if k != missing) for missing in fields]
        for key, value in (("data", Poison()), ("identity", (True, 10)),
                           ("identity", (1, Poison())), ("mode", True), ("seal", Poison()),
                           ("extra", None), ("data", None)):
            cases.append(dict(fields, **{key: value}))
        for values in cases:
            malformed = object.__new__(Image)
            vars(malformed).update(values)
            backend = FakeBackend()
            with self.assertRaisesRegex(TransitionError, "^transition_input_invalid$"):
                stage(backend, source=malformed)
            self.assertEqual(backend.events, [])
            for source, destination in ((malformed, ABSENT), (OLD, malformed)):
                ticket = Ticket("target", "owned-temp", "owned-recovery", source, destination, False)
                for operation in (classify, transition, recover):
                    self.assertEqual(operation(backend, ticket)["reason"], "ticket-invalid")

    def test_partial_backend_observations_are_redacted_and_never_renamed(self):
        backend = FakeBackend()
        ticket = stage(backend)
        backend.files["target"] = object.__new__(Image)
        events = list(backend.events)
        for operation in (classify, transition, recover):
            self.assert_public(operation(backend, ticket), "recovery-required")
        with self.assertRaisesRegex(TransitionError, "^transition_preparation_recovery_required$"):
            stage(backend)
        self.assertEqual(backend.events, events)

    def test_partial_staging_result_retains_created_image(self):
        backend = FakeBackend()
        original_create = backend.create_exclusive

        def partial_result(*args):
            original_create(*args)
            return object.__new__(Image)

        backend.create_exclusive = partial_result
        with self.assertRaisesRegex(TransitionError, "^transition_preparation_recovery_required$"):
            stage(backend)
        self.assertEqual(backend.files["target"], OLD)
        self.assertIn("owned-temp", backend.files)
        self.assertEqual([e[0] for e in backend.events], ["create"])

    def test_postrename_sync_failure_cannot_close_via_unsynced_noop_either_direction(self):
        for source, data, mode in ((OLD, b"new", 0o600), (ABSENT, b"new", 0o600),
                                   (OLD, None, None)):
            for returning in (False, True):
                backend = FakeBackend(source)
                ticket = stage(backend, source=source, data=data, mode=mode)
                if returning:
                    self.assert_public(transition(backend, ticket), "completed")
                operation = recover if returning else transition
                backend.on("sync", fail)
                self.assert_public(operation(backend, ticket), "recovery-required")
                files, events = dict(backend.files), list(backend.events)
                syncs = backend.sync_count
                backend.on("sync", fail)
                self.assert_public(operation(backend, ticket), "recovery-required")
                self.assertEqual(backend.sync_count, syncs + 1)
                self.assertEqual(backend.files, files)
                self.assertEqual(backend.events, events)
                self.assert_public(operation(backend, ticket), "noop")
                self.assertEqual(backend.sync_count, syncs + 2)
                self.assertEqual(backend.events, events)

    def test_existing_present_and_absent_noops_require_sync_and_recheck(self):
        for source in (OLD, ABSENT):
            for operation in (transition, recover):
                backend = FakeBackend(source)
                ticket = stage(backend, source=source, data=source.data, mode=source.mode)
                backend.on("sync", fail)
                self.assert_public(operation(backend, ticket), "recovery-required")
                backend.on("sync", lambda b: b.files.update(target=THIRD))
                result = self.assert_public(operation(backend, ticket), "recovery-required")
                self.assertEqual(result["reason"], "post-sync-drift")
                self.assertEqual(backend.files["target"], THIRD)
                self.assertEqual(backend.events, [])

    def test_destination_origin_and_recovered_noop_sync_drift_preserves_evidence(self):
        for state in ("destination", "origin", "recovered"):
            backend = FakeBackend(ABSENT if state == "recovered" else OLD)
            ticket = stage(backend, source=ABSENT if state == "recovered" else OLD)
            if state != "origin":
                transition(backend, ticket)
            if state == "recovered":
                recover(backend, ticket)
            events, files = list(backend.events), dict(backend.files)
            backend.on("sync", lambda b: b.files.update(target=THIRD))
            operation = transition if state == "destination" else recover
            result = self.assert_public(operation(backend, ticket), "recovery-required")
            self.assertEqual(result["reason"], "post-sync-drift")
            self.assertEqual(backend.files, dict(files, target=THIRD))
            self.assertEqual(backend.events, events)


if __name__ == "__main__":
    unittest.main()
