"""Actual OwnedParent/DescriptorBackend over fake OS only; no native fixtures."""

import copy
import importlib.util
from pathlib import Path
import stat
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import phase5_trusted_files as files
from lib import phase5_runtime_paths as paths
from lib import phase5_runtime_backend as backend

spec = importlib.util.spec_from_file_location("trusted_file_fakes", ROOT / "tests/test_phase5_runtime_targets.py")
fakes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fakes)
HOME, LEAF = "/Users/owner", "phase5-trusted-task.Abc123"
SCRATCH = HOME + "/AIDev/scratch"
CHILD = SCRATCH + "/" + LEAF
SCHEMA, RESULT = CHILD + "/schema.json", CHILD + "/result.json"
SCHEMA_BYTES = b'{"type":"object","properties":{"ok":{"type":"boolean"}}}\n'


class FakeOS(fakes.TransitionOS):
    def mkdir(self, leaf, mode, *, dir_fd):
        target = self.path(leaf, dir_fd)
        self.event("mkdir", target)
        assert target == CHILD and mode == 0o700
        if target in self.nodes:
            raise FileExistsError("private child")
        self.add(target, directory=True, mode=mode)
        self.event("created-directory", target)

    def unlink(self, leaf, *, dir_fd):
        target = self.path(leaf, dir_fd)
        self.event("unlink", target)
        assert target in (SCHEMA, RESULT)
        del self.nodes[target]
        self.event("unlinked", target)

    def rmdir(self, leaf, *, dir_fd):
        target = self.path(leaf, dir_fd)
        self.event("rmdir", target)
        assert target == CHILD
        assert not any(path.startswith(target + "/") for path in self.nodes)
        del self.nodes[target]
        self.event("removed-directory", target)


def fixture():
    fake = FakeOS()
    fake.add("/", directory=True, mode=0o755)
    for name in ("/Users", HOME, HOME + "/AIDev", SCRATCH):
        fake.add(name, directory=True, mode=0o750 if name == HOME else 0o755)
    return fake, fakes.Metadata(fake)


class TrustedFilesTests(unittest.TestCase):
    def allocate(self, fake, metadata, **changes):
        arguments = dict(home=HOME, uid=501, leaf=LEAF, schema=SCHEMA_BYTES,
                         admit_sources=lambda: True, paths=paths, backend=backend,
                         syscalls=fake, platform=metadata)
        arguments.update(changes)
        return files.allocate(**arguments)

    def denied(self, operation, owner=None):
        with self.assertRaises(files.TrustedFilesError) as caught:
            operation()
        self.assertEqual(str(caught.exception), "trusted_files_recovery_required")
        self.assertIs(caught.exception.private_owner, owner)
        self.assertNotIn("owner", repr(caught.exception))
        return caught.exception

    def result(self, fake, owner, raw=b'{"ok":true}\n'):
        fake.nodes[RESULT]["data"] = raw
        fake.nodes[RESULT]["st_mtime_ns"] += 1
        fake.nodes[RESULT]["st_ctime_ns"] += 1
        return owner.result(child_settled=True)

    def test_exact_private_files_held_initial_result_and_cleanup(self):
        fake, metadata = fixture()
        original = copy.deepcopy(fake.nodes)
        owner = self.allocate(fake, metadata)
        self.assertEqual(owner.directory_path, CHILD)
        self.assertEqual(owner.schema_path, SCHEMA)
        self.assertEqual(owner.result_path, RESULT)
        self.assertTrue(owner.verify_initial())
        self.assertEqual(set(fake.nodes) - set(original), {CHILD, SCHEMA, RESULT})
        self.assertEqual(fake.nodes[SCHEMA]["data"], SCHEMA_BYTES)
        self.assertEqual(fake.nodes[RESULT]["data"], b"")
        self.assertEqual(stat.S_IMODE(fake.nodes[CHILD]["st_mode"]), 0o700)
        self.assertTrue(all(stat.S_IMODE(fake.nodes[path]["st_mode"]) == 0o600 for path in (SCHEMA, RESULT)))
        observed = self.result(fake, owner)
        self.assertEqual(observed.data, b'{"ok":true}\n')
        self.assertNotIn("ok", repr(observed))
        self.assertNotIn(CHILD, repr(owner))
        result = owner.cleanup(observed, child_settled=True)
        self.assertEqual(result["filesRemoved"], 2)
        self.assertTrue(result["directoryRemoved"] and result["handlesClosed"])
        self.assertEqual(fake.nodes, original)
        self.assertEqual(fake.handles, {})
        self.assertEqual([path for op, path in fake.calls if op == "unlink"], [SCHEMA, RESULT])
        self.assertEqual([path for op, path in fake.calls if op == "rmdir"], [CHILD])

    def test_wrong_paths_uid_schema_or_admission_never_mutate(self):
        for changes in ({"home": "/"}, {"home": HOME + "/.."}, {"uid": True}, {"uid": 0},
                        {"leaf": ".."}, {"leaf": LEAF + "/extra"}, {"schema": b""},
                        {"schema": b"{}"}, {"schema": b"[]"}, {"schema": b'{"x":1,"x":2}'},
                        {"schema": b'{"x":NaN}'}, {"schema": b"x" * (files.MAX_BYTES + 1)},
                        {"admit_sources": lambda: 1}, {"admit_sources": lambda: False}):
            fake, metadata = fixture()
            self.denied(lambda: self.allocate(fake, metadata, **changes))
            self.assertEqual(fake.calls, [])

    def test_existing_directory_not_adopted_or_deleted(self):
        fake, metadata = fixture()
        fake.add(CHILD, directory=True)
        original = copy.deepcopy(fake.nodes)
        with self.assertRaises(files.TrustedFilesError) as caught:
            self.allocate(fake, metadata)
        owner = caught.exception.private_owner
        self.assertIsNotNone(owner)
        self.assertEqual(fake.nodes, original)
        self.assertFalse(any(op in ("unlink", "rmdir") for op, _ in fake.calls))
        self.denied(owner.close, owner)
        self.assertEqual(fake.handles, {})

    def test_ambiguous_mkdir_keeps_private_context_and_no_retry(self):
        fake, metadata = fixture()
        interrupted = KeyboardInterrupt()
        fake.effects["created-directory", CHILD] = interrupted
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.allocate(fake, metadata)
        self.assertIs(caught.exception, interrupted)
        owner = interrupted.private_owner
        self.assertIn(CHILD, fake.nodes)
        self.assertEqual(sum(op == "mkdir" for op, _ in fake.calls), 1)
        self.assertFalse(any(op in ("write", "unlink", "rmdir") for op, _ in fake.calls))
        with self.assertRaises(KeyboardInterrupt):
            owner.close()
        self.assertEqual(fake.handles, {})

    def test_partial_write_retained_without_cleanup(self):
        for target in (SCHEMA, RESULT):
            fake, metadata = fixture()
            fake.effects["fchmod", target] = OSError("private partial creation")
            with self.assertRaises(files.TrustedFilesError) as caught:
                self.allocate(fake, metadata)
            owner = caught.exception.private_owner
            self.assertIn(target, fake.nodes)
            self.assertIsNotNone(owner._error)
            self.assertFalse(any(op in ("unlink", "rmdir") for op, _ in fake.calls))
            self.denied(owner.close, owner)
            self.assertEqual(fake.handles, {})

    def test_no_payload_before_empty_file_metadata_admission(self):
        for target in (SCHEMA, RESULT):
            fake, metadata = fixture()
            fake.effects["created", target] = lambda _: metadata.set(target, 1, ())
            with self.assertRaises(files.TrustedFilesError) as caught:
                self.allocate(fake, metadata)
            self.assertEqual(fake.nodes[target]["data"], b"")
            self.assertFalse(any(op == "write" and path == target for op, path in fake.calls))
            self.denied(caught.exception.private_owner.close, caught.exception.private_owner)

    def test_new_directory_metadata_or_identity_drift_blocks(self):
        for mutate in (lambda fake, metadata: metadata.set(CHILD, 1, ()),
                       lambda fake, metadata: metadata.set(CHILD, 0, ("com.fake.private",))):
            fake, metadata = fixture()
            fake.effects["created-directory", CHILD] = lambda _: mutate(fake, metadata)
            with self.assertRaises(files.TrustedFilesError):
                self.allocate(fake, metadata)
            self.assertFalse(any(op in ("write", "unlink", "rmdir") for op, _ in fake.calls))
        fake, metadata = fixture()
        def replace_on_open(_):
            fake.nodes[CHILD] = dict(fake.nodes[CHILD], st_ino=9999)
        fake.effects["open", CHILD] = replace_on_open
        with self.assertRaises(files.TrustedFilesError):
            self.allocate(fake, metadata)
        self.assertFalse(any(op == "write" for op, _ in fake.calls))

    def test_result_not_returned_without_exact_settlement(self):
        for settled in (False, None, 1, "yes"):
            fake, metadata = fixture()
            owner = self.allocate(fake, metadata)
            before_calls = list(fake.calls)
            self.denied(lambda: owner.result(child_settled=settled), owner)
            self.assertEqual(fake.calls, before_calls)

    def test_cleanup_denied_before_settlement_without_mutation(self):
        for settled in (False, None, 1):
            fake, metadata = fixture()
            owner = self.allocate(fake, metadata)
            observed = self.result(fake, owner)
            original = copy.deepcopy(fake.nodes)
            self.denied(lambda: owner.cleanup(observed, child_settled=settled), owner)
            self.assertEqual(fake.nodes, original)
            self.assertFalse(any(op in ("unlink", "rmdir") for op, _ in fake.calls))

    def test_schema_and_result_drift_rejected_without_deletion(self):
        for target in (SCHEMA, RESULT):
            for change in ({"st_ino": 99999}, {"st_mode": stat.S_IFREG | 0o644}, {"st_uid": 502},
                           {"st_gid": 21}, {"st_nlink": 2}, {"st_flags": 1},
                           {"st_mode": stat.S_IFLNK | 0o600}, {"data": b"x" * (files.MAX_BYTES + 1)}):
                fake, metadata = fixture()
                owner = self.allocate(fake, metadata)
                fake.nodes[target].update(change)
                self.denied(lambda: owner.result(child_settled=True), owner)
                self.assertFalse(any(op in ("unlink", "rmdir") for op, _ in fake.calls))
        for change in ({"data": b'{"type":"string"}'}, {"st_ctime_ns": 9999}):
            fake, metadata = fixture()
            owner = self.allocate(fake, metadata)
            fake.nodes[SCHEMA].update(change)
            self.denied(lambda: owner.result(child_settled=True), owner)

    def test_result_replacement_even_equal_bytes_is_not_admitted(self):
        fake, metadata = fixture()
        owner = self.allocate(fake, metadata)
        fake.nodes[RESULT] = dict(fake.nodes[RESULT], st_ino=99999)
        self.denied(lambda: owner.result(child_settled=True), owner)

    def test_private_file_envelope_drift_blocks_result_and_cleanup(self):
        for target in (SCHEMA, RESULT):
            for acl, xattrs in ((1, ()), (0, ("com.fake.private",))):
                for cleanup in (False, True):
                    fake, metadata = fixture()
                    owner = self.allocate(fake, metadata)
                    observed = self.result(fake, owner) if cleanup else None
                    metadata.set(target, acl, xattrs)
                    original = copy.deepcopy(fake.nodes)
                    operation = (lambda: owner.cleanup(observed, child_settled=True)) if cleanup else (
                        lambda: owner.result(child_settled=True))
                    self.denied(operation, owner)
                    self.assertEqual(fake.nodes, original)
                    self.assertFalse(any(op in ("unlink", "rmdir") for op, _ in fake.calls))

    def test_changed_snapshot_or_third_file_blocks_cleanup(self):
        for mutation in (lambda f: f.nodes[RESULT].update(data=b"different"),
                         lambda f: f.nodes[RESULT].update(st_ctime_ns=9999),
                         lambda f: f.add(CHILD + "/third", b"unrelated")):
            fake, metadata = fixture()
            owner = self.allocate(fake, metadata)
            observed = self.result(fake, owner)
            mutation(fake)
            original = copy.deepcopy(fake.nodes)
            self.denied(lambda: owner.cleanup(observed, child_settled=True), owner)
            self.assertEqual(fake.nodes, original)
            self.assertFalse(any(op in ("unlink", "rmdir") for op, _ in fake.calls))

    def test_changed_remaining_file_after_first_delete_stops_next_delete(self):
        fake, metadata = fixture()
        owner = self.allocate(fake, metadata)
        observed = self.result(fake, owner)
        fake.effects["unlinked", SCHEMA] = lambda f: f.nodes[RESULT].update(data=b"third state")
        self.denied(lambda: owner.cleanup(observed, child_settled=True), owner)
        self.assertNotIn(SCHEMA, fake.nodes)
        self.assertIn(RESULT, fake.nodes)
        self.assertEqual([path for op, path in fake.calls if op == "unlink"], [SCHEMA])
        self.denied(lambda: owner.cleanup(observed, child_settled=True), owner)
        self.assertEqual([path for op, path in fake.calls if op == "unlink"], [SCHEMA])

    def test_close_only_retains_files_and_closes_each_descriptor_once(self):
        fake, metadata = fixture()
        owner = self.allocate(fake, metadata)
        original = copy.deepcopy(fake.nodes)
        owner.close()
        count = len(fake.calls)
        owner.close()
        self.assertEqual(len(fake.calls), count)
        self.assertEqual(fake.nodes, original)
        self.assertEqual(fake.handles, {})

    def test_ambiguous_removal_retains_context_and_never_retries(self):
        for event, target, remaining in (("unlinked", SCHEMA, {CHILD, RESULT}),
                                          ("unlinked", RESULT, {CHILD}),
                                          ("removed-directory", CHILD, set())):
            fake, metadata = fixture()
            original = set(fake.nodes)
            owner = self.allocate(fake, metadata)
            observed = self.result(fake, owner)
            fake.effects[event, target] = OSError("private ambiguous removal")
            self.denied(lambda: owner.cleanup(observed, child_settled=True), owner)
            self.assertEqual(set(fake.nodes) - original, remaining)
            deletion_calls = [(op, path) for op, path in fake.calls if op in ("unlink", "rmdir")]
            self.denied(lambda: owner.cleanup(observed, child_settled=True), owner)
            self.assertEqual([(op, path) for op, path in fake.calls if op in ("unlink", "rmdir")], deletion_calls)
            self.denied(owner.close, owner)
            self.assertEqual(fake.handles, {})

    def test_close_priority_across_all_owned_handles(self):
        for primary, first, later in (
            (None, OSError("private close"), KeyboardInterrupt()),
            (None, SystemExit(7), KeyboardInterrupt()),
            (OSError("private failure"), OSError("private close"), SystemExit(7)),
            (KeyboardInterrupt(), OSError("private close"), SystemExit(7)),
        ):
            fake, metadata = fixture()
            owner = self.allocate(fake, metadata)
            owner._error = primary
            descriptors = set(fake.handles)
            observed, native_close = [], fake.close
            split = len(owner._parents[-1]._fds) + 1
            def close(descriptor):
                observed.append(descriptor)
                native_close(descriptor)
                if len(observed) == 1:
                    raise first
                if len(observed) == split:
                    raise later
            fake.close = close
            expected = next((e for e in (primary, first, later) if isinstance(e, (KeyboardInterrupt, SystemExit))), None)
            with self.assertRaises(type(expected)) as caught:
                owner.close()
            self.assertIs(caught.exception, expected)
            self.assertIs(expected.private_owner, owner)
            self.assertEqual(set(observed), descriptors)
            self.assertEqual(len(observed), len(descriptors))
            self.assertEqual(fake.handles, {})

    def test_backend_read_interruption_survives_failing_close(self):
        for operation in ("verify_initial", "result"):
            for read_type, close_type in ((KeyboardInterrupt, OSError), (SystemExit, OSError),
                                          (KeyboardInterrupt, SystemExit), (SystemExit, KeyboardInterrupt)):
                with self.subTest(operation=operation, read=read_type.__name__, close=close_type.__name__):
                    fake, metadata = fixture()
                    owner = self.allocate(fake, metadata)
                    interrupted, later = read_type(), close_type()
                    fake.effects["read", SCHEMA] = interrupted
                    fake.effects["close", SCHEMA] = later
                    held = set(fake.handles)
                    closed, underlying_close = [], fake.close
                    def close(descriptor):
                        closed.append(descriptor)
                        underlying_close(descriptor)
                    fake.close = close
                    with self.assertRaises(BaseException) as caught:
                        if operation == "verify_initial":
                            owner.verify_initial()
                        else:
                            owner.result(child_settled=True)
                    self.assertIs(caught.exception, interrupted)
                    self.assertIs(owner._error, interrupted)
                    self.assertIs(interrupted.private_owner, owner)
                    self.assertEqual(set(fake.handles), held)
                    self.assertEqual(len(closed), 1)
                    with self.assertRaises(read_type) as closing:
                        owner.close()
                    self.assertIs(closing.exception, interrupted)
                    self.assertEqual(fake.handles, {})
                    self.assertEqual(set(closed[1:]), held)
                    self.assertEqual(len(closed), len(held) + 1)
                    self.assertEqual(len(closed), len(set(closed)))
                    with self.assertRaises(read_type):
                        owner.close()
                    self.assertEqual(len(closed), len(held) + 1)

    def test_context_interrupt_selection_respects_sticky_earliest_error(self):
        for sticky in (OSError(), KeyboardInterrupt(), SystemExit()):
            fake, metadata = fixture()
            owner = self.allocate(fake, metadata)
            owner._error = sticky
            original, later, wrapper = KeyboardInterrupt(), SystemExit(), OSError()
            earlier_context = RuntimeError()
            original.__context__ = earlier_context
            later.__context__ = original
            wrapper.__context__ = later
            expected = sticky if isinstance(sticky, (KeyboardInterrupt, SystemExit)) else original
            with self.assertRaises(type(expected)) as caught:
                owner._failed(wrapper)
            self.assertIs(caught.exception, expected)
            self.assertIs(owner._error, expected)
            self.assertIs(expected.private_owner, owner)
            self.assertIs(original.__context__, earlier_context)
            with self.assertRaises(type(expected)) as closing:
                owner.close()
            self.assertIs(closing.exception, expected)
            self.assertEqual(fake.handles, {})

    def test_context_cycles_and_deep_chains_terminate_with_bounded_selection(self):
        for cycle in (True, False):
            fake, metadata = fixture()
            owner = self.allocate(fake, metadata)
            if cycle:
                incoming, later, expected = OSError(), SystemExit(), KeyboardInterrupt()
                incoming.__context__ = later
                later.__context__ = expected
                expected.__context__ = incoming
            else:
                chain = [OSError() for _ in range(files._ERROR_CONTEXT_LIMIT * 4)]
                chain[1] = SystemExit()
                chain[files._ERROR_CONTEXT_LIMIT - 1] = KeyboardInterrupt()
                chain[files._ERROR_CONTEXT_LIMIT] = SystemExit()
                for error, context in zip(chain, chain[1:]):
                    error.__context__ = context
                incoming, expected = chain[0], chain[files._ERROR_CONTEXT_LIMIT - 1]
            # unittest 3.9 clear_frames can hang on deliberately cyclic
            # exception contexts; catch directly without altering the graph.
            caught = None
            try:
                owner._failed(incoming)
            except BaseException as error:
                caught = error
            self.assertIs(caught, expected)
            self.assertIs(owner._error, expected)
            self.assertIs(expected.private_owner, owner)
            closing = None
            try:
                owner.close()
            except BaseException as error:
                closing = error
            self.assertIs(closing, expected)
            self.assertEqual(fake.handles, {})

    def test_ordinary_context_cycle_stays_redacted_and_preserves_first_error(self):
        fake, metadata = fixture()
        owner = self.allocate(fake, metadata)
        original, incoming = OSError("private first"), OSError("private second")
        incoming.__context__ = incoming
        owner._error = original
        self.denied(lambda: owner._failed(incoming), owner)
        self.assertIs(owner._error, original)
        self.denied(owner.close, owner)
        self.assertEqual(fake.handles, {})


if __name__ == "__main__":
    unittest.main()
