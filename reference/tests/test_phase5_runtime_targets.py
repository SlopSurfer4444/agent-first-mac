"""Actual descriptor/envelope classes over fake syscalls/metadata; no native I/O."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import phase5_runtime_targets as targets  # noqa: E402
from lib import phase5_runtime_capture as capture_module  # noqa: E402
from lib import phase5_runtime_session as session  # noqa: E402
from lib.phase5_runtime_transition import ABSENT  # noqa: E402
from lib.phase5_runtime_paths import OwnedParent, Envelope  # noqa: E402
from lib.phase5_runtime_backend import DescriptorBackend, READ_FLAGS, RENAME_SWAP, RENAME_EXCL  # noqa: E402

spec = importlib.util.spec_from_file_location("target_legacy_fakes", ROOT / "tests/test_phase5_runtime_legacy.py")
fakes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fakes)
HOME = "/Users/owner"


class Metadata:
    def __init__(self, fake):
        self.fake, self.values = fake, {}

    def acl_count(self, descriptor):
        path, node, _ = self.fake.handles[descriptor]
        self.fake.event("acl", path)
        return self.values.get((node["st_dev"], node["st_ino"]), (0, ()))[0]

    def xattr_names(self, descriptor):
        path, node, _ = self.fake.handles[descriptor]
        self.fake.event("xattrs", path)
        return self.values.get((node["st_dev"], node["st_ino"]), (0, ()))[1]

    def set(self, path, count, names):
        node = self.fake.nodes[path]
        self.values[(node["st_dev"], node["st_ino"])] = count, names


def fixture():
    source_fixture = fakes.fixtures.fixture()
    source_backends = source_fixture[0]
    fake = fakes.FakeOS()
    fake.add("/", directory=True, mode=0o755)
    fake.add("/Users", directory=True, mode=0o755)
    fake.add(HOME, directory=True, mode=0o750)
    for suffix in targets.PARENTS:
        parts = suffix.split("/")
        for index in range(1, len(parts) + 1):
            path = HOME + "/" + "/".join(parts[:index])
            if path not in fake.nodes:
                fake.add(path, directory=True, mode=0o755)
    for identifier, parent, leaf, mode in targets.ROWS:
        image = source_backends[identifier][0].files[identifier]
        fake.add(HOME + "/" + targets.PARENTS[parent] + "/" + leaf, image.data, mode=mode)
    return fake, Metadata(fake), source_fixture


def path(index):
    _, parent, leaf, _ = targets.ROWS[index]
    return HOME + "/" + targets.PARENTS[parent] + "/" + leaf


class TransitionOS(fakes.FakeOS):
    """Extend only the in-memory fake with exclusive writes/renames/fsync."""
    def open(self, leaf, flags, mode=None, *, dir_fd=None):
        target = self.path(leaf, dir_fd)
        if flags & os.O_CREAT:
            assert flags & os.O_EXCL and flags & os.O_NOFOLLOW and mode == 0o600
            self.event("create", target)
            if target in self.nodes:
                raise FileExistsError()
            self.add(target, b"", mode=mode)
            self.event("created", target)
            flags = READ_FLAGS
        try:
            return super().open(leaf, flags, dir_fd=dir_fd)
        except KeyError:
            raise FileNotFoundError() from None

    def stat(self, leaf, *, dir_fd=None, follow_symlinks=False):
        try:
            return super().stat(leaf, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
        except KeyError:
            raise FileNotFoundError() from None

    def write(self, descriptor, data):
        name, node, offset = self.handles[descriptor]
        self.event("write", name)
        node["data"] = node["data"][:offset] + data
        node["st_mtime_ns"] += 1
        node["st_ctime_ns"] += 1
        self.handles[descriptor][2] += len(data)
        return len(data)

    def fchmod(self, descriptor, mode):
        name, node, _ = self.handles[descriptor]
        self.event("fchmod", name)
        node["st_mode"] = stat.S_IFREG | mode
        node["st_ctime_ns"] += 1

    def fsync(self, descriptor):
        self.event("fsync", self.handles[descriptor][0])

    def rename(self, descriptor, source, destination, flag):
        source, destination = self.path(source, descriptor), self.path(destination, descriptor)
        self.event("rename", source)
        if source not in self.nodes:
            raise FileNotFoundError()
        if flag == RENAME_SWAP:
            if destination not in self.nodes:
                raise FileNotFoundError()
            self.nodes[source], self.nodes[destination] = self.nodes[destination], self.nodes[source]
            self.nodes[source]["st_ctime_ns"] += 1
        else:
            assert flag == RENAME_EXCL
            if destination in self.nodes:
                raise FileExistsError()
            self.nodes[destination] = self.nodes.pop(source)
        self.nodes[destination]["st_ctime_ns"] += 1
        self.event("renamed", destination)


class TransitionTargetsTests(unittest.TestCase):
    SESSION = "p5-" + "a" * 32

    def fixture(self, *, metadata_change=None, guidance_mode=0o600):
        base, _, source = fixture()
        fake = TransitionOS()
        fake.nodes, fake.sequence = copy.deepcopy(base.nodes), base.sequence
        fake.nodes[path(1)]["st_mode"] = stat.S_IFREG | guidance_mode
        metadata = Metadata(fake)
        if metadata_change:
            metadata_change(metadata)
        held = targets.observe(HOME, 501, syscalls=fake, platform=metadata,
            backend_factory=lambda parent, **kw: DescriptorBackend(parent, rename=fake.rename, **kw))
        return fake, metadata, held, source

    def names(self, index=0, action="rollback"):
        prefix = self.SESSION + "-" + action + "-" + str(index)
        return prefix + "-tmp", prefix + "-rec"

    def rejected(self, fake, operation):
        with self.assertRaisesRegex(targets.TargetsError, "^runtime_targets_observation_required$"):
            operation()
        self.assertEqual(fake.handles, {})

    def test_capture_noop_rollback_return_actual_session_and_backend_with_borrowed_parents(self):
        for mode in (0o600, 0o644):
            fake, metadata, held, source = self.fixture(guidance_mode=mode,
                metadata_change=lambda m: m.set(HOME + "/.codex", 0, ("com.private.parent",)))
            original = copy.deepcopy(fake.nodes)
            _, store, receipt, before, after, _ = source
            self.assertEqual(capture_module.capture(held.bindings, store, receipt, before, after,
                session_id=self.SESSION, admit_current=lambda _: True,
                recheck_dependencies=held.verify)["verdict"], "captured")
            bindings = held.transition_bindings(self.SESSION)
            parent_fds = tuple(parent.descriptor for parent in held._parents)
            self.assertEqual(fake.nodes, original)
            self.assertTrue(all(not hasattr(backend, "close") for backend, _ in bindings.values()))
            for state in ("current", "rollback", "return"):
                if state != "current":
                    action = session.rollback if state == "rollback" else session.return_current
                    self.assertEqual(action(bindings, store)["verdict"], "completed")
                self.assertEqual(session.verify(bindings, store, state=state)["verdict"], "verified")
                self.assertEqual(session.noop(bindings, store, state=state)["verdict"], "noop")
            self.assertEqual(tuple(parent.descriptor for parent in held._parents), parent_fds)
            self.assertEqual(fake.nodes[path(1)], original[path(1)])
            for index in range(8):
                self.assertEqual(fake.nodes[path(index)]["data"], original[path(index)]["data"])
                self.assertEqual(fake.nodes[path(index)]["st_mode"], original[path(index)]["st_mode"])
            self.assertTrue(any(op == "rename" for op, _ in fake.calls))
            self.assertTrue(any(op == "fsync" for op, _ in fake.calls))
            self.assertTrue(all(name.endswith("-tmp") for op, name in fake.calls if op == "fchmod"))
            self.assertTrue(all(op != "unlink" for op, _ in fake.calls))
            held.close()
            for backend, _ in bindings.values():
                self.rejected(fake, backend.verify)

    def test_transfer_once_strict_session_and_original_empty_images(self):
        for bad in (None, True, "", "p5-" + "A" * 32, "p5-" + "a" * 31, "../" + self.SESSION):
            fake, _, held, _ = self.fixture()
            self.rejected(fake, lambda: held.transition_bindings(bad))
        for change in ("repeat", "image", "metadata"):
            fake, metadata, held, _ = self.fixture()
            if change == "repeat":
                held.transition_bindings(self.SESSION)
            elif change == "image":
                fake.nodes[path(0)]["data"] += b"unknown"
            else:
                metadata.set(path(0), 1, ())
            self.rejected(fake, lambda: held.transition_bindings(self.SESSION))
        fake, _, held, _ = self.fixture(metadata_change=lambda m: m.set(path(0), 1, ()))
        self.rejected(fake, lambda: held.transition_bindings(self.SESSION))

    def test_names_and_operations_are_per_target_per_session_and_no_recovery_write(self):
        tmp, rec = self.names()
        for operation in (
            lambda b, n: b.snapshot("AGENTS.md"), lambda b, n: b.snapshot("../config.toml"),
            lambda b, n: b.snapshot(tmp.replace("rollback-0", "rollback-2")),
            lambda b, n: b.snapshot(tmp.replace("a" * 32, "b" * 32)),
            lambda b, n: b.create_exclusive(n, b"bad", 0o600),
            lambda b, n: b.create_exclusive(rec, b"bad", 0o600),
            lambda b, n: b.swap(n, tmp), lambda b, n: b.swap(tmp, rec),
            lambda b, n: b.move_exclusive(n, rec), lambda b, n: b.move_exclusive(tmp, self.names(action="return")[0]),
        ):
            fake, _, held, _ = self.fixture()
            backend, name = held.transition_bindings(self.SESSION)["config"]
            before = copy.deepcopy(fake.nodes)
            self.rejected(fake, lambda: operation(backend, name))
            self.assertEqual(fake.nodes, before)

    def test_global_guidance_cannot_create_swap_or_move_even_matching_names(self):
        for operation in ("create_exclusive", "swap", "move_exclusive"):
            fake, _, held, _ = self.fixture(guidance_mode=0o644)
            backend, name = held.transition_bindings(self.SESSION)["global-agents"]
            tmp, _ = self.names(1)
            args = (tmp, b"changed", 0o600) if operation == "create_exclusive" else (tmp, name)
            before = copy.deepcopy(fake.nodes)
            self.rejected(fake, lambda: getattr(backend, operation)(*args))
            self.assertEqual(fake.nodes, before)

    def test_readonly_observation_stays_original_after_intentional_swap(self):
        fake, _, held, _ = self.fixture()
        readonly, name = held.bindings["config"]
        backend, _ = held.transition_bindings(self.SESSION)["config"]
        tmp, _ = self.names()
        backend.create_exclusive(tmp, b"new private image", 0o600)
        backend.swap(tmp, name)
        self.assertEqual(backend.snapshot(name).data, b"new private image")
        self.assertTrue(backend.verify())
        self.rejected(fake, lambda: readonly.snapshot(name))

    def test_present_target_and_aux_metadata_and_same_inode_byte_pairing(self):
        for kind in ("target", "stage", "stage-during-read", "replacement", "bytes"):
            fake, metadata, held, _ = self.fixture()
            backend, name = held.transition_bindings(self.SESSION)["config"]
            tmp, _ = self.names()
            stage = HOME + "/.codex/" + tmp
            backend.create_exclusive(tmp, b"stage", 0o600)
            if kind == "target":
                metadata.set(path(0), 1, ())
                operation = lambda: backend.snapshot(name)
            elif kind == "stage":
                metadata.set(stage, 0, ("com.private.stage",))
                operation = lambda: backend.swap(tmp, name)
            else:
                def drift(fs):
                    if kind == "stage-during-read":
                        metadata.set(stage, 1, ())
                    elif kind == "replacement":
                        fs.nodes[stage] = {**fs.nodes[stage], "st_ino": 999999}
                    else:
                        fs.nodes[stage]["data"] += b"changed"
                fake.effects[("acl", stage)] = drift
                operation = lambda: backend.snapshot(tmp)
            self.rejected(fake, operation)
            self.assertIn(stage, fake.nodes)
            self.assertFalse(any(op == "rename" for op, _ in fake.calls))

    def test_stage_metadata_drift_after_write_is_still_rejected_and_retained(self):
        fake, metadata, held, _ = self.fixture()
        backend, _ = held.transition_bindings(self.SESSION)["config"]
        tmp, _ = self.names()
        stage = HOME + "/.codex/" + tmp
        fake.effects[("write", stage)] = lambda _: metadata.set(stage, 1, ())
        self.rejected(fake, lambda: backend.create_exclusive(tmp, b"private stage", 0o600))
        self.assertIn(stage, fake.nodes)
        self.assertFalse(any(op == "rename" for op, _ in fake.calls))

    def test_inherited_stage_acl_or_xattr_rejected_before_payload_chmod_or_sync(self):
        for count, names in ((1, ()), (0, ("com.private.inherited",))):
            fake, metadata, held, _ = self.fixture(
                metadata_change=lambda m: m.set(HOME + "/.codex", 0, ("com.private.parent",)))
            backend, _ = held.transition_bindings(self.SESSION)["config"]
            tmp, _ = self.names()
            stage = HOME + "/.codex/" + tmp
            originals = copy.deepcopy(fake.nodes)
            parent_envelopes = held.parent_envelopes
            fake.effects[("created", stage)] = lambda _: metadata.set(stage, count, names)
            self.rejected(fake, lambda: backend.create_exclusive(tmp, b"private payload never written", 0o644))
            self.assertEqual(fake.nodes[stage]["data"], b"")
            self.assertEqual(stat.S_IMODE(fake.nodes[stage]["st_mode"]), 0o600)
            self.assertEqual({name: node for name, node in fake.nodes.items() if name != stage}, originals)
            self.assertEqual(held.parent_envelopes, parent_envelopes)
            self.assertEqual(metadata.values[(fake.nodes[stage]["st_dev"], fake.nodes[stage]["st_ino"])], (count, names))
            self.assertFalse(any(op in ("write", "fchmod", "fsync", "rename", "unlink") for op, _ in fake.calls))
            self.assertEqual(sum(op == "close" and name == stage for op, name in fake.calls), 1)

    def test_prewrite_admission_substitution_parent_drift_and_interrupt_retain_empty_stage(self):
        for kind in ("named", "parent", "interrupt"):
            fake, metadata, held, _ = self.fixture()
            backend, _ = held.transition_bindings(self.SESSION)["config"]
            tmp, _ = self.names()
            stage = HOME + "/.codex/" + tmp
            original = []
            error = KeyboardInterrupt()
            def during_admission(fs):
                original.append(fs.nodes[stage])
                if kind == "named":
                    fs.nodes[stage] = {**fs.nodes[stage], "st_ino": 999999, "data": b"unknown retained"}
                elif kind == "parent":
                    metadata.set(HOME + "/.codex", 1, ())
                else:
                    raise error
            fake.effects[("acl", stage)] = during_admission
            if kind == "interrupt":
                with self.assertRaises(KeyboardInterrupt) as raised:
                    backend.create_exclusive(tmp, b"secret", 0o600)
                self.assertIs(raised.exception, error)
                self.assertEqual(fake.handles, {})
            else:
                self.rejected(fake, lambda: backend.create_exclusive(tmp, b"secret", 0o600))
            self.assertEqual(original[0]["data"], b"")
            self.assertEqual(fake.nodes[stage]["data"], b"unknown retained" if kind == "named" else b"")
            self.assertFalse(any(op in ("write", "fchmod", "fsync", "rename", "unlink") for op, _ in fake.calls))
            self.assertEqual(sum(op == "close" and name == stage for op, name in fake.calls), 1)

    def test_metadata_drift_after_rename_retains_both_images_without_compensation(self):
        fake, metadata, held, _ = self.fixture()
        backend, name = held.transition_bindings(self.SESSION)["config"]
        original = backend.snapshot(name)
        tmp, _ = self.names()
        staged = backend.create_exclusive(tmp, b"new image", 0o600)
        fake.effects[("renamed", path(0))] = lambda _: metadata.set(path(0), 1, ())
        self.rejected(fake, lambda: backend.swap(tmp, name))
        self.assertEqual(fake.nodes[path(0)]["data"], staged.data)
        self.assertEqual(fake.nodes[HOME + "/.codex/" + tmp]["data"], original.data)
        self.assertEqual(sum(op == "rename" for op, _ in fake.calls), 1)

    def test_recovery_auxiliary_metadata_and_sync_drift_fail(self):
        for kind in ("recovery", "sync"):
            fake, metadata, held, _ = self.fixture()
            backend, name = held.transition_bindings(self.SESSION)["config"]
            _, rec = self.names()
            if kind == "recovery":
                aux = HOME + "/.codex/" + rec
                fake.add(aux, b"unknown retained evidence")
                metadata.set(aux, 1, ())
                operation = lambda: backend.snapshot(rec)
            else:
                fake.effects[("fsync", HOME + "/.codex")] = lambda _: metadata.set(path(0), 1, ())
                operation = backend.sync
            original = copy.deepcopy(fake.nodes)
            self.rejected(fake, operation)
            self.assertEqual(fake.nodes, original)

    def test_transition_interruptions_close_all_borrowed_lifetimes_without_cleanup(self):
        for operation in ("write", "acl", "rename", "fsync"):
            fake, _, held, _ = self.fixture()
            bindings = held.transition_bindings(self.SESSION)
            backend, name = bindings["config"]
            tmp, _ = self.names()
            stage = HOME + "/.codex/" + tmp
            if operation in ("rename", "fsync"):
                backend.create_exclusive(tmp, b"staging image", 0o600)
            error = KeyboardInterrupt()
            effect_path = HOME + "/.codex" if operation == "fsync" else stage
            fake.effects[(operation, effect_path)] = error
            invoke = backend.sync if operation == "fsync" else (
                lambda: backend.swap(tmp, name)) if operation == "rename" else (
                lambda: backend.create_exclusive(tmp, b"staging image", 0o600))
            with self.assertRaises(KeyboardInterrupt) as raised:
                invoke()
            self.assertIs(raised.exception, error)
            self.assertEqual(fake.handles, {})
            self.assertIn(stage, fake.nodes)
            self.assertFalse(any(op == "unlink" for op, _ in fake.calls))
            self.rejected(fake, bindings["quarantine-launcher"][0].verify)

    def test_parent_envelope_drift_or_substitution_invalidates_transition_adapters(self):
        for kind in ("metadata", "replacement"):
            fake, metadata, held, _ = self.fixture()
            backend, _ = held.transition_bindings(self.SESSION)["config"]
            if kind == "metadata":
                metadata.set(HOME + "/.codex", 1, ())
            else:
                fake.nodes[HOME + "/.codex"] = {**fake.nodes[HOME + "/.codex"], "st_ino": 999999}
            self.rejected(fake, backend.verify)


class TargetsTests(unittest.TestCase):
    def test_observer_constructor_failure_does_not_discard_cleanup_interrupt(self):
        for interrupt in (KeyboardInterrupt(), SystemExit(7)):
            fake, metadata, _ = fixture()
            original = copy.deepcopy(fake.nodes)
            closed, native_close = [], fake.close
            def close(descriptor):
                closed.append(descriptor)
                native_close(descriptor)
                if len(closed) == 1:
                    raise OSError("private close")
                if len(closed) == 2:
                    raise interrupt
            def backend(*args, **kwargs):
                raise OSError("private constructor")
            fake.close = close
            with self.assertRaises(type(interrupt)) as raised:
                targets.observe(HOME, 501, syscalls=fake, platform=metadata, backend_factory=backend)
            self.assertIs(raised.exception, interrupt)
            self.assertEqual(fake.handles, {})
            self.assertEqual(len(closed), len(set(closed)))
            self.assertEqual(fake.nodes, original)


    def test_release_and_context_cleanup_priority_across_actual_owned_parents(self):
        for primary, early, late in (
            (None, OSError("private first close"), KeyboardInterrupt()),
            (None, OSError("private first close"), SystemExit(7)),
            (None, KeyboardInterrupt(), SystemExit(7)),
            (OSError("private body"), OSError("private first close"), KeyboardInterrupt()),
            (OSError("private body"), OSError("private first close"), SystemExit(7)),
            (KeyboardInterrupt(), OSError("private first close"), SystemExit(7)),
            (SystemExit(7), OSError("private first close"), KeyboardInterrupt()),
            (OSError("private body"), OSError("private first close"), OSError("private later close")),
        ):
            fake, metadata, _ = fixture()
            held = targets.observe(HOME, 501, syscalls=fake, platform=metadata)
            original = copy.deepcopy(fake.nodes)
            descriptors = set(fake.handles)
            split = len(held._parents[-1]._fds) + 1
            closed, native_close = [], fake.close
            def close(descriptor):
                closed.append(descriptor)
                native_close(descriptor)
                if len(closed) == 1:
                    raise early
                if len(closed) == split:
                    raise late
            expected = next((error for error in (primary, early, late)
                             if isinstance(error, (KeyboardInterrupt, SystemExit))), primary or early)
            with self.assertRaises(type(expected)) as raised:
                if primary is None:
                    fake.close = close
                    held.close()
                else:
                    with held:
                        fake.close = close
                        raise primary
            self.assertIs(raised.exception, expected)
            self.assertEqual(fake.handles, {})
            self.assertEqual(set(closed), descriptors)
            self.assertEqual(len(closed), len(descriptors))
            self.assertEqual(fake.nodes, original)
            held.close()
            self.assertEqual(len(closed), len(descriptors))

    def test_verification_failure_cleanup_retains_earliest_interrupt(self):
        for primary, later in ((OSError("private verify"), KeyboardInterrupt()),
                               (OSError("private verify"), SystemExit(7)),
                               (KeyboardInterrupt(), SystemExit(7)),
                               (SystemExit(7), KeyboardInterrupt())):
            fake, metadata, _ = fixture()
            held = targets.observe(HOME, 501, syscalls=fake, platform=metadata)
            original = copy.deepcopy(fake.nodes)
            descriptors = set(fake.handles)
            split = len(held._parents[-1]._fds) + 1
            closed, native_close = [], fake.close
            def close(descriptor):
                closed.append(descriptor)
                native_close(descriptor)
                if len(closed) == 1:
                    raise OSError("private close")
                if len(closed) == split:
                    raise later
            fake.close = close
            fake.effects[("fstat", "/")] = primary
            expected = primary if isinstance(primary, (KeyboardInterrupt, SystemExit)) else later
            with self.assertRaises(type(expected)) as raised:
                held.verify()
            self.assertIs(raised.exception, expected)
            self.assertEqual(fake.handles, {})
            self.assertEqual(set(closed), descriptors)
            self.assertEqual(len(closed), len(descriptors))
            self.assertEqual(fake.nodes, original)

    def assert_failure(self, fake, operation):
        with self.assertRaisesRegex(targets.TargetsError, "^runtime_targets_observation_required$"):
            operation()
        self.assertEqual(fake.handles, {})

    def test_actual_classes_fixed_five_parents_eight_targets_and_no_writes(self):
        fake, metadata, _ = fixture()
        original = copy.deepcopy(fake.nodes)
        held = targets.observe(HOME, 501, syscalls=fake, platform=metadata)
        self.assertEqual(len(held._parents), 5)
        self.assertTrue(all(type(p) is OwnedParent for p in held._parents))
        self.assertTrue(all(type(b) is DescriptorBackend for b in held._backends))
        self.assertEqual(tuple(held.images), tuple(row[0] for row in targets.ROWS))
        self.assertEqual(tuple(held.parent_envelopes), targets.PARENTS)
        self.assertTrue(all(type(value) is Envelope for value in held.envelopes.values()))
        self.assertTrue(all(held.metadata_empty.values()))
        self.assertTrue(held.verify())
        self.assertNotIn("private", repr(held))
        for identifier, (backend, leaf) in held.bindings.items():
            backend.verify()
            self.assertEqual(backend.snapshot(leaf), held.images[identifier])
            for method in ("create_exclusive", "swap", "move_exclusive", "sync"):
                self.assertFalse(hasattr(backend, method))
        held.close()
        held.close()
        self.assertEqual(fake.handles, {})
        self.assertEqual(fake.nodes, original)
        self.assertLessEqual(set(op for op, _ in fake.calls), {"open", "read", "stat", "fstat", "close", "acl", "xattrs"})

    def test_nonempty_file_and_parent_metadata_observed_privately_not_rejected(self):
        fake, metadata, _ = fixture()
        metadata.set(path(0), 2, ("com.private.fixture",))
        metadata.set(HOME + "/.codex", 1, ("com.private.parent",))
        metadata.set(HOME, 5, ("com.private.home",))
        with targets.observe(HOME, 501, syscalls=fake, platform=metadata) as held:
            self.assertFalse(held.metadata_empty["config"])
            self.assertFalse(held.parent_metadata_empty[".codex"])
            self.assertEqual(held.envelopes["config"].acl_entries, 2)
            self.assertTrue(held.verify())
            metadata.set(HOME, 10, ("changed.home",))
            self.assertTrue(held.verify())
        self.assertFalse(any(op in ("acl", "xattrs") and name == HOME for op, name in fake.calls))

    def test_file_modes_presence_owner_and_single_link_required(self):
        for field, value in (("st_mode", stat.S_IFREG | 0o644), ("st_uid", 502),
                             ("st_nlink", 2), ("st_mode", stat.S_IFLNK | 0o600)):
            fake, metadata, _ = fixture()
            fake.nodes[path(0)][field] = value
            self.assert_failure(fake, lambda: targets.observe(HOME, 501, syscalls=fake, platform=metadata))
        fake, metadata, _ = fixture()
        fake.nodes[path(7)]["st_mode"] = stat.S_IFREG | 0o600
        self.assert_failure(fake, lambda: targets.observe(HOME, 501, syscalls=fake, platform=metadata))
        fake, metadata, _ = fixture()
        del fake.nodes[path(0)]
        self.assert_failure(fake, lambda: targets.observe(HOME, 501, syscalls=fake, platform=metadata))

    def test_distinct_identities_required(self):
        fake, metadata, _ = fixture()
        fake.nodes[path(1)]["st_ino"] = fake.nodes[path(0)]["st_ino"]
        self.assert_failure(fake, lambda: targets.observe(HOME, 501, syscalls=fake, platform=metadata))

    def test_every_target_byte_drift_invalidates_held_observation(self):
        for index in range(8):
            fake, metadata, _ = fixture()
            held = targets.observe(HOME, 501, syscalls=fake, platform=metadata)
            fake.nodes[path(index)]["data"] += b"private changed"
            self.assert_failure(fake, held.verify)
            self.assertTrue(fake.nodes[path(index)]["data"].endswith(b"private changed"))

    def test_file_ctime_identity_mode_and_stat_seal_drift(self):
        for field, value in (("st_ctime_ns", 999), ("st_ino", 999), ("st_mtime_ns", 999),
                             ("st_flags", 2), ("st_gid", 999), ("st_mode", stat.S_IFREG | 0o644)):
            fake, metadata, _ = fixture()
            held = targets.observe(HOME, 501, syscalls=fake, platform=metadata)
            fake.nodes[path(0)][field] = value
            self.assert_failure(fake, held.verify)

    def test_file_acl_and_xattr_drift_even_when_stat_does_not_change(self):
        for count, names in ((1, ()), (0, ("com.private.changed",))):
            fake, metadata, _ = fixture()
            held = targets.observe(HOME, 501, syscalls=fake, platform=metadata)
            metadata.set(path(3), count, names)
            self.assert_failure(fake, held.verify)

    def test_all_five_leaf_parent_envelopes_are_operation_bound(self):
        for suffix in targets.PARENTS:
            fake, metadata, _ = fixture()
            held = targets.observe(HOME, 501, syscalls=fake, platform=metadata)
            metadata.set(HOME + "/" + suffix, 1, ())
            self.assert_failure(fake, held.verify)

    def test_named_parent_substitution_closes_all_five_chains(self):
        fake, metadata, _ = fixture()
        held = targets.observe(HOME, 501, syscalls=fake, platform=metadata)
        replacement = dict(fake.nodes[HOME + "/.codex"])
        replacement["st_ino"] += 10000
        fake.nodes[HOME + "/.codex"] = replacement
        self.assert_failure(fake, held.verify)

    def test_envelope_is_bound_to_same_inode_name_as_image(self):
        fake, metadata, _ = fixture()

        def substitute(fs):
            replacement = dict(fs.nodes[path(0)])
            replacement["st_ino"] += 10000
            fs.nodes[path(0)] = replacement

        fake.effects[("acl", path(0))] = substitute
        self.assert_failure(fake, lambda: targets.observe(HOME, 501, syscalls=fake, platform=metadata))

    def test_bytes_change_during_metadata_observation_cannot_pair_old_image(self):
        fake, metadata, _ = fixture()
        fake.effects[("acl", path(0))] = lambda fs: fs.nodes[path(0)].update(data=b"changed bytes")
        self.assert_failure(fake, lambda: targets.observe(HOME, 501, syscalls=fake, platform=metadata))

    def test_bounded_metadata_invalid_types_and_unstable_observations(self):
        for count, names in ((True, ()), (129, ()), (0, ("duplicate", "duplicate"))):
            fake, metadata, _ = fixture()
            metadata.set(path(0), count, names)
            self.assert_failure(fake, lambda: targets.observe(HOME, 501, syscalls=fake, platform=metadata))
        fake, metadata, _ = fixture()
        fake.effects[("xattrs", path(0))] = lambda _: metadata.set(path(0), 1, ())
        self.assert_failure(fake, lambda: targets.observe(HOME, 501, syscalls=fake, platform=metadata))

    def test_interruptions_during_open_metadata_and_verification_close_owned_handles(self):
        for operation, name in (("open", HOME + "/.codex/hooks"), ("acl", path(0))):
            fake, metadata, _ = fixture()
            fake.effects[(operation, name)] = KeyboardInterrupt()
            with self.assertRaises(KeyboardInterrupt):
                targets.observe(HOME, 501, syscalls=fake, platform=metadata)
            self.assertEqual(fake.handles, {})
        fake, metadata, _ = fixture()
        held = targets.observe(HOME, 501, syscalls=fake, platform=metadata)
        fake.effects[("xattrs", path(0))] = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            held.verify()
        self.assertEqual(fake.handles, {})

    def test_close_error_continues_other_chains_without_retry(self):
        fake, metadata, _ = fixture()
        held = targets.observe(HOME, 501, syscalls=fake, platform=metadata)
        fake.effects[("close", HOME + "/AIDev/bin")] = OSError("private close error")
        self.assert_failure(fake, held.close)
        calls = list(fake.calls)
        held.close()
        self.assertEqual(fake.calls, calls)

    def test_readonly_snapshot_wrong_name_or_metadata_drift_closes_holder(self):
        for defect in ("name", "metadata"):
            fake, metadata, _ = fixture()
            held = targets.observe(HOME, 501, syscalls=fake, platform=metadata)
            backend, name = held.bindings["config"]
            if defect == "metadata":
                metadata.set(path(0), 1, ())
            self.assert_failure(fake, lambda: backend.snapshot("other" if defect == "name" else name))

    def test_actual_capture_wrapper_readiness_and_capture_using_readonly_bindings(self):
        fake, metadata, source_fixture = fixture()
        with targets.observe(HOME, 501, syscalls=fake, platform=metadata) as held:
            _, store, receipt, before, after, events = source_fixture
            kwargs = dict(admit_current=lambda _: True, recheck_dependencies=held.verify)
            self.assertEqual(capture_module.readiness(held.bindings, receipt, before, after, **kwargs)["verdict"], "ready")
            result = capture_module.capture(held.bindings, store, receipt, before, after,
                                             session_id=fakes.fixtures.fakes.SESSION, **kwargs)
            self.assertEqual(result["verdict"], "captured")
            self.assertIs(result["executionAdmission"], False)
            self.assertEqual(events, [("persist", "capture")])
        self.assertEqual(fake.handles, {})

    def test_public_global_guidance0644_readiness_capture_preserve_mode_and_bytes(self):
        fake, metadata, source_fixture = fixture()
        fake.nodes[path(1)]["st_mode"] = stat.S_IFREG | 0o644
        original = copy.deepcopy(fake.nodes)
        with targets.observe(HOME, 501, syscalls=fake, platform=metadata) as held:
            _, store, receipt, before, after, events = source_fixture

            def admit(images):
                self.assertEqual(images["global-agents"].mode, 0o644)
                self.assertEqual(images["global-agents"].data, original[path(1)]["data"])
                return True

            kwargs = dict(admit_current=admit, recheck_dependencies=held.verify)
            self.assertEqual(capture_module.readiness(held.bindings, receipt, before, after, **kwargs)["verdict"], "ready")
            result = capture_module.capture(held.bindings, store, receipt, before, after,
                                             session_id=fakes.fixtures.fakes.SESSION, **kwargs)
            self.assertEqual(result["verdict"], "captured")
            self.assertIs(result["executionAdmission"], False)
            record = json.loads(store.records["capture"])
            self.assertEqual(record["current"][1]["mode"], 0o644)
            self.assertEqual(record["before"][1]["mode"], 0o600)
            self.assertEqual(record["after"][1]["mode"], 0o600)
            self.assertEqual(events, [("persist", "capture")])
            self.assertTrue(held.verify())
        self.assertEqual(fake.nodes, original)
        self.assertEqual(fake.handles, {})

    def test_global_guidance_rejects_writable_executable_and_other_unlisted_modes(self):
        for mode in (0o660, 0o664, 0o666, 0o602, 0o606, 0o646, 0o700, 0o744, 0o755, 0o640, 0o604, 0o444):
            fake, metadata, _ = fixture()
            fake.nodes[path(1)]["st_mode"] = stat.S_IFREG | mode
            self.assert_failure(fake, lambda: targets.observe(HOME, 501, syscalls=fake, platform=metadata))

    def test_other_seven_targets_still_reject0644_including_config(self):
        for index in (0, 2, 3, 4, 5, 6, 7):
            fake, metadata, _ = fixture()
            fake.nodes[path(index)]["st_mode"] = stat.S_IFREG | 0o644
            self.assert_failure(fake, lambda: targets.observe(HOME, 501, syscalls=fake, platform=metadata))

    def test_guidance_drift_between_allowed_modes_is_not_a_new_baseline(self):
        for initial, changed in ((0o600, 0o644), (0o644, 0o600)):
            fake, metadata, _ = fixture()
            fake.nodes[path(1)]["st_mode"] = stat.S_IFREG | initial
            held = targets.observe(HOME, 501, syscalls=fake, platform=metadata)
            fake.nodes[path(1)]["st_mode"] = stat.S_IFREG | changed
            self.assert_failure(fake, held.verify)
            self.assertEqual(stat.S_IMODE(fake.nodes[path(1)]["st_mode"]), changed)


if __name__ == "__main__":
    unittest.main()
