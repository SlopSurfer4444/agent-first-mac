"""Fake-only allocation syscalls, actual OwnedParent and metadata admission."""

import copy
import importlib.util
import os
from pathlib import Path
import stat
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import phase5_runtime_directory as directory  # noqa: E402
from lib.phase5_runtime_paths import OwnedParent  # noqa: E402
from lib.phase5_runtime_store import DurableStore  # noqa: E402

spec = importlib.util.spec_from_file_location("directory_target_fakes", ROOT / "tests/test_phase5_runtime_targets.py")
fakes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fakes)
HOME = "/Users/owner"
STATE = HOME + directory.STATE_SUFFIX
RUN_ID = "p5-" + "b" * 32
CHILD = STATE + "/" + RUN_ID


class FakeOS(fakes.fakes.FakeOS):
    def __init__(self):
        super().__init__()
        self.umask, self.durable = 0o077, set()
        self.scan_count, self.scan_exit_effects = 0, {}

    def open(self, leaf, flags, mode=None, *, dir_fd=None):
        path = self.path(leaf, dir_fd)
        if flags & os.O_CREAT:
            assert flags & os.O_EXCL and flags & os.O_RDWR and mode == 0o600
            assert flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK
            assert self.handles[dir_fd][0] == CHILD
            assert self.durable >= {STATE, CHILD}
            self.event("create-record", path)
            if path in self.nodes:
                raise FileExistsError("private existing record")
            self.add(path, mode=mode & ~self.umask)
            self.nodes[CHILD]["st_ctime_ns"] += 1
            self.nodes[CHILD]["st_mtime_ns"] += 1
            descriptor = self.sequence + 1000
            self.sequence += 1
            self.handles[descriptor] = [path, self.nodes[path], 0]
            return descriptor
        if path not in self.nodes:
            raise FileNotFoundError("private missing name")
        return super().open(leaf, flags, dir_fd=dir_fd)

    def stat(self, leaf, *, dir_fd=None, follow_symlinks):
        if self.path(leaf, dir_fd) not in self.nodes:
            raise FileNotFoundError("private missing name")
        return super().stat(leaf, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    def write(self, descriptor, value):
        path, node, offset = self.handles[descriptor]
        assert path.startswith(CHILD + "/")
        self.event("write-record", path)
        node["data"] = node["data"][:offset] + value + node["data"][offset + len(value):]
        self.handles[descriptor][2] += len(value)
        node["st_ctime_ns"] += 1
        node["st_mtime_ns"] += 1
        return len(value)

    def pread(self, descriptor, maximum, offset):
        path, node, _ = self.handles[descriptor]
        self.event("pread-record", path)
        return node["data"][offset:offset + maximum]

    def scandir(self, descriptor):
        scan = super().scandir(descriptor)
        self.scan_count += 1
        effect = self.scan_exit_effects.pop(self.scan_count, None)

        class ExitEffect:
            def __enter__(self):
                return scan.__enter__()

            def __exit__(self, *args):
                result = scan.__exit__(*args)
                if effect is not None:
                    effect()
                return result

        return ExitEffect()

    def mkdir(self, leaf, mode, *, dir_fd):
        path = self.path(leaf, dir_fd)
        self.event("mkdir", path)
        assert self.handles[dir_fd][0] == STATE and mode == 0o700
        if path in self.nodes:
            raise FileExistsError("private existing sibling")
        self.add(path, directory=True, mode=mode & ~self.umask)
        self.nodes[STATE]["st_ctime_ns"] += 1
        self.nodes[STATE]["st_mtime_ns"] += 1
        self.event("after-mkdir", path)

    def fsync(self, descriptor):
        path = self.handles[descriptor][0]
        self.event("fsync", path)
        self.durable.add(path)


def fixture():
    fake = FakeOS()
    fake.add("/", directory=True, mode=0o755)
    parts = STATE[1:].split("/")
    for i in range(1, len(parts) + 1):
        path = "/" + "/".join(parts[:i])
        fake.add(path, directory=True, mode=0o750 if path == HOME else 0o700)
    return fake, fakes.Metadata(fake)


class DirectoryTests(unittest.TestCase):
    def test_allocator_constructor_failure_does_not_discard_cleanup_interrupt(self):
        for interrupt in (KeyboardInterrupt(), SystemExit(7)):
            fake, metadata = fixture()
            closed, native_close = [], fake.close
            def close(descriptor):
                closed.append(descriptor)
                native_close(descriptor)
                if len(closed) == 1:
                    raise OSError("private close")
                if len(closed) == 2:
                    raise interrupt
            fake.close = close
            fake.effects[("acl", CHILD)] = OSError("private admission")
            with self.assertRaises(type(interrupt)) as raised:
                self.allocate(fake, metadata)
            self.assertIs(raised.exception, interrupt)
            self.assertEqual(fake.handles, {})
            self.assertEqual(len(closed), len(set(closed)))
            self.assertIn(CHILD, fake.nodes)
            self.assertEqual(sum(op == "mkdir" for op, _ in fake.calls), 1)
            self.assertFalse(any(op in ("unlink", "chmod", "write-record") for op, _ in fake.calls))


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
            fake, metadata = fixture()
            held = self.allocate(fake, metadata)
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
            fake, metadata = fixture()
            held = self.allocate(fake, metadata)
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
        with self.assertRaisesRegex(directory.DirectoryError, "^runtime_directory_recovery_required$"):
            operation()
        self.assertEqual(fake.handles, {})

    def allocate(self, fake, metadata, run_id=RUN_ID):
        return directory.allocate(HOME, 501, run_id, syscalls=fake, platform=metadata)

    def test_one_exclusive_mkdir_durable_private_handoff_with_actual_owned_parent(self):
        fake, metadata = fixture()
        held = self.allocate(fake, metadata)
        self.assertTrue(all(type(p) is OwnedParent for p in held._parents))
        self.assertEqual(held.uid, 501)
        self.assertEqual(fake.handles[held.descriptor][0], CHILD)
        self.assertEqual(stat.S_IMODE(fake.nodes[CHILD]["st_mode"]), 0o700)
        self.assertEqual(fake.durable, {CHILD, STATE})
        self.assertEqual([c for c in fake.calls if c[0] == "mkdir"], [("mkdir", CHILD)])
        self.assertEqual([c for c in fake.calls if c[0] == "fsync"], [("fsync", CHILD), ("fsync", STATE)])
        self.assertFalse(any(c == ("scandir", STATE) for c in fake.calls))
        self.assertFalse(any(op in ("acl", "xattrs") and path == HOME for op, path in fake.calls))
        self.assertIsNone(held.verify())
        self.assertNotIn(RUN_ID, repr(held))
        held.close()
        held.close()
        self.assertEqual(fake.handles, {})
        self.assertIn(CHILD, fake.nodes)

    def test_invalid_leaf_legacy_id_and_invalid_uid_fail_before_io(self):
        for value in (directory.LEGACY_LEAF, "p5-" + "A" * 32, "p5-" + "a" * 31, "p5-" + "a" * 33,
                       "../" + RUN_ID, "/" + RUN_ID, RUN_ID + "/child", True, None):
            fake, metadata = fixture()
            self.assert_failure(fake, lambda: self.allocate(fake, metadata, value))
            self.assertEqual(fake.calls, [])
        fake, metadata = fixture()
        self.assert_failure(fake, lambda: directory.allocate(HOME, True, RUN_ID, syscalls=fake, platform=metadata))
        self.assertEqual(fake.calls, [])

    def test_collision_existing_empty_or_nonempty_is_not_adopted_or_changed(self):
        for nonempty in (False, True):
            fake, metadata = fixture()
            fake.add(CHILD, directory=True)
            if nonempty:
                fake.add(CHILD + "/owner-file", b"private owner")
            original = copy.deepcopy(fake.nodes)
            self.assert_failure(fake, lambda: self.allocate(fake, metadata))
            self.assertEqual(fake.nodes, original)
            self.assertEqual(fake.durable, set())
            self.assertEqual([c for c in fake.calls if c[0] == "mkdir"], [("mkdir", CHILD)])

    def test_uncertain_after_mkdir_failure_retains_child_without_retry(self):
        fake, metadata = fixture()
        fake.effects[("after-mkdir", CHILD)] = OSError("private uncertain create")
        self.assert_failure(fake, lambda: self.allocate(fake, metadata))
        self.assertIn(CHILD, fake.nodes)
        self.assertEqual(fake.durable, set())
        self.assertEqual([c for c in fake.calls if c[0] == "mkdir"], [("mkdir", CHILD)])

    def test_child_or_parent_fsync_failure_cannot_handoff(self):
        for failed in (CHILD, STATE):
            fake, metadata = fixture()
            fake.effects[("fsync", failed)] = OSError("private uncertain sync")
            self.assert_failure(fake, lambda: self.allocate(fake, metadata))
            self.assertIn(CHILD, fake.nodes)
            self.assertNotIn(failed, fake.durable)
            self.assertEqual([c for c in fake.calls if c[0] == "mkdir"], [("mkdir", CHILD)])

    def test_observed_name_substitution_before_open_or_after_sync_retains_unknown(self):
        for event in (("open", CHILD), ("fsync", STATE)):
            fake, metadata = fixture()

            def substitute(fs):
                replacement = dict(fs.nodes[CHILD])
                replacement["st_ino"] = 999999
                fs.nodes[CHILD] = replacement

            fake.effects[event] = substitute
            self.assert_failure(fake, lambda: self.allocate(fake, metadata))
            self.assertEqual(fake.nodes[CHILD]["st_ino"], 999999)

    def test_parent_namespace_substitution_after_creation_fails_without_cleanup(self):
        fake, metadata = fixture()

        def replace_parent(fs):
            changed = dict(fs.nodes[STATE])
            changed["st_ino"] = 999999
            fs.nodes[STATE] = changed

        fake.effects[("after-mkdir", CHILD)] = replace_parent
        self.assert_failure(fake, lambda: self.allocate(fake, metadata))
        self.assertIn(CHILD, fake.nodes)

    def test_nonempty_before_or_after_durability_barriers_is_retained(self):
        for event in (("after-mkdir", CHILD), ("fsync", STATE)):
            fake, metadata = fixture()
            fake.effects[event] = lambda fs: fs.add(CHILD + "/intruder", b"private third state")
            self.assert_failure(fake, lambda: self.allocate(fake, metadata))
            self.assertEqual(fake.nodes[CHILD + "/intruder"]["data"], b"private third state")

    def test_inherited_or_postsync_acl_xattrs_are_never_normalized(self):
        for count, names in ((1, ()), (0, ("com.private.inherited",))):
            for event in (("after-mkdir", CHILD), ("fsync", STATE)):
                fake, metadata = fixture()
                fake.effects[event] = lambda _: metadata.set(CHILD, count, names)
                self.assert_failure(fake, lambda: self.allocate(fake, metadata))
                self.assertIn(CHILD, fake.nodes)
                identity = fake.nodes[CHILD]["st_dev"], fake.nodes[CHILD]["st_ino"]
                self.assertEqual(metadata.values[identity], (count, names))

    def test_umask_is_observed_never_changed_or_repaired(self):
        for mask in (0, 0o022, 0o077):
            fake, metadata = fixture()
            fake.umask = mask
            held = self.allocate(fake, metadata)
            self.assertEqual(stat.S_IMODE(fake.nodes[CHILD]["st_mode"]), 0o700)
            self.assertEqual(fake.umask, mask)
            held.close()
        fake, metadata = fixture()
        fake.umask = 0o400
        self.assert_failure(fake, lambda: self.allocate(fake, metadata))
        self.assertEqual(stat.S_IMODE(fake.nodes[CHILD]["st_mode"]), 0o300)
        self.assertEqual(fake.umask, 0o400)

    def test_wrong_owner_or_mode_after_create_fails_and_retains_object(self):
        for field, value in (("st_uid", 502), ("st_mode", stat.S_IFDIR | 0o750)):
            fake, metadata = fixture()
            fake.effects[("after-mkdir", CHILD)] = lambda fs: fs.nodes[CHILD].update({field: value})
            self.assert_failure(fake, lambda: self.allocate(fake, metadata))
            self.assertEqual(fake.nodes[CHILD][field], value)

    def test_later_records_allowed_but_metadata_identity_and_chain_stay_bound(self):
        fake, metadata = fixture()
        held = self.allocate(fake, metadata)
        fake.add(CHILD + "/capture", b"fake store record")
        self.assertIsNone(held.verify())
        # Constructor exercises actual DurableStore parent borrowing, no record write.
        store = DurableStore(held, syscalls=fake)
        self.assertIsNone(store.verify())
        metadata.set(CHILD, 1, ())
        self.assert_failure(fake, held.verify)
        self.assertIn(CHILD + "/capture", fake.nodes)

    def test_reuse_of_completed_or_failed_id_cannot_be_a_fresh_allocation(self):
        for failed in (False, True):
            fake, metadata = fixture()
            if failed:
                fake.effects[("fsync", STATE)] = OSError("private uncertain sync")
                self.assert_failure(fake, lambda: self.allocate(fake, metadata))
            else:
                self.allocate(fake, metadata).close()
            original = copy.deepcopy(fake.nodes)
            self.assert_failure(fake, lambda: self.allocate(fake, metadata))
            self.assertEqual(fake.nodes, original)

    def test_interruptions_close_all_owned_handles_and_never_delete_child(self):
        for event in (("after-mkdir", CHILD), ("open", CHILD), ("fsync", CHILD), ("fsync", STATE)):
            fake, metadata = fixture()
            fake.effects[event] = KeyboardInterrupt()
            with self.assertRaises(KeyboardInterrupt):
                self.allocate(fake, metadata)
            self.assertEqual(fake.handles, {})
            self.assertIn(CHILD, fake.nodes)

    def test_close_error_closes_other_handles_without_retry(self):
        fake, metadata = fixture()
        held = self.allocate(fake, metadata)
        fake.effects[("close", CHILD)] = OSError("private close failure")
        self.assert_failure(fake, held.close)
        calls = list(fake.calls)
        held.close()
        self.assertEqual(fake.calls, calls)

    def test_existing_parent_missing_or_wrong_mode_never_creates_it(self):
        for missing in (False, True):
            fake, metadata = fixture()
            if missing:
                del fake.nodes[STATE]
            else:
                fake.nodes[STATE]["st_mode"] = stat.S_IFDIR | 0o750
            self.assert_failure(fake, lambda: self.allocate(fake, metadata))
            self.assertFalse(any(op == "mkdir" for op, _ in fake.calls))

    def test_explicit_false_parent_verification_stops_before_mkdir(self):
        fake, metadata = fixture()

        def opener(*args, **kwargs):
            parent = OwnedParent.open(*args, **kwargs)
            parent.verify = lambda: False
            return parent

        self.assert_failure(fake, lambda: directory.allocate(HOME, 501, RUN_ID, syscalls=fake,
                                                             platform=metadata, parent_open=opener))
        self.assertFalse(any(op == "mkdir" for op, _ in fake.calls))

    def test_combined_freshness_rejects_scan_exit_intruder_acl_and_xattr_mutation(self):
        # Reviewer repro: mutate AFTER empty scan context exit, BEFORE the
        # allocator's post-scan checks. Round2 is the final post-fsync scan.
        for round_number in (1, 2):
            for defect in ("intruder", "acl", "xattr"):
                fake, metadata = fixture()

                def on_exit():
                    if defect == "intruder":
                        fake.add(CHILD + "/intruder", b"private third state")
                    else:
                        metadata.set(CHILD, 1 if defect == "acl" else 0,
                                     ("com.fixture.private",) if defect == "xattr" else ())
                    fake.nodes[CHILD]["st_ctime_ns"] += 1
                    fake.nodes[CHILD]["st_mtime_ns"] += 1

                fake.scan_exit_effects[round_number] = on_exit
                self.assert_failure(fake, lambda: self.allocate(fake, metadata))
                self.assertEqual(fake.scan_count, round_number)
                self.assertIn(CHILD, fake.nodes)
                if defect == "intruder":
                    self.assertEqual(fake.nodes[CHILD + "/intruder"]["data"], b"private third state")
                self.assertFalse(any(op == "create-record" for op, _ in fake.calls))
                if round_number == 2:
                    self.assertEqual(fake.durable, {STATE, CHILD})

    def test_final_scan_exit_mutation_stamps_are_all_bound(self):
        for field in ("st_ctime_ns", "st_mtime_ns", "st_nlink"):
            fake, metadata = fixture()
            fake.scan_exit_effects[2] = lambda: fake.nodes[CHILD].update({field: fake.nodes[CHILD][field] + 1})
            self.assert_failure(fake, lambda: self.allocate(fake, metadata))
            self.assertEqual(fake.scan_count, 2)
            self.assertIn(CHILD, fake.nodes)

    def test_final_scan_exit_envelope_rechecked_even_without_stat_change(self):
        for count, names in ((1, ()), (0, ("com.fixture.private",))):
            fake, metadata = fixture()
            fake.scan_exit_effects[2] = lambda: metadata.set(CHILD, count, names)
            self.assert_failure(fake, lambda: self.allocate(fake, metadata))
            self.assertEqual(fake.scan_count, 2)
            self.assertIn(CHILD, fake.nodes)

    def test_final_scan_exit_interrupt_retains_child_and_closes_all(self):
        fake, metadata = fixture()

        def interrupt():
            raise KeyboardInterrupt()

        fake.scan_exit_effects[2] = interrupt
        with self.assertRaises(KeyboardInterrupt):
            self.allocate(fake, metadata)
        self.assertEqual(fake.handles, {})
        self.assertIn(CHILD, fake.nodes)

    def test_actual_store_absence_put_read_sync_after_allocation_remains_allowed(self):
        fake, metadata = fixture()
        held = self.allocate(fake, metadata)
        self.assertEqual(fake.scan_count, 2)
        prior_stamp = tuple(fake.nodes[CHILD][k] for k in ("st_ctime_ns", "st_mtime_ns"))
        store = DurableStore(held, syscalls=fake)
        self.assertIsNone(store.read("capture"))
        value = b'{"private":"fake-only capture record"}\n'
        self.assertIsNone(store.put_exclusive("capture", value))
        self.assertEqual(store.read("capture"), value)
        self.assertIsNone(store.sync_record("capture", value))
        self.assertEqual(store.read("capture"), value)
        self.assertNotEqual(tuple(fake.nodes[CHILD][k] for k in ("st_ctime_ns", "st_mtime_ns")), prior_stamp)
        self.assertIsNone(held.verify())
        self.assertEqual(fake.scan_count, 2)  # Later verification never demands emptiness.
        self.assertEqual(fake.nodes[CHILD + "/capture"]["data"], value)
        self.assertEqual(stat.S_IMODE(fake.nodes[CHILD + "/capture"]["st_mode"]), 0o600)
        self.assertEqual([c for c in fake.calls if c[0] == "mkdir"], [("mkdir", CHILD)])
        self.assertTrue({STATE, CHILD, CHILD + "/capture"} <= fake.durable)
        held.close()
        self.assertEqual(fake.handles, {})


if __name__ == "__main__":
    unittest.main()
