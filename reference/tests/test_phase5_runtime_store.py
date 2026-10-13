"""Pure fake descriptor I/O; never creates a directory or opens owner state."""

import copy
import importlib
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
S = importlib.import_module("lib.phase5_runtime_store")


def node(raw=b"fixture", *, inode=20, mode=0o600, kind=stat.S_IFREG):
    return {"raw": bytearray(raw), "st_dev": 3, "st_ino": inode, "st_uid": 501,
            "st_gid": 20, "st_nlink": 1, "st_mode": kind | mode, "st_flags": 0,
            "st_mtime_ns": 100, "st_ctime_ns": 200}


class FakeOS:
    def __init__(self):
        self.files, self.handles = {}, {}
        self.parent = node(inode=10, mode=0o700, kind=stat.S_IFDIR)
        self.calls, self.counts, self.effects = [], {}, {}
        self.file_synced, self.directory_synced = set(), set()
        self.next_fd, self.next_inode = 100, 30
        self.short_write = self.short_read = None

    def event(self, name, *args):
        self.calls.append((name,) + args)
        index = self.counts.get(name, 0) + 1
        self.counts[name] = index
        effect = self.effects.get((name, index))
        if isinstance(effect, BaseException):
            raise effect
        if effect is not None:
            effect()

    def facts(self, item):
        return SimpleNamespace(**{k: v for k, v in item.items() if k != "raw"},
                               st_size=len(item["raw"]))

    def fstat(self, fd):
        self.event("fstat", fd)
        return self.facts(self.parent if fd == 99 else self.handles[fd])

    def stat(self, name, *, dir_fd, follow_symlinks):
        assert dir_fd == 99 and follow_symlinks is False
        self.event("stat", name)
        if name not in self.files:
            raise FileNotFoundError("private-missing")
        return self.facts(self.files[name])

    def open(self, name, flags, mode=None, *, dir_fd):
        assert dir_fd == 99
        assert flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK and flags & os.O_CLOEXEC
        self.event("open", name, flags, mode)
        if flags & os.O_CREAT:
            assert flags & os.O_EXCL and flags & os.O_RDWR and mode == 0o600
            if name in self.files:
                raise FileExistsError("private-collision")
            self.files[name] = node(b"", inode=self.next_inode)
            self.next_inode += 1
            self.parent["st_mtime_ns"] += 1
            self.parent["st_ctime_ns"] += 1
        elif name not in self.files:
            raise FileNotFoundError("private-missing")
        elif stat.S_ISLNK(self.files[name]["st_mode"]):
            raise OSError("private-link")
        fd, self.next_fd = self.next_fd, self.next_fd + 1
        self.handles[fd] = self.files[name]
        return fd

    def close(self, fd):
        assert fd != 99, "borrowed parent descriptor must remain held"
        self.event("close", fd)
        del self.handles[fd]

    def pread(self, fd, size, offset):
        self.event("pread", fd, size, offset)
        if self.short_read is not None:
            size = min(size, self.short_read)
        return bytes(self.handles[fd]["raw"][offset:offset + size])

    def write(self, fd, raw):
        self.event("write", fd, len(raw))
        size = len(raw) if self.short_write is None else min(len(raw), self.short_write)
        item = self.handles[fd]
        item["raw"].extend(raw[:size])
        item["st_mtime_ns"] += 1
        item["st_ctime_ns"] += 1
        self.file_synced.discard(item["st_ino"])
        return size

    def fsync(self, fd):
        self.event("fsync", fd)
        if fd == 99:
            self.directory_synced = {(name, item["st_ino"]) for name, item in self.files.items()}
        else:
            self.file_synced.add(self.handles[fd]["st_ino"])
        self.event("fsync-return", fd)

    def durable(self, name):
        inode = self.files[name]["st_ino"]
        return inode in self.file_synced and (name, inode) in self.directory_synced


class Parent:
    descriptor, uid = 99, 501

    def __init__(self, fake):
        self.fake = fake

    def verify(self):
        self.fake.event("verify")


class StoreTests(unittest.TestCase):
    def fixture(self):
        fake = FakeOS()
        parent = Parent(fake)
        return fake, parent, S.DurableStore(parent, syscalls=fake)

    def assert_redacted(self, action):
        with self.assertRaises(S.StoreError) as raised:
            action()
        self.assertEqual(str(raised.exception), "runtime_store_recovery_required")
        self.assertNotIn("private", repr(raised.exception))

    def test_fixed_names_cover_only_session_channels(self):
        names = ["capture"]
        for action in ("rollback", "return"):
            names.extend(action + ".ticket." + str(i) for i in range(8))
            for attempt in ("initial", "resume"):
                names.extend(action + "." + attempt + "." + field
                             for field in ("intent", "failure", "terminal"))
                names.extend(action + "." + attempt + ".result." + str(i) for i in range(8))
        self.assertEqual(len(names), 61)
        fake, _, store = self.fixture()
        for name in names:
            self.assertIsNone(store.read(name))
        self.assertFalse(fake.files)
        self.assertFalse(fake.handles)

    def test_invalid_name_types_and_shapes_have_zero_io(self):
        for name in (None, True, b"capture", "", ".", "..", "../capture", "/capture",
                     "capture\n", "capture\0", "Capture", "rollback.ticket.8",
                     "rollback.ticket.00", "rollback.initial.result.-1", "return.resume.result.8",
                     "return.other.intent", "rollback.initial.extra", "capture.json", "x" * 1000):
            for method in ("read", "put_exclusive", "sync_record"):
                fake, _, store = self.fixture()
                before = list(fake.calls)
                args = (name,) if method == "read" else (name, b"fixture")
                self.assert_redacted(lambda: getattr(store, method)(*args))
                self.assertEqual(fake.calls, before)

    def test_bytes_type_and_record_cap_reject_before_io(self):
        self.assertEqual(S.MAX_RECORD_BYTES, 40 * 1024 * 1024)
        for raw in (None, True, "private", bytearray(b"x"), b"x" * (S.MAX_RECORD_BYTES + 1)):
            for method in ("put_exclusive", "sync_record"):
                fake, _, store = self.fixture()
                before = list(fake.calls)
                self.assert_redacted(lambda: getattr(store, method)("capture", raw))
                self.assertEqual(fake.calls, before)

    def test_exclusive_write_read_and_exact_barrier_are_durable(self):
        fake, _, store = self.fixture()
        self.assertIsNone(store.read("capture"))
        fake.short_write, fake.short_read = 2, 3
        self.assertIsNone(store.put_exclusive("capture", b"abcdefghij"))
        self.assertEqual(store.read("capture"), b"abcdefghij")
        self.assertTrue(fake.durable("capture"))
        self.assertEqual(fake.counts["write"], 5)
        self.assertEqual([c[1] for c in fake.calls if c[0] == "fsync"], [100, 99])
        self.assertIsNone(store.sync_record("capture", b"abcdefghij"))
        self.assertFalse(fake.handles)

    def test_zero_and_maximum_record_boundary(self):
        for raw in (b"", b"x" * S.MAX_RECORD_BYTES):
            fake, _, store = self.fixture()
            store.put_exclusive("capture", raw)
            self.assertEqual(store.read("capture"), raw)
            self.assertTrue(fake.durable("capture"))
            self.assertTrue(all(c[2] <= S.CHUNK_BYTES for c in fake.calls if c[0] == "write"))
            self.assertFalse(fake.handles)

    def test_read_proves_bytes_not_durability(self):
        fake, _, store = self.fixture()
        fake.files["capture"] = node()
        self.assertEqual(store.read("capture"), b"fixture")
        self.assertFalse(fake.durable("capture"))
        self.assertNotIn("fsync", fake.counts)
        store.sync_record("capture", b"fixture")
        self.assertTrue(fake.durable("capture"))

    def test_completed_proof_reuses_fsync_but_never_bytes_or_named_checks(self):
        fake, _, store = self.fixture()
        store.put_exclusive("capture", b"fixture")
        before = dict(fake.counts)
        for _ in range(10):
            store.sync_record("capture", b"fixture")
        self.assertEqual(fake.counts["fsync"], 2)  # 22 without proof reuse
        self.assertEqual(fake.counts["open"] - before["open"], 10)
        self.assertEqual(fake.counts["pread"] - before["pread"], 40)  # two data+EOF reads per barrier
        self.assertEqual(fake.counts["stat"] - before["stat"], 20)
        self.assertGreater(fake.counts["verify"], before["verify"])
        self.assertFalse(fake.handles)

    def test_full_file_stamp_drift_requires_new_full_barrier_even_same_bytes(self):
        for field in ("st_mtime_ns", "st_ctime_ns", "st_gid", "st_flags"):
            fake, _, store = self.fixture()
            store.put_exclusive("capture", b"fixture")
            fake.files["capture"][field] += 1
            store.sync_record("capture", b"fixture")
            self.assertEqual(fake.counts["fsync"], 4)
            store.sync_record("capture", b"fixture")
            self.assertEqual(fake.counts["fsync"], 4)

    def test_proof_binds_bytes_even_if_fake_restores_all_stat_fields(self):
        fake, _, store = self.fixture()
        store.put_exclusive("capture", b"fixture")
        fake.files["capture"]["raw"] = bytearray(b"changed")  # deliberately same length/stamp
        fake.file_synced.clear()
        store.sync_record("capture", b"changed")
        self.assertEqual(fake.counts["fsync"], 4)
        self.assertTrue(fake.durable("capture"))

    def test_full_directory_generation_drift_requires_new_full_barrier(self):
        for field in ("st_mtime_ns", "st_ctime_ns", "st_nlink", "raw"):
            fake, _, store = self.fixture()
            store.put_exclusive("capture", b"fixture")
            if field == "raw":
                fake.parent[field].extend(b"size changed")
            else:
                fake.parent[field] += 1
            store.sync_record("capture", b"fixture")
            self.assertEqual(fake.counts["fsync"], 4)
            store.sync_record("capture", b"fixture")
            self.assertEqual(fake.counts["fsync"], 4)

    def test_other_record_creation_invalidates_old_directory_proof(self):
        fake, _, store = self.fixture()
        store.put_exclusive("capture", b"fixture")
        store.put_exclusive("rollback.initial.intent", b"intent")
        self.assertEqual(fake.counts["fsync"], 4)
        store.sync_record("capture", b"fixture")
        self.assertEqual(fake.counts["fsync"], 6)
        store.sync_record("capture", b"fixture")
        self.assertEqual(fake.counts["fsync"], 6)

    def test_rename_away_and_back_needs_directory_barrier_even_same_file_stamp(self):
        fake, _, store = self.fixture()
        store.put_exclusive("capture", b"fixture")
        original = copy.deepcopy(fake.files["capture"])
        item = fake.files.pop("capture")  # external namespace changes, not Store operations
        fake.files["capture"] = item
        fake.parent["st_ctime_ns"] += 2
        fake.parent["st_mtime_ns"] += 2
        fake.directory_synced.clear()
        self.assertEqual(fake.files["capture"], original)
        store.sync_record("capture", b"fixture")
        self.assertEqual(fake.counts["fsync"], 4)
        self.assertTrue(fake.durable("capture"))

    def test_reuse_observations_reject_substitution_and_bracket_stamp_drift(self):
        for kind in ("named", "file", "directory", "bytes"):
            fake, _, store = self.fixture()
            store.put_exclusive("capture", b"fixture")
            def drift():
                if kind == "named":
                    fake.files["capture"] = node(inode=999)
                elif kind == "file":
                    fake.files["capture"]["st_ctime_ns"] += 1
                elif kind == "directory":
                    fake.parent["st_ctime_ns"] += 1
                else:
                    fake.files["capture"]["raw"] = bytearray(b"changed")
            # Change during the second full read, after a reusable proof was selected.
            fake.effects[("pread", fake.counts["pread"] + 3)] = drift
            self.assert_redacted(lambda: store.sync_record("capture", b"fixture"))
            self.assertEqual(store._barriers, {})
            self.assertFalse(fake.handles)
            self.assertEqual(fake.counts["fsync"], 2)

    def test_new_store_has_no_reusable_proof_and_rechecks_parent_before_reuse(self):
        fake, parent, store = self.fixture()
        store.put_exclusive("capture", b"fixture")
        new_store = S.DurableStore(parent, syscalls=fake)
        new_store.sync_record("capture", b"fixture")
        self.assertEqual(fake.counts["fsync"], 4)
        parent.verify = lambda: False
        self.assert_redacted(lambda: store.sync_record("capture", b"fixture"))
        self.assertEqual(store._barriers, {})
        self.assertEqual(fake.counts["fsync"], 4)

    def test_any_failed_observation_or_interrupt_clears_all_proofs(self):
        for error in (OSError("private read"), KeyboardInterrupt(), SystemExit(7)):
            fake, _, store = self.fixture()
            store.put_exclusive("capture", b"fixture")
            store.put_exclusive("rollback.initial.intent", b"intent")
            store.sync_record("capture", b"fixture")
            self.assertEqual(len(store._barriers), 2)
            fake.effects[("pread", fake.counts["pread"] + 1)] = error
            if isinstance(error, Exception):
                self.assert_redacted(lambda: store.read("capture"))
            else:
                with self.assertRaises(type(error)) as raised:
                    store.read("capture")
                self.assertIs(raised.exception, error)
            self.assertEqual(store._barriers, {})
            before = fake.counts["fsync"]
            store.sync_record("rollback.initial.intent", b"intent")
            self.assertEqual(fake.counts["fsync"], before + 2)

    def test_failed_or_interrupted_first_barrier_cannot_create_reusable_proof(self):
        for operation, index in (("fsync", 1), ("fsync", 2), ("fsync-return", 2)):
            for error in (OSError("private sync"), KeyboardInterrupt(), SystemExit(7)):
                fake, _, store = self.fixture()
                fake.files["capture"] = node()
                fake.effects[(operation, index)] = error
                if isinstance(error, Exception):
                    self.assert_redacted(lambda: store.sync_record("capture", b"fixture"))
                else:
                    with self.assertRaises(type(error)) as raised:
                        store.sync_record("capture", b"fixture")
                    self.assertIs(raised.exception, error)
                self.assertEqual(store._barriers, {})
                previous = fake.counts["fsync"]
                store.sync_record("capture", b"fixture")
                self.assertEqual(fake.counts["fsync"], previous + 2)
                self.assertFalse(fake.handles)

    def test_close_failure_discards_completed_proof_and_preserves_first_interrupt(self):
        for primary, late in ((None, OSError("private close")),
                              (KeyboardInterrupt(), SystemExit(7)),
                              (SystemExit(7), OSError("private close"))):
            fake, _, store = self.fixture()
            store.put_exclusive("capture", b"fixture")
            close = fake.close
            def fail_close(descriptor):
                close(descriptor)
                raise late
            fake.close = fail_close
            if primary is None:
                self.assert_redacted(lambda: store.sync_record("capture", b"fixture"))
            else:
                fake.effects[("pread", fake.counts["pread"] + 1)] = primary
                with self.assertRaises(type(primary)) as raised:
                    store.sync_record("capture", b"fixture")
                self.assertIs(raised.exception, primary)
            self.assertEqual(store._barriers, {})
            self.assertFalse(fake.handles)
            fake.close = close
            before = fake.counts["fsync"]
            store.sync_record("capture", b"fixture")
            self.assertEqual(fake.counts["fsync"], before + 2)

    def test_uncertain_full_write_requires_exact_durability_barrier(self):
        for failure_index in (1, 2):
            fake, _, store = self.fixture()
            fake.effects[("fsync", failure_index)] = OSError("private-sync-failure")
            self.assert_redacted(lambda: store.put_exclusive("capture", b"complete"))
            self.assertEqual(store.read("capture"), b"complete")
            self.assertFalse(fake.durable("capture"))
            store.sync_record("capture", b"complete")
            self.assertTrue(fake.durable("capture"))
            self.assertFalse(fake.handles)

    def test_uncertain_partial_write_retained_and_not_silently_completed(self):
        fake, _, store = self.fixture()
        fake.short_write = 2
        fake.effects[("write", 2)] = OSError("private-write-failure")
        self.assert_redacted(lambda: store.put_exclusive("capture", b"complete"))
        self.assertEqual(store.read("capture"), b"co")
        self.assert_redacted(lambda: store.sync_record("capture", b"complete"))
        self.assertFalse(fake.durable("capture"))
        self.assertEqual(bytes(fake.files["capture"]["raw"]), b"co")
        self.assertFalse(fake.handles)

    def test_existing_record_never_overwritten_or_removed(self):
        for kind in (stat.S_IFREG, stat.S_IFLNK, stat.S_IFIFO, stat.S_IFDIR):
            fake, _, store = self.fixture()
            fake.files["capture"] = node(kind=kind)
            before = copy.deepcopy(fake.files)
            self.assert_redacted(lambda: store.put_exclusive("capture", b"replacement"))
            self.assertEqual(fake.files, before)
            self.assertFalse(fake.handles)

    def test_record_inode_pins_survive_read_and_exclusive_creation(self):
        for created in (False, True):
            fake, _, store = self.fixture()
            if created:
                store.put_exclusive("capture", b"fixture")
            else:
                fake.files["capture"] = node()
                store.read("capture")
            fake.files["capture"] = node(inode=999)
            for method in (lambda: store.read("capture"),
                           lambda: store.sync_record("capture", b"fixture")):
                self.assert_redacted(method)
            self.assertEqual(fake.files["capture"]["st_ino"], 999)
            self.assertFalse(fake.handles)

    def test_absence_pin_updates_only_after_owned_exclusive_creation(self):
        fake, _, store = self.fixture()
        self.assertIsNone(store.read("capture"))
        fake.files["capture"] = node()
        self.assert_redacted(lambda: store.read("capture"))
        self.assert_redacted(lambda: store.sync_record("capture", b"fixture"))
        self.assert_redacted(lambda: store.put_exclusive("capture", b"replacement"))
        self.assertEqual(bytes(fake.files["capture"]["raw"]), b"fixture")

    def test_present_pin_disappearance_cannot_be_recreated(self):
        fake, _, store = self.fixture()
        fake.files["capture"] = node()
        store.read("capture")
        fake.files.pop("capture")  # external actor, not Store cleanup
        self.assert_redacted(lambda: store.read("capture"))
        before = list(fake.calls)
        self.assert_redacted(lambda: store.put_exclusive("capture", b"replacement"))
        self.assertEqual(fake.calls, before)
        self.assertFalse(fake.files)

    def test_uncertain_creation_retains_inode_pin(self):
        fake, _, store = self.fixture()
        fake.effects[("write", 1)] = OSError("private-write-failure")
        self.assert_redacted(lambda: store.put_exclusive("capture", b"new"))
        fake.files["capture"] = node(b"", inode=999)
        self.assert_redacted(lambda: store.read("capture"))
        self.assert_redacted(lambda: store.sync_record("capture", b""))
        self.assertFalse(fake.handles)

    def test_metadata_failure_after_creation_still_retains_known_inode(self):
        fake, _, store = self.fixture()
        fake.effects[("fstat", 3)] = lambda: fake.files["capture"].update(st_mode=stat.S_IFREG | 0o644)
        self.assert_redacted(lambda: store.put_exclusive("capture", b"new"))
        fake.files["capture"] = node(b"", inode=999)
        self.assert_redacted(lambda: store.read("capture"))
        self.assertFalse(fake.handles)

    def test_sync_unknown_bytes_or_missing_record_does_not_fsync(self):
        fake, _, store = self.fixture()
        self.assert_redacted(lambda: store.sync_record("capture", b"expected"))
        fake.files["capture"] = node(b"unknown")
        self.assert_redacted(lambda: store.sync_record("capture", b"expected"))
        self.assertNotIn("fsync", fake.counts)
        self.assertEqual(bytes(fake.files["capture"]["raw"]), b"unknown")

    def test_barrier_readbacks_use_same_fd_around_file_then_parent_fsync(self):
        fake, _, store = self.fixture()
        fake.files["capture"] = node()
        store.sync_record("capture", b"fixture")
        self.assertEqual(fake.counts["open"], 1)
        self.assertEqual([c[1] for c in fake.calls if c[0] == "fsync"], [100, 99])
        self.assertEqual({c[1] for c in fake.calls if c[0] == "pread"}, {100})
        fsync_indices = [i for i, call in enumerate(fake.calls) if call[0] == "fsync"]
        read_indices = [i for i, call in enumerate(fake.calls) if call[0] == "pread"]
        self.assertLess(min(read_indices), min(fsync_indices))
        self.assertGreater(max(read_indices), max(fsync_indices))

    def test_barrier_detects_same_bytes_inode_substitution(self):
        for point in (1, 2):
            fake, _, store = self.fixture()
            fake.files["capture"] = node()
            fake.effects[("fsync", point)] = lambda: fake.files.update(capture=node(inode=999))
            self.assert_redacted(lambda: store.sync_record("capture", b"fixture"))
            self.assertEqual(fake.files["capture"]["st_ino"], 999)
            self.assertFalse(fake.handles)

    def test_barrier_detects_bytes_and_envelope_drift(self):
        changes = {"raw": bytearray(b"changed"), "st_dev": 4, "st_ino": 999,
                   "st_uid": 502, "st_gid": 21, "st_nlink": 2,
                   "st_mode": stat.S_IFREG | 0o644, "st_flags": 1,
                   "st_mtime_ns": 101, "st_ctime_ns": 201}
        for field, value in changes.items():
            fake, _, store = self.fixture()
            fake.files["capture"] = node()
            fake.effects[("fsync", 1)] = lambda: fake.files["capture"].update({field: value})
            self.assert_redacted(lambda: store.sync_record("capture", b"fixture"))
            self.assertFalse(fake.handles)

    def test_parent_drift_before_or_during_barrier_fails_closed(self):
        for during in (False, True):
            fake, _, store = self.fixture()
            fake.files["capture"] = node()
            if during:
                fake.effects[("fsync", 1)] = lambda: fake.parent.update(st_ino=999)
            else:
                fake.parent["st_ino"] = 999
            self.assert_redacted(lambda: store.sync_record("capture", b"fixture"))
            self.assertFalse(fake.handles)

    def test_parent_requires_exact_mode_owner_and_stable_envelope(self):
        for field, value in (("st_mode", stat.S_IFDIR | 0o755), ("st_mode", stat.S_IFREG | 0o700),
                             ("st_uid", 502), ("st_gid", 21), ("st_dev", 4),
                             ("st_ino", 11), ("st_flags", 1), ("st_flags", True)):
            fake, _, store = self.fixture()
            fake.parent[field] = value
            self.assert_redacted(store.verify)
        fake, parent, store = self.fixture()
        parent.verify = lambda: False
        self.assert_redacted(store.verify)
        for descriptor in (True, -1, 2 ** 31, None):
            fake, parent, store = self.fixture()
            parent.descriptor = descriptor
            self.assert_redacted(store.verify)

    def test_owner_mode_link_type_validation_precedes_record_read(self):
        changes = ({"st_uid": 502}, {"st_mode": stat.S_IFREG | 0o644},
                   {"st_mode": stat.S_IFREG | 0o4600}, {"st_mode": stat.S_IFREG | 0o400},
                   {"st_nlink": 2}, {"st_nlink": 0}, {"st_ino": True}, {"st_flags": -1})
        for change in changes:
            fake, _, store = self.fixture()
            fake.files["capture"] = node()
            fake.files["capture"].update(change)
            self.assert_redacted(lambda: store.read("capture"))
            self.assertNotIn("pread", fake.counts)
            self.assertFalse(fake.handles)
        for kind in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFDIR):
            fake, _, store = self.fixture()
            fake.files["capture"] = node(kind=kind)
            self.assert_redacted(lambda: store.read("capture"))
            self.assertNotIn("pread", fake.counts)
            self.assertFalse(fake.handles)

    def test_oversize_file_rejected_without_read_and_growth_is_bounded(self):
        fake, _, store = self.fixture()
        fake.files["capture"] = node(b"x" * (S.MAX_RECORD_BYTES + 1))
        self.assert_redacted(lambda: store.read("capture"))
        self.assertNotIn("pread", fake.counts)
        fake.files["capture"]["raw"] = bytearray(b"short")
        fake.effects[("pread", 1)] = lambda: fake.files["capture"]["raw"].extend(b"grew")
        self.assert_redacted(lambda: store.read("capture"))
        self.assertFalse(fake.handles)

    def test_zero_progress_and_invalid_write_counts_keep_partial_record(self):
        for result in (0, -1, True, None, 100):
            fake, _, store = self.fixture()
            fake.write = lambda fd, raw: result
            self.assert_redacted(lambda: store.put_exclusive("capture", b"123"))
            self.assertEqual(set(fake.files), {"capture"})
            self.assertFalse(fake.handles)

    def test_corrupted_write_count_cannot_substitute_for_readback(self):
        fake, _, store = self.fixture()
        original_write = fake.write
        fake.write = lambda fd, raw: original_write(fd, b"!" * len(raw))
        self.assert_redacted(lambda: store.put_exclusive("capture", b"expected"))
        self.assertEqual(bytes(fake.files["capture"]["raw"]), b"!!!!!!!!")
        self.assertNotIn("fsync", fake.counts)
        self.assertFalse(fake.handles)

    def test_invalid_read_result_is_rejected_without_leaking_or_spinning(self):
        for result in ("private", bytearray(b"fixture"), b"x" * (S.CHUNK_BYTES + 1)):
            fake, _, store = self.fixture()
            fake.files["capture"] = node()
            fake.pread = lambda fd, size, offset: result
            self.assert_redacted(lambda: store.read("capture"))
            self.assertFalse(fake.handles)

    def test_interruptions_close_owned_descriptors_and_preserve_records(self):
        for event, index in (("fstat", 3), ("write", 1), ("pread", 1), ("fsync", 1),
                             ("fsync", 2), ("stat", 2)):
            fake, _, store = self.fixture()
            fake.effects[(event, index)] = KeyboardInterrupt()
            with self.assertRaises(KeyboardInterrupt):
                store.put_exclusive("capture", b"expected")
            self.assertEqual(set(fake.files), {"capture"})
            self.assertFalse(fake.handles)
        for event, index in (("fstat", 4), ("pread", 1), ("fsync", 1), ("fsync", 2)):
            fake, _, store = self.fixture()
            fake.files["capture"] = node()
            fake.effects[(event, index)] = SystemExit(1)
            with self.assertRaises(SystemExit):
                store.sync_record("capture", b"fixture")
            self.assertFalse(fake.handles)

    def test_ambiguous_close_has_no_retry_or_cleanup(self):
        fake, _, store = self.fixture()
        original_close = fake.close

        def close(fd):
            original_close(fd)
            raise OSError("private-ambiguous-close")

        fake.close = close
        self.assert_redacted(lambda: store.put_exclusive("capture", b"expected"))
        self.assertEqual(fake.counts["close"], 1)
        self.assertEqual(set(fake.files), {"capture"})
        self.assertFalse(fake.handles)

    def test_postsync_failure_retains_a_complete_record_for_new_barrier(self):
        fake, _, store = self.fixture()
        fake.effects[("fsync-return", 2)] = OSError("private-ambiguous-durability")
        self.assert_redacted(lambda: store.put_exclusive("capture", b"complete"))
        self.assertTrue(fake.durable("capture"))
        store.sync_record("capture", b"complete")
        self.assertFalse(fake.handles)

    def test_absence_recheck_rejects_new_object(self):
        fake, _, store = self.fixture()
        fake.effects[("stat", 1)] = lambda: fake.files.update(capture=node())
        self.assert_redacted(lambda: store.read("capture"))
        self.assertEqual(set(fake.files), {"capture"})

    def test_real_session_with_fake_descriptor_store_completes_full_lifecycle(self):
        fixture_module = importlib.import_module("tests.test_phase5_runtime_session")
        self.assertEqual(fixture_module.MAX_RECORD_BYTES, S.MAX_RECORD_BYTES)
        backends, _, before, after, _ = fixture_module.fixture()
        original = fixture_module.images(backends)
        fake, _, store = self.fixture()
        self.assertEqual(fixture_module.capture(backends, store, before, after,
                                               session_id=fixture_module.SESSION)["verdict"], "captured")
        self.assertEqual(fixture_module.noop(backends, store)["verdict"], "noop")
        self.assertEqual(fixture_module.rollback(backends, store)["verdict"], "completed")
        self.assertEqual(fixture_module.return_current(backends, store)["verdict"], "completed")
        self.assertEqual(fixture_module.verify(backends, store, state="return")["verdict"], "verified")
        self.assertEqual([(i.data, i.mode) for i in fixture_module.images(backends)],
                         [(i.data, i.mode) for i in original])
        self.assertTrue(all(fake.durable(name) for name in fake.files))
        self.assertFalse(fake.handles)

    def test_real_session_deterministic_barrier_reduction_preserves_every_call(self):
        fixture_module = importlib.import_module("tests.test_phase5_runtime_session")
        class AlwaysFsync(S.DurableStore):
            def _barrier(self, *args, **kwargs):
                self._barriers.clear()  # test-only baseline: never reuse completed proof
                return super()._barrier(*args, **kwargs)
        counts = []
        for store_type in (AlwaysFsync, S.DurableStore):
            fake = FakeOS()
            store = store_type(Parent(fake), syscalls=fake)
            backends, _, before, after, _ = fixture_module.fixture()
            self.assertEqual(fixture_module.capture(backends, store, before, after,
                session_id=fixture_module.SESSION)["verdict"], "captured")
            self.assertEqual(fixture_module.noop(backends, store)["verdict"], "noop")
            self.assertEqual(fixture_module.rollback(backends, store)["verdict"], "completed")
            self.assertEqual(fixture_module.return_current(backends, store)["verdict"], "completed")
            self.assertEqual(fixture_module.verify(backends, store, state="return")["verdict"], "verified")
            self.assertTrue(all(fake.durable(name) for name in fake.files))
            self.assertFalse(fake.handles)
            counts.append({key: fake.counts[key] for key in ("fsync", "open", "pread", "stat")})
        self.assertLess(counts[1]["fsync"], counts[0]["fsync"] // 2)
        for key in ("open", "pread", "stat"):
            self.assertEqual(counts[0][key], counts[1][key])
        self.barrier_counts = counts  # synthetic count projection for root's source-only handoff

    def test_real_session_resume_barriers_uncertain_ticket_before_target_rename(self):
        fixture_module = importlib.import_module("tests.test_phase5_runtime_session")
        backends, _, before, after, _ = fixture_module.fixture()
        fake, _, store = self.fixture()
        self.assertEqual(fixture_module.capture(backends, store, before, after,
                                               session_id=fixture_module.SESSION)["verdict"], "captured")
        original_fsync = fake.fsync
        failed = []

        def fsync(fd):
            if (fd != 99 and not failed and fake.handles[fd] is fake.files.get("rollback.ticket.0")):
                failed.append(True)
                raise OSError("private-before-ticket-durability")
            original_fsync(fd)

        fake.fsync = fsync
        self.assertEqual(fixture_module.rollback(backends, store)["verdict"], "recovery-required")
        self.assertTrue(failed)
        self.assertFalse(fake.durable("rollback.ticket.0"))
        durable_at_rename = []
        backends["config"][0].hooks["before-rename"] = lambda _: durable_at_rename.append(
            fake.durable("rollback.ticket.0"))
        self.assertEqual(fixture_module.rollback(backends, store, resume=True)["verdict"], "completed")
        self.assertEqual(durable_at_rename, [True])
        self.assertIn("rollback.initial.failure", fake.files)
        self.assertFalse(fake.handles)

    def test_pure_fake_sequence_never_calls_native_io(self):
        with patch.object(S.os, "open", side_effect=AssertionError("native open forbidden")), \
                patch.object(S.os, "pread", side_effect=AssertionError("native pread forbidden")), \
                patch.object(S.os, "write", side_effect=AssertionError("native write forbidden")), \
                patch.object(S.os, "fsync", side_effect=AssertionError("native fsync forbidden")), \
                patch.object(S.os, "rename", side_effect=AssertionError("native rename forbidden")), \
                patch.object(S.os, "unlink", side_effect=AssertionError("native unlink forbidden")):
            fake, _, store = self.fixture()
            store.put_exclusive("capture", b"fixture")
            self.assertEqual(store.read("capture"), b"fixture")
            store.sync_record("capture", b"fixture")
            self.assertFalse(fake.handles)


if __name__ == "__main__":
    unittest.main()
