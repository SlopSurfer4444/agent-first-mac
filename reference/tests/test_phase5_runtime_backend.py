"""Fake syscalls ONLY. No temporary directories, native rename or owner reads."""

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
B = importlib.import_module("lib.phase5_runtime_backend")
T = importlib.import_module("lib.phase5_runtime_transition")


def node(data=b"private-fixture", *, inode=20, mode=0o600, kind=stat.S_IFREG):
    return {"data": data, "st_dev": 3, "st_ino": inode, "st_uid": 501,
            "st_gid": 20, "st_nlink": 1, "st_mode": kind | mode,
            "st_flags": 0, "st_mtime_ns": 100, "st_ctime_ns": 200}


class FakeOS:
    def __init__(self):
        self.files = {}
        self.parent = node(inode=10, mode=0o700, kind=stat.S_IFDIR)
        self.handles = {}
        self.next_fd = 100
        self.next_inode = 30
        self.calls, self.counts, self.effects = [], {}, {}
        self.short_write = None
        self.short_read = None

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
        return SimpleNamespace(**{k: v for k, v in item.items() if k != "data"},
                               st_size=len(item["data"]))

    def fstat(self, fd):
        self.event("fstat", fd)
        return self.facts(self.parent if fd == 99 else self.handles[fd][0])

    def stat(self, leaf, *, dir_fd, follow_symlinks):
        assert dir_fd == 99 and follow_symlinks is False
        self.event("stat", leaf)
        if leaf not in self.files:
            raise FileNotFoundError("private-fixture-not-found")
        return self.facts(self.files[leaf])

    def open(self, leaf, flags, mode=None, *, dir_fd):
        assert dir_fd == 99
        assert flags & os.O_CLOEXEC and flags & os.O_NOFOLLOW and flags & os.O_NONBLOCK
        self.event("open", leaf, flags, mode)
        if flags & os.O_CREAT:
            assert flags & os.O_EXCL and mode == 0o600
            if leaf in self.files:
                raise FileExistsError("private-fixture-existing")
            self.files[leaf] = node(b"", inode=self.next_inode, mode=mode)
            self.next_inode += 1
        elif leaf not in self.files:
            raise FileNotFoundError("private-fixture-not-found")
        elif stat.S_ISLNK(self.files[leaf]["st_mode"]):
            raise OSError("private-fixture-symlink")
        fd, self.next_fd = self.next_fd, self.next_fd + 1
        self.handles[fd] = [self.files[leaf], 0]
        return fd

    def close(self, fd):
        assert fd != 99, "borrowed parent must never be closed"
        self.event("close", fd)
        del self.handles[fd]

    def read(self, fd, maximum):
        self.event("read", fd, maximum)
        item, offset = self.handles[fd]
        count = maximum if self.short_read is None else min(maximum, self.short_read)
        result = item["data"][offset:offset + count]
        self.handles[fd][1] += len(result)
        return result

    def write(self, fd, data):
        self.event("write", fd, len(data))
        item, offset = self.handles[fd]
        count = len(data) if self.short_write is None else min(len(data), self.short_write)
        item["data"] = item["data"][:offset] + data[:count]
        item["st_mtime_ns"] += 1
        item["st_ctime_ns"] += 1
        self.handles[fd][1] += count
        return count

    def fchmod(self, fd, mode):
        self.event("fchmod", fd, mode)
        self.handles[fd][0]["st_mode"] = stat.S_IFREG | mode
        self.handles[fd][0]["st_ctime_ns"] += 1

    def fsync(self, fd):
        self.event("fsync", fd)

    def rename(self, fd, source, destination, flag):
        assert fd == 99
        self.event("rename", source, destination, flag)
        if source not in self.files:
            raise FileNotFoundError("private-source-missing")
        if flag == B.RENAME_SWAP:
            if destination not in self.files:
                raise FileNotFoundError("private-destination-missing")
            self.files[source], self.files[destination] = self.files[destination], self.files[source]
            self.files[source]["st_ctime_ns"] += 1
        else:
            assert flag == B.RENAME_EXCL
            if destination in self.files:
                raise FileExistsError("private-destination-existing")
            self.files[destination] = self.files.pop(source)
        self.files[destination]["st_ctime_ns"] += 1
        self.event("rename-return")


class Parent:
    descriptor, uid = 99, 501

    def __init__(self, fake):
        self.fake = fake

    def verify(self):
        self.fake.event("verify")


class BackendTests(unittest.TestCase):
    def test_canonical_transition_identity_is_shared(self):
        canonical = importlib.import_module("lib.phase5_runtime_transition")
        self.assertIs(T, canonical)
        self.assertIs(B.Image, canonical.Image)
        self.assertIs(B.ABSENT, canonical.ABSENT)
        self.assertNotIn("phase5_runtime_transition", sys.modules)
        fake, _, backend = self.fixture()
        self.assertIs(backend.snapshot("missing"), canonical.ABSENT)
        fake.files["target"] = node()
        self.assertIs(type(backend.snapshot("target")), canonical.Image)

    def fixture(self, **kwargs):
        fake = FakeOS()
        parent = Parent(fake)
        backend = B.DescriptorBackend(parent, syscalls=fake, rename=fake.rename, **kwargs)
        return fake, parent, backend

    def assert_redacted(self, operation):
        with self.assertRaises(B.BackendError) as raised:
            operation()
        self.assertEqual(str(raised.exception), "runtime_backend_recovery_required")
        self.assertNotIn("private", repr(raised.exception))

    def test_snapshot_absent_and_regular_preserve_all_files(self):
        fake, _, backend = self.fixture()
        self.assertEqual(backend.snapshot("missing"), T.ABSENT)
        fake.files["target"] = node()
        before = copy.deepcopy(fake.files)
        image = backend.snapshot("target")
        self.assertEqual((image.data, image.identity, image.mode), (b"private-fixture", (3, 20), 0o600))
        self.assertEqual(len(image.seal), 40)
        self.assertEqual(fake.files, before)
        self.assertFalse(fake.handles)

    def test_creation_short_writes_readback_and_sync_order(self):
        fake, _, backend = self.fixture()
        fake.short_write, fake.short_read = 2, 3
        result = backend.create_exclusive("stage", b"0123456789", 0o644)
        self.assertEqual(result.data, b"0123456789")
        self.assertEqual(result.mode, 0o644)
        self.assertEqual(fake.counts["write"], 5)
        syncs = [row[1] for row in fake.calls if row[0] == "fsync"]
        self.assertEqual(syncs, [100, 99])
        self.assertFalse(fake.handles)
        self.assertEqual(set(fake.files), {"stage"})

    def test_empty_image_and_maximum_image(self):
        for data in (b"", b"x" * T.MAX_IMAGE_BYTES):
            with self.subTest(size=len(data)):
                fake, _, backend = self.fixture()
                self.assertEqual(backend.create_exclusive("stage", data, 0o600).data, data)
                self.assertFalse(fake.handles)

    def test_descriptor_admission_runs_on_same_empty_fd_before_any_payload_or_chmod(self):
        fake, _, backend = self.fixture()
        descriptors = []
        def admit(descriptor):
            descriptors.append(descriptor)
            self.assertIs(fake.handles[descriptor][0], fake.files["stage"])
            self.assertEqual(fake.files["stage"]["data"], b"")
            self.assertEqual(stat.S_IMODE(fake.files["stage"]["st_mode"]), 0o600)
            self.assertFalse(any(op in fake.counts for op in ("write", "fchmod", "fsync")))
            return True
        result = backend.create_exclusive("stage", b"private payload", 0o644, admit_descriptor=admit)
        self.assertEqual(result.data, b"private payload")
        self.assertEqual(len(descriptors), 1)
        self.assertFalse(fake.handles)

    def test_descriptor_admission_nonexact_true_or_failure_retains_empty_stage(self):
        for value in (False, None, 0, 1, "yes", [], {}):
            fake, _, backend = self.fixture()
            self.assert_redacted(lambda: backend.create_exclusive("stage", b"secret", 0o644,
                admit_descriptor=lambda _: value))
            self.assertEqual(fake.files["stage"]["data"], b"")
            self.assertEqual(stat.S_IMODE(fake.files["stage"]["st_mode"]), 0o600)
            self.assertFalse(any(op in fake.counts for op in ("write", "fchmod", "fsync")))
            self.assertEqual(fake.counts["close"], 1)
            self.assertFalse(fake.handles)
        for error in (OSError("private admission error"), KeyboardInterrupt(), SystemExit(7)):
            fake, _, backend = self.fixture()
            def admit(_):
                raise error
            if isinstance(error, Exception):
                self.assert_redacted(lambda: backend.create_exclusive("stage", b"secret", 0o600, admit_descriptor=admit))
            else:
                with self.assertRaises(type(error)) as raised:
                    backend.create_exclusive("stage", b"secret", 0o600, admit_descriptor=admit)
                self.assertIs(raised.exception, error)
            self.assertEqual(fake.files["stage"]["data"], b"")
            self.assertFalse(any(op in fake.counts for op in ("write", "fchmod", "fsync")))
            self.assertEqual(fake.counts["close"], 1)
            self.assertFalse(fake.handles)

    def test_descriptor_admission_invalid_callback_refused_before_creation(self):
        for callback in (False, 1, "yes", {}, []):
            fake, _, backend = self.fixture()
            self.assert_redacted(lambda: backend.create_exclusive("stage", b"secret", 0o600,
                                                                  admit_descriptor=callback))
            self.assertEqual(fake.files, {})
            self.assertNotIn("open", fake.counts)

    def test_admission_interrupt_survives_failed_single_close(self):
        for error, late in ((KeyboardInterrupt(), OSError("private close")), (SystemExit(7), KeyboardInterrupt())):
            fake, _, backend = self.fixture()
            close = fake.close
            def interrupted(_):
                raise error
            def close_once(descriptor):
                close(descriptor)
                raise late
            fake.close = close_once
            with self.assertRaises(type(error)) as raised:
                backend.create_exclusive("stage", b"secret", 0o600, admit_descriptor=interrupted)
            self.assertIs(raised.exception, error)
            self.assertEqual(fake.counts["close"], 1)
            self.assertFalse(fake.handles)
            self.assertEqual(fake.files["stage"]["data"], b"")
            self.assertFalse(any(op in fake.counts for op in ("write", "fchmod", "fsync")))

    def test_descriptor_admission_substitution_or_stat_drift_fails_before_write(self):
        for change in ("named", "held", "parent"):
            fake, _, backend = self.fixture()
            held = []
            def admit(descriptor):
                held.append(fake.handles[descriptor][0])
                if change == "named":
                    fake.files["stage"] = node(b"unknown", inode=999)
                elif change == "held":
                    fake.handles[descriptor][0]["st_ctime_ns"] += 1
                else:
                    fake.parent["st_ino"] += 1
                return True
            self.assert_redacted(lambda: backend.create_exclusive("stage", b"secret", 0o600, admit_descriptor=admit))
            self.assertEqual(held[0]["data"], b"")
            self.assertFalse(any(op in fake.counts for op in ("write", "fchmod", "fsync")))
            self.assertEqual(fake.counts["close"], 1)
            self.assertFalse(fake.handles)

    def test_invalid_names_are_rejected_before_any_syscall(self):
        for leaf in (None, b"name", ".", "..", "", "/tmp/file", "a/b", "a\x00b", "é", "x" * 129, True):
            for method in ("snapshot", "create_exclusive", "swap", "move_exclusive"):
                with self.subTest(leaf_type=type(leaf).__name__, method=method):
                    fake, _, backend = self.fixture()
                    before = list(fake.calls)
                    args = ((leaf,) if method == "snapshot" else (leaf, b"x", 0o600)
                            if method == "create_exclusive" else (leaf, "other"))
                    self.assert_redacted(lambda: getattr(backend, method)(*args))
                    self.assertEqual(fake.calls, before)

    def test_invalid_bytes_modes_and_limits(self):
        for data, mode in ((bytearray(b"x"), 0o600), ("x", 0o600), (None, 0o600),
                           (b"x" * (T.MAX_IMAGE_BYTES + 1), 0o600), (b"x", True),
                           (b"x", 0o666), (b"x", 0o200), (b"x", 0o4600), (b"x", -1)):
            fake, _, backend = self.fixture()
            before = list(fake.calls)
            self.assert_redacted(lambda: backend.create_exclusive("stage", data, mode))
            self.assertEqual(before, fake.calls)
        for maximum in (-1, True, None, T.MAX_IMAGE_BYTES + 1):
            self.assert_redacted(lambda: self.fixture(maximum=maximum))

    def test_owner_link_type_and_mode_negatives_close_fd(self):
        mutations = ({"st_uid": 502}, {"st_nlink": 2}, {"st_nlink": 0},
                     {"st_mode": stat.S_IFIFO | 0o600}, {"st_mode": stat.S_IFDIR | 0o700},
                     {"st_mode": stat.S_IFSOCK | 0o600}, {"st_mode": stat.S_IFCHR | 0o600},
                     {"st_mode": stat.S_IFREG | 0o666}, {"st_mode": stat.S_IFREG | 0o4600},
                     {"st_mode": stat.S_IFREG | 0o200}, {"st_ino": True}, {"st_flags": -1})
        for values in mutations:
            with self.subTest(fields=list(values)):
                fake, _, backend = self.fixture()
                fake.files["target"] = node()
                fake.files["target"].update(values)
                self.assert_redacted(lambda: backend.snapshot("target"))
                self.assertFalse(fake.handles)
                self.assertNotIn("read", fake.counts)

    def test_symlink_and_existing_stage_are_not_followed_or_modified(self):
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFREG | 0o600):
            fake, _, backend = self.fixture()
            fake.files["stage"] = node()
            fake.files["stage"]["st_mode"] = mode
            before = copy.deepcopy(fake.files)
            self.assert_redacted(lambda: backend.create_exclusive("stage", b"new", 0o600))
            if stat.S_ISLNK(mode):
                self.assert_redacted(lambda: backend.snapshot("stage"))
            self.assertEqual(fake.files, before)
            self.assertFalse(fake.handles)

    def test_limit_before_read_and_growth_during_read(self):
        fake, _, backend = self.fixture(maximum=3)
        fake.files["target"] = node(b"1234")
        self.assert_redacted(lambda: backend.snapshot("target"))
        self.assertNotIn("read", fake.counts)
        fake.files["target"]["data"] = b"123"
        fake.effects[("read", 1)] = lambda: fake.files["target"].update(data=b"12345")
        self.assert_redacted(lambda: backend.snapshot("target"))
        self.assertFalse(fake.handles)

    def test_each_metadata_field_drift_during_read_is_detected(self):
        changes = {"st_dev": 9, "st_ino": 999, "st_uid": 502, "st_gid": 21,
                   "st_nlink": 2, "st_mode": stat.S_IFREG | 0o644,
                   "st_flags": 1, "st_mtime_ns": 101, "st_ctime_ns": 201}
        for field, value in changes.items():
            fake, _, backend = self.fixture()
            fake.files["target"] = node()
            fake.effects[("read", 1)] = lambda: fake.files["target"].update({field: value})
            self.assert_redacted(lambda: backend.snapshot("target"))
            self.assertFalse(fake.handles)

    def test_named_replacement_with_equal_bytes_is_detected(self):
        fake, _, backend = self.fixture()
        fake.files["target"] = node()
        fake.effects[("read", 1)] = lambda: fake.files.update(target=node(inode=999))
        self.assert_redacted(lambda: backend.snapshot("target"))
        self.assertEqual(fake.files["target"]["st_ino"], 999)
        self.assertFalse(fake.handles)

    def test_name_appearing_during_absence_check_is_conflict(self):
        fake, _, backend = self.fixture()
        fake.effects[("stat", 1)] = lambda: fake.files.update(target=node())
        self.assert_redacted(lambda: backend.snapshot("target"))
        self.assertEqual(set(fake.files), {"target"})

    def test_zero_progress_or_bad_write_count_retains_stage(self):
        for count in (0, -1, True, 100, None):
            fake, _, backend = self.fixture()
            fake.write = lambda descriptor, data: count
            self.assert_redacted(lambda: backend.create_exclusive("stage", b"abc", 0o600))
            self.assertEqual(set(fake.files), {"stage"})
            self.assertFalse(fake.handles)

    def test_partial_write_error_retains_exact_partial_file(self):
        fake, _, backend = self.fixture()
        fake.short_write = 2
        fake.effects[("write", 2)] = OSError("private-native-error")
        self.assert_redacted(lambda: backend.create_exclusive("stage", b"abcdef", 0o600))
        self.assertEqual(fake.files["stage"]["data"], b"ab")
        self.assertFalse(fake.handles)

    def test_full_write_count_does_not_substitute_for_readback(self):
        fake, _, backend = self.fixture()
        original_write = fake.write
        fake.write = lambda fd, data: original_write(fd, b"!" * len(data))
        self.assert_redacted(lambda: backend.create_exclusive("stage", b"owned", 0o600))
        self.assertEqual(fake.files["stage"]["data"], b"!!!!!")
        self.assertFalse(fake.handles)

    def test_bad_read_type_or_oversized_chunk_fails_closed(self):
        for result in ("private", bytearray(b"x"), b"x" * 65537):
            fake, _, backend = self.fixture()
            fake.files["target"] = node()
            fake.read = lambda fd, count: result
            self.assert_redacted(lambda: backend.snapshot("target"))
            self.assertFalse(fake.handles)

    def test_ambiguous_close_is_not_retried_and_no_file_is_removed(self):
        fake, _, backend = self.fixture()
        original_close = fake.close

        def close(fd):
            original_close(fd)
            raise OSError("private-ambiguous-close")

        fake.close = close
        self.assert_redacted(lambda: backend.create_exclusive("stage", b"owned", 0o600))
        self.assertEqual(fake.files["stage"]["data"], b"owned")
        self.assertEqual(fake.counts["close"], 2)  # readback FD and staging FD once each
        self.assertFalse(fake.handles)

    def test_stage_fd_is_closed_and_file_retained_on_interruptions(self):
        for event, index in (("fstat", 3), ("write", 1), ("fchmod", 1), ("fsync", 1),
                             ("read", 1), ("fsync", 2), ("stat", 2)):
            with self.subTest(event=event, index=index):
                fake, _, backend = self.fixture()
                fake.effects[(event, index)] = KeyboardInterrupt()
                with self.assertRaises(KeyboardInterrupt):
                    backend.create_exclusive("stage", b"abc", 0o600)
                self.assertEqual(set(fake.files), {"stage"})
                self.assertFalse(fake.handles)

    def test_read_fd_is_closed_on_interruptions(self):
        for event, index in (("fstat", 3), ("read", 1), ("stat", 1)):
            fake, _, backend = self.fixture()
            fake.files["target"] = node()
            fake.effects[(event, index)] = SystemExit(1)
            with self.assertRaises(SystemExit):
                backend.snapshot("target")
            self.assertFalse(fake.handles)

    def test_creation_substitution_on_readback_retains_unknown(self):
        fake, _, backend = self.fixture()
        fake.effects[("open", 2)] = lambda: fake.files.update(stage=node(b"unknown", inode=999))
        self.assert_redacted(lambda: backend.create_exclusive("stage", b"owned", 0o600))
        self.assertEqual(fake.files["stage"]["data"], b"unknown")
        self.assertFalse(fake.handles)

    def test_creation_sync_failure_retains_complete_file(self):
        for index in (1, 2):
            fake, _, backend = self.fixture()
            fake.effects[("fsync", index)] = OSError("private-sync-error")
            self.assert_redacted(lambda: backend.create_exclusive("stage", b"owned", 0o600))
            self.assertEqual(fake.files["stage"]["data"], b"owned")
            self.assertFalse(fake.handles)

    def test_parent_binding_and_safe_metadata(self):
        for field, value in (("st_ino", 11), ("st_uid", 502), ("st_gid", 21),
                             ("st_mode", stat.S_IFDIR | 0o777), ("st_flags", 1)):
            fake, _, backend = self.fixture()
            fake.parent[field] = value
            self.assert_redacted(lambda: backend.verify())
            self.assertFalse(fake.handles)
        fake, parent, backend = self.fixture()
        parent.descriptor = True
        self.assert_redacted(lambda: backend.verify())
        parent.descriptor, parent.uid = 99, True
        self.assert_redacted(lambda: backend.verify())
        parent.uid, parent.verify = 501, lambda: False
        self.assert_redacted(lambda: backend.verify())

    def test_sync_checks_chain_before_and_after_fsync(self):
        fake, _, backend = self.fixture()
        before = len(fake.calls)
        backend.sync()
        self.assertEqual([row[0] for row in fake.calls[before:]],
                         ["verify", "fstat", "fsync", "verify", "fstat"])
        fake.effects[("fsync", 2)] = lambda: fake.parent.update(st_ino=999)
        self.assert_redacted(lambda: backend.sync())

    def test_swap_and_exclusive_move_preserve_images_not_ctime(self):
        fake, _, backend = self.fixture()
        fake.files.update(source=node(b"source", inode=20), destination=node(b"dest", inode=21))
        source, destination = backend.snapshot("source"), backend.snapshot("destination")
        backend.swap("source", "destination")
        self.assertEqual((backend.snapshot("source"), backend.snapshot("destination")),
                         (destination, source))
        backend.move_exclusive("source", "recovery")
        self.assertEqual(backend.snapshot("recovery"), destination)
        self.assertEqual(backend.snapshot("source"), T.ABSENT)
        self.assertEqual([row[-1] for row in fake.calls if row[0] == "rename"],
                         [B.RENAME_SWAP, B.RENAME_EXCL])

    def test_rename_precondition_conflicts_make_zero_renames(self):
        for swap, source_exists, dest_exists in ((True, False, True), (True, True, False),
                                                  (False, False, False), (False, True, True)):
            fake, _, backend = self.fixture()
            if source_exists:
                fake.files["source"] = node(inode=20)
            if dest_exists:
                fake.files["dest"] = node(inode=21)
            self.assert_redacted(lambda: (backend.swap if swap else backend.move_exclusive)("source", "dest"))
            self.assertNotIn("rename", fake.counts)
        fake, _, backend = self.fixture()
        self.assert_redacted(lambda: backend.swap("same", "same"))
        self.assertNotIn("open", fake.counts)

    def test_swap_race_displaces_but_retains_unknown(self):
        fake, _, backend = self.fixture()
        fake.files.update(source=node(b"source", inode=20), dest=node(b"dest", inode=21))
        fake.effects[("rename", 1)] = lambda: fake.files.update(dest=node(b"unknown", inode=999))
        self.assert_redacted(lambda: backend.swap("source", "dest"))
        self.assertEqual(fake.files["source"]["data"], b"unknown")
        self.assertEqual(fake.files["dest"]["data"], b"source")
        self.assertEqual(fake.counts["rename"], 1)

    def test_exclusive_race_never_overwrites_collision(self):
        fake, _, backend = self.fixture()
        fake.files["source"] = node(b"source")
        fake.effects[("rename", 1)] = lambda: fake.files.update(dest=node(b"unknown", inode=999))
        self.assert_redacted(lambda: backend.move_exclusive("source", "dest"))
        self.assertEqual(fake.files["source"]["data"], b"source")
        self.assertEqual(fake.files["dest"]["data"], b"unknown")
        self.assertEqual(fake.counts["rename"], 1)

    def test_rename_failure_after_effect_is_not_reversed(self):
        for failure in (OSError("private-ambiguous"), KeyboardInterrupt()):
            fake, _, backend = self.fixture()
            fake.files["source"] = node(b"source")
            fake.effects[("rename-return", 1)] = failure
            if isinstance(failure, Exception):
                self.assert_redacted(lambda: backend.move_exclusive("source", "dest"))
            else:
                with self.assertRaises(KeyboardInterrupt):
                    backend.move_exclusive("source", "dest")
            self.assertEqual(set(fake.files), {"dest"})
            self.assertEqual(fake.counts["rename"], 1)
            self.assertFalse(fake.handles)

    def test_transition_consumes_real_adapter_with_fake_syscalls_only(self):
        for source, destination in ((b"old", b"new"), (None, b"new"), (b"old", None),
                                     (b"same", b"same"), (None, None)):
            with self.subTest(source_present=source is not None, dest_present=destination is not None):
                fake, _, backend = self.fixture()
                if source is not None:
                    fake.files["target"] = node(source)
                ticket = T.prepare(backend, target="target", temporary="stage", recovery="saved",
                                   source=backend.snapshot("target"), destination_bytes=destination,
                                   mode=0o600 if destination is not None else None)
                result = T.transition(backend, ticket)
                self.assertIn(result["verdict"], ("completed", "noop"))
                self.assertFalse(result["executionAdmission"])
                self.assertEqual(backend.snapshot("target").data, destination)
                self.assertIn(T.recover(backend, ticket)["verdict"], ("recovered", "noop"))
                self.assertEqual(backend.snapshot("target").data, source)
                self.assertFalse(fake.handles)

    def test_native_adapter_uses_only_exact_darwin_symbol_with_fake_library(self):
        class Function:
            def __init__(self):
                self.calls, self.result = [], 0

            def __call__(self, *args):
                self.calls.append(args)
                return self.result

        function = Function()
        library = SimpleNamespace(renameatx_np=function)
        with patch.object(B.sys, "platform", "darwin"), patch.object(B.ctypes, "CDLL", return_value=library) as load:
            B._native_rename(99, "source", "dest", B.RENAME_EXCL)
            load.assert_called_once_with("/usr/lib/libSystem.B.dylib", use_errno=True)
            self.assertEqual(function.calls, [(99, b"source", 99, b"dest", 4)])
            self.assertEqual(len(function.argtypes), 5)
            function.result = -1
            self.assert_redacted(lambda: B._native_rename(99, "source", "dest", B.RENAME_SWAP))
        with patch.object(B.sys, "platform", "linux"), patch.object(B.ctypes, "CDLL") as load:
            self.assert_redacted(lambda: B._native_rename(99, "source", "dest", B.RENAME_EXCL))
            load.assert_not_called()
        for descriptor in (True, -1, 2 ** 31, None):
            with patch.object(B.sys, "platform", "darwin"), patch.object(B.ctypes, "CDLL") as load:
                self.assert_redacted(lambda: B._native_rename(descriptor, "source", "dest", B.RENAME_EXCL))
                load.assert_not_called()

    def test_no_native_filesystem_fallback_is_exercised(self):
        with patch.object(B.os, "open", side_effect=AssertionError("native open forbidden")), \
                patch.object(B.os, "rename", side_effect=AssertionError("native rename forbidden")), \
                patch.object(B.os, "replace", side_effect=AssertionError("native replace forbidden")), \
                patch.object(B.os, "unlink", side_effect=AssertionError("native unlink forbidden")), \
                patch.object(B.ctypes, "CDLL", side_effect=AssertionError("native library forbidden")):
            fake, _, backend = self.fixture()
            backend.create_exclusive("source", b"safe-fake", 0o600)
            backend.move_exclusive("source", "dest")
            backend.sync()
            self.assertFalse(fake.handles)


if __name__ == "__main__":
    unittest.main()
