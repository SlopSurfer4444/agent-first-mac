"""PURE fake syscalls/library tests: no native metadata or directory operations."""

import copy
import ctypes
import errno
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
P = importlib.import_module("lib.phase5_runtime_paths")
_reference_uint = P._uint


def node(inode, *, uid=501, mode=0o700, kind=stat.S_IFDIR):
    return dict(st_dev=3, st_ino=inode, st_uid=uid, st_gid=20, st_mode=kind | mode,
                st_flags=0, st_nlink=2, st_ctime_ns=10, st_mtime_ns=20)


def reference_identity(facts, *, directory=False):
    """Pre-optimization scalar oracle; no filesystem operations."""
    fields = tuple(getattr(facts, key) for key in
                   ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_flags"))
    if (not all(_reference_uint(value) for value in fields)
            or (directory and not stat.S_ISDIR(facts.st_mode))
            or (not directory and not (stat.S_ISDIR(facts.st_mode)
                                       or stat.S_ISREG(facts.st_mode)))):
        P._fail()
    return fields


def reference_observation(facts):
    fields = reference_identity(facts) + tuple(getattr(facts, key) for key in
                                              ("st_nlink", "st_ctime_ns", "st_mtime_ns"))
    if not all(_reference_uint(value) for value in fields):
        P._fail()
    return fields


def scalar_benchmark():
    """Opt-in bounded pure timing; no timing assertion in correctness tests."""
    import timeit
    facts = SimpleNamespace(**node(17))
    result = {}
    for name, old, new in (
        ("identity", lambda: reference_identity(facts, directory=True),
         lambda: P._identity(facts, directory=True)),
        ("observation", lambda: reference_observation(facts), lambda: P._observation(facts)),
    ):
        assert old() == new()
        before = timeit.repeat(old, number=100000, repeat=3)
        after = timeit.repeat(new, number=100000, repeat=3)
        result[name] = {"callsPerRepeat": 100000, "referenceSeconds": before,
                        "candidateSeconds": after, "speedup": min(before) / min(after)}
    return result


class ScalarTests(unittest.TestCase):
    def equivalent(self, factory):
        for old, new in (
            (reference_identity, P._identity),
            (lambda facts: reference_identity(facts, directory=True),
             lambda facts: P._identity(facts, directory=True)),
            (reference_observation, P._observation),
        ):
            results = []
            for function in (old, new):
                facts = factory()
                try:
                    results.append(("value", function(facts)))
                except BaseException as error:
                    results.append(("error", type(error), error.args))
            self.assertEqual(results[0], results[1])

    def test_all_fields_exact_types_bounds_and_order(self):
        class IntSubclass(int):
            pass

        class HostileNumber:
            def __index__(self):
                raise AssertionError("must not coerce")

            def __le__(self, other):
                raise AssertionError("must reject type first")

            __ge__ = __le__

        for key in node(17):
            for value in (0, 1, 2 ** 32 - 1, 2 ** 32, 2 ** 63, 2 ** 64 - 1,
                          -1, -(2 ** 80), 2 ** 64, 2 ** 80, True, False, None,
                          0.0, float("inf"), float("nan"), "1", b"1", [], {}, (),
                          IntSubclass(0), IntSubclass(2 ** 64 - 1), HostileNumber()):
                with self.subTest(field=key, value_type=type(value).__name__):
                    self.equivalent(lambda: SimpleNamespace(**dict(node(17), **{key: value})))
        facts = SimpleNamespace(**node(17))
        self.assertEqual(P._identity(facts), (3, 17, 501, 20, stat.S_IFDIR | 0o700, 0))
        self.assertEqual(P._observation(facts),
                         (3, 17, 501, 20, stat.S_IFDIR | 0o700, 0, 2, 10, 20))

    def test_stat_kinds_and_permissions_are_equivalent(self):
        # Every low-16-bit mode, including unknown kinds and privileged bits.
        for mode in range(2 ** 16):
            facts = SimpleNamespace(**dict(node(17), st_mode=mode))
            for directory in (False, True):
                valid = stat.S_ISDIR(mode) or (not directory and stat.S_ISREG(mode))
                if valid:
                    self.assertEqual(P._identity(facts, directory=directory),
                                     reference_identity(facts, directory=directory))
                else:
                    with self.assertRaises(P.PathsError):
                        P._identity(facts, directory=directory)
        for mode in (2 ** 31, 2 ** 32, 2 ** 63, 2 ** 64 - 1):
            self.equivalent(lambda: SimpleNamespace(**dict(node(17), st_mode=mode)))

    def test_missing_fields_and_malformed_builtin_objects(self):
        for value in (None, True, 1, 1.0, "stat", b"stat", [], (), {}, object(),
                      os.stat_result((0,) * 10)):
            self.equivalent(lambda: value)
        for key in node(17):
            values = node(17)
            del values[key]
            self.equivalent(lambda: SimpleNamespace(**values))

    def test_custom_attribute_access_order_and_interrupt_identity(self):
        keys = tuple(node(17))
        for fail_at in range(1, 12):
            for error in (AttributeError("synthetic"), ValueError("synthetic"),
                          StopIteration("synthetic"), KeyboardInterrupt(), SystemExit(7)):
                for old, new in ((reference_identity, P._identity),
                                 (reference_observation, P._observation)):
                    runs = []
                    for function in (old, new):
                        log = []

                        class Facts:
                            def __getattr__(self, key):
                                log.append(key)
                                if len(log) == fail_at:
                                    raise error
                                return node(17)[key]

                        try:
                            outcome = ("value", function(Facts()))
                        except BaseException as caught:
                            outcome = ("error", type(caught), caught.args)
                            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                                self.assertIs(caught, error)
                        runs.append((log, outcome))
                    self.assertEqual(runs[0], runs[1])
        # Slots/properties are supported without imposing a container type.
        class Slots:
            __slots__ = keys
        facts = Slots()
        for key, value in node(17).items():
            setattr(facts, key, value)
        self.equivalent(lambda: facts)

    def test_stateful_kind_reads_and_directory_truth_are_preserved(self):
        for modes in ((stat.S_IFREG, stat.S_IFDIR),
                      (stat.S_IFREG, stat.S_IFREG, stat.S_IFDIR),
                      (stat.S_IFDIR, stat.S_IFLNK, stat.S_IFREG),
                      (stat.S_IFDIR, True, stat.S_IFREG),
                      (stat.S_IFDIR, None), (stat.S_IFDIR, 2 ** 80)):
            for truths in ((False, False), (True, True), (True, False), (False, True)):
                runs = []
                for function in (reference_identity, P._identity):
                    log, mode_values, truth_values = [], iter(modes), iter(truths)

                    class Facts:
                        def __getattr__(self, key):
                            log.append(key)
                            return next(mode_values) if key == "st_mode" else node(17)[key]

                    class Directory:
                        def __bool__(self):
                            log.append("directory truth")
                            return next(truth_values)

                    try:
                        outcome = ("value", function(Facts(), directory=Directory()))
                    except BaseException as error:
                        outcome = ("error", type(error), error.args)
                    runs.append((log, outcome))
                self.assertEqual(runs[0], runs[1])

    def test_connected_fake_filesystem_and_metadata_trace_is_unchanged(self):
        traces = []
        for old in (True, False):
            fake, lib = FakeOS(), FakeLibrary()
            with patch.object(P, "_identity", reference_identity if old else P._identity), \
                 patch.object(P, "_observation", reference_observation if old else P._observation):
                with P.OwnedParent.open("/Users/owner/state/private", "/Users/owner", 501,
                                       syscalls=fake) as parent:
                    parent.verify()
                    envelope = P.require_empty_envelope(parent, syscalls=fake,
                                                        platform=lib.platform())
            traces.append((fake.calls, lib.calls, fake.nodes, envelope))
            self.assertEqual(fake.handles, {})
            self.assertEqual(lib.allocations, set())
        self.assertEqual(traces[0], traces[1])


class FakeOS:
    def __init__(self):
        self.nodes = {"/": node(1, uid=0, mode=0o755),
                      "/Users": node(2, uid=0, mode=0o755),
                      "/Users/owner": node(3, mode=0o750),
                      "/Users/owner/state": node(4),
                      "/Users/owner/state/private": node(5)}
        self.handles, self.calls, self.counts, self.effects = {}, [], {}, {}
        self.next_fd = 50

    def event(self, name, *args):
        self.calls.append((name,) + args)
        index = self.counts.get(name, 0) + 1
        self.counts[name] = index
        effect = self.effects.get((name, index))
        if isinstance(effect, BaseException):
            raise effect
        if effect is not None:
            return effect(*args)

    def path(self, name, dir_fd):
        if dir_fd is None:
            assert name == "/"
            return name
        parent, _ = self.handles[dir_fd]
        return parent.rstrip("/") + "/" + name

    def open(self, name, flags, *, dir_fd=None):
        assert flags == P._OPEN_FLAGS
        assert flags & os.O_NOFOLLOW and flags & os.O_DIRECTORY and flags & os.O_CLOEXEC
        self.event("open", name, dir_fd)
        path = self.path(name, dir_fd)
        item = self.nodes[path]
        if not stat.S_ISDIR(item["st_mode"]):
            raise OSError("private-unsafe-type")
        fd, self.next_fd = self.next_fd, self.next_fd + 1
        self.handles[fd] = (path, item)
        return fd

    def fstat(self, fd):
        self.event("fstat", fd)
        return SimpleNamespace(**self.handles[fd][1])

    def stat(self, name, *, dir_fd=None, follow_symlinks):
        assert follow_symlinks is False
        self.event("stat", name, dir_fd)
        return SimpleNamespace(**self.nodes[self.path(name, dir_fd)])

    def close(self, fd):
        del self.handles[fd]
        self.event("close", fd)


class Function:
    def __init__(self, function):
        self.function = function

    def __call__(self, *args):
        return self.function(*args)


class FakeLibrary:
    def __init__(self, *, count=0, raw=b""):
        self.count, self.raw, self.errno, self.cursor = count, raw, 0, 0
        self.calls, self.effects, self.counts = [], {}, {}
        self.allocations = set()
        self.next_acl = 1000
        for name in ("acl_get_fd_np", "acl_get_entry", "acl_free", "flistxattr"):
            setattr(self, name, Function(getattr(self, "_" + name)))

    def event(self, name, *args):
        self.calls.append((name,) + args)
        index = self.counts.get(name, 0) + 1
        self.counts[name] = index
        effect = self.effects.get((name, index))
        if isinstance(effect, BaseException):
            raise effect
        if effect is not None:
            return effect(*args)
        return None

    def _acl_get_fd_np(self, fd, kind):
        assert kind == P.ACL_TYPE_EXTENDED
        result = self.event("acl_get_fd_np", fd, kind)
        if result is not None:
            return result
        acl, self.next_acl = self.next_acl, self.next_acl + 1
        self.allocations.add(acl)
        self.cursor = 0
        return acl

    def _acl_get_entry(self, acl, entry_id, output):
        assert acl in self.allocations
        result = self.event("acl_get_entry", acl, entry_id)
        if result is not None:
            return result
        assert entry_id == (P.ACL_FIRST_ENTRY if self.cursor == 0 else P.ACL_NEXT_ENTRY)
        if self.cursor == self.count:
            self.errno = errno.EINVAL
            return -1
        self.cursor += 1
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = 2000 + self.cursor
        return 0

    def _acl_free(self, acl):
        self.allocations.remove(acl)
        result = self.event("acl_free", acl)
        return 0 if result is None else result

    def _flistxattr(self, fd, buffer, size, options):
        assert options == P.XATTR_SHOWCOMPRESSION
        result = self.event("flistxattr", fd, buffer is None, size, options)
        if result is not None:
            return result
        if buffer is not None:
            if len(self.raw) > size:
                self.errno = errno.ERANGE
                return -1
            ctypes.memmove(buffer, self.raw, len(self.raw))
        return len(self.raw)

    def platform(self):
        return P.DarwinEnvelope(library=self, get_errno=lambda: self.errno,
                               set_errno=lambda value: setattr(self, "errno", value), platform="darwin")


class PathsTests(unittest.TestCase):
    def fixture(self):
        fake = FakeOS()
        parent = P.OwnedParent.open("/Users/owner/state/private", "/Users/owner", 501,
                                    syscalls=fake)
        return fake, parent

    def assert_redacted(self, function):
        with self.assertRaises(P.PathsError) as error:
            function()
        self.assertEqual(str(error.exception), "runtime_paths_admission_required")
        self.assertNotIn("private", repr(error.exception))

    def test_close_priority_first_interrupt_and_active_exception_with_all_fds_once(self):
        for primary, early, late in (
            (None, OSError("early close"), KeyboardInterrupt()),
            (None, OSError("early close"), SystemExit(7)),
            (None, KeyboardInterrupt(), SystemExit(7)),
            (OSError("body"), OSError("early close"), KeyboardInterrupt()),
            (OSError("body"), OSError("early close"), SystemExit(7)),
            (KeyboardInterrupt(), OSError("early close"), SystemExit(7)),
            (SystemExit(7), OSError("early close"), KeyboardInterrupt()),
            (OSError("body"), OSError("early close"), OSError("late close")),
        ):
            fake, parent = self.fixture()
            original = copy.deepcopy(fake.nodes)
            descriptors = set(fake.handles)
            fake.effects[("close", 1)], fake.effects[("close", 2)] = early, late
            expected = next((error for error in (primary, early, late)
                             if isinstance(error, (KeyboardInterrupt, SystemExit))), primary or early)
            with self.assertRaises(type(expected)) as raised:
                if primary is None:
                    parent.close()
                else:
                    with parent:
                        raise primary
            self.assertIs(raised.exception, expected)
            self.assertEqual(fake.handles, {})
            closed = [call[1] for call in fake.calls if call[0] == "close"]
            self.assertEqual(len(closed), len(set(closed)))
            self.assertEqual(set(closed), descriptors)
            self.assertEqual(fake.nodes, original)
            parent.close()
            self.assertEqual(fake.counts["close"], len(descriptors))

    def test_constructor_active_ordinary_yields_to_cleanup_interrupt(self):
        for interrupt in (KeyboardInterrupt(), SystemExit(7)):
            fake = FakeOS()
            fake.effects[("open", 4)] = OSError("private open")
            fake.effects[("close", 1)] = OSError("private close")
            fake.effects[("close", 2)] = interrupt
            with self.assertRaises(type(interrupt)) as raised:
                P.OwnedParent.open("/Users/owner/state/private", "/Users/owner", 501, syscalls=fake)
            self.assertIs(raised.exception, interrupt)
            self.assertEqual(fake.handles, {})
            self.assertEqual(fake.counts["close"], 3)

    def test_open_verify_close_owns_all_and_mutates_nothing(self):
        fake = FakeOS()
        before = copy.deepcopy(fake.nodes)
        with P.OwnedParent.open("/Users/owner/state/private", "/Users/owner", 501,
                               syscalls=fake) as parent:
            self.assertEqual((parent.descriptor, parent.uid), (54, 501))
            self.assertEqual(len(fake.handles), 5)
            parent.verify()
        self.assertFalse(fake.handles)
        self.assertEqual(fake.nodes, before)
        self.assertEqual([call[1] for call in fake.calls if call[0] == "close"],
                         [54, 53, 52, 51, 50])
        parent.close()
        self.assert_redacted(parent.verify)
        self.assert_redacted(lambda: parent.descriptor)

    def test_root_itself_and_unicode_canonical_paths(self):
        fake = FakeOS()
        fake.nodes["/Users/owner/é"] = node(10)
        for path in ("/Users/owner", "/Users/owner/é"):
            parent = P.OwnedParent.open(path, "/Users/owner", 501, syscalls=fake)
            parent.verify()
            parent.close()
        self.assertFalse(fake.handles)

    def test_safe_custom_modes_and_child_activity_are_not_false_drift(self):
        fake = FakeOS()
        fake.nodes["/Users/owner"]["st_mode"] = stat.S_IFDIR | 0o711
        parent = P.OwnedParent.open("/Users/owner/state/private", "/Users/owner", 501,
                                    modes={0o700, 0o711}, syscalls=fake)
        fake.nodes["/Users/owner/state/private"].update(st_nlink=3, st_ctime_ns=80, st_mtime_ns=80)
        parent.verify()
        parent.close()

    def test_context_entry_failure_closes_and_preserves_interrupt(self):
        for error in (OSError("private-enter"), KeyboardInterrupt()):
            fake, parent = self.fixture()
            fake.effects[("fstat", fake.counts["fstat"] + 1)] = error
            with self.assertRaises(P.PathsError if isinstance(error, Exception) else type(error)):
                with parent:
                    self.fail("failed entry cannot enter body")
            self.assertFalse(fake.handles)

    def test_context_body_interrupt_cleanup_failure_keeps_primary(self):
        fake, parent = self.fixture()
        fake.effects[("close", 1)] = OSError("private-close")
        with self.assertRaises(KeyboardInterrupt):
            with parent:
                raise KeyboardInterrupt()
        self.assertFalse(fake.handles)

    def test_paths_fail_before_syscalls(self):
        values = (None, True, b"/Users/owner", Path("/Users/owner"), "", "/", "relative",
                  "/Users//owner", "/Users/owner/", "/Users/./owner", "/Users/a/../owner",
                  "/Users/owner\0x", "/Users/owner/" + "x" * 256,
                  "/Users/owner/" + "/".join(["a"] * 129), "/" + "a/" * 600)
        for value in values:
            for is_root in (False, True):
                fake = FakeOS()
                args = ("/Users/owner", value) if is_root else (value, "/Users/owner")
                self.assert_redacted(lambda: P.OwnedParent.open(*args, 501, syscalls=fake))
                self.assertFalse(fake.calls)
        for path in ("/Users/owner-other", "/Users", "/other"):
            fake = FakeOS()
            self.assert_redacted(lambda: P.OwnedParent.open(path, "/Users/owner", 501, syscalls=fake))
            self.assertFalse(fake.calls)

    def test_uid_modes_are_strict_and_bound_before_open(self):
        for uid in (None, True, -1, 2 ** 32):
            fake = FakeOS()
            self.assert_redacted(lambda: P.OwnedParent.open("/Users/owner", "/Users/owner", uid,
                                                          syscalls=fake))
            self.assertFalse(fake.calls)
        for modes in ((), [0o700], set(), {True}, {0o777}, {0o770}, {0o1700},
                      {0o600}, {0o700, -1}, {None}):
            fake = FakeOS()
            self.assert_redacted(lambda: P.OwnedParent.open("/Users/owner", "/Users/owner", 501,
                                                          modes=modes, syscalls=fake))
            self.assertFalse(fake.calls)

    def test_owner_mode_type_and_metadata_reject_and_close(self):
        mutations = ({"st_uid": 502}, {"st_mode": stat.S_IFDIR | 0o777},
                     {"st_mode": stat.S_IFDIR | 0o1700}, {"st_mode": stat.S_IFLNK | 0o700},
                     {"st_mode": stat.S_IFREG | 0o700}, {"st_ino": True}, {"st_flags": -1})
        for path in ("/Users/owner", "/Users/owner/state", "/Users/owner/state/private"):
            for change in mutations:
                fake = FakeOS()
                fake.nodes[path].update(change)
                self.assert_redacted(lambda: P.OwnedParent.open("/Users/owner/state/private",
                                                               "/Users/owner", 501, syscalls=fake))
                self.assertFalse(fake.handles)

    def test_ancestor_directory_but_not_owner_policy(self):
        fake = FakeOS()
        fake.nodes["/Users"].update(st_uid=0, st_mode=stat.S_IFDIR | 0o775)
        parent = P.OwnedParent.open("/Users/owner", "/Users/owner", 501, syscalls=fake)
        parent.close()
        fake.nodes["/Users"]["st_mode"] = stat.S_IFLNK | 0o755
        self.assert_redacted(lambda: P.OwnedParent.open("/Users/owner", "/Users/owner", 501,
                                                      syscalls=fake))
        self.assertFalse(fake.handles)

    def test_all_open_fstat_stat_failures_and_interruptions_close(self):
        baseline, parent = self.fixture()
        counts = dict(baseline.counts)
        parent.close()
        for event in ("open", "fstat", "stat"):
            for index in range(1, counts[event] + 1):
                for error in (OSError("private-native"), KeyboardInterrupt(), SystemExit(9)):
                    fake = FakeOS()
                    fake.effects[(event, index)] = error
                    expected = P.PathsError if isinstance(error, Exception) else type(error)
                    with self.assertRaises(expected):
                        P.OwnedParent.open("/Users/owner/state/private", "/Users/owner", 501,
                                           syscalls=fake)
                    self.assertFalse(fake.handles, (event, index, type(error)))

    def test_constructor_failure_and_interruption_close(self):
        for error in (ValueError("private-constructor"), KeyboardInterrupt()):
            class Broken(P.OwnedParent):
                def __init__(self, *args):
                    raise error
            fake = FakeOS()
            with self.assertRaises(P.PathsError if isinstance(error, Exception) else type(error)):
                Broken.open("/Users/owner/state/private", "/Users/owner", 501, syscalls=fake)
            self.assertFalse(fake.handles)

    def test_close_failure_attempts_every_owned_fd_once(self):
        for error in (OSError("private-close"), KeyboardInterrupt()):
            fake, parent = self.fixture()
            fake.effects[("close", 1)] = error
            with self.assertRaises(P.PathsError if isinstance(error, Exception) else type(error)):
                parent.close()
            self.assertFalse(fake.handles)
            parent.close()
            self.assertEqual(fake.counts["close"], 5)

    def test_cleanup_does_not_mask_primary_interrupt(self):
        fake = FakeOS()
        fake.effects[("fstat", 4)] = KeyboardInterrupt()
        fake.effects[("close", 1)] = OSError("private-close")
        with self.assertRaises(KeyboardInterrupt):
            P.OwnedParent.open("/Users/owner/state/private", "/Users/owner", 501, syscalls=fake)
        self.assertFalse(fake.handles)

    def test_verify_detects_each_named_edge_substitution(self):
        for path in FakeOS().nodes:
            fake, parent = self.fixture()
            fake.nodes[path] = dict(fake.nodes[path], st_ino=900)
            self.assert_redacted(parent.verify)
            parent.close()
            self.assertFalse(fake.handles)

    def test_verify_detects_held_metadata_changes(self):
        for key, value in (("st_dev", 9), ("st_uid", 502), ("st_gid", 21),
                           ("st_mode", stat.S_IFDIR | 0o755), ("st_flags", 1)):
            fake, parent = self.fixture()
            fake.handles[parent.descriptor][1][key] = value
            self.assert_redacted(parent.verify)
            parent.close()

    def test_verify_failure_does_not_close_borrowed_parent(self):
        fake, parent = self.fixture()
        fake.effects[("fstat", fake.counts["fstat"] + 1)] = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            parent.verify()
        self.assertEqual(len(fake.handles), 5)
        parent.close()


class EnvelopeTests(unittest.TestCase):
    def test_acl_free_priority_preserves_first_interrupt_and_frees_once(self):
        for primary, cleanup in ((OSError("private read"), KeyboardInterrupt()),
                                 (OSError("private read"), SystemExit(7)),
                                 (KeyboardInterrupt(), SystemExit(7)),
                                 (SystemExit(7), OSError("private free"))):
            lib = FakeLibrary(count=1)
            lib.effects[("acl_get_entry", 1)] = primary
            lib.effects[("acl_free", 1)] = cleanup
            expected = primary if isinstance(primary, (KeyboardInterrupt, SystemExit)) else cleanup
            with self.assertRaises(type(expected)) as raised:
                lib.platform().acl_count(9)
            self.assertIs(raised.exception, expected)
            self.assertEqual(lib.allocations, set())
            self.assertEqual(lib.counts["acl_free"], 1)

    assert_redacted = PathsTests.assert_redacted
    fixture = PathsTests.fixture

    def test_exact_sdk_ctypes_signatures(self):
        lib = FakeLibrary()
        with patch.object(ctypes, "CDLL", side_effect=AssertionError("native forbidden")):
            lib.platform()
        self.assertEqual(lib.acl_get_fd_np.argtypes, [ctypes.c_int, ctypes.c_int])
        self.assertIs(lib.acl_get_fd_np.restype, ctypes.c_void_p)
        self.assertEqual(lib.acl_get_entry.argtypes,
                         [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)])
        self.assertIs(lib.acl_get_entry.restype, ctypes.c_int)
        self.assertEqual(lib.acl_free.argtypes, [ctypes.c_void_p])
        self.assertIs(lib.acl_free.restype, ctypes.c_int)
        self.assertEqual(lib.flistxattr.argtypes,
                         [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int])
        self.assertIs(lib.flistxattr.restype, ctypes.c_ssize_t)
        with patch.object(ctypes, "CDLL", side_effect=AssertionError("native forbidden")):
            self.assert_redacted(lambda: P.DarwinEnvelope(platform="linux"))

    def test_darwin_entry_count_empty_nonempty_and_limit(self):
        for count in (0, 1, 8, P.MAX_ACL_ENTRIES):
            lib = FakeLibrary(count=count)
            self.assertEqual(lib.platform().acl_count(9), count)
            self.assertFalse(lib.allocations)
            self.assertEqual(lib.counts["acl_get_entry"], count + 1)
            self.assertEqual(lib.counts["acl_free"], 1)
        lib = FakeLibrary(count=P.MAX_ACL_ENTRIES + 1)
        self.assert_redacted(lambda: lib.platform().acl_count(9))
        self.assertFalse(lib.allocations)

    def test_acl_errors_linux_convention_null_entry_fail_closed(self):
        for result, error in ((-1, errno.EIO), (1, 0), (0, 0), (True, 0), (None, 0)):
            lib = FakeLibrary()
            # None is the fake's normal sentinel; explicit function replacement
            # permits a malformed native result without executing native code.
            def get_entry(*args):
                lib.errno = error
                return result
            lib.acl_get_entry = Function(get_entry)
            self.assert_redacted(lambda: lib.platform().acl_count(9))
            self.assertFalse(lib.allocations)
            self.assertEqual(lib.counts["acl_free"], 1)
        lib = FakeLibrary()
        lib.acl_get_fd_np = Function(lambda *args: None)
        self.assert_redacted(lambda: lib.platform().acl_count(9))
        self.assertNotIn("acl_free", lib.counts)

    def test_darwin_null_enoent_is_absent_and_stale_errno_is_not(self):
        for error in (errno.ENOENT, errno.EACCES, errno.EBADF, errno.EINVAL,
                      errno.ENOMEM, errno.ENOTSUP, 0):
            lib = FakeLibrary()
            def no_acl(*args):
                lib.errno = error
                return None
            lib.acl_get_fd_np = Function(no_acl)
            if error == errno.ENOENT:
                self.assertEqual(lib.platform().acl_count(9), 0)
            else:
                self.assert_redacted(lambda: lib.platform().acl_count(9))
            self.assertFalse(lib.allocations)
            self.assertNotIn("acl_free", lib.counts)
        lib = FakeLibrary()
        lib.errno = errno.ENOENT
        lib.acl_get_fd_np = Function(lambda *args: None)
        self.assert_redacted(lambda: lib.platform().acl_count(9))
        lib = FakeLibrary()
        lib.errno = errno.EINVAL
        lib.acl_get_entry = Function(lambda *args: -1)
        self.assert_redacted(lambda: lib.platform().acl_count(9))
        self.assertFalse(lib.allocations)

    def test_acl_entry_interrupt_and_free_failure_cleanup(self):
        for error in (OSError("private-acl"), KeyboardInterrupt(), SystemExit(4)):
            lib = FakeLibrary(count=2)
            lib.effects[("acl_get_entry", 2)] = error
            with self.assertRaises(P.PathsError if isinstance(error, Exception) else type(error)):
                lib.platform().acl_count(9)
            self.assertFalse(lib.allocations)
        lib = FakeLibrary()
        lib.effects[("acl_free", 1)] = lambda *args: -1
        self.assert_redacted(lambda: lib.platform().acl_count(9))
        self.assertFalse(lib.allocations)
        lib = FakeLibrary()
        lib.effects[("acl_get_entry", 1)] = KeyboardInterrupt()
        lib.effects[("acl_free", 1)] = OSError("private-free")
        with self.assertRaises(KeyboardInterrupt):
            lib.platform().acl_count(9)
        self.assertFalse(lib.allocations)

    def test_xattr_sorted_utf8_empty_and_max_name(self):
        for raw, expected in ((b"", ()), (b"z\0a\0", ("a", "z")),
                              ("é\0".encode(), ("é",)), (b"a" * 127 + b"\0", ("a" * 127,))):
            lib = FakeLibrary(raw=raw)
            self.assertEqual(lib.platform().xattr_names(9), expected)
            self.assertEqual(lib.counts["flistxattr"], 2)
            if not raw:
                self.assertEqual(lib.calls[-1][3], 1)

    def test_xattr_malformed_duplicate_encoding_and_bounds(self):
        for raw in (b"missing-terminal", b"\0", b"a\0\0", b"a\0a\0", b"\xff\0",
                    b"a" * 128 + b"\0", b"x" * (P.MAX_XATTR_BYTES + 1),
                    b"".join(str(i).encode() + b"\0" for i in range(P.MAX_XATTR_NAMES + 1))):
            lib = FakeLibrary(raw=raw)
            self.assert_redacted(lambda: lib.platform().xattr_names(9))

    def test_xattr_query_growth_shrink_errors_and_interruptions(self):
        for result in (-1, True, None, P.MAX_XATTR_BYTES + 1):
            lib = FakeLibrary()
            lib.flistxattr = Function(lambda *args: result)
            self.assert_redacted(lambda: lib.platform().xattr_names(9))
        for initial, later in ((b"", b"a\0"), (b"a\0", b""), (b"a\0", b"long\0")):
            lib = FakeLibrary(raw=initial)
            lib.effects[("flistxattr", 2)] = lambda *args: setattr(lib, "raw", later)
            self.assert_redacted(lambda: lib.platform().xattr_names(9))
        lib = FakeLibrary()
        lib.effects[("flistxattr", 2)] = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            lib.platform().xattr_names(9)

    def test_empty_observation_same_bound_fd_and_private_repr(self):
        fake, parent = self.fixture()
        lib = FakeLibrary()
        before = copy.deepcopy(fake.nodes)
        envelope = P.require_empty_envelope(parent, syscalls=fake, platform=lib.platform())
        self.assertEqual(envelope, P.Envelope(0, ()))
        self.assertFalse(lib.allocations)
        self.assertEqual(lib.counts["acl_get_fd_np"], 2)
        self.assertEqual(lib.counts["flistxattr"], 4)
        self.assertEqual({row[1] for row in lib.calls if row[0] in ("acl_get_fd_np", "flistxattr")},
                         {parent.descriptor})
        self.assertNotIn("private-name", repr(P.Envelope(2, ("private-name",))))
        with self.assertRaises(AttributeError):
            envelope.acl_entries = 2
        self.assertEqual(before, fake.nodes)
        self.assertEqual(len(fake.handles), 5)
        parent.close()

    def test_nonempty_can_be_observed_but_not_admitted(self):
        for count, raw in ((1, b""), (0, b"private-name\0"), (3, b"private-name\0")):
            fake, parent = self.fixture()
            lib = FakeLibrary(count=count, raw=raw)
            observed = P.observe_envelope(parent.descriptor, syscalls=fake, platform=lib.platform())
            self.assertEqual(observed.acl_entries, count)
            self.assert_redacted(lambda: P.require_empty_envelope(parent, syscalls=fake,
                                                                  platform=lib.platform()))
            self.assertEqual(len(fake.handles), 5)
            parent.close()

    def test_double_observation_acl_and_xattr_drift_fail(self):
        for which in ("acl", "xattr", "stat"):
            fake, parent = self.fixture()
            lib = FakeLibrary()
            if which == "acl":
                lib.effects[("acl_get_fd_np", 2)] = lambda *args: setattr(lib, "count", 1)
            elif which == "xattr":
                lib.effects[("flistxattr", 3)] = lambda *args: setattr(lib, "raw", b"private\0")
            else:
                fake.effects[("fstat", fake.counts["fstat"] + 2)] = lambda *args: fake.nodes[
                    "/Users/owner/state/private"].update(st_ctime_ns=999)
            self.assert_redacted(lambda: P.observe_envelope(parent.descriptor, syscalls=fake,
                                                            platform=lib.platform()))
            self.assertFalse(lib.allocations)
            parent.close()

    def test_observer_bad_fd_type_and_platform_values_fail(self):
        for descriptor in (None, True, -1, 2 ** 31):
            fake = FakeOS()
            self.assert_redacted(lambda: P.observe_envelope(descriptor, syscalls=fake,
                                                            platform=FakeLibrary().platform()))
            self.assertFalse(fake.calls)
        for count, names in ((True, ()), (-1, ()), (0, []), (0, ("z", "a")),
                              (0, ("",)), (0, ("x", "x")), (0, (b"x",))):
            fake, parent = self.fixture()
            platform = SimpleNamespace(acl_count=lambda fd: count, xattr_names=lambda fd: names)
            self.assert_redacted(lambda: P.observe_envelope(parent.descriptor, syscalls=fake,
                                                            platform=platform))
            parent.close()

    def test_observer_rejects_wrong_object_type_and_interrupt_keeps_parent_owned(self):
        fake, parent = self.fixture()
        descriptor = parent.descriptor
        fake.handles[descriptor][1]["st_mode"] = stat.S_IFIFO | 0o600
        self.assert_redacted(lambda: P.observe_envelope(descriptor, syscalls=fake,
                                                        platform=FakeLibrary().platform()))
        parent.close()
        fake, parent = self.fixture()
        lib = FakeLibrary()
        lib.effects[("acl_get_entry", 1)] = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            P.require_empty_envelope(parent, syscalls=fake, platform=lib.platform())
        self.assertFalse(lib.allocations)
        self.assertEqual(len(fake.handles), 5)
        parent.close()

    def test_empty_admission_requires_owner_exact_mode_and_pre_post_verify(self):
        for key, value in (("st_uid", 502), ("st_mode", stat.S_IFDIR | 0o755)):
            fake, parent = self.fixture()
            fake.nodes["/Users/owner/state/private"][key] = value
            self.assert_redacted(lambda: P.require_empty_envelope(parent, syscalls=fake,
                                                                  platform=FakeLibrary().platform()))
            parent.close()
        for call in (1, 2):
            fake, parent = self.fixture()
            borrowed = SimpleNamespace(descriptor=parent.descriptor, uid=parent.uid)
            verifications = []
            def verify():
                verifications.append(None)
                return False if len(verifications) == call else None
            borrowed.verify = verify
            self.assert_redacted(lambda: P.require_empty_envelope(borrowed, syscalls=fake,
                                                                  platform=FakeLibrary().platform()))
            self.assertEqual(len(fake.handles), 5)
            parent.close()

    def test_post_verification_descriptor_or_uid_substitution_rejected(self):
        for field, value in (("descriptor", 53), ("uid", 502)):
            fake, parent = self.fixture()
            borrowed = SimpleNamespace(descriptor=parent.descriptor, uid=parent.uid)
            calls = []
            def verify():
                calls.append(None)
                if len(calls) == 2:
                    setattr(borrowed, field, value)
            borrowed.verify = verify
            self.assert_redacted(lambda: P.require_empty_envelope(borrowed, syscalls=fake,
                                                                  platform=FakeLibrary().platform()))
            parent.close()


if __name__ == "__main__":
    unittest.main()
