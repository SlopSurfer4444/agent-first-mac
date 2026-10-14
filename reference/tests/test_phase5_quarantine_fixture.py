"""Real Paths/DescriptorBackend, fake OS/metadata only. No native fixtures."""

import copy
import importlib.util
from pathlib import Path
import stat
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import phase5_quarantine_fixture as F
from lib import phase5_current_quarantine as Q
from lib import phase5_runtime_paths as P
from lib import phase5_runtime_backend as B

spec = importlib.util.spec_from_file_location("quarantine_fakes", ROOT / "tests/test_phase5_runtime_targets.py")
fakes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fakes)
HOME, LEAF = "/Users/owner", "phase5-quarantine-task.Abc123"
QUARANTINE, SCRATCH = HOME + "/AIDev/quarantine", HOME + "/AIDev/scratch"
WORKSPACE, OUTSIDE = QUARANTINE + "/" + LEAF, SCRATCH + "/" + LEAF
PROFILE_HOME = WORKSPACE + "/profile-home"
TMP = PROFILE_HOME + "/tmp"
GIT = WORKSPACE + "/.git"
NEW_DIRS = (WORKSPACE, OUTSIDE, PROFILE_HOME, TMP, GIT, GIT + "/objects", GIT + "/refs")
# Historical fixture allocator still binds its exact predecessor profile.
PROFILE = (ROOT / "tests/fixtures/phase5-quarantine-before-temp-deny.config.toml").read_bytes()
FILE_PATHS = (WORKSPACE + "/visible.txt",) + tuple(WORKSPACE + "/" + leaf for leaf in Q.SECRET_LEAVES) + (
    OUTSIDE + "/outside.txt", PROFILE_HOME + "/quarantine.config.toml", GIT + "/HEAD")


class FakeOS(fakes.TransitionOS):
    def __init__(self):
        super().__init__()
        self.umask = 0o077
        self.scan_exit = None
        self.scan_exit_skip = 0

    def mkdir(self, leaf, mode, *, dir_fd):
        target = self.path(leaf, dir_fd)
        self.event("mkdir", target)
        assert target in NEW_DIRS and mode == 0o700
        if target in self.nodes:
            raise FileExistsError("private collision")
        self.add(target, directory=True, mode=mode & ~self.umask)
        self.handles[dir_fd][1]["st_ctime_ns"] += 1
        self.handles[dir_fd][1]["st_mtime_ns"] += 1
        self.event("created-directory", target)

    def scandir(self, descriptor):
        scan = super().scandir(descriptor)
        path = self.handles[descriptor][0]
        fake = self
        class Scan:
            def __enter__(self):
                return scan.__enter__()
            def __exit__(self, *args):
                result = scan.__exit__(*args)
                if fake.scan_exit is not None:
                    if fake.scan_exit_skip:
                        fake.scan_exit_skip -= 1
                    else:
                        effect, fake.scan_exit = fake.scan_exit, None
                        effect(path)
                return result
        return Scan()


def fixture():
    fake = FakeOS()
    for path in ("/", "/Users", HOME, HOME + "/AIDev", QUARANTINE, SCRATCH):
        fake.add(path, directory=True, mode=0o750 if path == HOME else 0o755)
    return fake, fakes.Metadata(fake)


class FixtureTests(unittest.TestCase):
    def allocate(self, fake, metadata, **changes):
        args = dict(home=HOME, uid=501, leaf=LEAF, installed_profile=PROFILE,
                    admit_sources=lambda: True, paths=P, backend=B,
                    syscalls=fake, platform=metadata)
        args.update(changes)
        return F.allocate(**args)

    def denied(self, operation, owner=None):
        with self.assertRaises(F.FixtureError) as caught:
            operation()
        self.assertEqual(str(caught.exception), "quarantine_fixture_recovery_required")
        if owner is not None:
            self.assertIs(caught.exception.private_owner, owner)
        self.assertNotIn(HOME, repr(caught.exception))
        return caught.exception.private_owner

    def close_failed(self, fake, owner):
        self.denied(owner.close, owner)
        self.assertEqual(fake.handles, {})
        self.assertFalse(any(op in ("unlink", "rmdir", "rename") for op, _ in fake.calls))

    def test_complete_fixed_material_preserved_and_plan_connected(self):
        fake, metadata = fixture()
        before = copy.deepcopy(fake.nodes)
        calls = []
        owner = self.allocate(fake, metadata, admit_sources=lambda: calls.append(1) or True)
        self.assertEqual(len(calls), 2)
        self.assertTrue(owner.verify())
        self.assertEqual(len(calls), 2)  # No expensive runtime admission in verify.
        self.assertEqual(owner.workspace, WORKSPACE)
        self.assertEqual(owner.profile_home, PROFILE_HOME)
        self.assertEqual(set(fake.nodes) - set(before), {*FILE_PATHS, *NEW_DIRS})
        self.assertTrue(all(stat.S_IMODE(fake.nodes[p]["st_mode"]) == 0o600 for p in FILE_PATHS))
        self.assertTrue(all(stat.S_IMODE(fake.nodes[p]["st_mode"]) == 0o700 for p in NEW_DIRS))
        self.assertEqual(fake.nodes[FILE_PATHS[0]]["data"], b"visible\n")
        self.assertEqual(fake.nodes[PROFILE_HOME + "/quarantine.config.toml"]["data"], PROFILE)
        self.assertEqual(fake.nodes[GIT + "/HEAD"]["data"], b"ref: refs/heads/codex/quarantine-probe\n")
        self.assertEqual(len({fake.nodes[p]["st_ino"] for p in FILE_PATHS}), 10)
        q = Q.build_plan(HOME, owner.workspace, owner.fixture_paths, 43210, PROFILE,
                         profile_home=owner.profile_home)
        self.assertIsNone(Q.recheck_plan(q))
        self.assertNotIn(HOME, repr(owner))
        retained = copy.deepcopy(fake.nodes)
        owner.close()
        count = len(fake.calls)
        owner.close()
        self.assertEqual(len(fake.calls), count)
        self.assertEqual(fake.handles, {})
        self.assertEqual(fake.nodes, retained)
        self.assertFalse(hasattr(owner, "cleanup"))

    def test_invalid_input_and_source_admission_have_zero_effects(self):
        for changes in ({"home": "/"}, {"uid": True}, {"uid": 0}, {"leaf": "../bad"},
                        {"leaf": LEAF + "/x"}, {"installed_profile": PROFILE + b"\n"},
                        {"installed_profile": bytearray(PROFILE)}, {"platform": None},
                        {"admit_sources": lambda: False}, {"admit_sources": lambda: 1}):
            fake, metadata = fixture()
            owner = self.denied(lambda: self.allocate(fake, metadata, **changes))
            self.assertEqual(fake.calls, [])
            if owner is not None:
                self.close_failed(fake, owner)

    def test_post_source_failure_retains_complete_fixture(self):
        fake, metadata = fixture()
        calls = []
        owner = self.denied(lambda: self.allocate(fake, metadata,
            admit_sources=lambda: calls.append(1) or len(calls) == 1))
        self.assertEqual(set(FILE_PATHS) - set(fake.nodes), set())
        self.close_failed(fake, owner)

    def test_post_source_target_mutation_not_success(self):
        fake, metadata = fixture()
        calls = []
        def admission():
            calls.append(1)
            if len(calls) == 2:
                fake.nodes[FILE_PATHS[0]]["data"] = b"third state"
            return True
        owner = self.denied(lambda: self.allocate(fake, metadata, admit_sources=admission))
        self.assertEqual(fake.nodes[FILE_PATHS[0]]["data"], b"third state")
        self.close_failed(fake, owner)

    def test_collisions_at_each_directory_are_not_adopted(self):
        for path in NEW_DIRS:
            fake, metadata = fixture()
            if path in (WORKSPACE, OUTSIDE):
                fake.add(path, directory=True)
            else:
                fake.effects["created-directory", path.rsplit("/", 1)[0]] = lambda f: f.add(path, directory=True)
            owner = self.denied(lambda: self.allocate(fake, metadata))
            self.assertIn(path, fake.nodes)
            self.assertFalse(any(op == "write" for op, _ in fake.calls))
            self.close_failed(fake, owner)

    def test_ambiguous_creation_and_partial_file_retained(self):
        for event, path in tuple(("created-directory", p) for p in NEW_DIRS) + (
                ("created", FILE_PATHS[0]), ("fchmod", FILE_PATHS[-1])):
            fake, metadata = fixture()
            fake.effects[event, path] = OSError("private ambiguous creation")
            owner = self.denied(lambda: self.allocate(fake, metadata))
            self.assertIn(path, fake.nodes)
            self.assertEqual(sum(op == "mkdir" and target == path for op, target in fake.calls),
                             1 if event == "created-directory" else 0)
            self.close_failed(fake, owner)

    def test_fsync_failure_and_restrictive_umask_fail_without_repair(self):
        for path in (*NEW_DIRS, QUARANTINE, SCRATCH, FILE_PATHS[0], FILE_PATHS[-1]):
            fake, metadata = fixture()
            fake.effects["fsync", path] = OSError("private uncertain durability")
            owner = self.denied(lambda: self.allocate(fake, metadata))
            self.close_failed(fake, owner)
        fake, metadata = fixture()
        fake.umask = 0o777
        owner = self.denied(lambda: self.allocate(fake, metadata))
        self.assertEqual(fake.nodes[WORKSPACE]["st_mode"], stat.S_IFDIR)
        self.assertFalse(any(op in ("write", "fchmod") for op, _ in fake.calls))
        self.close_failed(fake, owner)

    def test_directory_metadata_modes_and_name_substitution(self):
        for path in NEW_DIRS:
            for kind in ("acl", "xattr", "mode", "identity"):
                fake, metadata = fixture()
                def change(f):
                    if kind == "acl": metadata.set(path, 1, ())
                    elif kind == "xattr": metadata.set(path, 0, ("com.fake",))
                    elif kind == "mode": f.nodes[path]["st_mode"] = stat.S_IFDIR | 0o755
                    else: f.nodes[path] = dict(f.nodes[path], st_ino=999999)
                event = "open" if kind == "identity" else "created-directory"
                fake.effects[event, path] = change
                owner = self.denied(lambda: self.allocate(fake, metadata))
                self.assertFalse(any(op == "write" for op, _ in fake.calls))
                self.close_failed(fake, owner)

    def test_no_payload_before_empty_exact_mode_file_envelope(self):
        for path in FILE_PATHS:
            for kind in ("acl", "xattr", "mode"):
                fake, metadata = fixture()
                def change(f):
                    if kind == "acl": metadata.set(path, 1, ())
                    elif kind == "xattr": metadata.set(path, 0, ("com.fake",))
                    else: f.nodes[path]["st_mode"] = stat.S_IFREG | 0o400
                fake.effects["created", path] = change
                owner = self.denied(lambda: self.allocate(fake, metadata))
                self.assertEqual(fake.nodes[path]["data"], b"")
                self.assertFalse(any(op == "write" and name == path for op, name in fake.calls))
                self.close_failed(fake, owner)

    def test_all_ten_file_bytes_identity_seals_and_metadata_are_pinned(self):
        for path in FILE_PATHS:
            for kind in ("data", "inode", "ctime", "mode", "link", "acl", "xattr"):
                fake, metadata = fixture()
                owner = self.allocate(fake, metadata)
                if kind == "acl": metadata.set(path, 1, ())
                elif kind == "xattr": metadata.set(path, 0, ("com.fake",))
                else:
                    key, value = {"data": ("data", b"third"), "inode": ("st_ino", 999999),
                        "ctime": ("st_ctime_ns", 999999), "mode": ("st_mode", stat.S_IFREG | 0o644),
                        "link": ("st_nlink", 2)}[kind]
                    fake.nodes[path][key] = value
                retained = copy.deepcopy(fake.nodes)
                self.denied(owner.verify, owner)
                self.close_failed(fake, owner)
                self.assertEqual(fake.nodes, retained)

    def test_baseconfig_extra_or_missing_names_are_rejected(self):
        for path in (PROFILE_HOME + "/config.toml", PROFILE_HOME + "/auth.json",
                     WORKSPACE + "/third", OUTSIDE + "/third"):
            fake, metadata = fixture()
            owner = self.allocate(fake, metadata)
            fake.add(path, b"synthetic third state")
            self.denied(owner.verify, owner)
            self.assertIn(path, fake.nodes)
            self.close_failed(fake, owner)
        fake, metadata = fixture()
        owner = self.allocate(fake, metadata)
        del fake.nodes[FILE_PATHS[1]]
        self.denied(owner.verify, owner)
        self.close_failed(fake, owner)

    def test_final_scan_exit_intruder_and_metadata_changes_fail(self):
        for kind in ("child", "acl", "xattr"):
            fake, metadata = fixture()
            owner = self.allocate(fake, metadata)
            def change(path):
                if kind == "child": fake.add(path + "/intruder", b"synthetic")
                elif kind == "acl": metadata.set(path, 1, ())
                else: metadata.set(path, 0, ("com.fake",))
                fake.nodes[path]["st_ctime_ns"] += 1
                fake.nodes[path]["st_mtime_ns"] += 1
            fake.scan_exit = change
            fake.scan_exit_skip = 11  # Six immutable directories; tmp is not scanned.
            self.denied(owner.verify, owner)
            self.close_failed(fake, owner)

    def test_parent_chain_drift_fails_without_cleanup(self):
        for path in (HOME, QUARANTINE, SCRATCH, *NEW_DIRS):
            fake, metadata = fixture()
            owner = self.allocate(fake, metadata)
            fake.nodes[path] = dict(fake.nodes[path], st_ino=999999)
            self.denied(owner.verify, owner)
            self.close_failed(fake, owner)

    def test_masked_read_interrupts_restore_earliest_private_owner(self):
        for first_type, later_type in ((KeyboardInterrupt, OSError), (SystemExit, OSError),
                                       (KeyboardInterrupt, SystemExit), (SystemExit, KeyboardInterrupt)):
            fake, metadata = fixture()
            owner = self.allocate(fake, metadata)
            first, later = first_type(), later_type()
            fake.effects["read", FILE_PATHS[0]] = first
            fake.effects["close", FILE_PATHS[0]] = later
            with self.assertRaises(type(first)) as caught:
                owner.verify()
            self.assertIs(caught.exception, first)
            self.assertIs(first.private_owner, owner)
            with self.assertRaises(type(first)):
                owner.close()
            self.assertEqual(fake.handles, {})

    def test_exact_git_skeleton_empty_children_and_no_extra_git_surface(self):
        fake, metadata = fixture()
        owner = self.allocate(fake, metadata)
        self.assertEqual({p[len(GIT) + 1:] for p in fake.nodes if p.startswith(GIT + "/")},
                         {"HEAD", "objects", "refs"})
        self.assertEqual(fake.nodes[GIT + "/HEAD"]["data"], F.GIT_HEAD)
        self.assertTrue(owner.verify())
        owner.close()
        for leaf in ("config", "hooks", "templates", "objects/third", "refs/third"):
            fake, metadata = fixture()
            owner = self.allocate(fake, metadata)
            fake.add(GIT + "/" + leaf, b"synthetic third state")
            self.denied(owner.verify, owner)
            self.assertIn(GIT + "/" + leaf, fake.nodes)
            self.close_failed(fake, owner)

    def test_git_directories_metadata_is_bound_after_allocation(self):
        for path in (GIT, GIT + "/objects", GIT + "/refs"):
            for kind in ("acl", "xattr", "mode"):
                fake, metadata = fixture()
                owner = self.allocate(fake, metadata)
                if kind == "acl": metadata.set(path, 1, ())
                elif kind == "xattr": metadata.set(path, 0, ("com.fake",))
                else: fake.nodes[path]["st_mode"] = stat.S_IFDIR | 0o755
                self.denied(owner.verify, owner)
                self.close_failed(fake, owner)

    def test_native_tmp_case_precreated_and_mutable_only_inside_boundary(self):
        fake, metadata = fixture()
        owner = self.allocate(fake, metadata)
        self.assertEqual({path[len(PROFILE_HOME) + 1:] for path in fake.nodes
                          if path.startswith(PROFILE_HOME + "/")},
                         {"quarantine.config.toml", "tmp"})
        identity = fake.nodes[TMP]["st_dev"], fake.nodes[TMP]["st_ino"]
        fake.add(TMP + "/vendor-cache", directory=True)
        fake.add(TMP + "/vendor-cache/opaque", b"synthetic cache bytes")
        fake.nodes[TMP]["st_ctime_ns"] += 10
        fake.nodes[TMP]["st_mtime_ns"] += 10
        fake.nodes[TMP]["st_nlink"] += 1
        start = len(fake.calls)
        self.assertTrue(owner.verify())
        self.assertEqual((fake.nodes[TMP]["st_dev"], fake.nodes[TMP]["st_ino"]), identity)
        observed = fake.calls[start:]
        self.assertFalse(any(op == "scandir" and path.startswith(TMP) for op, path in observed))
        self.assertFalse(any(path.startswith(TMP + "/") for _, path in observed))
        # Change activity stamps during the whole-state round, outside the small
        # stable ACL/xattr observation. It is not fixture source drift.
        fake.effects["read", FILE_PATHS[0]] = lambda f: f.nodes[TMP].update(
            st_ctime_ns=9999, st_mtime_ns=9999, st_nlink=5)
        self.assertTrue(owner.verify())
        retained = copy.deepcopy(fake.nodes)
        owner.close()
        self.assertEqual(fake.nodes, retained)

    def test_tmp_name_type_mode_identity_and_envelope_remain_exact(self):
        for kind in ("absent", "replacement", "symlink", "mode", "owner", "flags", "acl", "xattr"):
            fake, metadata = fixture()
            owner = self.allocate(fake, metadata)
            if kind == "absent": del fake.nodes[TMP]
            elif kind == "replacement": fake.nodes[TMP] = dict(fake.nodes[TMP], st_ino=999999)
            elif kind == "symlink": fake.nodes[TMP]["st_mode"] = stat.S_IFLNK | 0o700
            elif kind == "mode": fake.nodes[TMP]["st_mode"] = stat.S_IFDIR | 0o755
            elif kind == "owner": fake.nodes[TMP]["st_uid"] = 502
            elif kind == "flags": fake.nodes[TMP]["st_flags"] = 1
            elif kind == "acl": metadata.set(TMP, 1, ())
            else: metadata.set(TMP, 0, ("com.fake",))
            retained = copy.deepcopy(fake.nodes)
            self.denied(owner.verify, owner)
            self.close_failed(fake, owner)
            self.assertEqual(fake.nodes, retained)

    def test_cache_allowance_never_allows_profile_siblings_or_profile_drift(self):
        for leaf in ("config.toml", "unknown-cache", "auth.json"):
            fake, metadata = fixture()
            owner = self.allocate(fake, metadata)
            fake.add(TMP + "/vendor", b"synthetic")
            fake.add(PROFILE_HOME + "/" + leaf, b"synthetic")
            self.denied(owner.verify, owner)
            self.close_failed(fake, owner)
        fake, metadata = fixture()
        owner = self.allocate(fake, metadata)
        fake.add(TMP + "/vendor", b"synthetic")
        fake.nodes[PROFILE_HOME + "/quarantine.config.toml"]["data"] += b"\n"
        self.denied(owner.verify, owner)
        self.close_failed(fake, owner)

    def test_creation_interruption_retains_owner_and_no_retry(self):
        for first in (KeyboardInterrupt(), SystemExit(7)):
            fake, metadata = fixture()
            fake.effects["created-directory", OUTSIDE] = first
            with self.assertRaises(type(first)) as caught:
                self.allocate(fake, metadata)
            self.assertIs(caught.exception, first)
            owner = first.private_owner
            self.assertIn(OUTSIDE, fake.nodes)
            self.assertEqual(sum(op == "mkdir" for op, _ in fake.calls), 2)
            with self.assertRaises(type(first)):
                owner.close()
            self.assertEqual(fake.handles, {})

    def test_post_admission_interrupt_cannot_hide_creation_interrupt(self):
        fake, metadata = fixture()
        first, later, calls = KeyboardInterrupt(), SystemExit(7), []
        fake.effects["created-directory", OUTSIDE] = first
        def admit():
            calls.append(1)
            if len(calls) == 2:
                raise later
            return True
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.allocate(fake, metadata, admit_sources=admit)
        self.assertIs(caught.exception, first)
        self.assertEqual(len(calls), 2)
        with self.assertRaises(KeyboardInterrupt):
            first.private_owner.close()
        self.assertEqual(fake.handles, {})

    def test_close_all_once_and_interruption_priority(self):
        for primary, first, later in ((None, OSError("private"), KeyboardInterrupt()),
                                      (None, SystemExit(7), KeyboardInterrupt()),
                                      (KeyboardInterrupt(), OSError("private"), SystemExit(7))):
            fake, metadata = fixture()
            owner = self.allocate(fake, metadata)
            owner._error = primary
            descriptors, closed, underlying = set(fake.handles), [], fake.close
            split = len(owner._parents[-1]._fds) + 1
            def close(fd):
                closed.append(fd)
                underlying(fd)
                if len(closed) == 1: raise first
                if len(closed) == split: raise later
            fake.close = close
            expected = next(e for e in (primary, first, later) if isinstance(e, (KeyboardInterrupt, SystemExit)))
            with self.assertRaises(type(expected)) as caught:
                owner.close()
            self.assertIs(caught.exception, expected)
            self.assertIs(expected.private_owner, owner)
            self.assertEqual(set(closed), descriptors)
            self.assertEqual(len(closed), len(descriptors))
            self.assertEqual(fake.handles, {})


if __name__ == "__main__":
    unittest.main()
