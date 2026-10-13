"""Actual Observer/SourceFile/P4 collector, synthetic OS only; no native probe."""

import copy
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import posixpath
import stat
import sys
from types import SimpleNamespace
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import phase5_phase4_observer as O


def load(name, source):
    spec = importlib.util.spec_from_file_location(name, ROOT / source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


F = load("p4_observer_os_fixture", "tests/test_phase5_runtime_legacy.py")
C = load("p4_observer_health_fixture", "tests/test_phase5_phase4_health.py")
R = importlib.machinery.SourceFileLoader("p4_observer_readiness", str(ROOT / "bin/phase5-current-readiness")).load_module()
VERSION = "/nix/store/synthetic-darwin-version.json"


class FakeOS(F.FakeOS):
    def link(self, path, target):
        self.add(path, target.encode(), mode=0o755)
        self.nodes[path].update(st_mode=stat.S_IFLNK | 0o755, st_uid=0, st_gid=0)

    def resolve(self, path, *, follow_final=True, depth=0):
        assert depth <= 40
        path = posixpath.normpath(path)
        parts = path[1:].split("/") if path != "/" else []
        for i in range(1, len(parts) + 1):
            prefix = "/" + "/".join(parts[:i])
            if prefix not in self.nodes:
                raise FileNotFoundError("synthetic missing")
            node = self.nodes[prefix]
            if stat.S_ISLNK(node["st_mode"]) and (follow_final or i < len(parts)):
                raw = node["data"].decode()
                target = raw if raw.startswith("/") else posixpath.dirname(prefix) + "/" + raw
                return self.resolve(target + ("/" + "/".join(parts[i:]) if parts[i:] else ""),
                                    follow_final=follow_final, depth=depth + 1)
        return path

    def path(self, leaf, dir_fd):
        return self.resolve(super().path(leaf, dir_fd), follow_final=False)

    def lstat(self, path):
        self.event("lstat", path)
        node = self.nodes[self.resolve(path, follow_final=False)]
        return SimpleNamespace(**{k: v for k, v in node.items() if k != "data"}, st_size=len(node["data"]))

    def readlink(self, path):
        self.event("readlink", path)
        node = self.nodes[self.resolve(path, follow_final=False)]
        assert stat.S_ISLNK(node["st_mode"])
        return node["data"].decode()

    def lseek(self, descriptor, offset, whence):
        assert offset == whence == 0
        self.event("lseek", self.handles[descriptor][0])
        self.handles[descriptor][2] = 0
        return 0

    def scandir(self, value):
        path = value if type(value) is str else self.handles[value][0]
        self.event("scandir", path)
        return F.Scan([name[len(path) + 1:] for name in self.nodes
                       if name.startswith(path + "/") and "/" not in name[len(path) + 1:]])

    def Path(self, value):
        fake = self
        class Bound:
            def resolve(self, *, strict):
                assert strict is True
                fake.event("resolve", value)
                return fake.resolve(value)
        return Bound()


def world(*, aliases=True):
    fixture, fake = C.World(), FakeOS()
    def add(path, data=b"", *, directory=False, mode=0o755, uid=0, gid=0):
        parts = path[1:].split("/")
        for count in range(len(parts)):
            parent = "/" + "/".join(parts[:count])
            if parent not in fake.nodes:
                fake.add(parent, directory=True, mode=0o755)
                owner = 501 if parent == C.HOME or parent.startswith(C.HOME + "/") else 0
                fake.nodes[parent].update(st_uid=owner, st_gid=20 if owner else 0)
        fake.add(path, data, directory=directory, mode=mode)
        fake.nodes[path].update(st_uid=uid, st_gid=gid)
    def physical(path):
        return O.Observer._physical(path) if aliases else path
    for path, row in fixture.files.items():
        add(physical(path), row["data"], uid=row["uid"], gid=row["gid"], mode=row["mode"])
    for path in O.H.DIRECTORIES.values():
        add(physical(path), directory=True, mode=0o700)
    for number, row in fixture.current["targets"].items():
        add(row["path"], directory=True, mode=0o555)
        add(O.PROFILES, directory=True)
        fake.link(O.PROFILES + "/system-" + str(number) + "-link", row["path"])
    add(VERSION, fixture.current["versionBytes"], mode=0o444)
    fake.nodes[O.STORE].update(st_mode=stat.S_IFDIR | 0o775, st_gid=123)
    fake.link(O.H.PROFILE, "system-27-link")
    fake.link(C.TARGET + "/darwin-version.json", VERSION)
    add(physical(O.SYSTEM).rsplit("/", 1)[0], directory=True)
    fake.nodes[physical(O.SYSTEM).rsplit("/", 1)[0]].update(st_mode=stat.S_IFDIR | 0o775, st_gid=27)
    fake.link(physical(O.SYSTEM), C.TARGET)
    if aliases:
        for path, destination in O.ALIASES.items():
            fake.link(path, destination)
    fixture.io = O.Observer(P4=fixture.P4, R=R, home=C.HOME, uid=501, budget=fixture.budget,
                            syscalls=fake, path_api=fake.Path)
    fixture.P4.strict_json, fixture.P4.digest = fixture.io.json, fixture.io.digest
    fixture.recheck = fixture.io.verify
    return fixture, fake


class ObserverTests(unittest.TestCase):
    def reject(self, fixture, call, expected=O.ObserverError):
        with self.assertRaises(expected) as caught:
            call()
        error = caught.exception
        self.assertIs(error.private_owner, fixture.io)
        self.assertNotIn(C.HOME, str(error))
        self.assertNotIn(VERSION, repr(fixture.io))
        return error

    def finish(self, fixture, fake):
        try:
            fixture.io.close()
        except BaseException as error:
            self.assertIs(error.private_owner, fixture.io)
        self.assertEqual(fake.handles, {})
        count = len(fake.calls)
        fixture.io.close()
        self.assertEqual(len(fake.calls), count)

    def test_constructor_no_syscalls_and_stable_callbacks(self):
        fixture, fake = world()
        self.assertEqual(fake.calls, [])
        self.assertIs(fixture.io.json, fixture.P4.strict_json)
        self.assertIs(fixture.io.digest, fixture.P4.digest)
        self.finish(fixture, fake)

    def test_actual_collector_sourcefile_and_p4_bodies_pass_synthetic_state(self):
        fixture, fake = world()
        before = copy.deepcopy(fake.nodes)
        result = fixture.collect()
        self.assertEqual(result["verdict"], "CURRENT_PHASE4_COMPONENT_HEALTH")
        self.assertTrue(fixture.io.verify())
        self.assertTrue(fake.handles)
        self.assertEqual(before, fake.nodes)
        opened = [p for op, p in fake.calls if op == "open"]
        forbidden = [O.Observer._physical(O.H.SUDOERS), *(O.Observer._physical(p) for p in O.H.DIRECTORIES.values())]
        self.assertFalse(any(p in opened for p in forbidden))
        self.assertEqual([p for op, p in fake.calls if op == "scandir"], [O.PROFILES] * 4)
        self.finish(fixture, fake)

    def test_every_callback_rejects_unknown_path_without_io(self):
        for method in ("file", "json", "digest", "metadata", "directory", "absent"):
            fixture, fake = world()
            self.reject(fixture, lambda: getattr(fixture.io, method)(C.HOME + "/.codex/auth.json"))
            self.assertEqual(fake.calls, [])
            self.finish(fixture, fake)

    def test_receipt_unreadable_before_current_and_only_exact_observed_revision(self):
        fixture, fake = world()
        self.reject(fixture, lambda: fixture.io.file(fixture.receipt_path))
        self.assertEqual(fake.calls, [])
        self.finish(fixture, fake)
        fixture, fake = world()
        fixture.io.current()
        self.assertEqual(fixture.io.file(fixture.receipt_path)["mode"], 0o400)
        self.reject(fixture, lambda: fixture.io.file(fixture.receipt_path.replace(C.REVISION, "a" * 40)))
        self.finish(fixture, fake)

    def test_sudoers_and_root_private_directories_are_metadata_only(self):
        fixture, fake = world()
        self.assertEqual(fixture.io.metadata(O.H.SUDOERS)["mode"], 0o440)
        for path in O.H.DIRECTORIES.values():
            self.assertEqual(fixture.io.directory(path)["mode"], 0o700)
        for path in O.H.EMERGENCY:
            self.assertIs(fixture.io.absent(path), True)
        self.assertFalse(any(op in ("open", "read", "scandir") for op, _ in fake.calls))
        self.finish(fixture, fake)

    def test_fixed_symlink_is_rejected_before_resolution_or_open(self):
        for method, path in (("file", O.H.POLICY), ("metadata", O.H.SUDOERS), ("directory", O.H.DIRECTORIES["audit"])):
            fixture, fake = world()
            fake.link(O.Observer._physical(path), C.HOME + "/.codex/auth.json")
            self.reject(fixture, lambda: getattr(fixture.io, method)(path))
            self.assertFalse(any(op in ("open", "read", "resolve") for op, _ in fake.calls))
            self.finish(fixture, fake)

    def test_resolution_outside_canonical_alias_rejected_before_open(self):
        fixture, fake = world()
        fixture.io.Path = lambda p: SimpleNamespace(resolve=lambda **k: "/outside")
        self.reject(fixture, lambda: fixture.io.file(O.H.POLICY))
        self.assertFalse(any(op == "open" for op, _ in fake.calls))
        self.finish(fixture, fake)

    def test_direct_store_requirement_rejects_substituted_target_before_reads(self):
        for raw in ("/outside", "/nix/store/historical-two/../current-synthetic-target", "/nix/store/bridge"):
            fixture, fake = world()
            fake.link(O.PROFILES + "/system-27-link", raw)
            fake.link("/nix/store/bridge", C.TARGET)
            self.reject(fixture, fixture.io.current)
            self.assertFalse(any(op == "read" for op, _ in fake.calls))
            self.assertFalse(any(op == "open" and p.startswith(O.STORE + "/") for op, p in fake.calls))
            self.finish(fixture, fake)

    def test_store_nonroot_owner_and_world_writable_parent_are_rejected(self):
        for change in ({"st_uid": 501}, {"st_mode": stat.S_IFDIR | 0o777},
                       {"st_mode": stat.S_IFDIR | 0o1777}):
            fixture, fake = world()
            fake.nodes[O.STORE].update(change)
            self.reject(fixture, fixture.io.current)
            self.assertFalse(any(op == "read" for op, _ in fake.calls))
            self.finish(fixture, fake)

    def test_root_owned_nonwheel_group_writable_store_and_run_are_observed_not_replaced(self):
        fixture, fake = world()
        before = copy.deepcopy(fake.nodes)
        self.assertEqual(stat.S_IMODE(fake.nodes[O.STORE]["st_mode"]), 0o775)
        self.assertNotEqual(fake.nodes[O.STORE]["st_gid"], 0)
        self.assertEqual(stat.S_IMODE(fake.nodes["/private/var/run"]["st_mode"]), 0o775)
        self.assertNotEqual(fake.nodes["/private/var/run"]["st_gid"], 0)
        self.assertEqual(fixture.io.current()["systemTarget"], C.TARGET)
        self.assertTrue(fixture.io.verify())
        self.assertEqual(before, fake.nodes)
        self.finish(fixture, fake)

    def test_legitimate_store_and_run_group_mode_are_identity_bound(self):
        for path in (O.STORE, "/private/var/run"):
            for change in ({"st_uid": 501}, {"st_gid": 234}, {"st_mode": stat.S_IFDIR | 0o755}, {"st_ino": 99999}):
                fixture, fake = world()
                fixture.io.current()
                fake.nodes[path].update(change)
                self.reject(fixture, fixture.io.verify)
                self.finish(fixture, fake)

    def test_version_link_must_resolve_to_its_direct_regular_immutable_store_file(self):
        for mutate in (lambda f: f.link(C.TARGET + "/darwin-version.json", "/outside"),
                       lambda f: f.link(VERSION, "/outside"),
                       lambda f: f.nodes[VERSION].update(st_uid=501),
                       lambda f: f.nodes[VERSION].update(st_gid=20),
                       lambda f: f.nodes[VERSION].update(st_mode=stat.S_IFREG | 0o644),
                       lambda f: f.nodes[VERSION].update(st_nlink=2),
                       lambda f: f.nodes[VERSION].update(data=b"x" * 4097)):
            fixture, fake = world()
            mutate(fake)
            self.reject(fixture, fixture.io.current)
            self.assertFalse(any(op == "read" for op, _ in fake.calls))
            self.finish(fixture, fake)

    def test_current_system_disagreement_and_numbered_registry_change_fail(self):
        fixture, fake = world()
        fake.link(O.Observer._physical(O.SYSTEM), "/nix/store/historical-two")
        self.reject(fixture, fixture.io.current)
        self.finish(fixture, fake)
        fixture, fake = world()
        fixture.io.current()
        fake.link(O.PROFILES + "/system-28-link", C.TARGET)
        self.reject(fixture, fixture.io.verify)
        self.finish(fixture, fake)

    def test_profile_absolute_and_system_fixed_profile_reference_are_supported(self):
        fixture, fake = world(aliases=False)
        fake.link(O.H.PROFILE, O.PROFILES + "/system-27-link")
        fake.link(O.SYSTEM, O.H.PROFILE)
        self.assertEqual(fixture.io.current()["systemTarget"], C.TARGET)
        self.finish(fixture, fake)

    def test_current_result_detached_and_parent_activity_not_frozen(self):
        fixture, fake = world()
        snapshot = fixture.io.current()
        snapshot["targets"][27]["path"] = "/outside"
        for path in (O.STORE, O.PROFILES, "/private/var/run"):
            fake.nodes[path]["st_ctime_ns"] += 1
            fake.nodes[path]["st_mtime_ns"] += 1
            fake.nodes[path]["st_nlink"] += 1
        self.assertTrue(fixture.io.verify())
        self.finish(fixture, fake)

    def test_held_byte_name_mode_and_root_edge_changes_are_detected(self):
        for path, key, value in ((VERSION, "data", b"changed"), (VERSION, "st_ino", 99999),
                                 (O.H.BROKER, "st_mode", stat.S_IFREG | 0o755),
                                 ("/etc", "data", b"/outside"), (O.PROFILES, "st_ino", 99998),
                                 ("/private/var/run", "st_ino", 99997)):
            fixture, fake = world()
            fixture.io.current()
            fixture.io.file(O.H.BROKER)
            fixture.io.file(O.H.POLICY)
            fake.nodes[path][key] = value
            self.reject(fixture, fixture.io.verify)
            self.finish(fixture, fake)

    def test_emergency_creation_and_sudoers_identity_change_detected(self):
        for method, path in (("absent", O.H.EMERGENCY[0]), ("metadata", O.H.SUDOERS),
                             ("directory", O.H.DIRECTORIES["audit"])):
            fixture, fake = world()
            getattr(fixture.io, method)(path)
            actual = O.Observer._physical(path)
            if method == "absent":
                fake.add(actual, b"disabled")
            else:
                fake.nodes[actual]["st_ino"] += 100
            self.reject(fixture, fixture.io.verify)
            self.finish(fixture, fake)

    def test_version_read_midstream_byte_change_rejected_retained_and_closed(self):
        fixture, fake = world()
        fake.effects[("read", VERSION)] = lambda f: f.nodes[VERSION].update(data=b"{}")
        self.reject(fixture, fixture.io.current)
        self.assertTrue(fake.handles)
        self.assertIsNone(fixture.io._receipt)
        self.finish(fixture, fake)

    def test_source_acquisition_failure_retains_context_without_retry(self):
        fixture, fake = world()
        original = OSError("private open")
        fake.effects[("open", O.H.BROKER)] = original
        self.reject(fixture, lambda: fixture.io.file(O.H.BROKER))
        self.assertTrue(fixture.io.acquisition_pending)
        self.assertIsNotNone(fixture.io._error)
        calls = list(fake.calls)
        self.reject(fixture, fixture.io.verify)
        self.assertEqual(fake.calls, calls)
        self.finish(fixture, fake)

    def test_all_closes_attempted_once_and_earliest_interruption_preserved(self):
        for original, first, later in ((None, OSError("private close"), KeyboardInterrupt()),
                                      (OSError("private operation"), SystemExit(7), KeyboardInterrupt()),
                                      (KeyboardInterrupt(), OSError("private close"), SystemExit(8)),
                                      (SystemExit(9), KeyboardInterrupt(), OSError("private close"))):
            fixture, fake = world()
            fixture.io.file(O.H.BROKER)
            fixture.io.file(O.H.POLICY)
            fixture.io.current()
            descriptors, calls, native_close = set(fake.handles), [], fake.close
            if original is not None:
                fixture.budget.error = original
                self.reject(fixture, fixture.io.verify, type(original) if isinstance(original, O.INTERRUPTS) else O.ObserverError)
            def close(fd):
                calls.append(fd)
                native_close(fd)
                if len(calls) == 1:
                    raise first
                if len(calls) == 2:
                    raise later
            fake.close = close
            expected = next((e for e in (original, first, later) if isinstance(e, O.INTERRUPTS)), None)
            caught = self.reject(fixture, fixture.io.close, type(expected))
            self.assertIs(caught, expected)
            self.assertEqual(set(calls), descriptors)
            self.assertEqual(len(calls), len(descriptors))
            self.finish(fixture, fake)

    def test_source_constructor_masked_interrupt_remains_original(self):
        for original, later in ((KeyboardInterrupt(), OSError("private close")),
                                (SystemExit(4), KeyboardInterrupt()), (KeyboardInterrupt(), SystemExit(5))):
            fixture, fake = world()
            fake.effects[("read", O.H.BROKER)] = original
            fake.effects[("close", O.H.BROKER)] = later
            caught = self.reject(fixture, lambda: fixture.io.file(O.H.BROKER), type(original))
            self.assertIs(caught, original)
            self.finish(fixture, fake)

    def test_context_selector_terminates_on_cycle_and_depth_and_keeps_sticky_first(self):
        first, second, last = KeyboardInterrupt(), SystemExit(7), OSError("private")
        last.__context__, second.__context__, first.__context__ = second, first, last
        self.assertIs(O.earliest(last), first)
        root = OSError("root")
        cursor = root
        for _ in range(100):
            cursor.__context__ = OSError("context")
            cursor = cursor.__context__
        cursor.__context__ = first
        self.assertIs(O.earliest(root), root)


if __name__ == "__main__":
    unittest.main()
