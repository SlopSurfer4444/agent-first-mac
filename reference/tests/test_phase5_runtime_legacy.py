"""Pure fake filesystem with ACTUAL OwnedParent/DescriptorBackend; no native I/O.

Only tests patch production digest constants to synthetic in-memory fixtures.
The production API has no expected-digest override and never derives pins from
observed input. No real legacy receipt, owner state or historical bytes read.
"""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import phase5_runtime_legacy as legacy  # noqa: E402
from lib.phase5_runtime_backend import DescriptorBackend  # noqa: E402
from lib.phase5_runtime_paths import OwnedParent  # noqa: E402

spec = importlib.util.spec_from_file_location("legacy_capture_fixtures", ROOT / "tests/test_phase5_runtime_capture.py")
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
HOME = "/Users/owner"
RUN = HOME + "/AIDev/state/codex-transactions/" + legacy.LEGACY_RUN_ID


def raw(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def core(receipt):
    result = copy.deepcopy(receipt)
    for key in ("appliedOrder", "applyResult", "rollbackState", "state"):
        del result[key]
    for row in result["targets"]:
        del row["applied"]
    for row in result["directories"]:
        row.pop("createdByApply", None)
    return sha(json.dumps(result, sort_keys=True, separators=(",", ":")).encode())


class Scan:
    def __init__(self, names):
        self.names = names

    def __enter__(self):
        return iter(SimpleNamespace(name=n) for n in self.names)

    def __exit__(self, *_):
        return False


class FakeOS:
    def __init__(self):
        self.nodes, self.handles, self.effects, self.calls = {}, {}, {}, []
        self.sequence = 30

    def add(self, path, data=b"", *, directory=False, mode=None):
        self.sequence += 1
        self.nodes[path] = dict(data=data, st_dev=1, st_ino=self.sequence, st_uid=0 if path in ("/", "/Users") else 501,
                                st_gid=20, st_nlink=2 if directory else 1,
                                st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | (mode if mode is not None else (0o700 if directory else 0o600)),
                                st_flags=0, st_mtime_ns=10, st_ctime_ns=20)

    def event(self, operation, path):
        self.calls.append((operation, path))
        effect = self.effects.pop((operation, path), None)
        if effect is not None:
            if isinstance(effect, BaseException):
                raise effect
            effect(self)

    def path(self, leaf, dir_fd):
        return leaf if dir_fd is None else self.handles[dir_fd][0].rstrip("/") + "/" + leaf

    def open(self, leaf, flags, *, dir_fd=None):
        assert not flags & (os.O_CREAT | os.O_WRONLY | os.O_RDWR)
        assert flags & os.O_NOFOLLOW and flags & os.O_CLOEXEC
        path = self.path(leaf, dir_fd)
        self.event("open", path)
        node = self.nodes[path]
        if stat.S_ISLNK(node["st_mode"]) or flags & os.O_DIRECTORY and not stat.S_ISDIR(node["st_mode"]):
            raise OSError("private wrong type")
        descriptor = self.sequence + 1000
        self.sequence += 1
        self.handles[descriptor] = [path, node, 0]
        return descriptor

    def fstat(self, descriptor):
        path, node, _ = self.handles[descriptor]
        self.event("fstat", path)
        return SimpleNamespace(**{k: v for k, v in node.items() if k != "data"}, st_size=len(node["data"]))

    def stat(self, leaf, *, dir_fd=None, follow_symlinks):
        assert follow_symlinks is False
        path = self.path(leaf, dir_fd)
        self.event("stat", path)
        node = self.nodes[path]
        return SimpleNamespace(**{k: v for k, v in node.items() if k != "data"}, st_size=len(node["data"]))

    def read(self, descriptor, maximum):
        path, node, offset = self.handles[descriptor]
        self.event("read", path)
        value = node["data"][offset:offset + maximum]
        self.handles[descriptor][2] += len(value)
        return value

    def close(self, descriptor):
        path = self.handles.pop(descriptor)[0]
        self.event("close", path)

    def scandir(self, descriptor):
        path = self.handles[descriptor][0]
        self.event("scandir", path)
        return Scan([name[len(path) + 1:] for name in self.nodes
                     if name.startswith(path + "/") and "/" not in name[len(path) + 1:]])


def fixture(receipt_change=None, companion_change=None):
    _, _, receipt, before, after, _ = fixtures.fixture()
    receipt.update(runId=legacy.LEGACY_RUN_ID, acceptedControlCommit=legacy.LEGACY_ACCEPTED_COMMIT,
                   sourceCommit=legacy.LEGACY_ACCEPTED_COMMIT, manifestSHA256=legacy.LEGACY_MANIFEST_SHA256)
    if receipt_change:
        receipt_change(receipt)
    receipt_raw, core_hash = raw(receipt), core(receipt)
    overlay = b"synthetic private overlay" + b"x" * (6300 - len(b"synthetic private overlay"))
    companion = {"schema": 1, "phase": "phase5_external_config_overlay", "runId": legacy.LEGACY_RUN_ID,
                 "state": "reconciled", "rollbackState": "not-required", "receiptCoreSHA256": core_hash,
                 "receiptSHA256AtReconciliation": sha(receipt_raw), "configBeforeReconciliationSHA256": sha(overlay),
                 "hookOverlaySHA256": "a" * 64, "hookSource": "$HOME/.codex/hooks.json", "hookTrustRecords": {},
                 "projectTrustEntryRemoved": "$HOME/AIDev/control", "projectTrustRowsBefore": 20,
                 "projectTrustRowsAfter": 19, "reconciledConfigSHA256": "b" * 64}
    if companion_change:
        companion_change(companion)
    fake = FakeOS()
    parts = RUN[1:].split("/")
    fake.add("/", directory=True, mode=0o755)
    for i in range(1, len(parts) + 1):
        path = "/" + "/".join(parts[:i])
        fake.add(path, directory=True, mode=0o750 if path == HOME else 0o700)
    for child in ("preimages", "staged"):
        fake.add(RUN + "/" + child, directory=True)
    fake.add(RUN + "/receipt.json", receipt_raw)
    fake.add(RUN + "/" + legacy.COMPANION, raw(companion))
    for row in receipt["targets"]:
        identifier = row["id"]
        name = identifier if row["before"]["exists"] else identifier + ".absent"
        fake.add(RUN + "/preimages/" + name, before[identifier].data)
        fake.add(RUN + "/staged/" + identifier, after[identifier].data)
    fake.add(RUN + "/preimages/" + legacy.OVERLAY_PREIMAGE, overlay)
    pins = dict(LEGACY_RECEIPT_SHA256=sha(receipt_raw), LEGACY_RECEIPT_CORE_SHA256=core_hash,
                COMPANION_SHA256=sha(raw(companion)), OVERLAY_PREIMAGE_SHA256=sha(overlay))
    return fake, pins


class LegacyTests(unittest.TestCase):
    def test_observer_constructor_failure_does_not_discard_cleanup_interrupt(self):
        for interrupt in (KeyboardInterrupt(), SystemExit(7)):
            fake, _ = fixture()
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
                legacy.observe(HOME, 501, syscalls=fake, backend_factory=backend)
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
            fake, pins = fixture()
            with patch.multiple(legacy, **pins):
                held = legacy.observe(HOME, 501, syscalls=fake)
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
            fake, pins = fixture()
            with patch.multiple(legacy, **pins):
                held = legacy.observe(HOME, 501, syscalls=fake)
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
        with self.assertRaisesRegex(legacy.LegacyError, "^runtime_legacy_observation_required$"):
            operation()
        self.assertEqual(fake.handles, {})

    def test_real_owned_parent_backend_fake_io_full_generation_and_logical_mode(self):
        fake, pins = fixture()
        original = copy.deepcopy(fake.nodes)
        with patch.multiple(legacy, **pins):
            held = legacy.observe(HOME, 501, syscalls=fake)
            self.assertTrue(all(type(p) is OwnedParent for p in held._parents))
            self.assertTrue(all(type(b) is DescriptorBackend for b in held._backends))
            self.assertEqual(len(held._snapshots[0]) + len(held._snapshots[1]) + len(held._snapshots[2]), 19)
            self.assertEqual(held.history.after[-1].mode, 0o700)
            self.assertEqual(held.physical_after[legacy.TARGET_IDS[-1]].mode, 0o600)
            self.assertEqual(held.physical_before[legacy.TARGET_IDS[2]].data, b"absent\n")
            self.assertEqual(held.overlay_preimage.data, fake.nodes[RUN + "/preimages/" + legacy.OVERLAY_PREIMAGE]["data"])
            self.assertTrue(held.verify())
            self.assertNotIn("private", repr(held))
            held.close()
            held.close()
        self.assertEqual(fake.handles, {})
        self.assertEqual(fake.nodes, original)
        self.assertLessEqual(set(op for op, _ in fake.calls), {"open", "read", "stat", "fstat", "scandir", "close"})

    def test_production_digest_constants_reject_synthetic_generation(self):
        fake, _ = fixture()
        self.assert_failure(fake, lambda: legacy.observe(HOME, 501, syscalls=fake))

    def test_properties_do_not_mutate_held_receipt_or_physical_maps(self):
        fake, pins = fixture()
        with patch.multiple(legacy, **pins), legacy.observe(HOME, 501, syscalls=fake) as held:
            held.receipt["state"] = "changed"
            held.companion["state"] = "changed"
            held.physical_before.clear()
            held.physical_after.clear()
            self.assertEqual(held.receipt["state"], "applied")
            self.assertEqual(len(held.physical_before), 8)
            self.assertTrue(held.verify())

    def test_fixed_receipt_state_and_source_bindings_even_with_test_hashes(self):
        for key, value in (("state", "returned"), ("applyResult", "noop"), ("rollbackState", "not-run"),
                           ("sourceCommit", "0" * 40), ("acceptedControlCommit", "0" * 40),
                           ("manifestSHA256", "0" * 64), ("schema", True), ("runId", "other")):
            fake, pins = fixture(receipt_change=lambda r: r.update({key: value}))
            with patch.multiple(legacy, **pins):
                self.assert_failure(fake, lambda: legacy.observe(HOME, 501, syscalls=fake))

    def test_companion_state_and_bindings_even_with_test_hashes(self):
        for key, value in (("state", "prepared"), ("rollbackState", "complete"), ("schema", True),
                           ("receiptCoreSHA256", "0" * 64), ("receiptSHA256AtReconciliation", "0" * 64),
                           ("configBeforeReconciliationSHA256", "0" * 64)):
            fake, pins = fixture(companion_change=lambda r: r.update({key: value}))
            with patch.multiple(legacy, **pins):
                self.assert_failure(fake, lambda: legacy.observe(HOME, 501, syscalls=fake))

    def test_core_digest_is_independently_required(self):
        fake, pins = fixture()
        pins["LEGACY_RECEIPT_CORE_SHA256"] = "0" * 64
        with patch.multiple(legacy, **pins):
            self.assert_failure(fake, lambda: legacy.observe(HOME, 501, syscalls=fake))

    def test_exact_root_preimages_staged_childsets(self):
        for parent in (RUN, RUN + "/preimages", RUN + "/staged"):
            fake, pins = fixture()
            fake.add(parent + "/unexpected", b"private extra")
            with patch.multiple(legacy, **pins):
                self.assert_failure(fake, lambda: legacy.observe(HOME, 501, syscalls=fake))
        fake, pins = fixture()
        del fake.nodes[RUN + "/staged/config"]
        with patch.multiple(legacy, **pins):
            self.assert_failure(fake, lambda: legacy.observe(HOME, 501, syscalls=fake))

    def test_every_physical_file_bytes_drift_fails_without_accepting_new_baseline(self):
        seed, _ = fixture()
        files = [p for p, n in seed.nodes.items() if stat.S_ISREG(n["st_mode"])]
        self.assertEqual(len(files), 19)
        for path in files:
            fake, pins = fixture()
            with patch.multiple(legacy, **pins):
                held = legacy.observe(HOME, 501, syscalls=fake)
                fake.nodes[path]["data"] += b"changed"
                self.assert_failure(fake, held.verify)
                self.assertTrue(fake.nodes[path]["data"].endswith(b"changed"))

    def test_identity_mode_seal_symlink_and_linkcount_drift_close_all(self):
        for field, value in (("st_ino", 99999), ("st_mode", stat.S_IFREG | 0o644),
                             ("st_mtime_ns", 999), ("st_flags", 2),
                             ("st_mode", stat.S_IFLNK | 0o600), ("st_nlink", 2)):
            fake, pins = fixture()
            with patch.multiple(legacy, **pins):
                held = legacy.observe(HOME, 501, syscalls=fake)
                fake.nodes[RUN + "/preimages/config"][field] = value
                self.assert_failure(fake, held.verify)

    def test_leaf_parent_requires0700_not_merely_safe_chain_mode(self):
        for path in (RUN, RUN + "/preimages", RUN + "/staged"):
            fake, pins = fixture()
            fake.nodes[path]["st_mode"] = stat.S_IFDIR | 0o750
            with patch.multiple(legacy, **pins):
                self.assert_failure(fake, lambda: legacy.observe(HOME, 501, syscalls=fake))

    def test_named_parent_and_childset_substitution_on_verify(self):
        for defect in ("parent", "child"):
            fake, pins = fixture()
            with patch.multiple(legacy, **pins):
                held = legacy.observe(HOME, 501, syscalls=fake)
                if defect == "parent":
                    replacement = dict(fake.nodes[RUN + "/preimages"])
                    replacement["st_ino"] += 10000
                    fake.nodes[RUN + "/preimages"] = replacement
                else:
                    fake.add(RUN + "/staged/unknown", b"unknown")
                self.assert_failure(fake, held.verify)

    def test_interruptions_during_parent_open_file_read_and_verify_close_all(self):
        for operation, path in (("open", RUN + "/preimages"), ("read", RUN + "/receipt.json")):
            fake, pins = fixture()
            fake.effects[(operation, path)] = KeyboardInterrupt()
            with patch.multiple(legacy, **pins), self.assertRaises(KeyboardInterrupt):
                legacy.observe(HOME, 501, syscalls=fake)
            self.assertEqual(fake.handles, {})
        fake, pins = fixture()
        with patch.multiple(legacy, **pins):
            held = legacy.observe(HOME, 501, syscalls=fake)
            fake.effects[("scandir", RUN)] = KeyboardInterrupt()
            with self.assertRaises(KeyboardInterrupt):
                held.verify()
            self.assertEqual(fake.handles, {})

    def test_close_failure_still_closes_other_parents_and_never_retries(self):
        fake, pins = fixture()
        with patch.multiple(legacy, **pins):
            held = legacy.observe(HOME, 501, syscalls=fake)
            fake.effects[("close", RUN + "/staged")] = OSError("private close")
            self.assert_failure(fake, held.close)
            closed = list(fake.calls)
            held.close()
            self.assertEqual(fake.calls, closed)

    def test_context_preserves_primary_interrupt_despite_close_failure(self):
        fake, pins = fixture()
        with patch.multiple(legacy, **pins), self.assertRaises(KeyboardInterrupt):
            with legacy.observe(HOME, 501, syscalls=fake):
                fake.effects[("close", RUN + "/staged")] = OSError("private close")
                raise KeyboardInterrupt()
        self.assertEqual(fake.handles, {})

    def test_parse_duplicate_keys_is_rejected_even_under_fake_digest_patch(self):
        fake, pins = fixture()
        node = fake.nodes[RUN + "/receipt.json"]
        node["data"] = b'{"schema":1,' + node["data"][1:]
        pins["LEGACY_RECEIPT_SHA256"] = sha(node["data"])
        with patch.multiple(legacy, **pins):
            self.assert_failure(fake, lambda: legacy.observe(HOME, 501, syscalls=fake))

    def test_receipt_bound_and_marker_staged_physical_modes(self):
        for path, field, value in ((RUN + "/receipt.json", "data", b"x" * (legacy.MAX_RECEIPT_BYTES + 1)),
                                   (RUN + "/preimages/quarantine-profile.absent", "data", b"wrong\n"),
                                   (RUN + "/staged/quarantine-launcher", "st_mode", stat.S_IFREG | 0o700)):
            fake, pins = fixture()
            fake.nodes[path][field] = value
            with patch.multiple(legacy, **pins):
                self.assert_failure(fake, lambda: legacy.observe(HOME, 501, syscalls=fake))


if __name__ == "__main__":
    unittest.main()
