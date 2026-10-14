"""Connected publication fault/race tests in disposable private homes only."""

import errno
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lib import prepared_receipt as R


class PreparedReceiptTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="receipt-fixture-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.directory = self.home / "AIDev/state/phase-4/apply-receipts"
        self.commit = "a" * 40
        self.value = {"schema": 1, "controlCommit": self.commit, "reviewed": True}
        self.target = self.directory / (self.commit + ".json")
        self.data = (json.dumps(self.value, indent=2, sort_keys=True) + "\n").encode()

    def publish(self):
        return R.publish_receipt(self.home, self.commit, self.value)

    def prepare(self):
        self.directory.mkdir(parents=True, mode=0o700)

    def test_exact_private_durable_receipt_and_retained_staging(self):
        fsync = os.fsync
        calls = []
        def observe(fd):
            calls.append(os.fstat(fd).st_mode)
            return fsync(fd)
        with patch.object(R.os, "fsync", side_effect=observe):
            self.assertEqual(self.publish(), self.target)
        self.assertEqual(self.target.read_bytes(), self.data)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertTrue(any(stat.S_ISREG(mode) for mode in calls))
        self.assertTrue(any(stat.S_ISDIR(mode) for mode in calls))
        staging, = self.directory.glob(".prepared-*.tmp")
        self.assertEqual(staging.stat().st_ino, self.target.stat().st_ino)
        self.assertEqual(staging.stat().st_nlink, 2)

    def test_preexisting_modes_are_preserved_and_never_chmodded(self):
        self.prepare()
        self.home.chmod(0o750)
        before = {path: stat.S_IMODE(path.stat().st_mode) for path in
                  (self.home, self.home / "AIDev", self.directory)}
        with patch.object(R.os, "chmod", side_effect=AssertionError("chmod forbidden")):
            self.publish()
        self.assertEqual(before, {path: stat.S_IMODE(path.stat().st_mode) for path in before})

    def test_unsafe_existing_directory_rejected_without_repair(self):
        self.prepare()
        for path, mode in ((self.home, 0o777), (self.directory, 0o755)):
            with self.subTest(path=path):
                before = stat.S_IMODE(path.stat().st_mode)
                path.chmod(mode)
                with self.assertRaises(R.ReceiptError):
                    self.publish()
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
                self.assertFalse(self.target.exists())
                path.chmod(before)

    def test_wrong_directory_owner_is_rejected(self):
        self.prepare()
        fstat = os.fstat
        inode = self.home.stat().st_ino
        def wrong_owner(fd):
            facts = fstat(fd)
            if facts.st_ino == inode:
                return SimpleNamespace(st_mode=facts.st_mode, st_uid=facts.st_uid + 1,
                                       st_gid=facts.st_gid, st_ino=facts.st_ino,
                                       st_dev=facts.st_dev, st_flags=0)
            return facts
        with patch.object(R.os, "fstat", side_effect=wrong_owner):
            with self.assertRaisesRegex(R.ReceiptError, "receipt_parent_metadata"):
                self.publish()
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_symlink_at_each_relevant_level_never_writes_outside(self):
        for level in range(5):
            with self.subTest(level=level), tempfile.TemporaryDirectory(dir=self.root) as name:
                base = Path(name)
                home = base / "home"
                outside = base / "outside"
                outside.mkdir(mode=0o700)
                parts = ("home",) + R._SUFFIX
                parent = base
                for part in parts[:level]:
                    parent = parent / part
                    parent.mkdir(mode=0o700)
                (parent / parts[level]).symlink_to(outside, target_is_directory=True)
                with self.assertRaises(R.ReceiptError):
                    R.publish_receipt(home, self.commit, self.value)
                self.assertEqual(list(outside.iterdir()), [])

    def test_short_and_interrupted_writes_complete_exactly(self):
        write = os.write
        count = 0
        def short(fd, data):
            nonlocal count
            count += 1
            if count == 1:
                raise InterruptedError(errno.EINTR, "fixture")
            return write(fd, data[:3])
        with patch.object(R.os, "write", side_effect=short):
            self.publish()
        self.assertGreater(count, 3)
        self.assertEqual(self.target.read_bytes(), self.data)

    def test_zero_write_fails_without_publishing_or_unlinking(self):
        with patch.object(R.os, "write", return_value=0), \
                patch.object(R.os, "unlink", side_effect=AssertionError("unlink forbidden")):
            with self.assertRaisesRegex(R.ReceiptError, "receipt_short_write"):
                self.publish()
        self.assertFalse(self.target.exists())
        self.assertEqual(len(list(self.directory.glob(".prepared-*.tmp"))), 1)

    def test_write_error_retains_staging_and_no_destination(self):
        with patch.object(R.os, "write", side_effect=OSError(errno.ENOSPC, "fixture")):
            with self.assertRaises(R.ReceiptError):
                self.publish()
        self.assertFalse(self.target.exists())
        self.assertEqual(len(list(self.directory.glob(".prepared-*.tmp"))), 1)

    def test_corrupted_write_readback_cannot_publish(self):
        write = os.write
        with patch.object(R.os, "write", side_effect=lambda fd, data: write(fd, b"x" * len(data))):
            with self.assertRaisesRegex(R.ReceiptError, "receipt_content_mismatch"):
                self.publish()
        self.assertFalse(self.target.exists())

    def test_existing_and_concurrent_foreign_destinations_are_preserved(self):
        self.prepare()
        link = os.link
        for kind in ("existing", "concurrent", "symlink"):
            with self.subTest(kind=kind):
                foreign = self.root / (kind + "-foreign")
                foreign.write_bytes(b"foreign bytes")
                def compete(source, destination, **kwargs):
                    if kind == "concurrent":
                        self.target.write_bytes(b"foreign bytes")
                    return link(source, destination, **kwargs)
                if kind == "existing":
                    self.target.write_bytes(b"foreign bytes")
                if kind == "symlink":
                    self.target.symlink_to(foreign)
                with patch.object(R.os, "link", side_effect=compete), \
                        patch.object(R.os, "unlink", side_effect=AssertionError("unlink forbidden")):
                    with self.assertRaises(R.ReceiptError):
                        self.publish()
                self.assertEqual(self.target.read_bytes(), b"foreign bytes")
                self.assertEqual(foreign.read_bytes(), b"foreign bytes")
                self.target.unlink()

    def test_parent_replaced_after_open_is_detected_before_publication(self):
        self.prepare()
        write = os.write
        moved = self.directory.with_name("retained")
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        def swap(fd, data):
            self.directory.rename(moved)
            self.directory.symlink_to(outside, target_is_directory=True)
            return write(fd, data)
        with patch.object(R.os, "write", side_effect=swap):
            with self.assertRaisesRegex(R.ReceiptError, "receipt_parent_drift"):
                self.publish()
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((moved / self.target.name).exists())

    def test_home_replaced_after_publication_never_returns_success(self):
        self.prepare()
        link = os.link
        moved = self.root / "retained-home"
        def swap(source, destination, **kwargs):
            link(source, destination, **kwargs)
            self.home.rename(moved)
            self.home.mkdir(mode=0o700)
        with patch.object(R.os, "link", side_effect=swap):
            with self.assertRaisesRegex(R.ReceiptError, "receipt_parent_drift"):
                self.publish()
        self.assertEqual(list(self.home.iterdir()), [])
        self.assertEqual((moved / self.target.relative_to(self.home)).read_bytes(), self.data)

    def test_temporary_replacement_is_preserved_without_cleanup(self):
        self.prepare()
        link = os.link
        temporary = []
        def swap(source, destination, **kwargs):
            path = self.directory / source
            temporary.append(path)
            path.rename(self.directory / "retained-original")
            path.write_bytes(b"foreign staging")
            return link(source, destination, **kwargs)
        with patch.object(R.os, "link", side_effect=swap), \
                patch.object(R.os, "unlink", side_effect=AssertionError("unlink forbidden")):
            with self.assertRaises(R.ReceiptError):
                self.publish()
        self.assertEqual(temporary[0].read_bytes(), b"foreign staging")
        # Linking a raced source may have created an UNKNOWN final name. The
        # operation rejects it, preserves bytes and never claims readiness.
        self.assertEqual(self.target.read_bytes(), b"foreign staging")
        self.assertEqual((self.directory / "retained-original").read_bytes(), self.data)

    def test_final_content_replacement_during_fsync_is_detected(self):
        self.prepare()
        fsync = os.fsync
        swapped = False
        def replace(fd):
            nonlocal swapped
            if stat.S_ISDIR(os.fstat(fd).st_mode) and self.target.exists() and not swapped:
                swapped = True
                self.target.rename(self.directory / "retained-published")
                self.target.write_bytes(b"foreign final")
            return fsync(fd)
        with patch.object(R.os, "fsync", side_effect=replace), \
                patch.object(R.os, "unlink", side_effect=AssertionError("unlink forbidden")):
            with self.assertRaises(R.ReceiptError):
                self.publish()
        self.assertTrue(swapped)
        self.assertEqual(self.target.read_bytes(), b"foreign final")
        self.assertEqual((self.directory / "retained-published").read_bytes(), self.data)

    def test_close_failure_is_redacted_and_remaining_descriptors_are_closed(self):
        self.prepare()
        close = os.close
        closed = []
        def fail_receipt(fd):
            regular = stat.S_ISREG(os.fstat(fd).st_mode)
            close(fd)
            closed.append(fd)
            if regular:
                raise OSError(errno.EIO, "private fixture data")
        with patch.object(R.os, "close", side_effect=fail_receipt):
            with self.assertRaisesRegex(R.ReceiptError, "^receipt_close_failed$"):
                self.publish()
        self.assertGreater(len(closed), 5)
        self.assertEqual(len(closed), len(set(closed)))

    def test_file_and_directory_fsync_failure_cannot_return_success(self):
        self.prepare()
        fsync = os.fsync
        for fail_directory in (False, True):
            with self.subTest(directory=fail_directory):
                def fail(fd):
                    if stat.S_ISDIR(os.fstat(fd).st_mode) == fail_directory:
                        raise OSError(errno.EIO, "fixture")
                    return fsync(fd)
                with patch.object(R.os, "fsync", side_effect=fail):
                    with self.assertRaises(R.ReceiptError):
                        self.publish()
                if self.target.exists():
                    self.assertEqual(self.target.read_bytes(), self.data)
                    self.target.unlink()

    def test_interrupted_reads_and_fsync_are_retried(self):
        self.prepare()
        read, fsync = os.read, os.fsync
        counts = {"read": 0, "fsync": 0}
        def interrupt_once(name, original):
            def call(*args):
                counts[name] += 1
                if counts[name] == 1:
                    raise InterruptedError(errno.EINTR, "fixture")
                return original(*args)
            return call
        with patch.object(R.os, "read", side_effect=interrupt_once("read", read)), \
                patch.object(R.os, "fsync", side_effect=interrupt_once("fsync", fsync)):
            self.publish()
        self.assertEqual(self.target.read_bytes(), self.data)

    def test_invalid_input_has_no_side_effects(self):
        for commit, value in (("../bad", self.value), (self.commit, {}),
                              (self.commit, dict(self.value, invalid=float("nan")))):
            with self.subTest(commit=commit, value=value):
                with self.assertRaises(R.ReceiptError):
                    R.publish_receipt(self.home, commit, value)
                self.assertEqual(list(self.home.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
