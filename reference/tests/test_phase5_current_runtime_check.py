"""Pure fake snapshots only; no production configuration or process calls."""

import copy
import hashlib
from importlib.machinery import SourceFileLoader
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
CHECK = SourceFileLoader("phase5_runtime_check_test", str(ROOT / "bin/phase5-current-runtime-check")).load_module()
FIXTURE = SourceFileLoader("phase5_runtime_fixtures", str(ROOT / "tests/test_phase5_current_runtime.py")).load_module()


def snapshot(value=None):
    value = FIXTURE.fixture(43) if value is None else value
    return {"bytes": value, "identity": (10, 20), "metadata": {
        "exists": True, "linkCount": 1, "mode": "0600",
        "ownerClass": "current-user", "size": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
    }}


def observe(provider):
    return CHECK.observe(provider, control_root=FIXTURE.CONTROL,
                         hook_source=FIXTURE.HOOK_SOURCE, hook_records=FIXTURE.RECORDS)


class RuntimeObservationTests(unittest.TestCase):
    def test_real_descriptor_reader_rejects_fifo_without_blocking(self):
        transaction = SourceFileLoader("phase5_reader_fixture", str(ROOT / "bin/phase5-apply-transaction")).load_module()
        with tempfile.TemporaryDirectory(prefix="phase5-reader-fixture-") as directory:
            root = Path(directory).resolve()
            target = root / "config.toml"
            os.mkfifo(target, 0o600)
            native_open = os.open
            def checked_open(path, flags, *args, **kwargs):
                if path == target.name:
                    # A regression fails before calling blocking open, so the
                    # negative test itself cannot hang on the old implementation.
                    self.assertTrue(flags & os.O_NONBLOCK)
                return native_open(path, flags, *args, **kwargs)
            with patch.object(transaction.os, "open", side_effect=checked_open):
                with self.assertRaisesRegex(transaction.TransactionError, "^target_metadata$"):
                    transaction.snapshot_path(target, os.getuid(), CHECK.MAX_CONFIG_BYTES,
                                              allow_absent=False, user_root=root)

    def test_real_descriptor_reader_regular_symlink_and_hardlink(self):
        transaction = SourceFileLoader("phase5_reader_regular_fixture", str(ROOT / "bin/phase5-apply-transaction")).load_module()
        with tempfile.TemporaryDirectory(prefix="phase5-reader-fixture-") as directory:
            root = Path(directory).resolve()
            target = root / "config.toml"
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.write(descriptor, FIXTURE.fixture())
            finally:
                os.close(descriptor)
            def read(path=target):
                return transaction.snapshot_path(path, os.getuid(), CHECK.MAX_CONFIG_BYTES,
                                                 allow_absent=False, user_root=root)
            self.assertEqual(read()["bytes"], FIXTURE.fixture())
            alias = root / "alias"
            alias.symlink_to(target)
            with self.assertRaises(transaction.TransactionError):
                read(alias)
            hardlink = root / "hardlink"
            os.link(target, hardlink)
            with self.assertRaisesRegex(transaction.TransactionError, "^target_metadata$"):
                read()

    def test_main_real_adapter_signature_stays_read_only(self):
        calls = []
        home = Path("/fixture/home")
        def read(path, uid, maximum, *, allow_absent, user_root):
            self.assertEqual(path, home / ".codex/config.toml")
            self.assertEqual(uid, 123)
            self.assertEqual(maximum, CHECK.MAX_CONFIG_BYTES)
            self.assertIs(allow_absent, False)
            self.assertEqual(user_root, home)
            calls.append("read")
            return snapshot()
        module = SimpleNamespace(canonical_account_home=lambda: home, snapshot_path=read,
                                 HOOK_TRUST_RECORDS=[("fixture", slot, digest)
                                     for slot, digest in FIXTURE.RECORDS.items()])
        output = io.StringIO()
        with patch.object(CHECK.importlib.machinery, "SourceFileLoader",
                          return_value=SimpleNamespace(load_module=lambda: module)), \
                patch.object(CHECK.sys, "argv", ["check"]), \
                patch.object(CHECK.os, "getuid", return_value=123), \
                patch.object(CHECK.sys, "stdout", output):
            code = CHECK.main()
        self.assertEqual(code, 1)
        self.assertEqual(calls, ["read", "read"])
        self.assertEqual(json.loads(output.getvalue())["classification"]["verdict"], "needs-review")

    def test_valid_current_config_is_not_inventory_or_execution_admission(self):
        result = observe(snapshot)
        self.assertTrue(result["configObservationStable"])
        self.assertEqual(result["classification"]["verdict"], "needs-review")
        self.assertEqual(result["classification"]["projectCount"], 43)
        self.assertEqual(result["classification"]["reasonCodes"],
                         ["plugins_need_review", "mcp_need_review"])
        for key in ("integrationAdmission", "signedRuntimeAttested", "executionAdmission",
                    "configMutationAuthorized", "trustMutationAuthorized", "phase5PassClaimed",
                    "phase6Authorized"):
            self.assertIs(result[key], False)

    def test_bytes_identity_and_metadata_drift_discard_classification(self):
        before = snapshot()
        variants = [snapshot(before["bytes"] + b"\n")]
        for path, value in (("identity", (10, 21)), ("mode", "0644"),
                            ("linkCount", 2), ("ownerClass", "other-user")):
            candidate = copy.deepcopy(before)
            if path == "identity":
                candidate[path] = value
            else:
                candidate["metadata"][path] = value
            variants.append(candidate)
        for after in variants:
            with self.subTest(after_id=after["identity"]):
                values = iter((before, after))
                result = observe(lambda: next(values))
                self.assertEqual(result["error"], "config_observation_drift")
                self.assertFalse(result["configObservationStable"])
                self.assertIsNone(result["classification"])

    def test_failed_classification_still_reads_after(self):
        calls = []
        def provider():
            calls.append(True)
            return snapshot()
        with patch.object(CHECK, "classify", side_effect=RuntimeError("PRIVATE-CANARY")):
            result = observe(provider)
        self.assertEqual(len(calls), 2)
        self.assertEqual(result["error"], "classification_failed")
        self.assertNotIn("PRIVATE-CANARY", json.dumps(result))

    def test_invalid_toml_still_reads_after(self):
        values = iter((snapshot(b"bad =["), snapshot(b"bad =[")))
        result = observe(lambda: next(values))
        self.assertTrue(result["configObservationStable"])
        self.assertEqual(result["classification"]["verdict"], "invalid")
        with self.assertRaises(StopIteration):
            next(values)

    def test_read_failures_are_redacted(self):
        def failed():
            raise OSError("/PRIVATE/CANARY")
        self.assertEqual(observe(failed)["error"], "config_observation_failed")
        calls = []
        def late_failure():
            calls.append(True)
            return snapshot() if len(calls) == 1 else failed()
        result = observe(late_failure)
        self.assertEqual(result["error"], "config_observation_drift")
        self.assertNotIn("/PRIVATE", json.dumps(result))

    def test_invalid_snapshots_rejected(self):
        for field, value in (("identity", (True, 2)), ("bytes", bytearray(b"x")),
                             ("metadata", None)):
            item = snapshot()
            item[field] = value
            self.assertEqual(observe(lambda: item)["error"], "config_observation_failed")
        item = snapshot()
        item["metadata"]["sha256"] = "a" * 64
        self.assertEqual(observe(lambda: item)["error"], "config_observation_failed")

    def test_mutable_snapshot_provider_cannot_change_saved_prestate(self):
        item, calls = snapshot(), []
        def provider():
            calls.append(True)
            if len(calls) == 2:
                item["identity"] = (10, 30)
            return item
        self.assertEqual(observe(provider)["error"], "config_observation_drift")

    def test_no_io_and_no_private_values_in_output(self):
        with patch("builtins.open", side_effect=AssertionError("no IO")), \
                patch("os.open", side_effect=AssertionError("no IO")), \
                patch("subprocess.run", side_effect=AssertionError("no processes")), \
                patch("socket.socket", side_effect=AssertionError("no network")):
            result = observe(snapshot)
        output = json.dumps(result)
        for value in ("/fixture", "not-a-real-secret", "sha256:"):
            self.assertNotIn(value, output)


if __name__ == "__main__":
    unittest.main()
