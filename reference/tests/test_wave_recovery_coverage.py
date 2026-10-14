"""W42 connected preservation/compatibility checks; synthetic roots only.

This does not reread real owner data or implement an arbitrary-data backup.
Component suites own crash matrices; these checks cover cross-package meaning
of rollback and refusal of unsupported private recovery records.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest

from lib import harness_offramp as hooks
from test_wine_runtime_overlay import Fixture as WineFixture
from test_wine_runtime_overlay import w as wine


ROOT = Path(__file__).resolve().parents[1]
SHELL = runpy.run_path(str(ROOT / "bin/shell-nofile"))
COMMIT = "a" * 40


def opaque(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def facts(path):
    value = path.lstat()
    return (value.st_dev, value.st_ino, value.st_mode, path.read_bytes())


def private_files(root):
    """Only explicit fixture trees; preserve content and identity, not mtime."""
    return {str(path.relative_to(root)): facts(path)
            for path in root.rglob("*") if path.is_file() and not path.is_symlink()}


def hook_fixture():
    manifest, historical = hooks._sources()
    definitions = hooks.definitions(manifest, historical)
    events = {}
    for event, group in definitions.values():
        events.setdefault(event, []).append(copy.deepcopy(group))
    events["UnknownOwnerEvent"] = [{"hooks": [{"type": "command", "command": "opaque-owner-handler"}]}]
    return hooks.wire({"ownerSetting": "preserve", "hooks": events})


class RecoveryCoverage(unittest.TestCase):
    def test_shell_and_hook_return_preserve_newer_opaque_owner_data(self):
        with tempfile.TemporaryDirectory(prefix="wave-recovery-home-") as name:
            home = Path(name).resolve()
            home.chmod(0o700)
            (home / ".codex").mkdir(mode=0o700)
            hook_path = opaque(home / ".codex/hooks.json", hook_fixture())
            canaries = [opaque(home / "Games/Saves/synthetic.save", b"initial synthetic save"),
                        opaque(home / "Library/SyntheticProfile/opaque.bin", b"initial synthetic profile"),
                        opaque(home / ".codex/config.toml", b"opaque synthetic owner config\n")]
            fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertEqual(SHELL["transaction"](fd, "apply", COMMIT), "INSTALLED")
                hooks.execute_fixture(home, "disable", operation="coverage")
                for path in canaries:
                    path.write_bytes(path.read_bytes() + b"new owner state\n")
                newer = {path: facts(path) for path in canaries}
                self.assertEqual(SHELL["transaction"](fd, "rollback", COMMIT), "REMOVED")
                returned = hooks.execute_fixture(home, "restore", operation="coverage")
                self.assertEqual(returned["status"], "RESTORED")
                self.assertFalse(returned["nativeTrustRestored"])
                self.assertFalse(returned["harnessRemovalComplete"])
                self.assertEqual({path: facts(path) for path in canaries}, newer)
                self.assertEqual(hook_path.read_bytes(), hook_fixture())
                self.assertFalse((home / SHELL["TARGET"]).exists())
                self.assertTrue((home / "AIDev/state/harness-offramp/coverage/active.json").is_file())
            finally:
                os.close(fd)

    def test_wine_runtime_rollback_is_not_save_or_profile_restoration(self):
        fixture = WineFixture()
        self.addCleanup(fixture.close)
        saves = [opaque(fixture.path / route / "profiles/opaque-owner/synthetic.save", b"old synthetic save")
                 for route in ("hub", "ds3")]
        before = fixture.images()
        fixture.plan()
        fixture.tx().run("after")
        for path in saves:
            path.write_bytes(b"newer synthetic save after runtime update")
        newer = {path: facts(path) for path in saves}
        result = fixture.tx().run("before")
        self.assertEqual(result["state"], "ROLLED-BACK")
        self.assertEqual(fixture.images(), before)
        self.assertEqual({path: facts(path) for path in saves}, newer)
        for route in ("hub", "ds3"):
            # Existing poisoned profile link also survives; the runtime adapter
            # must not follow it, clone profiles or invent backup coverage.
            self.assertTrue((fixture.path / route / "profiles/private-sentinel").is_symlink())

    def test_unsupported_shell_journal_preserves_all_fixture_objects(self):
        for schema in (99, True):
            with self.subTest(schema=schema), tempfile.TemporaryDirectory(prefix="wave-schema-shell-") as name:
                home = Path(name)
                opaque(home / "owner-file", b"synthetic foreign state")
                fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    self.assertEqual(SHELL["transaction"](fd, "apply", COMMIT), "INSTALLED")
                    target = SHELL["snapshot_at"](fd, SHELL["TARGET"])
                    receipt = SHELL["snapshot_at"](fd, SHELL["RECEIPT"])
                    # A complete admissible rollback record except its schema:
                    # missing fields must not accidentally make this pass.
                    record = {"schema": schema, "operation": "rollback", "commit": COMMIT,
                              "targetIdentity": target[1], "receiptIdentity": receipt[1],
                              "receiptSha256": hashlib.sha256(receipt[0]).hexdigest()}
                    opaque(home / SHELL["JOURNAL"], json.dumps(record).encode())
                    before = private_files(home)
                    for action in ("status", "apply", "rollback", "recover"):
                        with self.assertRaisesRegex(RuntimeError, "journal_drift"):
                            SHELL["transaction"](fd, action, None if action == "status" else COMMIT)
                        self.assertEqual(private_files(home), before)
                finally:
                    os.close(fd)

    def test_unsupported_hook_record_preserves_current_and_recovery_images(self):
        for schema in (99, True):
            with self.subTest(schema=schema), tempfile.TemporaryDirectory(prefix="wave-schema-hooks-") as name:
                home = Path(name).resolve()
                home.chmod(0o700)
                (home / ".codex").mkdir(mode=0o700)
                opaque(home / ".codex/hooks.json", hook_fixture())
                hooks.execute_fixture(home, "disable", operation="coverage")
                active = home / "AIDev/state/harness-offramp/coverage/active.json"
                record = json.loads(active.read_bytes())
                record["schema"] = schema
                active.write_bytes(hooks.wire(record))
                before = private_files(home)
                with self.assertRaisesRegex(hooks.OfframpError, "recovery_record"):
                    hooks.execute_fixture(home, "restore", operation="coverage")
                self.assertEqual(private_files(home), before)

    def test_unsupported_wine_journal_preserves_targets_and_private_transaction(self):
        for schema in (99, True):
            with self.subTest(schema=schema):
                fixture = WineFixture()
                try:
                    fixture.plan()
                    journal = fixture.path / "state/transaction/journal.json"
                    record = json.loads(journal.read_bytes())
                    record["schema"] = schema
                    journal.write_bytes(wine.encode(record))
                    before = private_files(fixture.path)
                    for side in ("after", "before"):
                        with self.assertRaisesRegex(wine.Blocked, "journal_binding_drift"):
                            fixture.tx().run(side, recover=True)
                        self.assertEqual(private_files(fixture.path), before)
                finally:
                    fixture.close()


if __name__ == "__main__":
    unittest.main()
