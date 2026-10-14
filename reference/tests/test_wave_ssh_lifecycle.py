"""Fixture-only custody/readiness tests; never launch native commands or SSH."""
import importlib.machinery
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
holder = importlib.machinery.SourceFileLoader(
    "wave_ssh_custody", str(ROOT / "bin/codex-windows-host-ssh-app-server-holder")
).load_module()
COMMIT = "a" * 40


class FixtureDeath(BaseException):
    """Abrupt interruption seam bypasses ordinary Exception compensation."""


class CustodyFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="holder-wave-")
        self.root = Path(self.tmp.name).resolve()
        self.paths = {"runtime": self.root / "bin/runtime", "plist": self.root / "agents/holder.plist",
                      "state": self.root / "state/holder", "receipt": self.root / "state/holder/receipt.json",
                      "journal": self.root / "state/journal.json", "lock": self.root / "state/lock"}
        for name in ("bin", "agents", "state"):
            (self.root / name).mkdir(mode=0o700)
        holder.ACTIVE_JOURNAL = None
        holder.JOURNAL_EXPECTED = None
        self.layout = patch.object(holder, "layout", return_value=self.paths)
        self.layout.start()
        self.native = patch.object(holder, "run", side_effect=AssertionError("native call forbidden"))
        self.native.start()
        self.source = patch.object(holder, "require_exact_commit")
        self.source.start()
        self.absence = patch.object(holder, "REMOTE_ABSENCE_SUPPORTED", True)
        self.absence.start()

    def tearDown(self):
        holder.ACTIVE_JOURNAL = None
        holder.JOURNAL_EXPECTED = None
        self.native.stop()
        self.source.stop()
        self.absence.stop()
        self.layout.stop()
        self.tmp.cleanup()

    def install_fixture(self):
        self.paths["state"].mkdir(mode=0o700)
        runtime = holder.payload_bytes()
        plist = holder.render_plist(self.paths["runtime"])
        holder.atomic_create(self.paths["runtime"], runtime, 0o755)
        holder.atomic_create(self.paths["plist"], plist, 0o644)
        holder.write_receipt(self.paths["receipt"], COMMIT, holder.sha256(runtime), holder.sha256(plist))

    def test_no_replace_creation_preserves_concurrent_arrival(self):
        target = self.paths["runtime"]
        link = os.link
        def race(source, destination, **kwargs):
            target.write_bytes(b"foreign arrival")
            return link(source, destination, **kwargs)
        with patch.object(holder.os, "link", side_effect=race):
            with self.assertRaisesRegex(holder.ContractError, "managed_target_collision"):
                holder.atomic_create(target, b"owned", 0o755)
        self.assertEqual(target.read_bytes(), b"foreign arrival")

    def test_parent_replacement_never_writes_replacement_tree(self):
        target = self.paths["runtime"]
        link = os.link
        def race(source, destination, **kwargs):
            target.parent.rename(self.root / "held-old")
            target.parent.mkdir(mode=0o700)
            return link(source, destination, **kwargs)
        with patch.object(holder.os, "link", side_effect=race):
            with self.assertRaisesRegex(holder.ContractError, "managed_parent_changed"):
                holder.atomic_create(target, b"owned", 0o755)
        self.assertEqual(list(target.parent.iterdir()), [])
        self.assertEqual((self.root / "held-old/runtime").read_bytes(), b"owned")

    def test_short_writes_are_completed_and_verified(self):
        write = os.write
        with patch.object(holder.os, "write", side_effect=lambda fd, data: write(fd, data[:2])):
            holder.atomic_create(self.paths["runtime"], b"complete fixture", 0o755)
        self.assertEqual(self.paths["runtime"].read_bytes(), b"complete fixture")

    def test_preimage_receipt_replacement_refuses_changed_inode(self):
        target = self.root / "state/receipt"
        holder.atomic_create(target, b"original", 0o600)
        original = holder.bound_file(target)
        target.unlink()
        holder.atomic_create(target, b"foreign", 0o600)
        with self.assertRaisesRegex(holder.ContractError, "exact_preimage_changed"):
            holder.replace_exact_file(target, b"new", 0o600, original)
        self.assertEqual(target.read_bytes(), b"foreign")

    def test_leaf_swap_during_withdrawal_keeps_foreign_bytes_in_custody(self):
        target = self.paths["runtime"]
        holder.atomic_create(target, b"original", 0o755)
        original = holder.bound_file(target)
        rename = holder.rename_exclusive
        def race(parent, source, destination):
            target.write_bytes(b"foreign")
            return rename(parent, source, destination)
        with patch.object(holder, "rename_exclusive", side_effect=race):
            with self.assertRaisesRegex(holder.ContractError, "displaced_foreign_file_preserved"):
                holder.withdraw_exact(target, original)
        custody = list(target.parent.glob("*.custody"))
        self.assertEqual(len(custody), 1)
        self.assertEqual(custody[0].read_bytes(), b"foreign")

    def test_replacement_does_not_overwrite_arrival_after_withdrawal(self):
        target = self.paths["runtime"]
        holder.atomic_create(target, b"original", 0o755)
        original = holder.bound_file(target)
        create = holder.atomic_create
        def race(path, data, mode, **kwargs):
            target.write_bytes(b"foreign")
            return create(path, data, mode, **kwargs)
        with patch.object(holder, "atomic_create", side_effect=race):
            with self.assertRaisesRegex(holder.ContractError, "replacement_recovery_required"):
                holder.replace_exact_file(target, b"new", 0o755, original)
        self.assertEqual(target.read_bytes(), b"foreign")
        self.assertEqual(next(target.parent.glob("*.custody")).read_bytes(), b"original")

    def test_lock_excludes_second_holder_invocation(self):
        with holder.lifecycle_lock():
            with self.assertRaisesRegex(holder.ContractError, "holder_operation_busy"):
                with holder.lifecycle_lock():
                    self.fail("second lock admitted")

    def test_incomplete_journal_blocks_ordinary_retry(self):
        value = holder.begin_operation("install", COMMIT)
        self.assertEqual(holder.filesystem_state()[0], "incomplete")
        with self.assertRaisesRegex(holder.ContractError, "incomplete_operation"):
            holder.begin_operation("install", COMMIT)
        self.assertEqual(holder.load_journal(), value)

    def test_death_during_journal_publication_is_not_absence(self):
        holder.begin_operation("install", COMMIT)
        self.paths["journal"].rename(self.paths["journal"].parent /
            f".{holder.PROFILE}-operation.previous.json")
        with self.assertRaisesRegex(holder.ContractError, "interrupted_journal_publication"):
            holder.filesystem_state()

    def test_lost_bootstrap_response_retains_all_owned_artifacts(self):
        with patch.object(holder, "mutation_gate"), patch.object(holder, "require_exact_commit"), \
             patch.object(holder, "preflight", return_value={"verdict": "PASS"}), \
             patch.object(holder, "bootstrap", side_effect=holder.ContractError("lost response")):
            with self.assertRaisesRegex(holder.ContractError, "recovery_required_state_preserved"):
                holder.apply(COMMIT)
        self.assertTrue(self.paths["runtime"].exists())
        self.assertTrue(self.paths["plist"].exists())
        self.assertEqual(holder.load_journal()["phase"], "starting")
        self.assertEqual(holder.filesystem_state()[0], "incomplete")

    def test_state_directory_swap_before_receipt_is_not_adopted(self):
        def swap(_):
            self.paths["state"].rename(self.root / "original-state")
            self.paths["state"].mkdir(mode=0o700)
        with patch.object(holder, "mutation_gate"), \
             patch.object(holder, "preflight", return_value={"verdict": "PASS"}), \
             patch.object(holder, "bootstrap", side_effect=swap), \
             patch.object(holder, "wait_for_proxy", return_value=True):
            with self.assertRaisesRegex(holder.ContractError, "recovery_required_state_preserved"):
                holder.apply(COMMIT)
        self.assertFalse(self.paths["receipt"].exists())
        self.assertEqual(list(self.paths["state"].iterdir()), [])
        with self.assertRaisesRegex(holder.ContractError, "state_directory_changed"):
            holder.verify_state_identity(holder.load_journal())

    def test_concurrent_state_directory_creator_is_not_overwritten_or_adopted(self):
        rename = holder.rename_exclusive
        def race(parent, source, target):
            if target == self.paths["state"].name:
                self.paths["state"].mkdir(mode=0o700)
                (self.paths["state"] / "foreign").write_bytes(b"preserve")
            return rename(parent, source, target)
        with patch.object(holder, "mutation_gate"), patch.object(holder, "preflight", return_value={"verdict": "PASS"}), \
             patch.object(holder, "rename_exclusive", side_effect=race):
            with self.assertRaisesRegex(holder.ContractError, "recovery_required_state_preserved"):
                holder.apply(COMMIT)
        self.assertEqual((self.paths["state"] / "foreign").read_bytes(), b"preserve")
        value = holder.load_journal()
        self.assertNotEqual(holder.state_identity(), value["stateIdentity"])
        self.assertTrue((self.paths["state"].parent / value["stateStage"]).is_dir())

    def test_state_directory_inode_is_journaled_before_publication(self):
        rename = holder.rename_exclusive
        def die(parent, source, target):
            if target == self.paths["state"].name:
                value = holder.load_journal()
                self.assertEqual(value["stateStage"], source)
                self.assertEqual(holder.directory_identity(self.paths["state"].parent / source),
                                 value["stateIdentity"])
                self.assertFalse(self.paths["state"].exists())
                raise FixtureDeath()
            return rename(parent, source, target)
        with patch.object(holder, "mutation_gate"), patch.object(holder, "preflight", return_value={"verdict": "PASS"}), \
             patch.object(holder, "rename_exclusive", side_effect=die):
            with self.assertRaises(FixtureDeath):
                holder.apply(COMMIT)
        self.assertEqual(holder.filesystem_state()[0], "incomplete")

    def test_bound_runtime_parent_changed_between_steps_is_preserved(self):
        create = holder.create_owned_state
        def swap(value):
            create(value)
            self.paths["runtime"].parent.rename(self.root / "old-bin")
            self.paths["runtime"].parent.mkdir(mode=0o700)
        with patch.object(holder, "mutation_gate"), patch.object(holder, "preflight", return_value={"verdict": "PASS"}), \
             patch.object(holder, "create_owned_state", side_effect=swap):
            with self.assertRaisesRegex(holder.ContractError, "recovery_required_state_preserved"):
                holder.apply(COMMIT)
        self.assertEqual(list(self.paths["runtime"].parent.iterdir()), [])

    def test_preflight_source_drift_blocks_before_intent_or_publication(self):
        with patch.object(holder, "mutation_gate"), \
             patch.object(holder, "preflight", return_value={"verdict": "PASS"}), \
             patch.object(holder, "require_exact_commit", side_effect=[None, holder.ContractError("source_drift")]):
            with self.assertRaisesRegex(holder.ContractError, "source_drift"):
                holder.apply(COMMIT)
        self.assertFalse(self.paths["journal"].exists())
        self.assertFalse(self.paths["runtime"].exists())

    def test_preflight_target_drift_blocks_before_intent_or_publication(self):
        def drift():
            self.paths["runtime"].write_bytes(b"foreign arrival")
            return {"verdict": "PASS"}
        with patch.object(holder, "mutation_gate"), patch.object(holder, "preflight", side_effect=drift):
            with self.assertRaisesRegex(holder.ContractError, "preflight_target_drift"):
                holder.apply(COMMIT)
        self.assertFalse(self.paths["journal"].exists())
        self.assertEqual(self.paths["runtime"].read_bytes(), b"foreign arrival")

    def test_abrupt_death_after_each_artifact_never_admits_fresh_retry(self):
        create = holder.atomic_create
        for key in ("runtime", "plist", "receipt"):
            with self.subTest(boundary=key):
                # Each scenario owns a distinct temporary tree; no prior state
                # is cleared or adopted to make a retry pass.
                with tempfile.TemporaryDirectory(prefix="holder-death-") as directory:
                    root = Path(directory).resolve()
                    paths = {name: root / str(value.relative_to(self.root))
                             for name, value in self.paths.items()}
                    for name in ("bin", "agents", "state"):
                        (root / name).mkdir(mode=0o700)
                    holder.JOURNAL_EXPECTED = None
                    def die(path, data, mode, **kwargs):
                        create(path, data, mode, **kwargs)
                        if path == paths[key]:
                            raise FixtureDeath()
                    with patch.object(holder, "layout", return_value=paths), \
                         patch.object(holder, "mutation_gate"), patch.object(holder, "require_exact_commit"), \
                         patch.object(holder, "preflight", return_value={"verdict": "PASS"}), \
                         patch.object(holder, "bootstrap"), patch.object(holder, "wait_for_proxy", return_value=True), \
                         patch.object(holder, "atomic_create", side_effect=die):
                        with self.assertRaises(FixtureDeath):
                            holder.apply(COMMIT)
                        self.assertTrue(paths[key].exists())
                        self.assertEqual(holder.filesystem_state()[0], "incomplete")
                        with self.assertRaisesRegex(holder.ContractError, "incomplete_operation"):
                            holder.begin_operation("install", COMMIT)

    def test_abrupt_death_between_owned_withdrawals_is_recoverable_only_with_absence(self):
        self.install_fixture()
        withdraw = holder.withdraw_exact
        def die(path, expected, **kwargs):
            custody = withdraw(path, expected, **kwargs)
            if path == self.paths["runtime"]:
                raise FixtureDeath()
            return custody
        with patch.object(holder, "mutation_gate"), \
             patch.object(holder, "observe_launchd", side_effect=["PRESENT", "ABSENT"]), \
             patch.object(holder, "bootout", return_value=True), \
             patch.object(holder, "wait_for_proxy", return_value=True), \
             patch.object(holder, "withdraw_exact", side_effect=die):
            with self.assertRaises(FixtureDeath):
                holder.rollback(COMMIT)
        self.assertFalse(self.paths["runtime"].exists())
        self.assertTrue(self.paths["receipt"].exists())
        self.assertEqual(holder.load_journal()["phase"], "retiring")
        with patch.object(holder, "mutation_gate"), patch.object(holder, "observe_launchd", return_value="ABSENT"), \
             patch.object(holder, "remote_proxy_observation", return_value={"state": "ABSENT"}):
            self.assertEqual(holder.recover(COMMIT)["verdict"], "PASS")
            self.assertTrue(holder.recover(COMMIT)["recovery_noop"])
        self.assertFalse(self.paths["receipt"].exists())

    def test_unknown_remote_stop_never_deletes_runtime_plist_receipt(self):
        self.install_fixture()
        before = {name: self.paths[name].read_bytes() for name in ("runtime", "plist", "receipt")}
        with patch.object(holder, "mutation_gate"), \
             patch.object(holder, "observe_launchd", side_effect=["PRESENT", "ABSENT"]), \
             patch.object(holder, "bootout", return_value=False), \
             patch.object(holder, "wait_for_proxy", return_value=False):
            with self.assertRaisesRegex(holder.ContractError, "stop_unknown_state_preserved"):
                holder.rollback(COMMIT)
        self.assertEqual(before, {name: self.paths[name].read_bytes() for name in before})
        self.assertEqual(holder.load_journal()["phase"], "stopping")

    def test_extra_state_entry_blocks_before_bootout(self):
        self.install_fixture()
        (self.paths["state"] / "foreign").write_bytes(b"preserve")
        with patch.object(holder, "mutation_gate"), patch.object(holder, "observe_launchd", return_value="PRESENT"), \
             patch.object(holder, "bootout") as stop:
            with self.assertRaisesRegex(holder.ContractError, "directory_not_empty"):
                holder.rollback(COMMIT)
            stop.assert_not_called()
        self.assertTrue(self.paths["receipt"].exists())

    def test_missing_native_absence_contract_blocks_before_any_stop_or_intent(self):
        self.install_fixture()
        with patch.object(holder, "mutation_gate"), patch.object(holder, "REMOTE_ABSENCE_SUPPORTED", False), \
             patch.object(holder, "bootout") as stop:
            with self.assertRaisesRegex(holder.ContractError, "absence_contract_unavailable"):
                holder.rollback(COMMIT)
            stop.assert_not_called()
        self.assertFalse(self.paths["journal"].exists())
        self.assertTrue(self.paths["receipt"].exists())

    def test_unknown_observation_cannot_make_absent_preflight_pass(self):
        with patch.object(holder, "filesystem_state", return_value=("absent", None)), \
             patch.object(holder, "observe_launchd", return_value="UNKNOWN"), \
             patch.object(holder, "remote_proxy_observation", return_value={"state": "UNKNOWN", "transport": False, "application": False}), \
             patch.object(holder, "session_flags_exact", return_value=True), \
             patch.object(holder, "helper_doctor_passes", return_value=True):
            self.assertEqual(holder.preflight()["verdict"], "BLOCKED")

    def test_recover_unknown_remote_preserves_intent_and_artifacts(self):
        holder.begin_operation("install", COMMIT)
        with patch.object(holder, "mutation_gate"), patch.object(holder, "observe_launchd", return_value="ABSENT"), \
             patch.object(holder, "remote_proxy_observation", return_value={"state": "UNKNOWN"}):
            with self.assertRaisesRegex(holder.ContractError, "absence_unknown_preserved"):
                holder.recover(COMMIT)
        self.assertEqual(holder.load_journal()["phase"], "planned")

    def test_exact_absence_fixture_recovers_owned_artifacts_without_deletion(self):
        value = holder.begin_operation("install", COMMIT)
        holder.ACTIVE_JOURNAL = value
        holder.atomic_create(self.paths["runtime"], b"owned", 0o755)
        holder.ACTIVE_JOURNAL = None
        with patch.object(holder, "mutation_gate"), patch.object(holder, "observe_launchd", return_value="ABSENT"), \
             patch.object(holder, "remote_proxy_observation", return_value={"state": "ABSENT"}):
            self.assertEqual(holder.recover(COMMIT)["verdict"], "PASS")
            self.assertTrue(holder.recover(COMMIT)["recovery_noop"])
        self.assertFalse(self.paths["runtime"].exists())
        self.assertEqual(next(self.paths["runtime"].parent.glob("*.custody")).read_bytes(), b"owned")


if __name__ == "__main__":
    unittest.main()
