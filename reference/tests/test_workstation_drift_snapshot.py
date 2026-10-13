"""Injected observations and owned disposable directories; no native scans."""
import copy
import importlib.machinery
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
M = importlib.machinery.SourceFileLoader("tested_workstation_drift_snapshot",
    str(ROOT / "bin/workstation-drift-snapshot")).load_module()


def observation(entries=None):
    scopes = {key: {"present": False, "root": M.digest(b"absent"), "entries": {}} for key in M.SCOPES}
    scopes["applications"] = {"present": True, "root": M.digest(b"fixed fixture directory"),
        "entries": {M.digest(k.encode()): M.digest(v.encode()) for k, v in (entries or {}).items()}}
    return M.snapshot(scopes)


class PureStateTests(unittest.TestCase):
    def test_baseline_unchanged_and_add_remove_change_have_no_acceptance_claim(self):
        first = M.evolve(None, observation({"private-app": "one", "removed-app": "two"}))
        self.assertEqual(first["latest"]["status"], "BASELINE_OBSERVED")
        unchanged = M.evolve(first, first["snapshot"])
        self.assertEqual(unchanged["latest"]["status"], "UNCHANGED")
        next_state = M.evolve(unchanged, observation({"private-app": "changed", "new-app": "new"}))
        latest = next_state["latest"]
        self.assertEqual(latest["status"], "DRIFT")
        self.assertEqual(latest["changes"], {"added": 1, "removed": 1, "changed": 1, "scopesChanged": 1})
        for key in ("fullInventory", "sourceAdmission", "ownershipAccepted", "installedHealthChecked", "configurationMutationsPerformed"):
            self.assertIs(latest[key], False)
        self.assertNotIn("private-app", M.encoded(next_state).decode())

    def test_unresolved_drift_and_failure_survive_later_unchanged(self):
        baseline = M.evolve(None, observation({"app": "v1"}))
        drift = M.evolve(baseline, observation({"app": "v2"}))
        failure = M.evolve(drift, failure="scan_unavailable")
        self.assertEqual(failure["snapshot"], drift["snapshot"])
        last = M.evolve(failure, drift["snapshot"])
        self.assertEqual(last["latest"]["status"], "UNCHANGED")
        self.assertTrue(last["latest"]["unresolvedDrift"] and last["latest"]["unresolvedFailure"])
        self.assertEqual(last["unresolvedDrift"], drift["unresolvedDrift"])
        self.assertEqual(last["unresolvedFailure"], failure["unresolvedFailure"])
        self.assertEqual(set(last), {"schema", "snapshot", "latest", "unresolvedDrift", "unresolvedFailure"})

    def test_failed_initial_scan_never_invents_snapshot_or_accepted_baseline(self):
        state = M.evolve(None, failure="scan_limit")
        self.assertIsNone(state["snapshot"])
        self.assertEqual(state["latest"]["status"], "SCAN_INCOMPLETE")
        state = M.evolve(state, observation())
        self.assertEqual(state["latest"]["status"], "BASELINE_OBSERVED")
        self.assertTrue(state["latest"]["unresolvedFailure"])

    def test_strict_state_schema_digest_bounds_and_types(self):
        valid = M.evolve(None, observation())
        mutations = [lambda v: v.update(schema=True), lambda v: v.update(extra="private"),
            lambda v: v["snapshot"].update(digest="a" * 64),
            lambda v: v["snapshot"]["scopes"].pop("applications"),
            lambda v: v["latest"].update(status=[]), lambda v: v["latest"].update(reason=[]),
            lambda v: v["latest"].update(sequence=True), lambda v: v["latest"].update(sourceAdmission=True),
            lambda v: v["latest"].update(observationPublished=False),
            lambda v: v["latest"].update(unresolvedDrift=True),
            lambda v: v["latest"].update(snapshotDigest="b" * 64),
            lambda v: v.update(unresolvedFailure=copy.deepcopy(v["latest"]))]
        for mutate in mutations:
            value = copy.deepcopy(valid)
            mutate(value)
            with self.assertRaises(M.Fault):
                M.valid_state(value)
        for content in (b"{}", b"[]", b"null", b"{", b"\xff", b"{" * 1100,
                M.encoded(valid)[:-1] + b',"schema":1}', b"x" * (M.MAX_STATE + 1)):
            with self.assertRaises(M.Fault):
                M.valid_state(M.parse_json(content))

    def test_status_reason_delta_and_required_retained_record_coherence(self):
        baseline = M.evolve(None, observation())
        unchanged = M.evolve(baseline, observation())
        for mutate in (lambda v: v["latest"].update(reason="metadata_difference"),
                lambda v: v["latest"]["changes"].update(added=1, scopesChanged=1)):
            value = copy.deepcopy(unchanged)
            mutate(value)
            with self.assertRaises(M.Fault):
                M.valid_state(value)
        for state, key in ((M.evolve(baseline, observation({"added": "one"})), "unresolvedDrift"),
                (M.evolve(baseline, failure="scan_unavailable"), "unresolvedFailure")):
            state[key] = None
            state["latest"][key] = False
            with self.assertRaises(M.Fault):
                M.valid_state(state)

    def test_retained_records_require_positive_sequence_capture_origin_and_publication(self):
        baseline = M.evolve(None, observation())
        drift = M.evolve(baseline, observation({"added": "one"}))
        failure = M.evolve(drift, failure="scan_unavailable")
        state = M.evolve(failure, failure["snapshot"])
        for key in ("unresolvedDrift", "unresolvedFailure"):
            for change in ({"sequence": 0}, {"operation": "status", "observationPublished": False},
                    {"observationPublished": False}):
                value = copy.deepcopy(state)
                value[key].update(change)
                with self.assertRaises(M.Fault):
                    M.valid_state(value)

    def test_complete_state_missing_snapshot_or_inconsistent_counts_rejected(self):
        baseline = M.evolve(None, observation())
        for mutate in (lambda v: v.update(snapshot=None),
                lambda v: (v.update(snapshot=None), v["latest"].update(snapshotDigest=None, scopeCounts={})),
                lambda v: v["latest"]["scopeCounts"].update(applications=1)):
            value = copy.deepcopy(baseline)
            mutate(value)
            with self.assertRaises(M.Fault):
                M.valid_state(value)

    def test_invalid_cli_arguments_do_not_call_operation(self):
        for args in ([], ["--json"], ["capture", "--root", "/tmp"], ["capture", "--json", "--json"],
                ["accept"], ["clear"], ["delete"], ["status", "--fixture"], [True], "capture"):
            call = Mock(side_effect=AssertionError("unexpected IO"))
            self.assertEqual(M.main(args, operation=call, emit=lambda _: None), 2)
            call.assert_not_called()

    def test_cli_busy_and_unresolved_are_not_success_and_output_is_bounded(self):
        baseline = M.evolve(None, observation())
        for value, expected in ((baseline["latest"], 0), (M.report("SKIPPED_BUSY", "busy"), 3),
                (M.report("STATE_MALFORMED", "state_malformed"), 1)):
            output = []
            self.assertEqual(M.main(["capture", "--json"], operation=lambda _: value, emit=output.append), expected)
            self.assertLess(len(output[0]), 4096)
        drift = M.evolve(baseline, observation({"private": "changed"}))
        unchanged = M.evolve(drift, drift["snapshot"])
        self.assertEqual(M.main(["capture"], operation=lambda _: unchanged["latest"], emit=lambda _: None), 1)

    def test_noncanonical_native_rejected_before_store_or_collect(self):
        with patch.object(M, "Store", side_effect=AssertionError("unexpected state access")), \
             patch.object(M, "collect", side_effect=AssertionError("unexpected scan")):
            with self.assertRaisesRegex(M.Fault, "noncanonical_source"):
                M.native("capture")


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aid-drift-state-test-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        (self.home / "AIDev").mkdir(mode=0o700)
        self.uid = os.getuid()
        self.directory = self.home / "AIDev/state/maintenance"

    def store(self, create=True):
        return M.Store(str(self.home), self.uid, create)

    def execute(self, value=None, operation="capture", collector=None):
        return M.execute(operation, store_factory=self.store,
            collector=collector or (lambda: observation() if value is None else value))

    def test_status_missing_then_capture_atomic_private_state_and_status(self):
        self.assertEqual(self.execute(operation="status")["status"], "STATE_MISSING")
        self.assertFalse(self.directory.exists())
        result = self.execute(observation({"private": "value"}))
        self.assertEqual(result["status"], "BASELINE_OBSERVED")
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        for path in self.directory.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual({p.name for p in self.directory.iterdir()}, {"observations.json", "persistent.lock"})
        state = M.valid_state(M.parse_json((self.directory / "observations.json").read_bytes()))
        self.assertNotIn("private", M.encoded(state).decode())
        readback = self.execute(operation="status", collector=lambda: self.fail("status must not scan"))
        self.assertEqual(readback["snapshotDigest"], result["snapshotDigest"])
        self.assertEqual(readback["operation"], "status")
        self.assertFalse(readback["observationPublished"])

    def test_actual_lock_contention_skips_without_scan_or_overwriting_state(self):
        self.execute()
        before = (self.directory / "observations.json").read_bytes()
        owner = self.store()
        try:
            result = self.execute(collector=lambda: self.fail("busy must not scan"))
            self.assertEqual(result["status"], "SKIPPED_BUSY")
            self.assertFalse(result["observationPublished"])
        finally:
            owner.close()
        self.assertEqual((self.directory / "observations.json").read_bytes(), before)

    def test_status_does_not_recreate_missing_lock_or_modify_existing_snapshot(self):
        self.execute()
        before = (self.directory / "observations.json").read_bytes()
        (self.directory / "persistent.lock").unlink()
        original_open = M.os.open
        with patch.object(M.os, "open", wraps=original_open) as opened:
            result = self.execute(operation="status", collector=lambda: self.fail("status must not scan"))
        self.assertEqual(result["status"], "STATE_MISSING")
        self.assertFalse(result["observationPublished"])
        self.assertFalse((self.directory / "persistent.lock").exists())
        self.assertEqual((self.directory / "observations.json").read_bytes(), before)
        lock_calls = [call for call in opened.call_args_list if call.args[0] == "persistent.lock"]
        self.assertEqual(len(lock_calls), 1)
        self.assertFalse(lock_calls[0].args[1] & os.O_CREAT)

    def test_incomplete_scan_preserves_snapshot_and_failure_survives_unchanged(self):
        previous = self.execute(observation({"fixture": "one"}))
        def fail():
            raise PermissionError("private scope/name must not escape")
        result = self.execute(collector=fail)
        self.assertEqual(result["status"], "SCAN_INCOMPLETE")
        self.assertEqual(result["snapshotDigest"], previous["snapshotDigest"])
        state = M.valid_state(M.parse_json((self.directory / "observations.json").read_bytes()))
        self.assertNotIn("private", M.encoded(state).decode())
        next_result = self.execute(observation({"fixture": "one"}))
        self.assertEqual(next_result["status"], "UNCHANGED")
        self.assertTrue(next_result["unresolvedFailure"])

    def test_malformed_existing_state_is_not_replaced_or_scanned(self):
        self.execute()
        path = self.directory / "observations.json"
        for content in (b"{}", b"not JSON private", b'{"schema":1,"schema":1}'):
            path.write_bytes(content)
            result = self.execute(collector=lambda: self.fail("malformed state must not scan"))
            self.assertEqual(result["status"], "STATE_MALFORMED")
            self.assertEqual(path.read_bytes(), content)

    def test_status_rejects_contradictory_unchanged_state_with_nonzero_exit(self):
        self.execute()
        state = M.valid_state(M.parse_json((self.directory / "observations.json").read_bytes()))
        state = M.evolve(state, state["snapshot"])
        state["latest"].update(reason="metadata_difference")
        state["latest"]["changes"].update(added=1, scopesChanged=1)
        content = M.encoded(state)
        (self.directory / "observations.json").write_bytes(content)
        output = []
        code = M.main(["status", "--json"], operation=lambda _: self.execute(operation="status"), emit=output.append)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output[0])["status"], "STATE_MALFORMED")
        self.assertEqual((self.directory / "observations.json").read_bytes(), content)

    def test_symlink_state_and_lock_and_unsafe_parent_fail_closed(self):
        self.execute()
        target = self.home / "outside-private"
        target.write_bytes(b"must not change")
        path = self.directory / "observations.json"
        path.unlink()
        path.symlink_to(target)
        self.assertEqual(self.execute(collector=lambda: self.fail("symlink state"))["status"], "STATE_UNAVAILABLE")
        self.assertEqual(target.read_bytes(), b"must not change")
        path.unlink()
        lock = self.directory / "persistent.lock"
        lock.unlink()
        lock.symlink_to(target)
        self.assertEqual(self.execute(collector=lambda: self.fail("symlink lock"))["status"], "STATE_UNAVAILABLE")
        lock.unlink()
        self.directory.chmod(0o755)
        self.assertEqual(self.execute(collector=lambda: self.fail("unsafe parent"))["status"], "STATE_UNAVAILABLE")

    def test_symlink_state_parent_never_created_through(self):
        elsewhere = self.home / "elsewhere"
        elsewhere.mkdir(mode=0o700)
        (self.home / "AIDev/state").symlink_to(elsewhere, target_is_directory=True)
        self.assertEqual(self.execute(collector=lambda: self.fail("symlink state parent"))["status"], "STATE_UNAVAILABLE")
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_hardlinked_or_writable_state_unavailable(self):
        self.execute()
        path = self.directory / "observations.json"
        alias = self.home / "state-alias"
        os.link(path, alias)
        self.assertEqual(self.execute()["status"], "STATE_UNAVAILABLE")
        alias.unlink()
        path.chmod(0o644)
        self.assertEqual(self.execute()["status"], "STATE_UNAVAILABLE")

    def test_failed_atomic_write_keeps_previous_bytes_and_cleans_only_owned_pending(self):
        self.execute()
        before = (self.directory / "observations.json").read_bytes()
        with patch.object(M.os, "fsync", side_effect=OSError("private failure")):
            result = self.execute(observation({"changed": "new"}))
        self.assertEqual(result["status"], "STATE_UNAVAILABLE")
        self.assertFalse(result["observationPublished"])
        self.assertEqual((self.directory / "observations.json").read_bytes(), before)
        self.assertFalse((self.directory / "observations.pending").exists())

    def test_post_replace_directory_fsync_failure_preserves_known_publication_and_drift(self):
        self.execute()
        original_fsync = M.os.fsync
        def fail_directory(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("private directory durability failure")
            original_fsync(fd)
        with patch.object(M.os, "fsync", side_effect=fail_directory):
            result = self.execute(observation({"changed": "new"}))
        self.assertEqual(result["status"], "STATE_UNAVAILABLE")
        self.assertEqual(result["sequence"], 2)
        self.assertTrue(result["observationPublished"] and result["unresolvedDrift"])
        self.assertFalse(result["completeObservation"])
        self.assertEqual(result["changes"]["added"], 1)
        M.valid_report(result)
        state = M.valid_state(M.parse_json((self.directory / "observations.json").read_bytes()))
        self.assertEqual(state["latest"]["status"], "DRIFT")
        self.assertEqual(result["snapshotDigest"], state["snapshot"]["digest"])
        self.assertNotIn("private", M.encoded(result).decode())

    def test_close_failure_after_publication_is_unavailable_but_not_unpublished(self):
        self.execute()
        original_close = M.Store.close
        def fail_after_close(store):
            original_close(store)
            raise OSError("private close failure")
        with patch.object(M.Store, "close", new=fail_after_close):
            result = self.execute(observation({"changed": "new"}))
        self.assertEqual(result["status"], "STATE_UNAVAILABLE")
        self.assertTrue(result["observationPublished"] and result["unresolvedDrift"])
        self.assertEqual(result["sequence"], 2)
        self.assertFalse(result["completeObservation"])
        M.valid_report(result)
        state = M.valid_state(M.parse_json((self.directory / "observations.json").read_bytes()))
        self.assertEqual(state["latest"]["status"], "DRIFT")
        self.assertEqual(result["snapshotDigest"], state["snapshot"]["digest"])

    def test_prepublication_failure_preserves_previous_retained_drift_without_new_publication(self):
        self.execute()
        prior = self.execute(observation({"changed": "v2"}))
        with patch.object(M.os, "fsync", side_effect=OSError("private file sync failure")):
            result = self.execute(observation({"changed": "v3"}))
        self.assertEqual(result["status"], "STATE_UNAVAILABLE")
        self.assertFalse(result["observationPublished"])
        self.assertTrue(result["unresolvedDrift"])
        self.assertEqual((result["sequence"], result["snapshotDigest"]), (prior["sequence"], prior["snapshotDigest"]))

    def test_existing_pending_and_unrelated_sibling_evidence_are_preserved(self):
        self.execute()
        sibling = self.directory / "last-cycle-failure.json"
        sibling.write_bytes(b"consumer evidence")
        pending = self.directory / "observations.pending"
        pending.write_bytes(b"unknown interrupted transaction")
        result = self.execute()
        self.assertEqual(result["status"], "STATE_UNAVAILABLE")
        self.assertEqual(pending.read_bytes(), b"unknown interrupted transaction")
        self.assertEqual(sibling.read_bytes(), b"consumer evidence")

    def test_external_state_drift_under_lock_refuses_overwrite(self):
        self.execute()
        store = self.store()
        try:
            previous = store.load()
            path = self.directory / "observations.json"
            path.write_bytes(b"external writer")
            with self.assertRaises(M.Fault):
                store.save(M.evolve(previous, observation({"new": "value"})))
            self.assertEqual(path.read_bytes(), b"external writer")
        finally:
            store.close()


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aid-drift-metadata-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def scan(self, **kwargs):
        return M.collect_scope(str(self.root), **kwargs)

    def test_shallow_metadata_changes_mode_size_and_symlink_target_without_names(self):
        file = self.root / "private-name"
        file.write_bytes(b"one")
        link = self.root / "private-link"
        link.symlink_to("private-target-one")
        first = self.scan()
        key = M.digest(b"private-name")
        file.write_bytes(b"two changed")
        second = self.scan()
        self.assertNotEqual(first["entries"][key], second["entries"][key])
        file.chmod(0o700)
        third = self.scan()
        self.assertNotEqual(second["entries"][key], third["entries"][key])
        link.unlink()
        link.symlink_to("private-target-two")
        fourth = self.scan()
        self.assertNotEqual(third["entries"][M.digest(b"private-link")], fourth["entries"][M.digest(b"private-link")])
        self.assertNotIn("private", M.encoded(fourth).decode())
        self.assertNotIn(str(self.root), M.encoded(fourth).decode())

    def test_package_version_depth_two_only_and_no_unknown_symlink_traversal(self):
        package = self.root / "private-package"
        version = package / "1.0"
        version.mkdir(parents=True)
        (version / "not-observed-deeper").write_bytes(b"private")
        elsewhere = self.root / "symlink-target"
        elsewhere.mkdir()
        (elsewhere / "version").mkdir()
        (self.root / "package-link").symlink_to(elsewhere)
        value = self.scan(package_versions=True)
        self.assertIn(M.digest(b"private-package/1.0"), value["entries"])
        self.assertNotIn(M.digest(b"private-package/1.0/not-observed-deeper"), value["entries"])
        self.assertNotIn(M.digest(b"package-link/version"), value["entries"])
        self.assertNotIn(M.digest(b"private-package/1.0"), self.scan()["entries"])

    def test_fixed_app_info_metadata_catches_inplace_update_without_reading_content(self):
        app = self.root / "Private.app"
        contents = app / "Contents"
        contents.mkdir(parents=True)
        info = contents / "Info.plist"
        info.write_bytes(b"private metadata payload v1")
        root_before = app.stat().st_mtime_ns
        with patch.object(M.os, "read", side_effect=AssertionError("must not read app content")):
            first = self.scan()
        info.write_bytes(b"private metadata payload v2 with longer version")
        self.assertEqual(app.stat().st_mtime_ns, root_before)
        with patch.object(M.os, "read", side_effect=AssertionError("must not read app content")):
            second = self.scan()
        self.assertNotEqual(first["entries"][M.digest(b"Private.app")], second["entries"][M.digest(b"Private.app")])
        self.assertNotIn("payload", M.encoded(second).decode())

    def test_app_missing_edges_observed_but_symlink_contents_incomplete(self):
        app = self.root / "Private.app"
        app.mkdir()
        absent = self.scan()
        (app / "Contents").mkdir()
        missing_info = self.scan()
        self.assertNotEqual(absent["entries"], missing_info["entries"])
        (app / "Contents").rmdir()
        (app / "Contents").symlink_to(self.root)
        with self.assertRaises(OSError):
            self.scan()

    def test_missing_scope_is_distinct_from_unavailable_or_unknown_symlink(self):
        self.assertFalse(M.collect_scope(str(self.root / "missing"))["present"])
        link = self.root / "alias"
        link.symlink_to(self.root)
        with self.assertRaises(M.Fault):
            M.collect_scope(str(link))
        with self.assertRaises(M.Fault):
            M.collect_scope(str(link), store_alias=True)
        with patch.object(M.os, "lstat", side_effect=PermissionError):
            with self.assertRaises(PermissionError):
                self.scan()

    def test_scope_and_total_limits_fail_incomplete_instead_of_truncating(self):
        for name in ("one", "two"):
            (self.root / name).write_bytes(b"value")
        with patch.object(M, "MAX_SCOPE", 1):
            with self.assertRaisesRegex(M.Fault, "scan_limit"):
                self.scan()
        row = self.scan()
        with patch.object(M, "collect_scope", return_value=row), patch.object(M, "MAX_ENTRIES", 2):
            with self.assertRaisesRegex(M.Fault, "scan_limit"):
                M.collect("/fixture-home")

    def test_scope_set_and_depth_are_fixed_not_manifest_selected(self):
        row = {"present": False, "root": M.digest(b"absent"), "entries": {}}
        with patch.object(M, "collect_scope", return_value=row) as observe:
            value = M.collect("/fixture-home")
        self.assertEqual(set(value["scopes"]), set(M.SCOPES))
        self.assertEqual(observe.call_count, 13)
        calls = {call.args[0]: call.kwargs for call in observe.call_args_list}
        self.assertTrue(calls["/opt/homebrew/Cellar"]["package_versions"])
        self.assertTrue(calls["/opt/homebrew/Caskroom"]["package_versions"])
        self.assertFalse(calls["/Library/LaunchAgents"]["package_versions"])
        self.assertTrue(calls["/Applications/Nix Apps"]["store_alias"])


if __name__ == "__main__":
    unittest.main()
