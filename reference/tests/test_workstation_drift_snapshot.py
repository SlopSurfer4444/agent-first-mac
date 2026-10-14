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
    def test_summary_exact_types_privacy_and_review_invariant(self):
        summary = dict(M.change_summary(), externalObserved=2)
        M.valid_summary(summary)
        for update in ({"managed": True}, {"externalObserved": -1}, {"unknown": 1},
                {"requiredReview": True}, {"actorAttributed": True}, {"completeInventory": True},
                {"unknown": 40014, "requiredReview": True}, {"rawName": "private"}):
            with self.assertRaises(M.Fault):
                M.valid_summary(dict(summary, **update))

    def test_preclassification_schema2_drift_migrates_unknown_without_closing_signal(self):
        state = M.evolve(M.evolve(None, observation()), observation({"app": "one"}))
        for report in (state["latest"], state["unresolvedDrift"]):
            report.pop("changeSummary")
        upgraded = M.upgrade(state)
        self.assertTrue(upgraded["latest"]["unresolvedDrift"])
        self.assertEqual(upgraded["latest"]["changeSummary"], M.change_summary(unknown=1))
        self.assertEqual(upgraded["unresolvedDrift"]["changeSummary"], M.change_summary(unknown=1))

    def test_exact_disposition_closes_only_signal_preserves_history_and_next_change(self):
        baseline = M.evolve(None, observation({"app": "v1"}))
        drift = M.evolve(baseline, observation({"app": "v2"}))
        signal = drift["latest"]["currentIncident"]
        for sequence, digest in ((1, signal["snapshotDigest"]), (signal["sequence"], "f" * 64),
                (True, signal["snapshotDigest"])):
            with self.assertRaises(M.Fault):
                M.dispose(drift, sequence, digest, "expected_external")
        closed = M.dispose(drift, signal["sequence"], signal["snapshotDigest"], "expected_external")
        self.assertFalse(closed["latest"]["unresolvedDrift"])
        self.assertEqual(closed["history"]["records"][0], drift["history"]["records"][0])
        self.assertFalse(closed["latest"]["ownershipAccepted"] or closed["latest"]["sourceAdmission"])
        self.assertEqual(M.main(["capture"], operation=lambda _: closed["latest"], emit=lambda _: None), 0)
        unchanged = M.evolve(closed, closed["snapshot"])
        self.assertFalse(unchanged["latest"]["unresolvedDrift"])
        next_drift = M.evolve(unchanged, observation({"app": "v3"}))
        self.assertTrue(next_drift["latest"]["unresolvedDrift"])
        with self.assertRaises(M.Fault):
            M.dispose(next_drift, signal["sequence"], signal["snapshotDigest"], "expected_external")
        self.assertEqual(len(next_drift["history"]["records"]), 3)

    def test_confirmed_conflict_remains_active_until_exact_lifecycle_disposition(self):
        drift = M.evolve(M.evolve(None, observation()), observation({"app": "one"}))
        incident = drift["latest"]["currentIncident"]
        conflict = M.dispose(drift, incident["sequence"], incident["snapshotDigest"], "confirmed_conflict")
        self.assertTrue(conflict["latest"]["unresolvedDrift"])
        self.assertEqual(conflict["latest"]["currentIncident"]["classification"], "confirmed_conflict")
        bad = copy.deepcopy(conflict)
        bad["latest"]["currentConflict"] = None
        with self.assertRaises(M.Fault):
            M.valid_state(bad)
        unchanged = M.evolve(conflict, conflict["snapshot"])
        self.assertEqual(unchanged["latest"]["currentIncident"], conflict["latest"]["currentIncident"])
        self.assertFalse(M.dispose(unchanged, incident["sequence"], incident["snapshotDigest"],
            "resolved_by_lifecycle")["latest"]["unresolvedDrift"])

    def test_undisposed_latest_drift_cannot_claim_no_current_incident(self):
        drift = M.evolve(M.evolve(None, observation()), observation({"app": "one"}))
        drift["unresolvedDrift"] = None
        drift["latest"].update(unresolvedDrift=False, currentIncident=None)
        with self.assertRaises(M.Fault):
            M.valid_state(drift)

    def test_disposition_cli_validates_arguments_before_scan_and_reports_only_assessment(self):
        drift = M.evolve(M.evolve(None, observation()), observation({"app": "one"}))
        signal = drift["latest"]["currentIncident"]
        def operation(op, disposition):
            self.assertEqual(op, "dispose")
            return dict(M.dispose(drift, *disposition)["latest"], operation=op)
        output = []
        args = ["dispose", str(signal["sequence"]), signal["snapshotDigest"], "expected_external", "--json"]
        self.assertEqual(M.main(args, operation=operation, emit=output.append), 0)
        self.assertFalse(json.loads(output[0])["installedHealthChecked"])
        for bad in (["dispose", "0", signal["snapshotDigest"], "expected_external"],
                ["dispose", "2", "private", "expected_external"],
                ["dispose", "2", signal["snapshotDigest"], []]):
            call = Mock(side_effect=AssertionError("must not access state"))
            self.assertEqual(M.main(bad, operation=call, emit=lambda _: None), 2)
            call.assert_not_called()

    def test_latest_distinct_change_is_not_hidden_by_first_drift_and_history_is_bounded(self):
        state = M.evolve(None, observation())
        first = M.evolve(state, observation({"app": "0"}))
        state = first
        for number in range(M.MAX_HISTORY + 5):
            state = M.evolve(state, observation({"app": str(number + 1)}))
        self.assertEqual(state["latest"]["currentIncident"]["sequence"], state["latest"]["sequence"])
        self.assertNotEqual(state["latest"]["currentIncident"], first["latest"]["currentIncident"])
        self.assertEqual(len(state["history"]["records"]), M.MAX_HISTORY)
        self.assertEqual(state["history"]["retiredCount"], 6)
        self.assertEqual(state["latest"]["historyCount"], M.MAX_HISTORY + 6)
        self.assertNotEqual(state["history"]["retiredDigest"], M.digest(b"maintenance-history-v2"))
        M.valid_state(state)

    def test_legacy_retained_failure_migrates_as_history_not_current_unavailability(self):
        drift = M.evolve(M.evolve(None, observation()), observation({"app": "one"}))
        failure = M.evolve(drift, failure="scan_unavailable")
        value = M.evolve(failure, failure["snapshot"])
        value.pop("history")
        value["schema"] = 1
        value["unresolvedFailure"] = copy.deepcopy(failure["unresolvedFailure"])
        value["latest"]["unresolvedFailure"] = True
        for report in (value["latest"], value["unresolvedDrift"], value["unresolvedFailure"]):
            for key in ("observedAt", "lastCompleteAt", "currentIncident", "currentConflict", "pendingConflicts", "historyCount", "historyDigest", "changeSummary"):
                report.pop(key)
        legacy = copy.deepcopy(value)
        upgraded = M.upgrade(value)
        self.assertTrue(upgraded["latest"]["unresolvedDrift"])
        self.assertFalse(upgraded["latest"]["unresolvedFailure"])
        self.assertEqual(upgraded["latest"]["historyCount"], 2)
        bad = copy.deepcopy(legacy)
        bad["latest"]["unresolvedDrift"] = False
        with self.assertRaises(M.Fault):
            M.upgrade(bad)

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

    def test_scan_recovers_current_failure_but_keeps_history_and_current_drift(self):
        baseline = M.evolve(None, observation({"app": "v1"}))
        drift = M.evolve(baseline, observation({"app": "v2"}))
        failure = M.evolve(drift, failure="scan_unavailable")
        self.assertEqual(failure["snapshot"], drift["snapshot"])
        last = M.evolve(failure, drift["snapshot"])
        self.assertEqual(last["latest"]["status"], "UNCHANGED")
        self.assertTrue(last["latest"]["unresolvedDrift"])
        self.assertFalse(last["latest"]["unresolvedFailure"])
        self.assertEqual(last["unresolvedDrift"], drift["unresolvedDrift"])
        self.assertIsNone(last["unresolvedFailure"])
        self.assertEqual([r["kind"] for r in last["history"]["records"]], ["DRIFT", "SCAN_INCOMPLETE", "SCAN_RECOVERED"])
        self.assertEqual(set(last), {"schema", "snapshot", "latest", "unresolvedDrift", "unresolvedFailure", "history"})

    def test_failed_initial_scan_never_invents_snapshot_or_accepted_baseline(self):
        state = M.evolve(None, failure="scan_limit")
        self.assertIsNone(state["snapshot"])
        self.assertEqual(state["latest"]["status"], "SCAN_INCOMPLETE")
        state = M.evolve(state, observation())
        self.assertEqual(state["latest"]["status"], "BASELINE_OBSERVED")
        self.assertFalse(state["latest"]["unresolvedFailure"])
        self.assertEqual(state["latest"]["historyCount"], 2)

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
        state = failure
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

    def test_disposition_native_seam_is_atomic_bound_no_scan_and_status_readonly(self):
        self.execute(observation())
        report = self.execute(observation({"app": "changed"}))
        signal = report["currentIncident"]
        raw = (self.directory / "observations.json").read_bytes()
        rejected = M.execute("dispose", store_factory=self.store, collector=lambda: self.fail("must not scan"),
            disposition=(1, signal["snapshotDigest"], "expected_external"))
        self.assertEqual(rejected["status"], "STATE_UNAVAILABLE")
        self.assertEqual((self.directory / "observations.json").read_bytes(), raw)
        result = M.execute("dispose", store_factory=self.store, collector=lambda: self.fail("must not scan"),
            disposition=(signal["sequence"], signal["snapshotDigest"], "expected_external"))
        M.valid_report(result)
        self.assertFalse(result["unresolvedDrift"])
        readback = self.execute(operation="status")
        self.assertEqual(readback["historyCount"], 2)
        self.assertFalse(readback["unresolvedDrift"])

    def test_capture_classifier_uses_actual_previous_and_new_snapshots_and_persists_counts(self):
        before = observation({"fixture": "one"})
        after = observation({"fixture": "two", "another": "one"})
        self.execute(before)
        calls = []
        def classifier(previous, current):
            self.assertEqual(previous, before)
            self.assertEqual(current, after)
            calls.append(M.changes(previous, current))
            return dict(M.change_summary(), externalObserved=calls[-1]["added"] + calls[-1]["changed"])
        result = M.execute("capture", store_factory=self.store, collector=lambda: after, classifier=classifier)
        self.assertEqual(calls, [{"added": 1, "removed": 0, "changed": 1, "scopesChanged": 1}])
        self.assertEqual(result["changeSummary"]["externalObserved"], 2)
        self.assertFalse(result["unresolvedDrift"])
        self.assertIsNone(result["currentIncident"])
        self.assertEqual(result["status"], "DRIFT")
        saved = self.execute(operation="status")
        self.assertEqual(saved["changeSummary"], result["changeSummary"])
        self.assertEqual(saved["historyCount"], 1)
        self.assertFalse(saved["ownershipAccepted"] or saved["installedHealthChecked"])

    def test_external_change_never_closes_existing_actionable_signal_or_concrete_conflict(self):
        self.execute(observation())
        first = self.execute(observation({"fixture": "one"}))
        signal = first["currentIncident"]
        M.execute("dispose", store_factory=self.store, collector=lambda: self.fail("no scan"),
            disposition=(signal["sequence"], signal["snapshotDigest"], "confirmed_conflict"))
        result = M.execute("capture", store_factory=self.store, collector=lambda: observation({"fixture": "one", "external": "one"}),
            classifier=lambda old, new: dict(M.change_summary(), externalObserved=1))
        self.assertTrue(result["unresolvedDrift"])
        self.assertEqual(result["currentIncident"]["sequence"], signal["sequence"])
        self.assertEqual(result["currentConflict"]["sequence"], signal["sequence"])
        self.assertFalse(result["changeSummary"]["requiredReview"])

    def test_classifier_failure_or_invalid_output_is_unknown_not_incomplete_scan(self):
        self.execute(observation())
        for index, classify in enumerate((Mock(side_effect=PermissionError("private source catalog")),
                lambda old, new: dict(M.change_summary(), externalObserved=1, actorAttributed=True),
                lambda old, new: M.change_summary())):
            result = M.execute("capture", store_factory=self.store,
                collector=lambda: observation({"fixture": str(index)}),
                classifier=classify)
            self.assertEqual(result["status"], "DRIFT")
            self.assertTrue(result["completeObservation"])
            self.assertFalse(result["unresolvedFailure"])
            self.assertEqual(result["changeSummary"], M.change_summary(unknown=1))
            self.assertNotIn("private", M.encoded(result).decode())

    def test_connected_managed_and_conflict_summaries_keep_metadata_limits_explicit(self):
        self.execute(observation())
        managed = M.execute("capture", store_factory=self.store, collector=lambda: observation({"target": "one"}),
            classifier=lambda old, new: dict(M.change_summary(), managed=1, requiredReview=True))
        self.assertTrue(managed["unresolvedDrift"])
        self.assertIsNone(managed["currentConflict"])
        conflict = M.execute("capture", store_factory=self.store, collector=lambda: observation(),
            classifier=lambda old, new: dict(M.change_summary(), conflict=1, requiredReview=True))
        self.assertEqual(conflict["currentConflict"]["classification"], "confirmed_conflict")
        self.assertFalse(conflict["changeSummary"]["actorAttributed"] or conflict["installedHealthChecked"])

    def test_reviewed_catalog_classifier_connected_to_capture_for_ten_owner_cases(self):
        classifier = M.source_classifier(ROOT)
        def sample(scope, entries):
            value = observation()
            value["scopes"][scope] = {"present": True, "root": M.digest(b"fixed fixture root"),
                "entries": {M.digest(name.encode()): M.digest(payload.encode()) for name, payload in entries.items()}}
            return M.snapshot(value["scopes"])
        cases = (
            ("applications", {}, {"Independent.app": "one"}, "externalObserved"),
            ("applications", {"Independent.app": "one"}, {}, "externalObserved"),
            ("applications", {"Independent.app": "one"}, {"Independent.app": "two"}, "externalObserved"),
            ("applications", {}, {"IINA.app": "one"}, "managed"),
            ("nix-applications", {"IINA.app": "one"}, {"IINA.app": "two"}, "managed"),
            ("nix-applications", {"IINA.app": "one"}, {}, "conflict"),
            ("usr-local-bin", {}, {"new-command": "one"}, "unknown"),
            ("user-launch-agents", {}, {"new-service": "one"}, "unknown"),
            ("user-applications", {}, {"Independent.app": "one"}, "externalObserved"),
            ("nix-applications", {}, {"Undeclared.app": "one"}, "unknown"),
        )
        for scope, before, after, kind in cases:
            with self.subTest(scope=scope, kind=kind):
                # Separate exact synthetic private homes avoid sharing an active
                # incident between logically independent owner scenarios.
                with tempfile.TemporaryDirectory(prefix="aid-catalog-case-") as scratch:
                    home = Path(scratch).resolve()
                    (home / "AIDev").mkdir(mode=0o700)
                    factory = lambda create: M.Store(str(home), self.uid, create)
                    M.execute("capture", store_factory=factory, collector=lambda: sample(scope, before), classifier=classifier)
                    result = M.execute("capture", store_factory=factory, collector=lambda: sample(scope, after), classifier=classifier)
                    self.assertEqual(result["status"], "DRIFT")
                    expected = dict(M.change_summary(), **{kind: 1}, requiredReview=kind != "externalObserved")
                    self.assertEqual(result["changeSummary"], expected)
                    self.assertEqual(result["unresolvedDrift"], kind != "externalObserved")
                    self.assertEqual(result["currentConflict"] is not None, kind == "conflict")
                    self.assertFalse(result["ownershipAccepted"] or result["installedHealthChecked"])
                    self.assertNotIn("Independent.app", M.encoded(result).decode())

    def test_two_and_three_managed_conflicts_cannot_be_closed_as_expected_external(self):
        classifier = M.source_classifier(ROOT)
        def sample(names):
            value = observation()
            value["scopes"]["nix-applications"] = {"present": True, "root": M.digest(b"fixed fixture root"),
                "entries": {M.digest(name.encode()): M.digest(b"payload") for name in names}}
            return M.snapshot(value["scopes"])
        names = ["IINA.app", "Keka.app", "LocalSend.app"]
        M.execute("capture", store_factory=self.store, collector=lambda: sample(names), classifier=classifier)
        signals = []
        for removed in range(1, 4):
            result = M.execute("capture", store_factory=self.store,
                collector=lambda: sample(names[removed:]), classifier=classifier)
            signals.append(copy.deepcopy(result["currentIncident"]))
            self.assertEqual(result["currentIncident"]["classification"], "confirmed_conflict")
            self.assertEqual(result["currentConflict"], signals[0])
            self.assertEqual(result["pendingConflicts"], signals[1:])
            for signal in signals:
                raw = (self.directory / "observations.json").read_bytes()
                rejected = M.execute("dispose", store_factory=self.store, collector=lambda: self.fail("no scan"),
                    disposition=(signal["sequence"], signal["snapshotDigest"], "expected_external"))
                self.assertEqual(rejected["status"], "STATE_UNAVAILABLE")
                self.assertEqual((self.directory / "observations.json").read_bytes(), raw)
        unchanged = M.execute("capture", store_factory=self.store, collector=lambda: sample([]), classifier=classifier)
        self.assertEqual(unchanged["currentConflict"], signals[0])
        self.assertEqual(unchanged["pendingConflicts"], signals[1:])
        self.assertFalse(unchanged["installedHealthChecked"])
        # Resolve the middle binding first. The latest C incident and primary A
        # must remain active; resolving A promotes C, never fabricates all-green.
        for index, remaining in ((1, [signals[0], signals[2]]), (0, [signals[2]]), (2, [])):
            signal = signals[index]
            result = M.execute("dispose", store_factory=self.store, collector=lambda: self.fail("no scan"),
                disposition=(signal["sequence"], signal["snapshotDigest"], "resolved_by_lifecycle"))
            self.assertEqual(([result["currentConflict"]] if result["currentConflict"] else []) + result["pendingConflicts"], remaining)
            if remaining:
                self.assertEqual(result["currentIncident"], signals[2])
                self.assertTrue(result["unresolvedDrift"])
            self.assertFalse(result["installedHealthChecked"])
        self.assertFalse(result["unresolvedDrift"])
        self.assertEqual(self.execute(operation="status")["pendingConflicts"], [])

    def test_conflict_capacity_overflow_preserves_all_exact_state_bytes_and_signals(self):
        self.execute(observation())
        for index in range(M.MAX_CONFLICTS):
            result = M.execute("capture", store_factory=self.store,
                collector=lambda: observation({"managed": str(index)}),
                classifier=lambda old, new: dict(M.change_summary(), conflict=1, requiredReview=True))
            self.assertEqual(result["status"], "DRIFT")
        self.assertEqual(len(result["pendingConflicts"]), M.MAX_CONFLICTS - 1)
        raw = (self.directory / "observations.json").read_bytes()
        overflow = M.execute("capture", store_factory=self.store,
            collector=lambda: observation({"managed": "overflow"}),
            classifier=lambda old, new: dict(M.change_summary(), conflict=1, requiredReview=True))
        self.assertEqual(overflow["status"], "STATE_UNAVAILABLE")
        self.assertFalse(overflow["observationPublished"] or overflow["completeObservation"])
        self.assertEqual(overflow["sequence"], result["sequence"])
        self.assertEqual(overflow["pendingConflicts"], result["pendingConflicts"])
        self.assertEqual((self.directory / "observations.json").read_bytes(), raw)
        self.assertNotIn("managed", M.encoded(result["pendingConflicts"]).decode())
        self.assertLess(len(M.encoded(overflow)), 16384)
        M.valid_report(overflow)

    def test_pending_conflict_schema_rejects_orphans_duplicates_overflow_and_unproven_latest(self):
        first = M.evolve(M.evolve(None, observation()), observation({"app": "one"}),
            summary=dict(M.change_summary(), conflict=1, requiredReview=True))
        second = M.evolve(first, observation({"app": "two"}),
            summary=dict(M.change_summary(), conflict=1, requiredReview=True))
        for mutate in (lambda report: report.update(currentConflict=None),
                lambda report: report["pendingConflicts"].append(copy.deepcopy(report["pendingConflicts"][0])),
                lambda report: report["pendingConflicts"][0].update(sequence=True),
                lambda report: report["pendingConflicts"][0].update(extra="private"),
                lambda report: report.update(pendingConflicts=report["pendingConflicts"] * M.MAX_CONFLICTS),
                lambda report: (report.update(pendingConflicts=[]), report["currentIncident"].update(classification="unknown_observation"))):
            value = copy.deepcopy(second)
            mutate(value["latest"])
            with self.assertRaises(M.Fault):
                M.valid_state(value)

    def test_pre_pending_schema2_migration_preserves_known_current_and_later_bound_conflict(self):
        first = M.evolve(M.evolve(None, observation()), observation({"app": "one"}),
            summary=dict(M.change_summary(), conflict=1, requiredReview=True))
        second = M.evolve(first, observation({"app": "two"}),
            summary=dict(M.change_summary(), conflict=1, requiredReview=True))
        latest = M.evolve(second, second["snapshot"])
        # Reproduce the earlier source-only candidate: A was primary, B was
        # recorded as an unknown latest incident despite its conflict summary.
        for report in (latest["latest"], latest["unresolvedDrift"]):
            report.pop("pendingConflicts")
            report["currentIncident"]["classification"] = "unknown_observation"
        upgraded = M.upgrade(latest)
        self.assertEqual(upgraded["latest"]["currentConflict"], first["latest"]["currentConflict"])
        self.assertEqual(upgraded["latest"]["pendingConflicts"], second["latest"]["pendingConflicts"])
        self.assertEqual(upgraded["latest"]["currentIncident"]["classification"], "confirmed_conflict")

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

    def test_incomplete_scan_preserves_snapshot_then_success_closes_only_current_failure(self):
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
        self.assertFalse(next_result["unresolvedFailure"])
        self.assertEqual(next_result["historyCount"], 2)

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
