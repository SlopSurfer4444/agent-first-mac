"""Connected synthetic cycles only; no native inventory or models."""
import importlib.machinery
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
import sys
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
M = importlib.machinery.SourceFileLoader("tested_workstation_maintenance_cycle",
    str(ROOT / "bin/workstation-maintenance-cycle")).load_module()
D = M.D
sys.path.insert(0, str(ROOT / "lib"))
from productivity_ownership import metadata_change_classifier
import productivity_ownership as O


def observation(content="one"):
    scopes = {key: {"present": False, "root": D.digest(b"absent"), "entries": {}} for key in D.SCOPES}
    scopes["applications"] = {"present": True, "root": D.digest(b"fixture-root"),
        "entries": {D.digest(b"fixture-entry"): D.digest(content.encode())}}
    return D.snapshot(scopes)


class CycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aid-maintenance-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        (self.home / "AIDev").mkdir(mode=0o700)
        self.clock = 1000000
        self.collector = lambda: observation()

    def store(self, create=True):
        return D.Store(str(self.home), os.getuid(), create)

    def observe(self, operation):
        return D.execute(operation, store_factory=self.store, collector=self.collector, now=lambda: self.clock)

    def cycle(self, operation="cycle"):
        return M.run(operation, observe=self.observe, now=lambda: self.clock)

    def test_connected_unchanged_cycle_executes_zero_model_or_subprocess_calls(self):
        self.assertEqual(self.cycle()["status"], "OBSERVED")
        with patch("subprocess.Popen", side_effect=AssertionError("must not launch")), \
                patch("socket.socket", side_effect=AssertionError("must not connect")):
            result = self.cycle()
        self.assertEqual(result["status"], "UNCHANGED")
        self.assertIsNone(result["event"])
        self.assertEqual(result["modelInvocations"], 0)
        self.assertFalse(result["scheduledOriginClaimed"] or result["scheduleInstalledByHelper"])
        self.assertEqual(result["coverage"]["cadenceSeconds"], 86400)
        self.assertFalse(result["coverage"]["hashesAnonymous"] or result["coverage"]["signaturesChecked"])

    def test_capture_crossing_second_evaluates_freshness_after_observation(self):
        order = []
        def observe(operation):
            order.append("observe")
            self.clock += 2
            return self.observe(operation)
        def now():
            order.append("evaluate")
            return self.clock
        result = M.run("cycle", observe=observe, now=now)
        self.assertEqual(order, ["observe", "evaluate"])
        self.assertEqual(result["ageSeconds"], 0)
        self.assertTrue(result["freshObservation"])
        self.assertEqual(result["status"], "OBSERVED")

    def test_relevant_change_bounded_event_then_unchanged_not_repeated(self):
        self.cycle()
        self.collector = lambda: observation("two")
        changed = self.cycle()
        self.assertEqual(changed["status"], "OBSERVED_CHANGE")
        self.assertEqual(changed["event"]["kind"], "metadata_change")
        self.assertEqual(changed["modelInvocations"], 0)
        self.assertLess(len(D.encoded(changed)), M.MAX_REPORT)
        self.assertIsNone(self.cycle()["event"])
        self.assertFalse(changed["installedHealthChecked"])

    def test_missed_cadence_reports_stale_without_inventing_sleep_or_scheduled_origin(self):
        self.cycle()
        raw = (self.home / "AIDev/state/maintenance/observations.json").read_bytes()
        self.clock += M.CADENCE_SECONDS + 1
        self.collector = lambda: self.fail("status must not collect")
        result = self.cycle("status")
        self.assertEqual(result["status"], "STALE")
        self.assertTrue(result["missedCadence"])
        self.assertFalse(result["freshObservation"])
        self.assertEqual(result["sleepingOrUnavailableCause"], "not_observed")
        self.assertEqual((self.home / "AIDev/state/maintenance/observations.json").read_bytes(), raw)

    def test_failed_scan_then_recovered_current_health_retains_failure_history(self):
        self.cycle()
        def unavailable():
            raise PermissionError("private fixture path must not escape")
        self.collector = unavailable
        first = self.cycle()
        second = self.cycle()
        self.assertEqual(first["status"], "UNAVAILABLE")
        self.assertEqual(first["event"]["id"], second["event"]["id"])
        self.assertNotIn("private", D.encoded(first).decode())
        self.collector = lambda: observation()
        recovered = self.cycle()
        self.assertEqual(recovered["status"], "UNCHANGED")
        self.assertFalse(recovered["observation"]["unresolvedFailure"])
        self.assertEqual(recovered["observation"]["historyCount"], 3)

    def test_busy_lock_skips_before_collector_and_preserves_state(self):
        self.cycle()
        holder = self.store()
        try:
            self.collector = lambda: self.fail("busy must not collect")
            result = self.cycle()
        finally:
            holder.close()
        self.assertEqual(result["status"], "SKIPPED_BUSY")
        self.assertFalse(result["freshObservation"])

    def test_conflict_survives_unrelated_change_and_expected_external_disposition(self):
        self.cycle()
        self.collector = lambda: observation("two")
        first = self.cycle()["observation"]["currentIncident"]
        def dispose(signal, disposition):
            return D.execute("dispose", store_factory=self.store, collector=lambda: self.fail("must not scan"),
                disposition=(signal["sequence"], signal["snapshotDigest"], disposition))
        dispose(first, "confirmed_conflict")
        self.assertEqual(self.cycle()["status"], "CONFLICT")
        self.collector = lambda: observation("three")
        changed = self.cycle()
        self.assertEqual(changed["status"], "CONFLICT")
        self.assertIsNotNone(changed["event"])
        dispose(changed["observation"]["currentIncident"], "expected_external")
        self.assertEqual(self.cycle()["status"], "CONFLICT")
        rejected = dispose(first, "expected_external")
        self.assertEqual(rejected["status"], "STATE_UNAVAILABLE")
        closed = dispose(first, "resolved_by_lifecycle")
        self.assertIsNone(closed["currentConflict"])
        self.assertFalse(closed["installedHealthChecked"])
        self.assertEqual(self.cycle()["status"], "UNCHANGED")

    def test_missing_malformed_and_throwing_observations_are_unavailable(self):
        self.assertEqual(self.cycle("status")["status"], "UNAVAILABLE")
        for observe in (lambda _: {}, Mock(side_effect=PermissionError("private"))):
            value = M.run("cycle", observe=observe, now=lambda: self.clock)
            self.assertEqual(value["status"], "UNAVAILABLE")
            self.assertEqual(value["modelInvocations"], 0)
            self.assertNotIn("private", D.encoded(value).decode())

    def test_cli_fixture_seam_json_and_invalid_arguments(self):
        self.cycle()
        output = []
        self.assertEqual(M.main(["cycle", "--json"], observe=self.observe, now=lambda: self.clock, emit=output.append), 0)
        self.assertEqual(json.loads(output[0])["status"], "UNCHANGED")
        for args in ([], ["cycle", "--scheduled"], ["cycle", "--root", "/tmp"], ["repair"], [True]):
            observe = Mock(side_effect=AssertionError("invalid CLI must not observe"))
            self.assertEqual(M.main(args, observe=observe, emit=lambda _: None), 2)
            observe.assert_not_called()

    def test_capture_callbacks_hold_same_store_lock_and_order_without_mutating_publication(self):
        order = []
        def locked(store):
            store.verify()
            other = self.observe("status")
            self.assertEqual(other["status"], "SKIPPED_BUSY")
        def preflight(store):
            order.append("preflight")
            self.assertIsNone(store.original)
            locked(store)
        def collector():
            order.append("collector")
            return observation()
        def consumer(report, store):
            order.append("consumer")
            self.assertEqual(report, store.publication)
            self.assertTrue(report["observationPublished"])
            locked(store)
            report["status"] = "mutated consumer copy"
        result = D.execute("capture", store_factory=self.store, collector=collector,
            now=lambda: self.clock, preflight=preflight, consumer=consumer)
        self.assertEqual(order, ["preflight", "collector", "consumer"])
        self.assertEqual(result["status"], "BASELINE_OBSERVED")
        self.assertEqual(self.observe("status")["status"], "BASELINE_OBSERVED")

    def test_callback_failures_are_unavailable_at_exact_publication_boundary(self):
        self.cycle()
        path = self.home / "AIDev/state/maintenance/observations.json"
        raw = path.read_bytes()
        collector = Mock(side_effect=AssertionError("preflight failure must not collect"))
        preflight = Mock(side_effect=RuntimeError("private scheduler conflict"))
        rejected = D.execute("capture", store_factory=self.store, collector=collector,
            now=lambda: self.clock, preflight=preflight)
        self.assertEqual(rejected["status"], "STATE_UNAVAILABLE")
        self.assertFalse(rejected["observationPublished"] or rejected["completeObservation"])
        collector.assert_not_called()
        self.assertEqual(path.read_bytes(), raw)
        consumer = Mock(side_effect=RuntimeError("private delivery failure"))
        failed = D.execute("capture", store_factory=self.store, collector=lambda: observation("new"),
            now=lambda: self.clock, consumer=consumer)
        self.assertEqual(failed["status"], "STATE_UNAVAILABLE")
        self.assertTrue(failed["observationPublished"])
        self.assertFalse(failed["completeObservation"])
        self.assertNotEqual(path.read_bytes(), raw)
        self.assertNotIn("private", D.encoded(failed).decode())
        self.assertEqual(self.observe("status")["status"], "DRIFT")

    def test_status_skips_optional_capture_callbacks(self):
        self.cycle()
        callback = Mock(side_effect=AssertionError("status must not schedule or deliver"))
        report = D.execute("status", store_factory=self.store, collector=lambda: self.fail("no scan"),
            preflight=callback, consumer=callback)
        self.assertEqual(report["status"], "BASELINE_OBSERVED")
        callback.assert_not_called()

    def test_native_classifier_override_uses_connected_fixture_capture_and_default_is_preserved(self):
        uid = os.getuid()
        script = str(self.home / "AIDev/control/bin/workstation-drift-snapshot")
        source = Mock(return_value=lambda old, new: D.change_summary())
        override = Mock(return_value=D.change_summary())
        with patch.object(D, "__file__", script), \
                patch.object(D.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(self.home))), \
                patch.object(D, "collect", return_value=observation()), \
                patch.object(D, "source_classifier", source):
            result = D.native("capture", classifier=override)
            self.assertEqual(result["status"], "BASELINE_OBSERVED")
            self.assertEqual(result["changeSummary"], D.change_summary())
            override.assert_called_once_with(None, observation())
            source.assert_not_called()
            result = D.native("capture")
            self.assertEqual(result["status"], "UNCHANGED")
            source.assert_called_once_with(self.home / "AIDev/control")
        # Actual owner-derived uid remains used by the fixture Store; no native
        # path, live collector, installed declaration or scheduler was accessed.
        self.assertGreater(uid, 0)
        self.assertEqual(self.observe("status")["status"], "UNCHANGED")

    def test_chmod_after_lock_rejects_capture_before_collection_publication_or_consumer(self):
        self.cycle()
        path = self.home / "AIDev/state/maintenance/observations.json"
        raw = path.read_bytes()
        for directory in (self.home, self.home / "AIDev", self.home / "AIDev/state", self.home / "AIDev/state/maintenance"):
            with self.subTest(directory=directory.name):
                mode = directory.stat().st_mode & 0o777
                collector = Mock(side_effect=AssertionError("unsafe parent must prevent collection"))
                consumer = Mock(side_effect=AssertionError("unsafe parent must prevent delivery"))
                def preflight(store):
                    store.verify()
                    directory.chmod(0o777 if directory in {self.home, self.home / "AIDev"} else 0o755)
                try:
                    result = D.execute("capture", store_factory=self.store, collector=collector,
                        now=lambda: self.clock, preflight=preflight, consumer=consumer)
                    self.assertEqual(result["status"], "STATE_UNAVAILABLE")
                    self.assertFalse(result["observationPublished"] or result["completeObservation"])
                    collector.assert_not_called()
                    consumer.assert_not_called()
                    self.assertEqual(path.read_bytes(), raw)
                finally:
                    directory.chmod(mode)

    def test_chmod_immediately_after_publication_prevents_consumer_and_retains_known_publication(self):
        self.cycle()
        directory = self.home / "AIDev/state/maintenance"
        original_save = D.Store.save
        def save_then_chmod(store, state):
            original_save(store, state)
            directory.chmod(0o755)
        consumer = Mock(side_effect=AssertionError("unsafe publication parent must prevent delivery"))
        try:
            with patch.object(D.Store, "save", save_then_chmod):
                result = D.execute("capture", store_factory=self.store, collector=lambda: observation("new"),
                    now=lambda: self.clock, consumer=consumer)
            self.assertEqual(result["status"], "STATE_UNAVAILABLE")
            self.assertTrue(result["observationPublished"])
            self.assertFalse(result["completeObservation"])
            consumer.assert_not_called()
        finally:
            directory.chmod(0o700)
        self.assertEqual(self.observe("status")["status"], "DRIFT")

    def test_schedule_cli_exact_operations_use_injected_adapter_and_no_capture(self):
        for name in sorted(M.SCHEDULE_OPERATIONS):
            with self.subTest(operation=name):
                callback = Mock(return_value={"schema": 1, "status": "SYNTHETIC_SCHEDULE_RESULT",
                    "operation": name, "exitCode": 0, "scheduledOriginClaimed": False})
                observer = Mock(side_effect=AssertionError("schedule action must not collect"))
                output = []
                code = M.main([name, "--json"], observe=observer,
                    schedule_operation=callback, emit=output.append)
                self.assertEqual(code, 0)
                callback.assert_called_once_with(name)
                observer.assert_not_called()
                self.assertFalse(json.loads(output[0])["scheduledOriginClaimed"])

    def test_scheduled_cli_injected_cycle_uses_connected_capture_without_inventing_provenance(self):
        def scheduled(*, now):
            report = D.execute("capture", store_factory=self.store, collector=self.collector,
                now=now, preflight=lambda store: store.verify(), consumer=lambda report, store: store.verify())
            result = M.run("cycle", observe=lambda _: report, now=now)
            return dict(result, exitCode=0)
        output = []
        code = M.main(["scheduled", "--json"], now=lambda: self.clock,
            scheduled_operation=scheduled, emit=output.append)
        self.assertEqual(code, 0)
        result = json.loads(output[0])
        self.assertEqual(result["status"], "OBSERVED")
        self.assertFalse(result["scheduledOriginClaimed"])
        self.assertTrue(result["observation"]["observationPublished"])

    def test_delivery_wrappers_lazily_route_fixed_apis_and_build_report(self):
        report = self.observe("capture")
        def scheduled(drift, *, build_report, now):
            self.assertIs(drift, D)
            self.assertEqual(now(), self.clock)
            return dict(build_report(report), exitCode=0)
        lifecycle = Mock(return_value={"schema": 1, "status": "SYNTHETIC", "exitCode": 0})
        api = SimpleNamespace(native_schedule=lifecycle, scheduled_native=scheduled)
        with patch.object(M, "delivery_api", return_value=api) as load:
            self.assertEqual(M.native_schedule("schedule-plan")["status"], "SYNTHETIC")
            result = M.scheduled_native(now=lambda: self.clock)
        self.assertEqual(load.call_count, 2)
        lifecycle.assert_called_once_with("plan")
        self.assertEqual(result["status"], "OBSERVED")
        self.assertFalse(result["scheduledOriginClaimed"])

    def test_schedule_cli_rejects_overrides_and_sanitizes_failed_or_invalid_adapter(self):
        callback = Mock(side_effect=AssertionError("invalid CLI must not invoke adapter"))
        for args in (["schedule-install", "--label", "other"], ["schedule-remove", "/private/tmp/path"],
                ["scheduled", "--notify"], ["schedule-plan", "--json", "--json"], ["schedule-list"]):
            self.assertEqual(M.main(args, schedule_operation=callback, scheduled_operation=callback, emit=lambda _: None), 2)
        callback.assert_not_called()
        for result in ({"schema": True, "status": "WRONG", "exitCode": 0},
                {"schema": 1, "status": "WRONG", "exitCode": True},
                {"schema": 1, "status": "WRONG", "exitCode": 2},
                {"schema": 1, "status": "WRONG", "exitCode": 0, "raw": "x" * M.MAX_REPORT}):
            output = []
            self.assertEqual(M.main(["schedule-plan", "--json"], schedule_operation=lambda _: result, emit=output.append), 1)
            self.assertEqual(json.loads(output[0])["status"], "UNAVAILABLE")
        output = []
        self.assertEqual(M.main(["scheduled", "--json"], scheduled_operation=Mock(side_effect=RuntimeError("private")), emit=output.append), 1)
        self.assertNotIn("private", output[0])
        self.assertFalse(json.loads(output[0])["scheduledOriginClaimed"])


class RoutedOwnerScenarioTests(unittest.TestCase):
    """Actual fixture metadata -> native capture seam -> maintenance consumer.

    Files are inert. Installer actor/signature/contents are deliberately unknown;
    an app-shaped directory models resulting metadata, not a real App Store run.
    """
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aid-owner-cycle-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        (self.home / "AIDev").mkdir(mode=0o700)
        self.apps = self.home / "observed-apps"
        self.managed = self.home / "observed-nix-apps"
        self.apps.mkdir(); self.managed.mkdir()
        self.clock = 1000000
        self.classifier = metadata_change_classifier(ROOT)

    def app(self, name, *, managed=False, content=b"inert-fixture-v1"):
        bundle = (self.managed if managed else self.apps) / name
        (bundle / "Contents").mkdir(parents=True, exist_ok=True)
        (bundle / "Contents/Info.plist").write_bytes(content)
        return bundle

    def remove(self, bundle):
        (bundle / "Contents/Info.plist").unlink()
        (bundle / "Contents").rmdir()
        bundle.rmdir()

    def collect(self):
        scopes = {key: {"present": False, "root": D.digest(b"absent"), "entries": {}} for key in D.SCOPES}
        scopes["applications"] = D.collect_scope(str(self.apps))
        scopes["nix-applications"] = D.collect_scope(str(self.managed))
        return D.snapshot(scopes)

    def observe(self, operation):
        return D.execute(operation,
            store_factory=lambda create: D.Store(str(self.home), os.getuid(), create),
            collector=self.collect, now=lambda: self.clock,
            classifier=self.classifier)

    def cycle(self):
        result = M.run("cycle", observe=self.observe, now=lambda: self.clock)
        self.assertFalse(result["requiresOwnershipAdmission"])
        self.assertFalse(result["changeClassification"]["actorAttributed"])
        self.assertFalse(result["observation"]["ownershipAccepted"])
        self.assertFalse(result["coverage"]["signaturesChecked"])
        self.assertNotIn(str(self.home), D.encoded(result).decode())
        return result

    def external(self, result):
        self.assertEqual(result["status"], "EXTERNAL_OBSERVED")
        self.assertGreater(result["changeClassification"]["externalObserved"], 0)
        self.assertFalse(result["actionable"])
        self.assertIsNone(result["event"])
        output = []
        self.assertEqual(M.main(["status", "--json"], observe=self.observe,
                         now=lambda: self.clock, emit=output.append), 0)

    def test_app_store_result_is_external_without_inferred_installer(self):
        self.cycle(); self.app("FixtureStore.app")
        self.external(self.cycle())

    def test_vendor_auto_update_metadata_is_external_not_old_version_pin(self):
        bundle = self.app("FixtureVendor.app")
        self.cycle()
        (bundle / "Contents/Info.plist").write_bytes(b"inert-longer-version-metadata-v2")
        self.external(self.cycle())

    def test_dmg_drag_drop_result_is_external_no_adoption_or_reinstall(self):
        self.cycle(); self.app("FixtureDMG.app")
        self.external(self.cycle())

    def test_owner_external_uninstall_preserves_unobserved_support_data(self):
        bundle = self.app("FixtureRemove.app")
        private = self.home / "unobserved-owner-support"
        private.write_bytes(b"preserved-private-fixture")
        self.cycle(); self.remove(bundle)
        self.external(self.cycle())
        self.assertEqual(private.read_bytes(), b"preserved-private-fixture")

    def test_install_outside_coverage_is_not_reported_or_claimed_complete(self):
        self.cycle()
        outside = self.home / "unobserved-root"
        outside.mkdir(); (outside / "Outside.app").mkdir()
        result = self.cycle()
        self.assertEqual(result["status"], "UNCHANGED")
        self.assertFalse(result["observation"]["fullInventory"])

    def test_first_scan_after_install_is_basis_not_intent_or_trust(self):
        self.app("AlreadyInstalled.app")
        result = self.cycle()
        self.assertEqual(result["status"], "OBSERVED")
        self.assertEqual(result["changeClassification"]["externalObserved"], 0)
        self.assertFalse(result["sourceAdmission"])

    def test_install_remove_between_scans_does_not_invent_hidden_payload_or_actor(self):
        self.cycle(); transient = self.app("Transient.app"); self.remove(transient)
        result = self.cycle()
        self.assertEqual(result["changeClassification"]["externalObserved"], 0)
        self.assertNotIn("Transient", D.encoded(result).decode())
        self.assertFalse(result["observation"]["fullInventory"])
        # Root-only metadata change can be UNKNOWN, never attributed as install.
        self.assertIn(result["status"], {"OBSERVED_CHANGE", "UNCHANGED"})

    def test_manual_managed_replacement_stays_scoped_not_external(self):
        bundle = self.app("IINA.app", managed=True)
        self.cycle()
        (bundle / "Contents/Info.plist").write_bytes(b"replacement-identity-is-unattested")
        result = self.cycle()
        self.assertTrue(result["actionable"])
        self.assertGreater(result["changeClassification"]["managed"], 0)
        self.assertTrue(result["event"]["requiresScopedReview"])
        self.remove(bundle)
        result = self.cycle()
        self.assertEqual(result["status"], "CONFLICT")

    def test_unsigned_authority_host_change_cannot_gain_authority_from_discovery(self):
        bundle = self.app("ChatGPT.app")
        self.cycle()
        (bundle / "Contents/Info.plist").write_bytes(b"identity-changing-unsigned-fixture-not-executed")
        result = self.cycle()
        self.assertTrue(result["actionable"])
        self.assertGreater(result["changeClassification"]["managed"], 0)
        self.assertTrue(result["event"]["requiresScopedReview"])
        # Metadata does not itself diagnose unsigned or grant execution.
        self.assertFalse(result["coverage"]["signaturesChecked"])
        self.assertFalse(result["observation"]["ownershipAccepted"])

    def test_owner_confirmed_expected_change_closes_exact_signal_not_next_change(self):
        self.app("IINA.app", managed=True)
        self.cycle()
        self.app("IINA.app", managed=True, content=b"observed-v2-owner-confirmed")
        first = self.cycle()["observation"]["currentIncident"]
        resolved = D.execute("dispose",
            store_factory=lambda create: D.Store(str(self.home), os.getuid(), create),
            collector=lambda: self.fail("assessment does not scan"),
            disposition=(first["sequence"], first["snapshotDigest"], "expected_external"))
        self.assertIsNone(resolved["currentIncident"])
        self.assertFalse(self.cycle()["actionable"])
        self.app("IINA.app", managed=True, content=b"unassessed-v3-longer-next-observation")
        self.assertTrue(self.cycle()["actionable"])

    def test_retired_payload_path_does_not_silently_reacquire_management(self):
        self.cycle(); self.app("GameToMac.app"); self.app("AmneziaVPN.app")
        self.external(self.cycle())

    def test_catalog_unavailable_is_unknown_not_adoption_or_scan_success_claim(self):
        self.classifier = metadata_change_classifier(self.home / "missing-source")
        first = self.cycle()
        self.assertEqual(first["status"], "UNKNOWN")
        self.assertTrue(first["actionable"])
        self.app("OtherwiseExternal.app")
        result = self.cycle()
        self.assertTrue(result["actionable"])
        self.assertGreater(result["changeClassification"]["unknown"], 0)
        self.assertTrue(result["observation"]["completeObservation"])

    def test_missing_and_malformed_catalog_stay_unknown_across_identical_captures(self):
        for mode in ("missing", "malformed"):
            with self.subTest(mode=mode):
                source = self.home / ("catalog-" + mode)
                if mode == "malformed":
                    (source / "manifests").mkdir(parents=True)
                    (source / "manifests/productivity-baseline.json").write_bytes(b"not JSON private fixture")
                self.classifier = metadata_change_classifier(source)
                first, second = self.cycle(), self.cycle()
                for result in (first, second):
                    self.assertEqual(result["status"], "UNKNOWN")
                    self.assertTrue(result["actionable"])
                    self.assertTrue(result["changeClassification"]["requiredReview"])
                    self.assertEqual(result["changeClassification"]["unknown"], 1)
                    self.assertEqual(result["event"]["kind"], "ownership_observation_unavailable")
                self.assertEqual(first["event"]["id"], second["event"]["id"])
                self.assertNotIn("private", D.encoded(second).decode())
        self.classifier = metadata_change_classifier(ROOT)
        recovered = self.cycle()
        self.assertEqual(recovered["status"], "UNCHANGED")
        self.assertFalse(recovered["actionable"])

    def test_invalid_declared_active_target_schema_or_flag_never_becomes_external(self):
        original = Path.read_bytes
        mutations = (("path", 17), ("path", "relative-RustDesk.app"),
                     ("path", "/Other/RustDesk.app"), ("schema", 99),
                     ("profileActive", 1), ("profileActive", None))
        for field, invalid in mutations:
            with self.subTest(field=field, invalid=invalid):
                def source_read(path):
                    raw = original(path)
                    if path.name == "rustdesk-mac-controller.json":
                        source = json.loads(raw)
                        if field == "path": source["application"]["path"] = invalid
                        else: source[field] = invalid
                        return json.dumps(source).encode()
                    return raw
                with patch.object(Path, "read_bytes", source_read):
                    self.classifier = metadata_change_classifier(ROOT)
                self.app("RustDesk.app", content=b"inert-version-" + str(invalid).encode())
                result = self.cycle()
                self.assertEqual(result["changeClassification"]["externalObserved"], 0)
                self.assertGreater(result["changeClassification"]["unknown"], 0)
                self.assertTrue(result["actionable"])
        # Valid explicit out-of-coverage identities are allowed source, not
        # catalog errors: the real phase3 manifest includes $HOME and /System.
        self.assertGreater(len(O.declared_metadata_catalog(ROOT)["applications"]), 0)

    def test_malformed_phase3_path_is_not_mistaken_for_legitimate_outside_coverage(self):
        original = Path.read_bytes
        def source_read(path):
            raw = original(path)
            if path.name == "phase3-capabilities.json":
                source = json.loads(raw)
                for identity in source["logical_identities"]:
                    if identity["path"] == "/Applications/Google Chrome.app":
                        identity["path"] = "relative-Chrome.app"
                return json.dumps(source).encode()
            return raw
        with patch.object(Path, "read_bytes", source_read):
            self.classifier = metadata_change_classifier(ROOT)
        self.cycle(); self.app("Google Chrome.app")
        result = self.cycle()
        self.assertEqual(result["changeClassification"]["externalObserved"], 0)
        self.assertTrue(result["actionable"])
        self.assertGreater(result["changeClassification"]["unknown"], 0)

    def test_three_missing_managed_targets_retain_each_concrete_conflict(self):
        bundles = [self.app(name, managed=True) for name in ("IINA.app", "Keka.app", "Shottr.app")]
        self.cycle()
        signals = []
        for bundle in bundles:
            self.remove(bundle)
            result = self.cycle()
            self.assertEqual(result["status"], "CONFLICT")
            signals.append(result["observation"]["currentIncident"])
        self.assertEqual(len(result["observation"]["pendingConflicts"]), 2)
        def assess(signal, disposition):
            return D.execute("dispose",
                store_factory=lambda create: D.Store(str(self.home), os.getuid(), create),
                collector=lambda: self.fail("assessment does not scan"),
                disposition=(signal["sequence"], signal["snapshotDigest"], disposition))
        rejected = assess(signals[1], "expected_external")
        self.assertEqual(rejected["status"], "STATE_UNAVAILABLE")
        self.assertFalse(rejected["observationPublished"])
        self.assertEqual(self.cycle()["status"], "CONFLICT")
        # Resolving A promotes B rather than proving the unchanged missing B/C
        # healthy. Resolving B still leaves C and does not drop its incident.
        assess(signals[0], "resolved_by_lifecycle")
        result = self.cycle()
        self.assertEqual(result["observation"]["currentConflict"], signals[1])
        self.assertEqual(result["status"], "CONFLICT")
        assess(signals[1], "resolved_by_lifecycle")
        self.assertEqual(self.cycle()["status"], "CONFLICT")
        assess(signals[2], "resolved_by_lifecycle")
        result = self.cycle()
        self.assertFalse(result["actionable"])
        self.assertIsNone(result["observation"]["currentConflict"])
        self.assertEqual(result["observation"]["pendingConflicts"], [])
        self.assertFalse(result["installedHealthChecked"])


if __name__ == "__main__":
    unittest.main()
