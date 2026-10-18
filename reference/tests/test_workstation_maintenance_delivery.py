"""One scheduler lifecycle on inert temporary state; never native launchd."""
import importlib.machinery
import json
import os
from pathlib import Path
import plistlib
import subprocess
import signal
import resource
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "lib"))
import workstation_maintenance_delivery as M
D = importlib.machinery.SourceFileLoader("schedule_fixture_drift", str(ROOT / "bin/workstation-drift-snapshot")).load_module()
C = importlib.machinery.SourceFileLoader("schedule_fixture_cycle", str(ROOT / "bin/workstation-maintenance-cycle")).load_module()


class Crash(BaseException):
    pass


class NativeFixture:
    def __init__(self):
        self.present = False
        self.unknown = False
        self.calls = []
        self.lost = None

    def __call__(self, operation, home):
        self.calls.append(operation)
        if operation == "observe":
            return "UNKNOWN" if self.unknown else "PRESENT" if self.present else "ABSENT"
        if operation == "bootstrap": self.present = True
        elif operation == "bootout": self.present = False
        else: raise AssertionError("arbitrary native command")
        return "UNKNOWN" if self.lost == operation else "SETTLED"


class ScheduledResourceTests(unittest.TestCase):
    def test_isolated_cycle_loader_exposes_existing_source_package(self):
        code = '''import runpy,sys
from pathlib import Path
root=Path(sys.argv[1])
entry=runpy.run_path(str(root/'bin/workstation-maintenance-cycle'))
entry['delivery_api']()
from lib import scoped_source_admission
assert str(root) in sys.path
'''
        result = subprocess.run(["/usr/bin/python3", "-I", "-B", "-c", code, str(ROOT)],
            cwd="/private/tmp", capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_scheduled_source_error_is_bounded_and_actionable_without_observation(self):
        from lib import scoped_source_admission as source
        def blocked(callback):
            raise source.SourceError("affected_source_uncommitted")
        with patch.object(M, "prepare_scheduled_limits", return_value=True):
            result = M.scheduled_native(None, build_report=lambda _: self.fail("source failure must not observe"),
                now=lambda: 0, source_gate=blocked)
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(result["reason"], "affected_source_uncommitted")
        self.assertTrue(result["nextAction"])
        self.assertFalse(result["runSourceAccepted"])

    def child(self, soft, hard):
        before = resource.getrlimit(resource.RLIMIT_NOFILE)
        code = '''import json,resource,sys
sys.path.insert(0,sys.argv[1]+"/lib")
import workstation_maintenance_delivery as M
soft,hard=int(sys.argv[2]),int(sys.argv[3])
resource.setrlimit(resource.RLIMIT_NOFILE,(soft,hard))
prior=resource.getrlimit(resource.RLIMIT_NOFILE)
calls=[]
if hard < M.SCHEDULED_OPEN_FILES:
 result=M.scheduled_native(None,build_report=lambda _:calls.append("report"),now=lambda:0,
                          source_gate=lambda _:calls.append("gate"),notifier=lambda:calls.append("notify"))
 assert result["status"]=="UNAVAILABLE" and result["exitCode"]==1
 assert result["failureReason"]=="file_descriptor_limit_unavailable"
 assert result["fileDescriptorBudgetReady"] is False and not calls
 assert resource.getrlimit(resource.RLIMIT_NOFILE)==prior
else:
 assert M.prepare_scheduled_limits() is True
 after=resource.getrlimit(resource.RLIMIT_NOFILE)
 assert after==(max(soft,M.SCHEDULED_OPEN_FILES),hard)
 # Representative concurrent held-leaf pressure, not a native capture or gate.
 handles=[open("/dev/null","rb") for _ in range(800)]
 assert len(handles)==800
 for handle in handles:handle.close()
print(json.dumps({"prior":prior,"after":resource.getrlimit(resource.RLIMIT_NOFILE),"calls":calls}))
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(ROOT), str(soft), str(hard)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
            env={'PATH': '/usr/bin:/bin'}, cwd=ROOT)
        self.assertEqual(resource.getrlimit(resource.RLIMIT_NOFILE), before)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return json.loads(result.stdout)

    def test_low_soft_child_gets_bounded_budget_without_changing_parent_or_hard(self):
        self.assertEqual(self.child(256, 8192)['after'], [2048, 8192])

    def test_low_hard_child_refuses_before_source_gate_capture_or_notification(self):
        self.assertEqual(self.child(256, 1024)['after'], [256, 1024])

    def test_already_higher_child_limit_is_not_lowered(self):
        self.assertEqual(self.child(4096, 8192)['after'], [4096, 8192])

    def test_infinite_soft_and_hard_are_not_lowered(self):
        unlimited = resource.RLIM_INFINITY
        with patch.object(M.resource, 'getrlimit', return_value=(unlimited, unlimited)), \
                patch.object(M.resource, 'setrlimit') as setting:
            self.assertTrue(M.prepare_scheduled_limits())
            setting.assert_not_called()

    def test_infinite_hard_permits_only_soft_raise(self):
        unlimited = resource.RLIM_INFINITY
        with patch.object(M.resource, 'getrlimit', side_effect=[(256, unlimited), (2048, unlimited)]), \
                patch.object(M.resource, 'setrlimit') as setting:
            self.assertTrue(M.prepare_scheduled_limits())
            setting.assert_called_once_with(resource.RLIMIT_NOFILE, (2048, unlimited))

    def test_resource_errors_and_failed_readback_refuse_before_gate(self):
        cases = ('get-error', 'set-error', 'low-readback', 'hard-drift')
        for case in cases:
            with self.subTest(case=case):
                readings = [(256, 8192), (1024, 8192) if case == 'low-readback' else (2048, 4096)]
                calls = []
                with patch.object(M.resource, 'getrlimit', side_effect=OSError('private') if case == 'get-error' else readings), \
                        patch.object(M.resource, 'setrlimit', side_effect=ValueError('private') if case == 'set-error' else None):
                    result = M.scheduled_native(None, build_report=lambda _: calls.append('report'), now=lambda: 0,
                        source_gate=lambda _: calls.append('gate'), notifier=lambda: calls.append('notify'))
                self.assertEqual(calls, [])
                self.assertEqual(result['failureReason'], 'file_descriptor_limit_unavailable')
                self.assertFalse(result['fileDescriptorBudgetReady'])
                self.assertNotIn('private', json.dumps(result))


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aid-maintenance-delivery-test-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.root = self.home / "AIDev/control"
        self.root.mkdir(parents=True, mode=0o700)
        for name in M.SOURCE_FILES:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())
        (self.home / "Library/LaunchAgents").mkdir(parents=True, mode=0o700)
        self.native = NativeFixture()
        self.clock = 1000000
        self.collected = "one"
        self.notify_calls = []

    def store(self):
        return D.Store(str(self.home), os.getuid(), True)

    def schedule(self, operation, *, fault=lambda _: None):
        store = self.store()
        owner = None
        try:
            owner = M.Schedule(store, self.root, self.home, self.native, create=True, fault=fault)
            return getattr(owner, operation)()
        finally:
            if owner is not None: owner.close()
            store.close()

    def row(self):
        return json.loads((self.home / "AIDev/state/maintenance" / M.JOURNAL).read_bytes())

    def observation(self):
        scopes = {key: {"present": False, "root": D.digest(b"absent"), "entries": {}} for key in D.SCOPES}
        scopes["local-bin"] = {"present": True, "root": D.digest(b"fixture-root"),
            "entries": {D.digest(b"fixture-entry"): D.digest(self.collected.encode())}}
        return D.snapshot(scopes)

    def cycle(self, *, admitted=True, guard=lambda: True, notifier=None):
        def native(operation, **callbacks):
            return D.execute(operation, store_factory=lambda _: self.store(), collector=self.observation,
                now=lambda: self.clock, **callbacks)
        def admission(callback):
            if not admitted: raise M.Fault("source_unadmitted")
            return callback("f" * 40, source_guard=guard)
        def notification():
            self.notify_calls.append("fixed")
            return "command_accepted_unverified"
        with patch.object(M, "prepare_scheduled_limits", return_value=True), patch.object(M, "ROOT", self.root), patch.object(M.pwd, "getpwuid", return_value=type("Owner", (), {"pw_dir": str(self.home)})()), patch.object(D, "native", side_effect=native), patch("subprocess.Popen", side_effect=AssertionError("native process forbidden")):
            return M.scheduled_native(D, build_report=lambda value: C.run("cycle", observe=lambda _: value, now=lambda: self.clock),
                now=lambda: self.clock, source_gate=admission, notifier=notifier or notification)

    def test_one_exact_agent_install_noop_remove_reenable_keeps_unrelated_state(self):
        unrelated = self.home / "Library/LaunchAgents/unrelated.plist"
        unrelated.write_bytes(b"owner bytes")
        self.assertEqual(self.schedule("install")["status"], "INSTALLED")
        content = plistlib.loads((self.home / "Library/LaunchAgents" / M.PLIST).read_bytes())
        self.assertEqual(content["Label"], M.LABEL)
        self.assertFalse(content["KeepAlive"])
        self.assertTrue(content["RunAtLoad"])
        self.assertEqual(content["StartCalendarInterval"], {"Hour": 12, "Minute": 0})
        self.assertEqual(content["ProgramArguments"][-2:], ["scheduled", "--json"])
        before = (self.home / "Library/LaunchAgents" / M.PLIST).stat().st_ino
        self.assertEqual(self.schedule("install")["status"], "INSTALLED")
        self.assertEqual((self.home / "Library/LaunchAgents" / M.PLIST).stat().st_ino, before)
        self.assertEqual(self.native.calls.count("bootstrap"), 1)
        self.assertEqual(self.schedule("remove")["status"], "REMOVED")
        self.assertFalse((self.home / "Library/LaunchAgents" / M.PLIST).exists())
        self.assertEqual(unrelated.read_bytes(), b"owner bytes")
        self.assertEqual(self.schedule("install")["status"], "INSTALLED")
        self.assertEqual(self.native.calls.count("bootstrap"), 2)

    def test_foreign_exact_bytes_without_journal_are_not_adopted(self):
        target = self.home / "Library/LaunchAgents" / M.PLIST
        target.write_bytes(M.payload(self.home)); target.chmod(0o600)
        with self.assertRaises(M.Fault): self.schedule("install")
        self.assertEqual(target.read_bytes(), M.payload(self.home))
        self.assertNotIn("bootstrap", self.native.calls)

    def test_unknown_loaded_job_never_means_absent(self):
        self.native.unknown = True
        with self.assertRaises(M.Fault): self.schedule("install")
        self.assertFalse((self.home / "Library/LaunchAgents" / M.PLIST).exists())

    def test_crash_at_each_install_boundary_recovers_without_duplicate_bootstrap(self):
        for boundary in ("preparing", "prepared", "target-published", "published", "starting", "bootstrap-returned", "installed"):
            with self.subTest(boundary=boundary):
                # Each case needs its own unrelated layout and native instance.
                fixture = DeliveryTests("test_unknown_loaded_job_never_means_absent")
                fixture.setUp()
                try:
                    with self.assertRaises(Crash):
                        fixture.schedule("install", fault=lambda current: (_ for _ in ()).throw(Crash()) if current == boundary else None)
                    fixture.schedule("recover")
                    self.assertEqual(fixture.row()["phase"], "installed")
                    self.assertEqual(fixture.native.calls.count("bootstrap"), 1)
                finally: fixture.doCleanups()

    def test_crash_at_each_remove_boundary_recovers_without_duplicate_bootout(self):
        for boundary in ("remove-prepared", "stopping", "bootout-returned", "stopped", "retiring", "target-removed", "removed"):
            with self.subTest(boundary=boundary):
                fixture = DeliveryTests("test_unknown_loaded_job_never_means_absent")
                fixture.setUp()
                try:
                    fixture.schedule("install")
                    with self.assertRaises(Crash):
                        fixture.schedule("remove", fault=lambda current: (_ for _ in ()).throw(Crash()) if current == boundary else None)
                    fixture.schedule("recover")
                    self.assertEqual(fixture.row()["phase"], "removed")
                    self.assertEqual(fixture.native.calls.count("bootout"), 1)
                    self.assertFalse((fixture.home / "Library/LaunchAgents" / M.PLIST).exists())
                finally: fixture.doCleanups()

    def test_lost_native_response_is_reconciled_by_observation_not_repeated(self):
        self.native.lost = "bootstrap"
        with self.assertRaises(M.Fault): self.schedule("install")
        self.assertEqual(self.row()["phase"], "starting")
        self.native.lost = None
        self.schedule("recover")
        self.assertEqual(self.native.calls.count("bootstrap"), 1)
        self.native.lost = "bootout"
        with self.assertRaises(M.Fault): self.schedule("remove")
        self.native.lost = None
        self.schedule("recover")
        self.assertEqual(self.native.calls.count("bootout"), 1)

    def test_foreign_same_bytes_replacement_inode_is_not_removed(self):
        self.schedule("install")
        target = self.home / "Library/LaunchAgents" / M.PLIST
        target.unlink(); target.write_bytes(M.payload(self.home)); target.chmod(0o600)
        with self.assertRaises(M.Fault): self.schedule("remove")
        self.assertTrue(target.exists())
        self.assertNotIn("bootout", self.native.calls)

    def test_symlink_parent_or_payload_refused_without_foreign_writes(self):
        target = self.home / "Library/LaunchAgents" / M.PLIST
        outside = self.home / "foreign"
        outside.write_bytes(b"foreign private")
        target.symlink_to(outside)
        with self.assertRaises((M.Fault, OSError)): self.schedule("install")
        self.assertEqual(outside.read_bytes(), b"foreign private")

    def test_short_writes_complete_and_zero_write_requires_explicit_recovery(self):
        original = M.os.write
        with patch.object(M.os, "write", side_effect=lambda fd, data: original(fd, data[:7])):
            self.schedule("install")
        self.assertEqual(self.row()["phase"], "installed")

    def test_reserved_private_partial_payload_recovers_but_foreign_bytes_do_not(self):
        with self.assertRaises(Crash):
            self.schedule("install", fault=lambda stage: (_ for _ in ()).throw(Crash()) if stage == "preparing" else None)
        path = self.home / "AIDev/state/maintenance" / M.PAYLOAD
        path.write_bytes(M.payload(self.home)[:73]); path.chmod(0o600)
        self.assertEqual(self.schedule("recover")["status"], "INSTALLED")
        self.assertEqual(path.read_bytes(), M.payload(self.home))

    def test_reserved_private_partial_foreign_payload_preserved(self):
        with self.assertRaises(Crash):
            self.schedule("install", fault=lambda stage: (_ for _ in ()).throw(Crash()) if stage == "preparing" else None)
        path = self.home / "AIDev/state/maintenance" / M.PAYLOAD
        path.write_bytes(b"foreign private payload"); path.chmod(0o600)
        with self.assertRaises(M.Fault): self.schedule("recover")
        self.assertEqual(path.read_bytes(), b"foreign private payload")
        self.assertFalse((self.home / "Library/LaunchAgents" / M.PLIST).exists())

    def test_zero_payload_write_has_known_preparation_and_recoverable_prefix(self):
        original = M.Files.create_payload
        def partial(files, raw):
            with patch.object(M.os, "write", return_value=0):
                return original(files, raw)
        with patch.object(M.Files, "create_payload", partial), self.assertRaises(M.Fault):
            self.schedule("install")
        self.assertEqual(self.row()["phase"], "preparing")
        self.assertEqual(self.schedule("recover")["status"], "INSTALLED")

    def test_concurrent_record_destination_is_preserved(self):
        store = self.store()
        files = M.Files(store)
        original = M.rename_exclusive
        def collide(fd, source, target):
            leaf = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=fd)
            os.write(leaf, b"foreign record"); os.close(leaf)
            return original(fd, source, target)
        try:
            with patch.object(M, "rename_exclusive", side_effect=collide), self.assertRaises(OSError):
                files.write(M.CYCLE, {"fixture": True}, None)
            self.assertEqual(files.read(M.CYCLE)[0], b"foreign record")
        finally: store.close()

    def test_connected_unchanged_scheduled_cycle_zero_models_processes_notifications(self):
        self.schedule("install")
        self.assertEqual(self.cycle()["status"], "OBSERVED")
        result = self.cycle()
        self.assertEqual(result["status"], "UNCHANGED")
        self.assertTrue(result["runSourceAccepted"])
        self.assertFalse(result["fullDoctorRun"])
        self.assertEqual(result["modelInvocations"], 0)
        self.assertEqual(self.notify_calls, [])
        record = json.loads((self.home / "AIDev/state/maintenance" / M.CYCLE).read_bytes())
        self.assertLess(len(M.encoded(record)), M.MAX_RECORD)
        self.assertFalse(result["scheduledOriginClaimed"])

    def test_accepted_catalogue_successor_works_without_scheduler_reinstall(self):
        self.schedule("install"); self.cycle()
        manifest = self.root / "manifests/productivity-baseline.json"
        value = json.loads(manifest.read_bytes()); value["ownerRuntimePreferences"]["fixtureAcceptedSuccessor"] = True
        manifest.write_text(json.dumps(value))
        result = self.cycle(admitted=True)
        self.assertEqual(result["status"], "UNCHANGED")
        self.assertEqual(self.native.calls.count("bootstrap"), 1)
        before = (self.home / "AIDev/state/maintenance" / M.CYCLE).read_bytes()
        result = self.cycle(admitted=False)
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertFalse(result["runSourceAccepted"])
        self.assertEqual((self.home / "AIDev/state/maintenance" / M.CYCLE).read_bytes(), before)

    def test_changed_run_source_is_unknown_not_stale_installed_snapshot_admission(self):
        self.schedule("install")
        self.assertEqual(self.cycle(guard=lambda: False)["status"], "UNAVAILABLE")
        self.assertEqual(self.notify_calls, [])

    def test_actual_source_gate_wrapper_uses_affected_source_and_held_callback(self):
        from lib import scoped_source_admission
        calls = []
        def scoped(root, **options):
            calls.append(root)
            self.assertIs(options["full"], False)
            self.assertEqual(options["extra_paths"], M.SOURCE_FILES)
            return {"verdict": "SOURCE_VALID"}
        owner = type("Owner", (), {"pw_dir": str(self.home)})()
        with patch.object(M.pwd, "getpwuid", return_value=owner), patch.object(scoped_source_admission, "observe", side_effect=scoped):
            self.assertEqual(M.admitted_source(self.root, full=False)["verdict"], "SOURCE_VALID")
        self.assertEqual(calls, [self.root])

    def test_new_actionable_event_one_attempt_not_delivery_and_reserved_unknown_no_retry(self):
        self.schedule("install"); self.cycle(); self.collected = "changed"
        result = self.cycle()
        self.assertEqual(len(self.notify_calls), 1)
        self.assertFalse(result["notificationDelivered"])
        self.assertEqual(result["notificationOutcome"], "command_accepted_unverified")
        self.cycle()
        self.assertEqual(len(self.notify_calls), 1)
        self.collected = "changed-again"
        self.cycle(notifier=lambda: "reserved_unknown")
        unknown_record = json.loads((self.home / "AIDev/state/maintenance" / M.CYCLE).read_bytes())
        unknown_id = unknown_record["eventId"]
        self.cycle()
        self.assertEqual(len(self.notify_calls), 1)
        self.collected = "new-event-after-unknown"
        self.cycle()
        self.assertEqual(len(self.notify_calls), 2)
        record = json.loads((self.home / "AIDev/state/maintenance" / M.CYCLE).read_bytes())
        self.assertIn(unknown_id, record["attemptedEvents"])

    def test_crash_after_notification_reservation_is_not_replayed(self):
        self.schedule("install"); self.cycle(); self.collected = "changed"
        def crash(): raise Crash()
        with self.assertRaises(Crash): self.cycle(notifier=crash)
        result = self.cycle()
        self.assertEqual(self.notify_calls, [])
        self.assertEqual(result["notificationOutcome"], "reserved_unknown")
        self.assertFalse(result["notificationDelivered"])
        self.collected = "next-change"
        self.assertEqual(self.cycle()["notificationOutcome"], "command_accepted_unverified")
        self.assertEqual(len(self.notify_calls), 1)

    def test_unknown_a_accepted_b_recurring_a_does_not_claim_a_accepted(self):
        self.schedule("install"); self.cycle()
        self.observation = lambda: (_ for _ in ()).throw(D.Fault("scan_unavailable"))
        first = self.cycle(notifier=lambda: "reserved_unknown")
        self.observation = lambda: (_ for _ in ()).throw(D.Fault("scan_limit"))
        second = self.cycle()
        self.observation = lambda: (_ for _ in ()).throw(D.Fault("scan_unavailable"))
        repeated = self.cycle()
        self.assertEqual(repeated["event"]["id"], first["event"]["id"])
        self.assertEqual(repeated["notificationOutcome"], "not_attempted")
        self.assertEqual(repeated["notificationEventId"], second["event"]["id"])
        self.assertEqual(len(self.notify_calls), 1)
        self.assertFalse(repeated["notificationDelivered"])

    def test_native_presence_parser_exact_argv_and_error_vs_not_found(self):
        path = str(self.home / "Library/LaunchAgents" / M.PLIST)
        script = str(self.home / "AIDev/control/bin/workstation-maintenance-cycle")
        text = f"path = {path}\nprogram = /usr/bin/python3\narguments = {{\n/usr/bin/python3\n-I\n-B\n{script}\nscheduled\n--json\n}}\n"
        with patch.object(M, "bounded", return_value=(0, text.encode(), b"", True)):
            self.assertEqual(M.runner("observe", self.home), "PRESENT")
        for wrong in (text.replace("--json", "--foreign"), text.replace("program = /usr/bin/python3", "program = /bin/sh")):
            with patch.object(M, "bounded", return_value=(0, wrong.encode(), b"", True)):
                self.assertEqual(M.runner("observe", self.home), "UNKNOWN")
        for code, error, expected in ((113, b"Could not find service", "ABSENT"), (1, b"permission denied", "UNKNOWN"), (113, b"network failure", "UNKNOWN")):
            with patch.object(M, "bounded", return_value=(code, b"", error, True)):
                self.assertEqual(M.runner("observe", self.home), expected)

    def test_real_cli_wrapper_translates_only_fixed_schedule_operations(self):
        seen = []
        def native(operation):
            seen.append(operation)
            M.need(operation in {"plan", "install", "remove", "recover", "status"})
            return M.output(operation, "PLANNED")
        with patch.object(M, "native_schedule", side_effect=native):
            for operation in ("plan", "install", "remove", "recover", "status"):
                output = []
                self.assertEqual(C.main(["schedule-" + operation, "--json"], emit=output.append), 0)
                self.assertEqual(json.loads(output[0])["operation"], operation)
        self.assertEqual(seen, ["plan", "install", "remove", "recover", "status"])

    def test_alternating_events_deduplicate_and_full_legacy_window_rotates(self):
        self.schedule("install"); self.cycle()
        normal = self.observation
        for reason in ("scan_unavailable", "scan_limit", "scan_unavailable"):
            self.observation = lambda reason=reason: (_ for _ in ()).throw(D.Fault(reason))
            self.cycle()
        self.observation = normal
        self.assertEqual(len(self.notify_calls), 2)
        path = self.home / "AIDev/state/maintenance" / M.CYCLE
        record = json.loads(path.read_bytes())
        self.assertEqual(len(record["attemptedEvents"]), 2)
        record["attemptedEvents"] += [M.sha(("synthetic-attempt-" + str(index)).encode()) for index in range(126)]
        record["notification"] = "capacity_exhausted"  # Legacy terminal state.
        path.write_bytes(M.encoded(record))
        attempted = list(record["attemptedEvents"])
        self.assertEqual(len(attempted), M.MAX_EVENTS)
        self.observation = lambda: (_ for _ in ()).throw(D.Fault("scan_changed"))
        result = self.cycle()
        self.assertTrue(result["runSourceAccepted"])
        self.assertEqual(result["notificationOutcome"], "command_accepted_unverified")
        self.assertEqual(result["observation"]["sequence"], 5)
        self.observation = normal
        self.collected = "129th-actionable-metadata-fixture"
        result = self.cycle()
        self.assertTrue(result["observation"]["completeObservation"])
        self.assertTrue(result["freshObservation"])
        self.assertTrue(result["actionable"])
        self.assertEqual(result["notificationOutcome"], "command_accepted_unverified")
        record = json.loads(path.read_bytes())
        self.assertEqual(len(record["attemptedEvents"]), M.MAX_EVENTS)
        self.assertEqual(record["attemptedEvents"][:-2], attempted[2:])
        self.assertEqual(record["latest"]["observation"]["sequence"], 6)
        self.assertEqual(len(self.notify_calls), 4)
        # Eviction is explicit bounded-window semantics, not lifetime silence.
        self.observation = lambda: (_ for _ in ()).throw(D.Fault("scan_unavailable"))
        self.cycle()
        self.assertEqual(len(self.notify_calls), 5)
        self.cycle()
        self.assertEqual(len(self.notify_calls), 5)

    def test_native_descendant_closed_pipes_is_stopped_before_custody_released(self):
        calls, original = [], os.killpg
        def signal_group(pid, action):
            calls.append(action)
            return original(pid, action)
        command = ["/usr/bin/python3", "-c", "import os,time; p=os.fork();\nif p==0:\n os.close(1);os.close(2);time.sleep(10)\nelse: os._exit(0)"]
        with patch.object(M.os, "killpg", side_effect=signal_group):
            result = M.bounded(command, timeout=0.5)
        self.assertIn(signal.SIGTERM, calls)
        self.assertIsNone(result[0])

    def test_unsettled_native_custody_is_retained_and_never_retried(self):
        native = self.native
        def unsettled(operation, home):
            return "UNKNOWN_CUSTODY" if operation == "bootstrap" else native(operation, home)
        self.native = unsettled
        with self.assertRaises(M.Fault): self.schedule("install")
        self.assertEqual(self.row()["phase"], "starting-unknown")
        self.native = native
        with self.assertRaises(M.Fault): self.schedule("recover")
        self.assertNotIn("bootstrap", native.calls)

    def test_crash_during_native_dispatch_cannot_replay_unsettled_attempt(self):
        for operation, phase in (("bootstrap", "starting-unknown"), ("bootout", "stopping-unknown")):
            with self.subTest(operation=operation):
                fixture = DeliveryTests("test_unknown_loaded_job_never_means_absent")
                fixture.setUp()
                native, attempts = fixture.native, []
                try:
                    if operation == "bootout": fixture.schedule("install")
                    def crash(current, home):
                        if current == operation:
                            attempts.append(current)
                            raise Crash()  # Pending child, no return/settlement.
                        return native(current, home)
                    fixture.native = crash
                    with self.assertRaises(Crash):
                        fixture.schedule("install" if operation == "bootstrap" else "remove")
                    self.assertEqual(fixture.row()["phase"], phase)
                    with self.assertRaises(M.Fault): fixture.schedule("recover")
                    self.assertEqual(attempts, [operation])
                finally: fixture.doCleanups()

    def test_install_held_admission_spans_mutation_without_vendor_preflight(self):
        gates, guard_state = [], [True]
        def admission(root, *, full, operation_check=None):
            gates.append(full)
            self.assertFalse(full, 'unrelated full vendor gate')
            return operation_check("f" * 40, source_guard=lambda: guard_state[0])
        owner = type("Owner", (), {"pw_dir": str(self.home)})()
        with patch.object(M, "ROOT", self.root), patch.object(M.pwd, "getpwuid", return_value=owner), patch.object(M, "runner", self.native), patch.object(M, "admitted_source", side_effect=admission):
            result = M.native_schedule("install")
        self.assertEqual(gates, [False])
        self.assertEqual(result["status"], "INSTALLED")
        self.assertEqual(result["operation"], "install")
        self.assertEqual(self.native.calls.count("bootstrap"), 1)

    def test_source_drift_under_held_admission_prevents_install(self):
        def admission(root, *, full, operation_check=None):
            self.assertFalse(full, 'unrelated full vendor gate')
            return operation_check("f" * 40, source_guard=lambda: False)
        owner = type("Owner", (), {"pw_dir": str(self.home)})()
        with patch.object(M, "ROOT", self.root), patch.object(M.pwd, "getpwuid", return_value=owner), patch.object(M, "runner", self.native), patch.object(M, "admitted_source", side_effect=admission):
            result = M.native_schedule("install")
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertNotIn("bootstrap", self.native.calls)
        self.assertFalse((self.home / "Library/LaunchAgents" / M.PLIST).exists())

    def test_source_failure_reports_closed_reason_without_native_dispatch(self):
        from lib import scoped_source_admission as source
        owner = type("Owner", (), {"pw_dir": str(self.home)})()
        with patch.object(M, "ROOT", self.root), patch.object(M.pwd, "getpwuid", return_value=owner), \
                patch.object(M, "runner", self.native), \
                patch.object(M, "admitted_source", side_effect=source.SourceError("affected_source_uncommitted")):
            result = M.native_schedule("install")
        self.assertEqual(result["reason"], "affected_source_uncommitted")
        self.assertTrue(result["nextAction"])
        self.assertNotIn("bootstrap", self.native.calls)

    def test_catalog_is_first_consumed_inside_held_source_callback(self):
        active, consumed = [False], []
        actual = M.sources
        def inputs(root):
            consumed.append(active[0])
            return actual(root)
        def admitted(root, *, full, operation_check):
            active[0] = True
            try:
                return operation_check('f' * 40, source_guard=lambda: active[0])
            finally:
                active[0] = False
        owner = type('Owner', (), {'pw_dir': str(self.home)})()
        with patch.object(M, 'ROOT', self.root), patch.object(M.pwd, 'getpwuid', return_value=owner), \
                patch.object(M, 'runner', self.native), patch.object(M, 'sources', side_effect=inputs), \
                patch.object(M, 'admitted_source', side_effect=admitted):
            self.assertEqual(M.native_schedule('install')['status'], 'INSTALLED')
        self.assertTrue(consumed)
        self.assertTrue(all(consumed))

    def test_connected_install_source_gate_never_requests_full_vendor_probe(self):
        from contextlib import contextmanager
        from lib import current_doctor_native as N
        from lib import scoped_source_admission as source
        calls = []
        @contextmanager
        def held(root, **options):
            self.assertEqual(options['data_paths'], ())
            self.assertEqual(options['opaque_paths'], M.SOURCE_FILES)
            calls.append(True)
            yield 'f' * 40, lambda: True
        owner = type('Owner', (), {'pw_dir': str(self.home)})()
        with patch.object(M, 'ROOT', self.root), patch.object(M.pwd, 'getpwuid', return_value=owner), \
                patch.object(M, 'runner', self.native), \
                patch.object(source, 'require_execution', return_value=True), \
                patch.object(source, 'admitted_source', side_effect=held), \
                patch.object(N.probe, 'observe', side_effect=AssertionError('vendor launch forbidden')):
            result = M.native_schedule('install')
        self.assertEqual(result['status'], 'INSTALLED')
        self.assertEqual(calls, [True])
        self.assertEqual(self.native.calls.count('bootstrap'), 1)

    def test_actual_manifest_drift_at_prepared_retains_recovery_without_publication(self):
        manifest = self.root / M.MANIFEST
        original = manifest.read_bytes()
        observed = []
        def admission(root, *, full, operation_check=None):
            self.assertFalse(full)
            def source_guard():
                stable = manifest.read_bytes() == original
                observed.append(stable)
                return stable
            return operation_check('f' * 40, source_guard=source_guard)
        original_init = M.Schedule.__init__
        def initialize(schedule, *args, **kwargs):
            def change(phase):
                if phase == 'prepared':
                    manifest.write_bytes(original + b'\n')
            kwargs['fault'] = change
            original_init(schedule, *args, **kwargs)
        owner = type('Owner', (), {'pw_dir': str(self.home)})()
        with patch.object(M, 'ROOT', self.root), patch.object(M.pwd, 'getpwuid', return_value=owner), \
                patch.object(M, 'runner', self.native), patch.object(M, 'admitted_source', side_effect=admission), \
                patch.object(M.Schedule, '__init__', initialize):
            result = M.native_schedule('install')
        self.assertEqual(result['status'], 'RECOVERY_REQUIRED')
        self.assertIn(False, observed)
        self.assertNotIn('bootstrap', self.native.calls)
        self.assertFalse((self.home / 'Library/LaunchAgents' / M.PLIST).exists())
        self.assertEqual(self.row()['phase'], 'prepared')
        self.assertTrue((self.home / 'AIDev/state/maintenance' / M.PAYLOAD).is_file())

    def test_own_agent_addition_nonactionable_but_unrelated_service_change_unknown(self):
        original = self.observation
        def observed():
            value = original()
            value["scopes"]["user-launch-agents"] = D.collect_scope(str(self.home / "Library/LaunchAgents"))
            return D.snapshot(value["scopes"])
        self.observation = observed
        # Actual metadata capture before the controlled installation.
        D.execute("capture", store_factory=lambda _: self.store(), collector=observed, now=lambda: self.clock,
                  classifier=D.source_classifier(self.root))
        self.schedule("install")
        result = self.cycle()
        self.assertEqual(result["status"], "EXTERNAL_OBSERVED")
        self.assertFalse(result["actionable"])
        self.assertEqual(self.notify_calls, [])
        (self.home / "Library/LaunchAgents/unrelated.plist").write_bytes(b"fixture service")
        result = self.cycle()
        self.assertTrue(result["actionable"])
        self.assertEqual(result["changeClassification"]["unknown"], 1)
        self.assertEqual(len(self.notify_calls), 1)

    def test_agent_parent_mode_drift_and_malformed_cycle_preserve_state(self):
        self.schedule("install")
        store = self.store()
        owner = M.Schedule(store, self.root, self.home, self.native)
        try:
            (self.home / "Library/LaunchAgents").chmod(0o777)
            with self.assertRaises(M.Fault): owner.remove()
            self.assertNotIn("bootout", self.native.calls)
        finally:
            (self.home / "Library/LaunchAgents").chmod(0o700)
            owner.close(); store.close()
        self.cycle()
        path = self.home / "AIDev/state/maintenance" / M.CYCLE
        record = json.loads(path.read_bytes()); record["latest"] = {"foreign": True}
        raw = M.encoded(record); path.write_bytes(raw)
        self.assertEqual(self.cycle()["status"], "UNAVAILABLE")
        self.assertEqual(path.read_bytes(), raw)

    def test_postconsumer_close_failure_downgrades_fresh_result_without_losing_attempt_outcome(self):
        self.schedule("install")
        original = D.Store.close
        def unknown(store):
            original(store)
            raise D.Fault("state_unavailable")
        with patch.object(D.Store, "close", unknown):
            result = self.cycle()
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(result["exitCode"], 1)
        self.assertFalse(result["freshObservation"])
        self.assertFalse(result["observation"]["completeObservation"])
        self.assertFalse(result["notificationDelivered"])
        self.assertEqual(result["notificationOutcome"], "not_attempted")


if __name__ == "__main__": unittest.main()
