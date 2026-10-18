"""Synthetic hook/home fixtures only: never owner HOME or machine probes."""
import copy
import fcntl
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lib import harness_offramp as h

MANIFEST, HISTORICAL = h._sources()
DEFS = h.definitions(MANIFEST, HISTORICAL)


def fixture():
    unrelated = {"matcher": "other", "hooks": [{"type": "command", "command": "other", "timeout": 3}]}
    return copy.deepcopy({"ownerSetting": "private-not-for-report", "hooks": {
        "SessionStart": [unrelated, DEFS["dynamicSessionStart"][1], DEFS["staticSessionStart"][1]],
        "PreToolUse": [DEFS["legacyPreToolUse"][1], unrelated, {"hooks": []}],
        "Stop": [DEFS["legacyStop"][1]], "OtherEvent": [unrelated]}})


def raw_fixture():
    return b" \r\n" + json.dumps(fixture(), indent=3, ensure_ascii=False).encode() + b"\n\t"


class PlannerTests(unittest.TestCase):
    def test_fixture_adversarial_mutations_are_independent(self):
        original = h.wire(DEFS)
        first, second = fixture(), fixture()
        first["hooks"]["SessionStart"][-1]["hooks"][0]["statusMessage"] = "changed"
        self.assertNotEqual(first, second)
        self.assertEqual(h.wire(DEFS), original)
        self.assertEqual(second, fixture())

    def test_retire_preserves_dynamic_and_unrelated_bytes(self):
        raw = raw_fixture()
        plan = h.build_plan(raw, MANIFEST, HISTORICAL)
        expected = fixture()
        expected["hooks"]["SessionStart"] = expected["hooks"]["SessionStart"][:2]
        expected["hooks"]["PreToolUse"] = expected["hooks"]["PreToolUse"][1:]
        expected["hooks"]["Stop"] = []
        self.assertEqual(h.parse(plan.after), expected)
        self.assertEqual(plan.removed, 3)
        self.assertTrue(plan.after.startswith(b" \r\n"))
        self.assertTrue(plan.after.endswith(b"\n\t"))
        # Every unknown group exact literal span survives unchanged.
        nodes = h.spans(raw)
        for event, index in (("SessionStart", 0), ("PreToolUse", 1), ("PreToolUse", 2), ("OtherEvent", 0)):
            a, b = nodes[("hooks", event)][2][index]
            self.assertIn(raw[a:b], plan.after)
        self.assertEqual(h.build_plan(plan.after, MANIFEST, HISTORICAL).removed, 0)

    def test_disable_removes_all_four_and_exact_restore(self):
        raw = raw_fixture()
        plan = h.build_plan(raw, MANIFEST, HISTORICAL, "disable")
        self.assertEqual(plan.removed, 4)
        self.assertEqual(h.restore_plan(plan.after, plan), raw)
        self.assertEqual(h.restore_plan(raw, plan), raw)
        self.assertEqual(h.build_plan(plan.after, MANIFEST, HISTORICAL, "disable").removed, 0)

    def test_array_positions_and_separator_runs(self):
        group = DEFS["legacyStop"][1]
        for items in ([group], [group, {}], [{}, group], [{}, group, {}], [group, {}, group]):
            raw = json.dumps({"hooks": {"Stop": items}}).encode()
            if items.count(group) == 2:
                with self.assertRaises(h.OfframpError):
                    h.build_plan(raw, MANIFEST, HISTORICAL)
            else:
                plan = h.build_plan(raw, MANIFEST, HISTORICAL)
                self.assertEqual(h.parse(plan.after)["hooks"]["Stop"], [g for g in items if g != group])

    def test_unknown_owned_like_wrong_event_extra_handler_timeout_refused(self):
        for change in ("timeout", "handler", "matcher", "event", "extra"):
            value = fixture()
            group = value["hooks"]["PreToolUse"][0]
            if change == "timeout":
                group["hooks"][0]["timeout"] = 5.0
            elif change == "handler":
                group["hooks"].append({"type": "command", "command": "private"})
            elif change == "matcher":
                group["matcher"] = ".*"
            elif change == "event":
                value["hooks"]["OtherEvent"].append(value["hooks"]["PreToolUse"].pop(0))
            else:
                group["owner"] = "unknown"
            with self.subTest(change=change), self.assertRaises(h.OfframpError):
                h.build_plan(h.wire(value), MANIFEST, HISTORICAL)

    def test_duplicate_and_historical_manifest_drift_refused(self):
        value = fixture()
        value["hooks"]["Stop"].append(copy.deepcopy(value["hooks"]["Stop"][0]))
        with self.assertRaises(h.OfframpError):
            h.build_plan(h.wire(value), MANIFEST, HISTORICAL)
        with self.assertRaises(h.OfframpError):
            h.build_plan(raw_fixture(), MANIFEST, HISTORICAL + b"\n")

    def test_static_exact_command_modified_status_remains_owned_collision(self):
        value = fixture()
        value["hooks"]["SessionStart"][-1]["hooks"][0]["statusMessage"] = "owner-modified-status"
        with self.assertRaisesRegex(h.OfframpError, "owned_definition_unknown"):
            h.build_plan(h.wire(value), MANIFEST, HISTORICAL)

    def test_malformed_bounded_json_refused(self):
        for raw in (b'{"hooks":{},"hooks":{}}', b'{"hooks":{"Stop":[{},]}}',
                    b'{"hooks":{"Stop":[]},"n":NaN}', b"\xff", b"x" * (h.LIMIT + 1),
                    b'{"hooks":{"Stop":[true]}}', b'{"hooks":{"Stop":{}}}'):
            with self.subTest(raw=raw[:60]), self.assertRaises(h.OfframpError):
                h.build_plan(raw, MANIFEST, HISTORICAL)

    def test_restore_preserves_other_event_and_top_level_concurrent_changes(self):
        plan = h.build_plan(raw_fixture(), MANIFEST, HISTORICAL, "disable")
        concurrent = plan.after.replace(b'"private-not-for-report"', b'"owner-new-choice"')
        concurrent = concurrent.replace(b'"OtherEvent": [', b'"OtherEvent": [ {"third": true},')
        restored = h.restore_plan(concurrent, plan)
        self.assertIn(b'"owner-new-choice"', restored)
        self.assertIn(b'"OtherEvent": [ {"third": true},', restored)
        self.assertEqual(h.parse(restored)["hooks"]["SessionStart"], fixture()["hooks"]["SessionStart"])

    def test_restore_affected_event_drift_refused(self):
        plan = h.build_plan(raw_fixture(), MANIFEST, HISTORICAL, "disable")
        concurrent = plan.after.replace(b'"Stop": [', b'"Stop": [ {"third": true}')
        with self.assertRaises(h.OfframpError):
            h.restore_plan(concurrent, plan)

    def test_public_reports_redact_private_data(self):
        plan = h.build_plan(raw_fixture(), MANIFEST, HISTORICAL)
        report = json.dumps(plan.public_report())
        for private in ("private-not-for-report", "phase5-contract", "$HOME", h.digest(plan.before)):
            self.assertNotIn(private, report)
        self.assertEqual(repr(plan), "<private harness hook plan>")


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="offramp-test-")
        self.home = Path(self.temp.name).resolve()
        self.codex = self.home / ".codex"
        self.codex.mkdir(mode=0o700)
        self.target = self.codex / "hooks.json"
        self.before = raw_fixture()
        self.target.write_bytes(self.before)
        self.target.chmod(0o600)
        self.config = self.codex / "config.toml"
        self.config.write_text('native-trust = "owner-state"\n')
        self.payload = self.home / "Library/Game/save.dat"
        self.payload.parent.mkdir(parents=True)
        self.payload.write_bytes(b"save-data")

    def tearDown(self):
        self.temp.cleanup()

    def run_action(self, action, **kwargs):
        return h.execute_fixture(self.home, action, **kwargs)

    def test_actual_disable_verify_noop_restore_with_doctor_unavailable(self):
        with patch("lib.operation_readiness.require_operation_ready", side_effect=AssertionError("no doctor")):
            report = self.run_action("disable")
            self.assertEqual(report["status"], "APPLIED")
            self.assertEqual(self.run_action("disable")["status"], "NOOP")
            self.assertEqual(self.run_action("restore")["status"], "RESTORED")
            self.assertEqual(self.run_action("restore")["status"], "ALREADY_RESTORED")
        self.assertEqual(self.target.read_bytes(), self.before)
        self.assertEqual(self.config.read_text(), 'native-trust = "owner-state"\n')
        self.assertEqual(self.payload.read_bytes(), b"save-data")

    def test_readonly_plan_does_not_create_recovery_or_change_home(self):
        report = self.run_action("plan", plan_action="remove")
        self.assertTrue(report["readOnly"])
        self.assertEqual(report["removedGroups"], 4)
        self.assertEqual([row["status"] for row in report["passiveTargets"]], ["ABSENT", "ABSENT"])
        self.assertFalse(self.home.joinpath(*h.RECOVERY).exists())
        self.assertEqual(self.target.read_bytes(), self.before)

    def test_cli_actual_synthetic_lifecycle_and_noop(self):
        emitted = []
        for action in ("disable", "disable", "restore"):
            self.assertEqual(h.main([action, "--fixture-home", str(self.home), "--operation", "cli"],
                                    emit=emitted.append), 0)
        self.assertEqual([json.loads(row)["status"] for row in emitted], ["APPLIED", "NOOP", "RESTORED"])
        self.assertNotIn("private-not-for-report", "".join(emitted))
        self.assertEqual(self.target.read_bytes(), self.before)

    def test_native_live_adapter_injected_source_acceptance_observes_dependencies(self):
        control = self.home / "AIDev/control"
        observed = []
        def observe(root, operation, commit, *, checks, target_guard, extra_paths):
            self.assertEqual(root, control)
            self.assertEqual(operation, "harness-disable")
            self.assertEqual(commit, "a" * 40)
            self.assertEqual(extra_paths, ("manifests/harness-hook-retirement.json", "manifests/sessionstart-exposure.json"))
            self.assertTrue(target_guard())
            for name, callback in checks.items():
                self.assertTrue(callback())
                observed.append(name)
            return {"scopedCandidateReady": True, "machineMutationAuthorized": False}
        with patch.object(h, "ROOT", control), patch.object(Path, "home", return_value=self.home), \
                patch.object(Path, "cwd", return_value=control), patch.object(h, "_sources", return_value=(MANIFEST, HISTORICAL)), \
                patch("lib.user_operation_readiness.require_scoped_operation_ready", side_effect=observe), \
                patch("lib.operation_readiness.require_operation_ready", side_effect=AssertionError("no full doctor")):
            result = h.execute_live("disable", "a" * 40)
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(set(observed), {"owned-target", "recovery"})
        self.assertEqual(self.config.read_text(), 'native-trust = "owner-state"\n')

    def test_native_live_adapter_source_refusal_preserves_target(self):
        control = self.home / "AIDev/control"
        with patch.object(h, "ROOT", control), patch.object(Path, "home", return_value=self.home), \
                patch.object(Path, "cwd", return_value=control), patch.object(h, "_sources", return_value=(MANIFEST, HISTORICAL)), \
                patch("lib.user_operation_readiness.require_scoped_operation_ready", side_effect=RuntimeError("unaccepted")):
            with self.assertRaises(RuntimeError):
                h.execute_live("disable", "a" * 40)
        self.assertEqual(self.target.read_bytes(), self.before)

    def test_live_disable_accepts_absent_or_empty_native_config_without_creating_it(self):
        control = self.home / "AIDev/control"
        for content in (None, b""):
            with self.subTest(content=content):
                if content is None:
                    self.config.unlink()
                else:
                    self.config.write_bytes(content)
                self.target.write_bytes(self.before)
                def observe(*args, **kwargs):
                    self.assertTrue(all(check() for check in kwargs["checks"].values()))
                with patch.object(h, "ROOT", control), patch.object(Path, "home", return_value=self.home), \
                        patch.object(Path, "cwd", return_value=control), \
                        patch.object(h, "_sources", return_value=(MANIFEST, HISTORICAL)), \
                        patch("lib.user_operation_readiness.require_scoped_operation_ready", side_effect=observe):
                    result = h.execute_live("disable", "a" * 40,
                                            operation="absent" if content is None else "empty")
                self.assertEqual(result["status"], "APPLIED")
                self.assertEqual(self.config.read_bytes() if self.config.exists() else None, content)

    def test_live_absent_unrelated_config_appearing_during_admission_is_preserved(self):
        self.config.unlink()
        control = self.home / "AIDev/control"
        def change(*args, **kwargs):
            self.config.write_bytes(b"owner-new-state")
        with patch.object(h, "ROOT", control), patch.object(Path, "home", return_value=self.home), \
                patch.object(Path, "cwd", return_value=control), patch.object(h, "_sources", return_value=(MANIFEST, HISTORICAL)), \
                patch("lib.user_operation_readiness.require_scoped_operation_ready", side_effect=change):
            self.assertEqual(h.execute_live("disable", "a" * 40)["status"], "APPLIED")
        self.assertNotEqual(self.target.read_bytes(), self.before)
        self.assertEqual(self.config.read_bytes(), b"owner-new-state")

    def test_native_snapshot_does_not_follow_dangling_symlink(self):
        self.config.unlink()
        self.config.symlink_to(self.home / "absent")
        directory = h.Directory(self.home, (".codex",))
        try:
            with self.assertRaises(OSError):
                h.native_snapshot(directory)
        finally:
            directory.close()

    def test_cli_default_cycles_keep_history_and_restore_latest(self):
        reports = []
        first_images = None
        for expected_id in ("hooks", "hooks-2", "hooks-3"):
            for action, status in (("disable", "APPLIED"), ("disable", "NOOP"),
                                   ("restore", "RESTORED"), ("restore", "ALREADY_RESTORED")):
                self.assertEqual(h.main([action, "--fixture-home", str(self.home)], emit=reports.append), 0)
                report = json.loads(reports[-1])
                self.assertEqual(report["status"], status)
                self.assertEqual(report["operationId"], expected_id)
            first = self.home.joinpath(*h.RECOVERY, "hooks")
            images = {p.name: p.read_bytes() for p in first.iterdir()}
            if first_images is None:
                first_images = images
            self.assertEqual(images, first_images)
        self.assertEqual(self.target.read_bytes(), self.before)

    def test_default_cycle_does_not_skip_interrupted_preparation(self):
        original = h.write_new
        def interrupt(directory, name, raw, *args):
            if name == "after.json":
                raise KeyboardInterrupt()
            return original(directory, name, raw, *args)
        with patch.object(h, "write_new", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_action("disable", operation=None)
        with self.assertRaises(FileExistsError):
            self.run_action("disable", operation=None)
        self.assertFalse(self.home.joinpath(*h.RECOVERY, "hooks-2").exists())
        self.assertEqual(self.target.read_bytes(), self.before)

    def test_completed_restore_without_marker_reconciles_and_advances_default_cycle(self):
        self.run_action("disable", operation=None)
        original = h.write_record
        def interrupt(directory, name, raw):
            if name == "restored.json":
                raise KeyboardInterrupt()
            return original(directory, name, raw)
        with patch.object(h, "write_record", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_action("restore", operation=None)
        self.assertEqual(self.target.read_bytes(), self.before)
        recovery = self.home.joinpath(*h.RECOVERY, "hooks")
        self.assertFalse((recovery / "restored.json").exists())
        result = self.run_action("restore", operation=None)
        self.assertEqual(result["status"], "ALREADY_RESTORED")
        self.assertEqual(h.parse((recovery / "restored.json").read_bytes()),
                         {"schema": 1, "status": "RESTORED"})
        result = self.run_action("disable", operation=None)
        self.assertEqual(result["status"], "APPLIED")
        self.assertEqual(result["operationId"], "hooks-2")

    def test_restore_marker_reconciliation_requires_admission(self):
        self.run_action("disable")
        self.run_action("restore")
        marker = self.home.joinpath(*h.RECOVERY, "hooks", "restored.json")
        marker.unlink()
        def refuse(*args):
            raise h.OfframpError("admission_refused")
        with self.assertRaisesRegex(h.OfframpError, "admission_refused"):
            h.execute(self.home, "restore", admission=refuse)
        self.assertFalse(marker.exists())
        self.assertEqual(self.target.read_bytes(), self.before)

    def test_default_cycle_rejects_unknown_completion_marker(self):
        self.run_action("disable")
        self.home.joinpath(*h.RECOVERY, "hooks", "restored.json").write_bytes(b'{"status":"UNKNOWN"}')
        self.home.joinpath(*h.RECOVERY, "hooks", "restored.json").chmod(0o600)
        with self.assertRaisesRegex(h.OfframpError, "recovery_record"):
            self.run_action("disable", operation=None)
        self.assertFalse(self.home.joinpath(*h.RECOVERY, "hooks-2").exists())

    def test_live_adapter_unrelated_config_drift_does_not_veto_hook_removal(self):
        control = self.home / "AIDev/control"
        def change(*args, **kwargs):
            self.config.write_text('native-trust = "third-choice"\n')
        with patch.object(h, "ROOT", control), patch.object(Path, "home", return_value=self.home), \
                patch.object(Path, "cwd", return_value=control), patch.object(h, "_sources", return_value=(MANIFEST, HISTORICAL)), \
                patch("lib.user_operation_readiness.require_scoped_operation_ready", side_effect=change):
            self.assertEqual(h.execute_live("disable", "a" * 40)["status"], "APPLIED")
        self.assertNotEqual(self.target.read_bytes(), self.before)
        self.assertEqual(self.config.read_text(), 'native-trust = "third-choice"\n')

    def test_live_plan_status_and_disable_ignore_cwd_and_unrelated_config_symlink(self):
        control = self.home / "AIDev/control"
        self.config.unlink()
        self.config.symlink_to(self.home / "private-missing-config")
        def observed(*args, **kwargs):
            self.assertEqual(set(kwargs["checks"]), {"owned-target", "recovery"})
            self.assertTrue(kwargs["target_guard"]())
            self.assertTrue(all(check() for check in kwargs["checks"].values()))
        with patch.object(h, "ROOT", control), patch.object(Path, "home", return_value=self.home), \
                patch.object(Path, "cwd", return_value=self.home), \
                patch.object(h, "_sources", return_value=(MANIFEST, HISTORICAL)), \
                patch.object(h, "native_snapshot", side_effect=AssertionError("unrelated config read")), \
                patch("lib.user_operation_readiness.require_scoped_operation_ready", side_effect=observed):
            self.assertTrue(h.execute_live("plan", "a" * 40)["readOnly"])
            self.assertTrue(h.execute_live("status", "a" * 40)["readOnly"])
            self.assertEqual(h.execute_live("disable", "a" * 40)["status"], "APPLIED")
        self.assertTrue(self.config.is_symlink())
        self.assertFalse(self.config.exists())

    def test_live_hooks_symlink_is_still_refused_from_another_cwd(self):
        control = self.home / "AIDev/control"
        self.target.rename(self.codex / "owner-hooks.json")
        self.target.symlink_to(self.codex / "owner-hooks.json")
        with patch.object(h, "ROOT", control), patch.object(Path, "home", return_value=self.home), \
                patch.object(Path, "cwd", return_value=self.home), \
                patch.object(h, "_sources", return_value=(MANIFEST, HISTORICAL)):
            with self.assertRaises(OSError):
                h.execute_live("disable", "a" * 40)
        self.assertEqual((self.codex / "owner-hooks.json").read_bytes(), self.before)

    def test_durable_preimages_private_and_second_operation_identity(self):
        self.run_action("disable", operation="first")
        directory = self.home.joinpath(*h.RECOVERY, "first")
        self.assertEqual((directory / "before.json").read_bytes(), self.before)
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual((directory / "before.json").stat().st_mode & 0o777, 0o600)
        self.run_action("restore", operation="first")
        self.run_action("disable", operation="second")
        self.assertTrue((directory / "before.json").exists())

    def test_preimage_drift_rejected_and_preimage_retained(self):
        concurrent = self.before.replace(b"private-not-for-report", b"owner-new-choice")
        def change():
            self.target.write_bytes(concurrent)
        with self.assertRaisesRegex(h.OfframpError, "preimage_drift"):
            self.run_action("disable", before_publish=change)
        self.assertEqual(self.target.read_bytes(), concurrent)
        self.assertEqual(self.home.joinpath(*h.RECOVERY, "hooks", "before.json").read_bytes(), self.before)

    def test_preparation_interrupt_reports_no_mutation_and_keeps_old_id(self):
        original_write = h.write_new
        def interrupt(directory, name, raw, *args):
            if name == "after.json":
                raise KeyboardInterrupt()
            return original_write(directory, name, raw, *args)
        with patch.object(h, "write_new", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_action("disable")
        report = self.run_action("restore")
        self.assertEqual(report["status"], "PREPARATION_ABORTED_NO_MUTATION")
        self.assertEqual(self.target.read_bytes(), self.before)
        self.assertTrue(self.home.joinpath(*h.RECOVERY, "hooks", "before.json").exists())
        self.run_action("disable", operation="fresh")

    def test_passive_preparation_interrupt_publishes_no_active_record_or_mutation(self):
        aid, skill = self.install_passive()
        original = skill.read_bytes()
        original_write = h.write_new
        def interrupt(directory, name, raw, *args):
            if name == "workstationSkill.json":
                raise KeyboardInterrupt()
            return original_write(directory, name, raw, *args)
        with patch.object(h, "write_new", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_action("remove")
        self.assertEqual(self.target.read_bytes(), self.before)
        self.assertEqual(skill.read_bytes(), original)
        self.assertTrue(aid.is_symlink())
        report = self.run_action("restore")
        self.assertEqual(report["status"], "PREPARATION_ABORTED_NO_MUTATION")
        self.run_action("remove", operation="fresh")

    def test_interrupt_during_active_record_write_never_publishes_partial_active(self):
        original_record = h.write_record
        def interrupt(directory, name, raw):
            if name == "active.json":
                with patch.object(h.os, "write", side_effect=KeyboardInterrupt()):
                    return original_record(directory, name, raw)
            return original_record(directory, name, raw)
        with patch.object(h, "write_record", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_action("disable")
        self.assertFalse(self.home.joinpath(*h.RECOVERY, "hooks", "active.json").exists())
        self.assertEqual(self.run_action("restore")["status"], "PREPARATION_ABORTED_NO_MUTATION")
        self.assertEqual(self.target.read_bytes(), self.before)

    def test_swap_interrupt_unknown_displaced_preimage_is_durably_bound_and_refused(self):
        third = self.before.replace(b'"Stop": [', b'"Stop": [ {"owner": "third"},')
        original_swap = h.swap
        def interrupt(directory, left, right):
            self.target.write_bytes(third)
            original_swap(directory, left, right)
            raise KeyboardInterrupt()
        with patch.object(h, "swap", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_action("disable")
        directory = self.home.joinpath(*h.RECOVERY, "hooks")
        intent = h.parse((directory / "publication.json").read_bytes())
        self.assertEqual((self.codex / intent["stage"]).read_bytes(), third)
        before_restore = self.target.read_bytes()
        with self.assertRaisesRegex(h.OfframpError, "publication_displaced_unknown_handoff"):
            self.run_action("restore")
        self.assertEqual(self.target.read_bytes(), before_restore)
        self.assertEqual((self.codex / intent["stage"]).read_bytes(), third)

    def test_swap_interrupt_exact_displaced_preimage_can_restore(self):
        original_swap = h.swap
        def interrupt(directory, left, right):
            original_swap(directory, left, right)
            raise KeyboardInterrupt()
        with patch.object(h, "swap", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_action("disable")
        self.assertEqual(self.run_action("restore")["status"], "RESTORED")
        self.assertEqual(self.target.read_bytes(), self.before)

    def test_restore_swap_interrupt_unknown_displaced_state_cannot_report_already_restored(self):
        self.run_action("disable")
        third = self.target.read_bytes().replace(b'"Stop": [', b'"Stop": [ {"owner": "third"}')
        original_swap = h.swap
        def interrupt(directory, left, right):
            self.target.write_bytes(third)
            original_swap(directory, left, right)
            raise KeyboardInterrupt()
        with patch.object(h, "swap", side_effect=interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_action("restore")
        before_second = self.target.read_bytes()
        with self.assertRaisesRegex(h.OfframpError, "restoration_displaced_unknown_handoff"):
            self.run_action("restore")
        self.assertEqual(self.target.read_bytes(), before_second)

    def test_named_custody_lock_replacement_refuses_publication(self):
        def change():
            lock = self.home.joinpath(*h.RECOVERY, "custody.lock")
            lock.rename(lock.with_suffix(".displaced"))
            lock.write_bytes(b"")
            lock.chmod(0o600)
        with self.assertRaisesRegex(h.OfframpError, "custody_drift"):
            self.run_action("disable", before_publish=change)
        self.assertEqual(self.target.read_bytes(), self.before)

    def test_concurrent_post_publish_not_overwritten(self):
        concurrent = h.build_plan(self.before, MANIFEST, HISTORICAL, "disable").after + b"\n"
        def change():
            self.target.write_bytes(concurrent)
        with self.assertRaisesRegex(h.OfframpError, "recovery_required"):
            self.run_action("disable", after_publish=change)
        self.assertEqual(self.target.read_bytes(), concurrent)
        self.run_action("restore")
        self.assertEqual(self.target.read_bytes(), self.before + b"\n")

    def test_symlink_target_hardlink_and_parent_refused(self):
        self.target.unlink()
        outside = self.home / "outside"
        outside.write_bytes(self.before)
        self.target.symlink_to(outside)
        with self.assertRaises((h.OfframpError, OSError)):
            self.run_action("disable")
        self.assertEqual(outside.read_bytes(), self.before)
        self.target.unlink()
        os.link(outside, self.target)
        with self.assertRaises(h.OfframpError):
            self.run_action("disable")
        self.target.unlink()
        self.codex.rename(self.home / "moved")
        self.codex.symlink_to(self.home / "moved")
        with self.assertRaises((h.OfframpError, OSError)):
            self.run_action("disable")

    def test_parent_swap_during_publish_has_zero_outside_writes(self):
        outside = self.home / "outside"
        outside.mkdir()
        outside_target = outside / "hooks.json"
        outside_target.write_bytes(b"untouched")
        def change():
            self.codex.rename(self.home / "moved")
            self.codex.symlink_to(outside)
        with self.assertRaises(h.OfframpError):
            self.run_action("disable", before_publish=change)
        self.assertEqual(outside_target.read_bytes(), b"untouched")

    def test_restore_concurrent_unknown_affected_array_preserved(self):
        self.run_action("disable")
        concurrent = self.target.read_bytes().replace(b'"Stop": [', b'"Stop": [ {"third": true}')
        self.target.write_bytes(concurrent)
        with self.assertRaises(h.OfframpError):
            self.run_action("restore")
        self.assertEqual(self.target.read_bytes(), concurrent)

    def test_busy_cross_operation_custody(self):
        self.run_action("disable")
        lock = os.open(self.home.joinpath(*h.RECOVERY, "custody.lock"), os.O_RDWR)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(h.OfframpError, "operation_busy"):
                self.run_action("restore", operation="second")
        finally:
            os.close(lock)

    def test_recovery_corruption_refuses(self):
        self.run_action("disable")
        directory = self.home.joinpath(*h.RECOVERY, "hooks")
        (directory / "before.json").write_bytes(self.before + b"\n")
        current = self.target.read_bytes()
        with self.assertRaisesRegex(h.OfframpError, "recovery_corrupt"):
            self.run_action("restore")
        self.assertEqual(self.target.read_bytes(), current)

    def test_exact_recovery_types_reject_boolean_count_and_numeric_schema(self):
        self.target.write_bytes(h.wire({"hooks": {"Stop": [DEFS["legacyStop"][1]]}}))
        self.run_action("disable")
        record_path = self.home.joinpath(*h.RECOVERY, "hooks", "active.json")
        original = h.parse(record_path.read_bytes())
        current = self.target.read_bytes()
        for field, value in (("removed", True), ("schema", 1.0), ("events", ["Stop", "Stop"]),
                             ("events", [True]), ("action", False)):
            record = copy.deepcopy(original)
            record[field] = value
            record_path.write_bytes(h.wire(record))
            with self.subTest(field=field, value=value), self.assertRaisesRegex(h.OfframpError, "recovery_record"):
                self.run_action("restore")
            self.assertEqual(self.target.read_bytes(), current)

    def install_passive(self):
        aid = self.home / "AIDev/bin/aid"
        aid.parent.mkdir(parents=True)
        aid.symlink_to("/nix/store/fixture-home-manager-files/AIDev/bin/aid")
        skill = self.home / ".codex/skills/manage-workstation/SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_bytes((h.ROOT / "skills/manage-workstation/SKILL.md").read_bytes())
        skill.chmod(0o600)
        return aid, skill

    def test_actual_passive_remove_restore_preserves_payloads_and_trust(self):
        aid, skill = self.install_passive()
        source = skill.read_bytes()
        link = os.fsencode(os.readlink(aid))
        report = self.run_action("remove", link_witness=(link, lambda: True))
        self.assertFalse(aid.is_symlink())
        self.assertFalse(skill.exists())
        self.assertFalse(report["harnessRemovalComplete"])
        self.run_action("restore")
        self.assertEqual(os.fsencode(os.readlink(aid)), link)
        self.assertEqual(skill.read_bytes(), source)
        self.assertEqual(self.payload.read_bytes(), b"save-data")
        self.assertEqual(self.config.read_text(), 'native-trust = "owner-state"\n')

    def test_unknown_passive_preserved_not_adopted(self):
        aid, skill = self.install_passive()
        skill.write_bytes(b"owner-edit")
        report = self.run_action("remove")
        self.assertTrue(aid.is_symlink())
        self.assertEqual(skill.read_bytes(), b"owner-edit")
        self.assertEqual([r["status"] for r in report["passiveTargets"]], ["RETAINED_EXTERNAL"] * 2)

    def test_passive_rename_race_returns_actual_third_state_without_overwrite(self):
        aid, skill = self.install_passive()
        original_rename = h.rename
        def race(directory, left, right, flag):
            if left == "SKILL.md":
                skill.write_bytes(b"owner-third-state")
            return original_rename(directory, left, right, flag)
        with patch.object(h, "rename", side_effect=race):
            with self.assertRaisesRegex(h.OfframpError, "passive_recovery_required"):
                self.run_action("remove")
        self.assertEqual(skill.read_bytes(), b"owner-third-state")
        with self.assertRaises(h.OfframpError):
            self.run_action("restore")
        self.assertEqual(skill.read_bytes(), b"owner-third-state")

    def test_interruption_before_passive_move_reconciles_exact_untouched_targets(self):
        aid, skill = self.install_passive()
        original = skill.read_bytes()
        with patch.object(h, "passive_apply", side_effect=RuntimeError("interrupted")):
            with self.assertRaises(RuntimeError):
                self.run_action("remove")
        self.assertTrue(skill.exists())
        self.run_action("restore")
        self.assertEqual(self.target.read_bytes(), self.before)
        self.assertEqual(skill.read_bytes(), original)

    def test_passive_only_remove_and_restore_without_hooks(self):
        aid, skill = self.install_passive()
        self.target.write_bytes(b'{"hooks":{"SessionStart":[],"Stop":[],"PreToolUse":[]}}')
        self.run_action("remove")
        self.assertFalse(skill.exists())
        self.run_action("restore")
        self.assertTrue(skill.exists())

    def test_passive_restore_collision_does_not_overwrite_or_reenable_hooks(self):
        aid, skill = self.install_passive()
        self.run_action("remove")
        after = self.target.read_bytes()
        skill.write_bytes(b"third-choice")
        with self.assertRaises(h.OfframpError):
            self.run_action("restore")
        self.assertEqual(skill.read_bytes(), b"third-choice")
        self.assertEqual(self.target.read_bytes(), after)

    def test_no_live_default_and_redacted_cli_errors(self):
        emitted = []
        self.assertEqual(h.main(["disable"], emit=emitted.append), 1)
        self.assertEqual(h.main(["disable", "--live-commit", "private-data"], emit=emitted.append), 1)
        self.assertNotIn("private-data", "".join(emitted))
        with self.assertRaises(h.OfframpError):
            h.execute_fixture(Path.home(), "status")

    def test_cli_source_refusal_keeps_closed_reason_scope_and_next_action(self):
        from lib import scoped_source_admission as source
        control = self.home / "AIDev/control"
        for reason, public in (("affected_source_drift", "affected_source_drift"),
                               ("private/path/not-a-public-code", "source_admission_failed")):
            emitted = []
            with self.subTest(reason=reason), patch.object(h, "ROOT", control), \
                    patch.object(Path, "home", return_value=self.home), \
                    patch.object(h, "_sources", return_value=(MANIFEST, HISTORICAL)), \
                    patch("lib.user_operation_readiness.require_scoped_operation_ready",
                          side_effect=source.SourceError(reason)):
                self.assertEqual(h.main(["disable", "--live-commit", "a" * 40,
                                         "--operation", "source-error-" + public.replace("_", "-")],
                                        emit=emitted.append), 1)
            report = json.loads(emitted[0])
            self.assertEqual(report["reason"], public)
            self.assertEqual(report["affectedScope"], "affected-user-helper-source")
            self.assertEqual(report["nextAction"], "review_affected_source_and_retry")
            self.assertNotIn("private/path", emitted[0])
            self.assertEqual(self.target.read_bytes(), self.before)


if __name__ == "__main__":
    unittest.main()
