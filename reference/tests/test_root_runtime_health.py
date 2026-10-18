"""Synthetic component-health evidence; never invoke native sudo or root paths."""
import copy
import hashlib
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import root_runtime_health as health


class Fixture:
    def __init__(self, selected="successor"):
        self.selected = selected
        def pin(raw):
            return {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        self.contract = {name: {"broker": pin(name.encode()), "policy": pin(b"policy"),
            "sudoers": pin(b"sudoers"), "attestation": {"size": 341}}
            for name in ("successor", "predecessor")}
        def file(raw, mode, private=False, size=None):
            return {"uid": 0, "gid": 0, "mode": mode, "kind": "file", "nlink": 1,
                "size": len(raw) if size is None else size, "data": None if private else raw}
        self.values = {
            health.BROKER: file(selected.encode(), 0o555),
            health.POLICY: file(b"policy", 0o444),
            health.ATTESTATION: file(b"", 0o400, True, 341),
            health.SUDOERS: file(b"sudoers", 0o440, True),
            **{p: {"uid": 0, "gid": 0, "mode": 0o700, "kind": "directory"} for p in health.DIRECTORIES},
            **{p: True for p in health.ABSENCES},
        }
        checks = {key: True for key in ("emergency_disable_absent", "installed_artifact_attestation",
                                       "installed_contract", "operation_settled", "policy_hash")}
        self.response = {"checks": checks, "command": "doctor-root", "problems": [], "readOnly": True,
            "schema": 1, "systemMutationsPerformed": False, "verdict": "ROOT_CONTRACT_READY"}
        self.commands = []
        self.source = lambda: True
        self.pair = lambda: True

    def observe(self, kind, path):
        return copy.deepcopy(self.values[path])

    def run(self, argv):
        self.commands.append(argv)
        return 0, json.dumps(self.response).encode(), b"", True

    def inspect(self, **kwargs):
        arguments = dict(observe=self.observe, runner=self.run, paired_guard=self.pair, source_guard=self.source)
        arguments.update(kwargs)
        return health.inspect_installed(self.contract, **arguments)


class RootRuntimeHealthTests(unittest.TestCase):
    def test_successor_requires_exact_fixed_typed_doctor(self):
        f = Fixture()
        report = f.inspect()
        self.assertEqual(f.commands, [("/usr/bin/sudo", "-n", health.BROKER, "doctor-root", "--json")])
        self.assertEqual(report["verdict"], "ROOT_RUNTIME_READY")
        self.assertTrue(report["operationJournalSettled"])
        self.assertIs(report["rootPrivateConsistencyAttestedByTypedDoctor"], True)
        self.assertIs(report["rootOwnedStateTrustAssumed"], True)
        self.assertIs(report["expectedPrivatePolicyHashVerified"], False)
        for key in ("nativeAuthenticationExercised", "emergencyActionsExecuted", "wholeMachineHealth", "installationAuthorized", "systemMutationsPerformed"):
            self.assertIs(report[key], False)

    def test_predecessor_not_ongoing_successor_health(self):
        f = Fixture("predecessor")
        with self.assertRaises(health.HealthError):
            f.inspect()
        self.assertEqual(f.commands, [])
        report = f.inspect(allow_predecessor=True)
        self.assertEqual(report["verdict"], "PREDECESSOR_READY")
        self.assertIs(report["operationJournalSettled"], True)

    def test_predecessor_requires_real_boolean_settlement_and_all_five_checks(self):
        for key in Fixture("predecessor").response["checks"]:
            for invalid in (False, 1, None, "true"):
                f = Fixture("predecessor")
                f.response["checks"][key] = invalid
                with self.subTest(key=key, invalid=invalid), self.assertRaisesRegex(
                        health.HealthError, "root_doctor_contract"):
                    f.inspect(allow_predecessor=True)
                self.assertEqual(f.commands, [health.COMMAND])

    def test_current_release_predecessor_is_the_journal_aware_broker(self):
        release = health.delivery.load_release(Path(__file__).resolve().parents[1])
        self.assertEqual(release["installedContracts"]["predecessor"]["broker"], {
            "sha256": "ccf7c87823476892f35d25ae5b65e614fbd9e2fc1ae6e8c409644e800e291b54",
            "size": 813680,
        })

    def test_handoff_health_adapter_observes_predecessor_settlement(self):
        f = Fixture("predecessor")
        observer = mock.Mock(observe=f.observe)
        release = object()
        uid = health.os.getuid()
        home = health.pwd.getpwuid(uid).pw_dir
        with mock.patch.object(health, "NativeObservation", return_value=observer), \
             mock.patch.object(health.delivery, "health_contract", return_value=f.contract), \
             mock.patch.object(health.delivery, "verify_durable", return_value={}) as pair, \
             mock.patch.object(health, "bounded", side_effect=lambda argv, **kw: f.run(tuple(argv))):
            report = health.native_health(release, home, uid, f.source, allow_predecessor=True)
        self.assertEqual(report["verdict"], "PREDECESSOR_READY")
        self.assertIs(report["operationJournalSettled"], True)
        self.assertEqual(f.commands, [health.COMMAND])
        self.assertEqual(pair.call_count, 3)
        observer.close.assert_called_once_with()

    def test_unknown_or_corrupt_broker_never_executes(self):
        for raw in (b"unknown", b"suCcessor", b"", b"successor\x00"):
            f = Fixture()
            f.values[health.BROKER]["data"] = raw
            with self.subTest(raw=raw), self.assertRaises(health.HealthError):
                f.inspect(allow_predecessor=True)
            self.assertEqual(f.commands, [])

    def test_metadata_ownership_mode_link_and_private_content(self):
        for path, key, value in ((health.BROKER, "uid", 501), (health.BROKER, "gid", 80),
                (health.BROKER, "nlink", 2), (health.BROKER, "mode", 0o755),
                (health.POLICY, "data", b"Policy"), (health.POLICY, "size", True),
                (health.ATTESTATION, "mode", 0o444), (health.ATTESTATION, "size", 340),
                (health.SUDOERS, "data", b"sudoers"), (health.SUDOERS, "kind", "symlink"),
                (health.DIRECTORIES[0], "uid", False), (health.DIRECTORIES[1], "mode", 0o755)):
            f = Fixture()
            f.values[path][key] = value
            with self.subTest(path=path, key=key, value=value), self.assertRaises(health.HealthError):
                f.inspect()
            self.assertEqual(f.commands, [])

    def test_disabled_or_unknown_absence_never_executes(self):
        for absent in health.ABSENCES:
            for value in (False, None, 1, "absent"):
                f = Fixture()
                f.values[absent] = value
                with self.subTest(absent=absent, value=value), self.assertRaises(health.HealthError):
                    f.inspect()
                self.assertEqual(f.commands, [])

    def test_source_or_pair_guard_at_each_boundary(self):
        for name in ("source_guard", "paired_guard"):
            for position in range(3):
                f = Fixture()
                answers = iter([True] * position + [False])
                with self.subTest(name=name, position=position), self.assertRaises(health.HealthError):
                    f.inspect(**{name: lambda: next(answers)})
                self.assertEqual(len(f.commands), int(position == 2))

    def test_private_attestation_failure_or_unknown_is_not_health(self):
        for changes in ({"installed_contract": False}, {"operation_settled": False}, {"policy_hash": 1}):
            f = Fixture()
            f.response["checks"].update(changes)
            with self.subTest(changes=changes), self.assertRaises(health.HealthError):
                f.inspect()

    def test_settled_exit_zero_and_clean_exact_protocol_required(self):
        good = Fixture().run(())
        variants = [(1, good[1], b"", True), (False, good[1], b"", True),
            (0, good[1], b"warning", True), (0, good[1], b"", False),
            (0, good[1], b"", 1), (0, b"{}", b"", True),
            (0, good[1].replace(b'"schema": 1', b'"schema": true'), b"", True),
            (0, b'{"schema":1,"schema":1}', b"", True),
            (0, b'{"value":NaN}', b"", True), (0, b"x" * 16385, b"", True),
            [0, good[1], b"", True]]
        for response in variants:
            with self.subTest(response=str(response)[:60]), self.assertRaises(health.HealthError):
                Fixture().inspect(runner=lambda _: response)

    def test_additional_or_missing_check_cannot_masquerade_as_current_contract(self):
        for selected in ("successor", "predecessor"):
            for missing in Fixture(selected).response["checks"]:
                f = Fixture(selected)
                del f.response["checks"][missing]
                with self.subTest(selected=selected, missing=missing), self.assertRaisesRegex(
                        health.HealthError, "root_doctor_contract"):
                    f.inspect(allow_predecessor=True)
            f = Fixture(selected)
            f.response["checks"]["unexpected_check"] = True
            with self.subTest(selected=selected, extra=True), self.assertRaisesRegex(
                    health.HealthError, "root_doctor_contract"):
                f.inspect(allow_predecessor=True)

    def test_post_command_drift_rejects_every_observation(self):
        for path in Fixture().values:
            f = Fixture()
            def run(argv):
                result = f.run(argv)
                if type(f.values[path]) is dict:
                    f.values[path]["uid"] = 501
                else:
                    f.values[path] = False
                return result
            with self.subTest(path=path), self.assertRaises(health.HealthError):
                f.inspect(runner=run)

    def test_usage_does_not_observe_and_failures_are_redacted(self):
        observe = mock.Mock(side_effect=RuntimeError("private recovery content"))
        output = []
        self.assertEqual(health.main(["--apply"], inspect=observe, emit=output.append), 2)
        observe.assert_not_called()
        self.assertEqual(health.main(["--json"], inspect=observe, emit=output.append), 1)
        self.assertNotIn("private recovery content", "".join(output))
        self.assertEqual(json.loads(output[-1])["verdict"], "BLOCKED")

    def test_directory_identity_replacement_refused_with_unchanged_metadata(self):
        observation = health.NativeObservation()
        before = SimpleNamespace(st_dev=1, st_ino=7, st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0)
        after = SimpleNamespace(**{**vars(before), "st_ino": 8})
        with mock.patch.object(observation, "parents", side_effect=lambda path: path), \
             mock.patch.object(health.os, "lstat", side_effect=[before, after]):
            self.assertEqual(observation.observe("directory", health.DIRECTORIES[0])["mode"], 0o700)
            with self.assertRaisesRegex(health.HealthError, "root_directory_drift"):
                observation.observe("directory", health.DIRECTORIES[0])

    def test_shared_mutable_observation_cannot_hide_after_command_drift(self):
        f = Fixture()
        def run(argv):
            result = f.run(argv)
            f.values[health.BROKER]["uid"] = 501
            return result
        with self.assertRaisesRegex(health.HealthError, "root_observation_drift"):
            f.inspect(observe=lambda kind, path: f.values[path], runner=run)

    def test_native_entry_holds_scoped_source_without_historical_admission(self):
        source_guard = mock.Mock(return_value=True)
        release = object()
        report = {"verdict": "synthetic-result"}
        def admitted(*, operation_check, entrypoint):
            self.assertEqual(entrypoint, 'bin/root-runtime-doctor')
            self.assertIs(operation_check("f" * 40, source_guard=source_guard), True)
        with mock.patch.object(health.os, "getuid", return_value=501), \
             mock.patch.object(health.pwd, "getpwuid", return_value=mock.Mock(pw_dir="/synthetic")), \
             mock.patch.object(health, "ROOT", Path("/synthetic/AIDev/control")), \
             mock.patch.object(Path, "resolve", return_value=Path("/synthetic/AIDev/control")), \
             mock.patch.object(health.delivery, "load_release", return_value=release), \
             mock.patch.object(health, "native_health", return_value=report) as inspect, \
             mock.patch.object(health.delivery, "admitted_source", side_effect=admitted):
            self.assertIs(health.native(), report)
            inspect.assert_called_once_with(release, "/synthetic", 501, source_guard)


if __name__ == "__main__":
    unittest.main()
