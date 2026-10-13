"""Pure injected observations/commands; actual P4 validator bodies, no native IO.

Only immutable public repository evidence is read as fixture input. No private
file, root state, subprocess, Git child, sudo, Nix, or doctor is executed.
"""

import copy
import importlib.machinery
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import phase5_phase4_health as H

HOME = "/Users/synthetic-owner"
CONTROL = HOME + "/AIDev/control"
REVISION = "b" * 40
TREE = "c" * 40
TARGET = "/nix/store/current-synthetic-target"
P2_RAW = (ROOT / H.P2_FILE).read_bytes()  # tracked, public, immutable fixture


def raw(value):
    return (json.dumps(value, sort_keys=True) + "\n").encode()


def file(data, *, uid=501, mode=0o644):
    return {"data": data, "uid": uid, "gid": 20 if uid else 0, "mode": mode,
            "kind": "file", "nlink": 1, "symlink": False, "size": len(data)}


class Budget:
    def __init__(self):
        self.error = None
        self.calls = 0

    def check(self):
        self.calls += 1
        if self.error is not None:
            raise self.error


class World:
    def __init__(self):
        # Separate module namespace; no source bodies are patched to return PASS.
        self.P4 = importlib.machinery.SourceFileLoader("phase4_health_fixture_module", str(ROOT / "bin/phase4-final-doctor")).load_module()
        self.P4.ROOT = Path(CONTROL)
        self.calls, self.observations = [], []
        self.rechecks = 0
        self.admitted = True
        self.recheck_error = self.command_effect = self.observation_effect = None
        self.budget = Budget()
        packages = {"sources": {"nix_darwin": {"revision": "d" * 40}, "nixpkgs": {"revision": "e" * 40}}}
        version = {"configurationRevision": REVISION, "darwinLabel": "26.05." + "d" * 7,
                   "darwinRevision": "d" * 40, "nixpkgsRevision": "e" * 40}
        def generation(path):
            return {"gid": 0, "kind": "directory", "mode": 0o555, "path": path,
                    "substituted": False, "uid": 0}
        self.current = {"profileTarget": TARGET, "systemTarget": TARGET,
            "targets": {2: generation("/nix/store/historical-two"), 3: generation("/nix/store/historical-three"),
                        27: generation(TARGET)},
            "versionLink": {"gid": 0, "kind": "symlink", "mode": 0o755, "uid": 0},
            "versionFile": {"gid": 0, "kind": "file", "modeWritable": False, "owner": 0,
                            "parent": "/nix/store", "sizeBounded": True}, "versionBytes": raw(version)}
        self.P4.PREVIOUS_PATH_SHA256 = H.sha(b"/nix/store/historical-two")
        self.P4.TARGET_PATH_SHA256 = H.sha(b"/nix/store/historical-three")
        self.receipt_path = HOME + "/AIDev/state/phase-4/apply-receipts/" + REVISION + ".json"
        receipt = {"controlCommit": REVISION, "controlTree": TREE, "policyHash": self.P4.POLICY_SHA256,
            "reviewed": True, "schema": 1, "targetSystemNarHash": "sha256-synthetic-nar", "targetSystemPath": TARGET}
        self.files = {CONTROL + "/" + H.P2_FILE: file(P2_RAW),
                      CONTROL + "/manifests/package-sources.json": file(raw(packages)),
                      self.receipt_path: file(raw(receipt), mode=0o400),
                      H.BROKER: file(b"b" * 483712, uid=0, mode=0o555),
                      H.POLICY: file(b"p" * 1617, uid=0, mode=0o444),
                      H.SUDOERS: file(b"s" * 122, uid=0, mode=0o440)}
        self.P4.BROKER_SHA256 = H.sha(self.files[H.BROKER]["data"])
        self.P4.POLICY_SHA256 = H.sha(self.files[H.POLICY]["data"])
        receipt["policyHash"] = self.P4.POLICY_SHA256
        self.files[self.receipt_path] = file(raw(receipt), mode=0o400)
        for name in self.P4.PHASE3_HASHES:
            self.files[CONTROL + "/" + name] = file((ROOT / name).read_bytes())
        self.directories = {p: {"gid": 0, "kind": "directory", "mode": 0o700, "symlink": False, "uid": 0}
                            for p in H.DIRECTORIES.values()}
        self.absence = {p: True for p in H.EMERGENCY}
        def observed(kind, *arguments):
            self.observations.append((kind, arguments))
            if self.observation_effect:
                self.observation_effect(kind, arguments)
            if kind == "current":
                return copy.deepcopy(self.current)
            if kind == "metadata":
                return {k: copy.deepcopy(v) for k, v in self.files[str(arguments[0])].items() if k != "data"}
            table = {"file": self.files, "directory": self.directories, "absent": self.absence}[kind]
            return copy.deepcopy(table[str(arguments[0])])
        self.io = SimpleNamespace(file=lambda p: observed("file", p), metadata=lambda p: observed("metadata", p),
            directory=lambda p: observed("directory", p),
            absent=lambda p: observed("absent", p), current=lambda: observed("current"),
            json=lambda p: H.parse(self.files[str(p)]["data"]),
            digest=lambda p: H.sha(self.files[str(p)]["data"]))
        self.runner = self.run
        self.P4.run, self.P4.strict_json, self.P4.digest = self.runner, self.io.json, self.io.digest

    def run(self, arguments, cwd=None, environment=None):
        args = tuple(map(str, arguments))
        self.calls.append(args)
        if self.command_effect:
            result = self.command_effect(args)
            if result is not None:
                return result
        if cwd is not None:
            assert str(cwd) == CONTROL
        prefix = tuple(self.P4.GIT)
        code, output = 0, ""
        if args[:len(prefix)] == prefix:
            git = args[len(prefix):]
            allowed = {
                ("rev-parse", "HEAD"): H.BASE + "\n",
                ("branch", "--show-current"): "main\n",
                ("status", "--porcelain=v1", "--untracked-files=all"): "",
                ("show", H.P2 + ":" + H.P2_FILE): P2_RAW.decode(),
                ("rev-parse", H.P2 + "^"): H.P2_PARENT + "\n",
                ("show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce%x00%s", H.P2): "\0".join(H.P2_METADATA) + "\n",
                ("diff-tree", "--no-commit-id", "--name-status", "-r", H.P2):
                    "\n".join(kind + "\t" + p for p, kind in H.P2_CHANGES.items()) + "\n",
                ("merge-base", "--is-ancestor", H.P2_PARENT, H.BASE): "",
                ("merge-base", "--is-ancestor", H.P2, H.BASE): "",
                ("cat-file", "-e", REVISION + "^{commit}"): "",
                ("cat-file", "-t", REVISION + "^{commit}"): "commit\n",
                ("merge-base", "--is-ancestor", "a2a607956745ca9a3f85960b3da0b98463a33880", REVISION): "",
                ("merge-base", "--is-ancestor", REVISION, "HEAD"): "",
                ("rev-parse", REVISION + "^{tree}"): TREE + "\n",
            }
            if git not in allowed:
                raise AssertionError("unexpected Git observation")
            output = allowed[git]
        elif args == ("/usr/bin/sudo", "-n", H.BROKER, "doctor-root", "--json"):
            output = raw({"checks": {"emergency_disable_absent": True, "installed_artifact_attestation": True,
                "installed_contract": True, "policy_hash": True}, "command": "doctor-root", "problems": [],
                "readOnly": True, "schema": 1, "systemMutationsPerformed": False, "verdict": "ROOT_CONTRACT_READY"}).decode()
        elif args == ("/usr/bin/sudo", "-n", H.BROKER, "unknown"):
            code, output = 64, "aid-admin: rejected: unknown_command\n"
        elif args in (("/usr/bin/sudo", "-n", "/usr/bin/true"), ("/usr/bin/sudo", "-n", "-v")):
            code, output = 1, "synthetic denial\n"
        elif args == ("/nix/var/nix/profiles/default/bin/nix-store", "--query", "--hash", TARGET):
            output = "sha256-synthetic-nar\n"
        elif args == ("/bin/ps", "-axo", "comm="):
            output = "/usr/bin/ordinary-synthetic-process\n"
        else:
            raise AssertionError("unexpected command")
        return SimpleNamespace(returncode=code, stdout=output)

    def recheck(self):
        self.rechecks += 1
        if self.recheck_error:
            raise self.recheck_error
        return True

    def collect(self, **overrides):
        args = dict(P4=self.P4, control=CONTROL, home=HOME, uid=501, runner=self.runner, io=self.io,
                    budget=self.budget, admit_dependencies=lambda *a: self.admitted, recheck=self.recheck)
        args.update(overrides)
        with patch.object(self.P4.subprocess, "run", side_effect=AssertionError("native forbidden")):
            return H.collect(**args)


class ComponentTests(unittest.TestCase):
    def rejected(self, world):
        with self.assertRaises(H.HealthError) as caught:
            world.collect()
        value = caught.exception.outcome.public
        self.assertEqual(value["verdict"], "NEEDS_REVIEW")
        self.assertFalse(value["currentPhase4Health"])
        self.assertTrue(all(value[k] is False for k in H.AUTHORITY))
        self.assertNotIn(HOME, json.dumps(value))
        self.assertNotIn(TARGET, json.dumps(value))
        return caught.exception

    def test_actual_validator_composed_without_native_calls_or_old_topology(self):
        world = World()
        value = world.collect()
        self.assertEqual(value["verdict"], "CURRENT_PHASE4_COMPONENT_HEALTH")
        self.assertTrue(value["historicalPhase2Accepted"] and value["historicalPhase3Accepted"])
        self.assertFalse(value["phase2LiveDoctorExecuted"] or value["historicalPhase4CLIExecuted"])
        self.assertEqual(world.rechecks, 2)
        self.assertTrue(all(value[k] is False for k in H.AUTHORITY))
        self.assertFalse(any("rev-list" in c or "clone" in c for c in world.calls))

    def test_receipt_selected_from_observed_revision_not_old_fixed_file(self):
        world = World()
        world.collect()
        receipts = [args[0] for kind, args in world.observations if kind == "file" and "apply-receipts/" in args[0]]
        self.assertEqual(receipts, [world.receipt_path] * 2)
        self.assertNotIn("21", str(receipts))

    def test_missing_dependency_admission_zero_observations(self):
        world = World()
        world.admitted = False
        self.rejected(world)
        self.assertEqual(world.calls, [])
        self.assertEqual(world.observations, [])

    def test_unbound_P4_runner_or_io_rejected_before_observation(self):
        for field in ("run", "strict_json", "digest"):
            world = World()
            setattr(world.P4, field, lambda *a, **k: True)
            self.rejected(world)
            self.assertFalse(world.calls or world.observations)

    def test_exact_baseline_and_attached_clean_main_required(self):
        for suffix, output in ((("rev-parse", "HEAD"), "f" * 40),
                               (("branch", "--show-current"), "other"),
                               (("status", "--porcelain=v1", "--untracked-files=all"), "dirty")):
            world = World()
            world.command_effect = lambda args, s=suffix, text=output: SimpleNamespace(returncode=0, stdout=text) if args[-len(s):] == s else None
            self.rejected(world)
            self.assertFalse(world.observations)

    def test_phase2_actual_multi_file_scope_parent_and_metadata_are_exact(self):
        for token, text in (("diff-tree", "A\tevidence/phase-2/acceptance.json\n"),
                            ("--format=%an%x00%ae%x00%cn%x00%ce%x00%s", "invented coordinator"),
                            (H.P2 + "^", "f" * 40)):
            world = World()
            world.command_effect = lambda args, t=token, value=text: SimpleNamespace(returncode=0, stdout=value) if t in args else None
            error = self.rejected(world)
            self.assertFalse(error.outcome.public["historicalPhase2Accepted"])

    def test_phase2_content_or_ancestor_failure_does_not_self_admit(self):
        world = World()
        world.files[CONTROL + "/" + H.P2_FILE]["data"] += b" "
        self.rejected(world)
        world = World()
        world.command_effect = lambda args: SimpleNamespace(returncode=1, stdout="") if "merge-base" in args else None
        self.rejected(world)

    def test_phase3_exact_validator_failure_propagates(self):
        world = World()
        location = CONTROL + "/evidence/phase-3/permissions-acceptance.json"
        world.files[location]["data"] += b" "
        error = self.rejected(world)
        self.assertEqual(error.outcome.public["failureStage"], "phase3-history")

    def test_generation_path_type_bool_and_substitution_fail_before_privileged_commands(self):
        for key, value in (("substituted", True), ("uid", False), ("mode", True),
                           ("path", "/nix/store/a/../b"), ("path", "/outside")):
            world = World()
            world.current["targets"][27][key] = value
            self.rejected(world)
            self.assertFalse(any(c[0] == "/usr/bin/sudo" for c in world.calls))

    def test_current_profile_and_version_metadata_must_match(self):
        for mutate in (lambda w: w.current.update(systemTarget="/nix/store/other"),
                       lambda w: w.current["versionFile"].update(modeWritable=True),
                       lambda w: w.current["versionLink"].update(uid=True),
                       lambda w: w.current.update(versionBytes=b'{"configurationRevision":"../private"}')):
            world = World()
            mutate(world)
            self.rejected(world)

    def test_receipt_metadata_and_exact_types(self):
        for key, bad in (("mode", 0o600), ("nlink", 2), ("symlink", True), ("uid", 0)):
            world = World()
            world.files[world.receipt_path][key] = bad
            self.rejected(world)
        for key, bad in (("reviewed", 1), ("schema", True), ("controlCommit", "f" * 40),
                         ("targetSystemPath", "/nix/store/other"), ("controlTree", "f" * 40),
                         ("targetSystemNarHash", "sha256-other")):
            world = World()
            value = H.parse(world.files[world.receipt_path]["data"])
            value[key] = bad
            world.files[world.receipt_path] = file(raw(value), mode=0o400)
            self.rejected(world)

    def test_artifact_drift_modes_and_metadata_fail(self):
        for location, key, bad in ((H.BROKER, "data", b"bad"), (H.POLICY, "mode", 0o666),
                                   (H.SUDOERS, "uid", 501), (H.BROKER, "nlink", True)):
            world = World()
            world.files[location][key] = bad
            self.rejected(world)

    def test_root_directory_and_emergency_state_fail(self):
        for kind in ("directory", "emergency"):
            world = World()
            if kind == "directory":
                world.directories[H.DIRECTORIES["audit"]]["gid"] = True
            else:
                world.absence[H.EMERGENCY[1]] = False
            self.rejected(world)

    def test_sudoers_is_metadata_only_never_read(self):
        world = World()
        def effect(kind, args):
            if args and str(args[0]) == H.SUDOERS:
                self.assertEqual(kind, "metadata")
        world.observation_effect = effect
        original_json, original_digest = world.io.json, world.io.digest
        def no_sudoers(callback):
            def call(p):
                self.assertNotEqual(str(p), H.SUDOERS)
                return callback(p)
            return call
        world.io.json, world.io.digest = no_sudoers(original_json), no_sudoers(original_digest)
        world.P4.strict_json, world.P4.digest = world.io.json, world.io.digest
        self.assertTrue(world.collect()["currentPhase4Health"])
        self.assertEqual([kind for kind, args in world.observations if args and args[0] == H.SUDOERS],
                         ["metadata", "metadata"])

    def test_sudoers_exact_metadata_types_and_root_wheel(self):
        for key, value in (("gid", 20), ("uid", False), ("mode", 0o644), ("nlink", 2), ("symlink", True)):
            world = World()
            world.files[H.SUDOERS][key] = value
            self.rejected(world)

    def test_root_exact_json_boolint_unknown_and_generic_denial(self):
        for kind in ("bool", "unknown", "generic", "process"):
            world = World()
            def effect(args):
                if kind == "bool" and "doctor-root" in args:
                    return SimpleNamespace(returncode=0, stdout=raw({"schema": True}).decode())
                if kind == "unknown" and "unknown" in args:
                    return SimpleNamespace(returncode=64, stdout="wrong reason\n")
                if kind == "generic" and "/usr/bin/true" in args:
                    return SimpleNamespace(returncode=0, stdout="")
                if kind == "process" and args[0] == "/bin/ps":
                    return SimpleNamespace(returncode=0, stdout="/usr/local/libexec/aid-admin\n")
            world.command_effect = effect
            self.rejected(world)

    def test_observation_drift_still_calls_root_final_guard(self):
        world = World()
        count = [0]
        def effect(kind, args):
            if kind == "current":
                count[0] += 1
                if count[0] == 2:
                    world.current["versionBytes"] += b" "
        world.observation_effect = effect
        self.rejected(world)
        self.assertEqual(world.rechecks, 2)

    def test_unknown_child_retained_and_no_additional_commands(self):
        world = World()
        owner = object()
        error = RuntimeError("private failed child")
        error.private_owner, error.settlement_failed = owner, True
        def effect(args):
            if "doctor-root" in args:
                raise error
        world.command_effect = effect
        caught = self.rejected(world)
        self.assertIs(caught.private_owner, owner)
        self.assertIs(caught.outcome.primary, error)
        self.assertFalse(caught.outcome.public["nativeChildrenSettled"])
        self.assertIn("doctor-root", world.calls[-1])
        self.assertEqual(world.rechecks, 2)

    def test_first_interrupt_preserved_through_late_guard_and_budget_interrupt(self):
        for first, late in ((KeyboardInterrupt("private"), SystemExit(7)),
                            (SystemExit(4), KeyboardInterrupt("later"))):
            world = World()
            owner = object()
            first.private_owner, first.settlement_failed = owner, True
            def effect(args):
                if "doctor-root" in args:
                    world.recheck_error = late
                    world.budget.error = late
                    raise first
            world.command_effect = effect
            with self.assertRaises(type(first)) as caught:
                world.collect()
            self.assertIs(caught.exception, first)
            self.assertIs(caught.exception.private_owner, owner)
            self.assertFalse(caught.exception.phase4_health_outcome.public["nativeChildrenSettled"])

    def test_hostile_nonbuiltin_observations_fail_without_rendering(self):
        class Bad:
            def __repr__(self):
                raise AssertionError("no representation")
        world = World()
        world.current["targets"][27]["uid"] = Bad()
        self.rejected(world)


if __name__ == "__main__":
    unittest.main()
