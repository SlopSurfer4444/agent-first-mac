"""Pure injected Git/source/runtime tests. Never invoke native() or a child."""

import copy
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
D = importlib.machinery.SourceFileLoader("doctor_test", str(ROOT / "bin/phase5-current-doctor")).load_module()


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Budget:
    def __init__(self):
        self.calls = 0
        self.failure = None

    def check(self):
        self.calls += 1
        if self.failure is not None:
            raise self.failure


class Source:
    def __init__(self, data, absent=False):
        self.data, self.absent = data, absent
        self.digest = D.digest(data)
        self.stamp = (1, 2, 501, 20, stat.S_IFREG | 0o644)
        self.initial = data
        self.verifications = self.closes = 0
        self.verify_error = self.close_error = None

    def verify(self):
        self.verifications += 1
        if self.verify_error is not None:
            raise self.verify_error
        D.require(self.data == self.initial and self.closes == 0)
        return True

    def close(self):
        self.closes += 1
        if self.close_error is not None:
            raise self.close_error


class Git:
    def __init__(self, accepted=True):
        self.files = {p: ("public source " + p).encode() for p in D.REQUIRED}
        self.protected = "evidence/phase-5/historical-receipt.json"
        self.files[self.protected] = b"immutable historical receipt"
        self.baseline = self.rows()
        del self.baseline["bin/phase5-current-doctor"]
        self.files["bin/phase5-current-doctor"] += b" successor"
        self.files["evidence/phase-5/fake-completion.json"] = b"inline fake only"
        self.reviewed = self.rows()
        self.record = {
            "schema": 1, "phase": 5, "status": "ACCEPTED_CURRENT_RUNTIME",
            "baseCommit": D.BASE, "reviewedHead": "a" * 40,
            "sources": {p: D.digest(self.files[p]) for p in D.REQUIRED},
            "evidence": {"evidence/phase-5/fake-completion.json": D.digest(b"inline fake only")},
            "checks": {role: {"status": "PASS", "evidence": "evidence/phase-5/fake-completion.json"}
                       for role in D.ROLES}, "phase5Accepted": True,
            **{key: False for key in D.AUTHORITY}}
        if accepted:
            self.save_record()
        self.value = {"head": "c" * 40, "branch": "main" if accepted else D.BRANCH,
                      "clean": True, "baseAncestor": True, "linear": True,
                      "tree": self.rows(), "baseTree": self.baseline}
        self.meta = {"commits": ("b" * 40,), "parents": ("a" * 40,),
                     "identity": D.COORDINATOR, "changes": (("A", D.ACCEPTANCE),),
                     "tree": self.reviewed}
        self.states = 0
        self.effect = None

    def rows(self):
        return {p: ("100644", D.oid(data)) for p, data in self.files.items()}

    def save_record(self):
        self.files[D.ACCEPTANCE] = raw(self.record)
        if hasattr(self, "value"):
            self.value["tree"] = self.rows()

    def state(self):
        self.states += 1
        if self.effect is not None:
            self.effect(self.states)
        return copy.deepcopy(self.value)

    def acceptance(self, reviewed):
        D.require(reviewed == self.record["reviewedHead"])
        return copy.deepcopy(self.meta)


class DoctorTests(unittest.TestCase):
    def fixture(self, accepted=True):
        self.git, self.budget, self.sources = Git(accepted), Budget(), []
        self.runtime_calls = 0
        self.source_effect = None
        self.runtime = lambda _: D.R.public("ready", observed=8)

    def invoke(self, **kwargs):
        def source(path, *, absent=False):
            D.require(absent == (path not in self.git.files))
            value = Source(self.git.files.get(path, b""), absent)
            self.sources.append(value)
            if self.source_effect is not None:
                self.source_effect(path, value)
            return value
        def runtime(budget):
            self.runtime_calls += 1
            return self.runtime(budget)
        with patch.object(D.R.catalog.subprocess, "Popen", side_effect=AssertionError("native forbidden")):
            return D.run(git=self.git, source_factory=source, runtime_check=runtime,
                         budget=self.budget, canonical_main=True, **kwargs)

    def rejected(self, **kwargs):
        with self.assertRaises(D.DoctorError) as caught:
            self.invoke(**kwargs)
        outcome = caught.exception.outcome
        self.assertEqual(outcome.public["verdict"], "NEEDS_REVIEW")
        self.assertTrue(all(s.closes == 1 for s in self.sources))
        self.assertNotIn("private", json.dumps(outcome.public))
        self.assertTrue(all(outcome.public[k] is False for k in D.AUTHORITY))
        return outcome

    def test_main_acceptance_and_current_readiness_are_separate(self):
        self.fixture()
        value = self.invoke()
        self.assertEqual(value["verdict"], "PASS")
        self.assertTrue(value["historicalPhase5Accepted"] and value["integratedMain"])
        self.assertTrue(value["currentRuntimeReady"] and value["liveRuntimeChecked"])
        self.assertEqual(self.runtime_calls, 1)
        self.assertEqual(self.git.states, 2)
        self.assertTrue(all(s.verifications == 2 and s.closes == 1 for s in self.sources))
        self.assertTrue(all(value[k] is False for k in D.AUTHORITY))

    def test_review_without_acceptance_is_not_phase_pass(self):
        self.fixture(False)
        value = self.invoke()
        self.assertEqual(value["verdict"], "PREPARED_FOR_INDEPENDENT_REVIEW")
        self.assertFalse(value["historicalPhase5Accepted"])

    def test_acceptance_on_review_branch_does_not_claim_integrated_pass(self):
        self.fixture()
        self.git.value["branch"] = D.BRANCH
        value = self.invoke()
        self.assertEqual(value["verdict"], "PREPARED_FOR_INDEPENDENT_REVIEW")
        self.assertFalse(value["integratedMain"])

    def test_git_only_never_dispatches_or_claims_live_pass(self):
        for accepted in (False, True):
            self.fixture(accepted)
            value = self.invoke(git_only=True)
            self.assertEqual(value["verdict"], "GIT_ONLY_VALID")
            self.assertFalse(value["currentRuntimeReady"] or value["liveRuntimeChecked"])
            self.assertEqual(self.runtime_calls, 0)

    def test_branch_dirty_ancestry_and_merge_fail_closed(self):
        for key, bad in (("branch", "other"), ("branch", "HEAD"), ("clean", False),
                         ("clean", 1), ("baseAncestor", False), ("linear", False)):
            self.fixture()
            self.git.value[key] = bad
            self.rejected()
            self.assertEqual(self.runtime_calls, 0)

    def test_main_requires_acceptance_and_canonical_location(self):
        self.fixture(False)
        self.git.value["branch"] = "main"
        self.rejected()
        self.fixture()
        with self.assertRaises(D.DoctorError):
            D.run(git=self.git, source_factory=lambda *a, **k: None,
                  runtime_check=self.runtime, budget=self.budget, canonical_main=False)

    def test_sole_acceptance_child_parent_identity_and_scope(self):
        for key, bad in (("commits", ("b" * 40, "c" * 40)), ("parents", (D.BASE,)),
                         ("parents", ("a" * 40, "c" * 40)), ("identity", ("private author",) * 4),
                         ("changes", (("M", D.ACCEPTANCE),)),
                         ("changes", (("A", D.ACCEPTANCE), ("M", "ARCHITECTURE.md")))):
            self.fixture()
            self.git.meta[key] = bad
            self.rejected()
            self.assertEqual(self.runtime_calls, 0)

    def test_schema_strict_booleans_and_unknown_authority(self):
        for key, bad in (("schema", True), ("phase", True), ("phase5Accepted", 1),
                         ("rootAuthorized", True), ("phase6Allowed", 0), ("unknown", False)):
            self.fixture()
            self.git.record[key] = bad
            self.git.save_record()
            self.rejected()

    def test_duplicate_json_key_rejected(self):
        self.fixture()
        self.git.files[D.ACCEPTANCE] = raw(self.git.record)[:-1] + b',"schema":1}'
        self.git.value["tree"] = self.git.rows()
        self.rejected()

    def test_missing_hash_or_role_and_wrong_evidence_digest(self):
        for kind in ("source", "role", "evidence", "extra-source"):
            self.fixture()
            if kind == "source":
                del self.git.record["sources"]["lib/phase5_probe_process.py"]
            elif kind == "role":
                del self.git.record["checks"]["finalCurrentReadiness"]
            elif kind == "extra-source":
                self.git.record["sources"]["unreviewed.py"] = "f" * 64
            else:
                self.git.record["evidence"]["evidence/phase-5/fake-completion.json"] = "f" * 64
            self.git.save_record()
            self.rejected()

    def test_hostile_relative_paths_not_used_for_io(self):
        for path in ("../private", "/private", "x/../y", "x//y", "x/./y", "x\0y"):
            self.fixture()
            self.git.record["sources"][path] = "f" * 64
            self.git.save_record()
            self.rejected()
            self.assertEqual(len(self.sources), 1)

    def test_baseline_historical_receipts_cannot_be_rewritten(self):
        self.fixture()
        self.git.value["tree"][self.git.protected] = ("100644", "f" * 40)
        self.rejected()

    def test_changed_successor_source_and_same_status_hidden_byte_drift(self):
        for update_tree in (False, True):
            self.fixture()
            self.git.files["lib/phase5_runtime_paths.py"] += b" changed"
            if update_tree:
                self.git.value["tree"] = self.git.rows()
            self.rejected()
            self.assertEqual(self.runtime_calls, 0)

    def test_unbound_python_package_addition_cannot_change_imports(self):
        self.fixture()
        self.git.files["lib/__init__.py"] = b"unreviewed"
        self.git.value["tree"] = self.git.rows()
        self.rejected()

    def test_unbound_root_or_external_code_additions_cannot_shadow_runtime(self):
        for path in ("argparse.py", "plistlib.py", "argparse/__init__.py",
                     "other/helper.py", "sitecustomize.py"):
            self.fixture()
            self.git.files[path] = b"unreviewed importable code"
            self.git.value["tree"] = self.git.rows()
            self.rejected()
            self.assertEqual(self.runtime_calls, 0)

    def test_mode_change_rejected_even_when_content_matches(self):
        self.fixture()
        self.source_effect = lambda p, s: setattr(s, "stamp", (*s.stamp[:4], stat.S_IFREG | 0o755))
        self.rejected()

    def test_post_runtime_source_and_git_drift(self):
        for kind in ("source", "git"):
            self.fixture()
            def runtime(_):
                if kind == "source":
                    self.sources[0].data += b" drift"
                else:
                    self.git.value["head"] = "d" * 40
                return D.R.public("ready", observed=8)
            self.runtime = runtime
            outcome = self.rejected()
            self.assertFalse(outcome.public["repositoryChecksPassed"])

    def test_runtime_drift_keeps_historical_acceptance_and_no_ready(self):
        self.fixture()
        self.runtime = lambda _: D.R.public("needs-review", stage="admission")
        outcome = self.rejected()
        self.assertTrue(outcome.public["historicalPhase5Accepted"])
        self.assertFalse(outcome.public["currentRuntimeReady"])
        self.assertEqual(outcome.public["failureStage"], "runtime")

    def test_runtime_forged_bool_integer_and_extra_values_rejected(self):
        for key, bad in (("childSettled", 1), ("executionAdmission", 0), ("observedTargets", True),
                         ("private", "secret")):
            self.fixture()
            value = D.R.public("ready", observed=8)
            value[key] = bad
            self.runtime = lambda _, v=value: v
            self.rejected()

    def test_unsettled_return_or_unclassified_runtime_exception_never_claims_settled(self):
        for kind in ("reported", "unknown", "exception"):
            self.fixture()
            def runtime(_):
                if kind == "exception":
                    raise OSError("private child acquisition unknown")
                if kind == "unknown":
                    return {"childSettled": True}
                return D.R.public("needs-review", settled=False)
            self.runtime = runtime
            outcome = self.rejected()
            self.assertFalse(outcome.public["childSettled"])
            self.assertEqual(self.git.states, 1)

    def test_clean_doc_only_descendant_retains_admitted_source_closure(self):
        self.fixture()
        self.git.files["docs/later-note.md"] = b"unrelated future documentation"
        self.git.value["tree"] = self.git.rows()
        self.assertEqual(self.invoke()["verdict"], "PASS")

    def test_unresolved_owner_and_original_error_retained_no_more_git_processes(self):
        self.fixture()
        owner = object()
        error = D.R.ReadinessError(private_owner=owner)
        def fail(_):
            raise error
        self.runtime = fail
        outcome = self.rejected()
        self.assertIs(outcome.private_owner, owner)
        self.assertIs(outcome.primary, error)
        self.assertFalse(outcome.public["childSettled"])
        self.assertEqual(self.git.states, 1)

    def test_interruption_priority_exact_owner_and_cleanup(self):
        for first, later in ((KeyboardInterrupt("private"), SystemExit(9)),
                             (SystemExit(4), KeyboardInterrupt("later")),
                             (ValueError("private"), KeyboardInterrupt("cleanup"))):
            self.fixture()
            owner = object()
            first.private_owner = owner
            def runtime(_):
                self.sources[-1].close_error = later
                raise first
            self.runtime = runtime
            expected = first if isinstance(first, (KeyboardInterrupt, SystemExit)) else later
            with self.assertRaises(type(expected)) as caught:
                self.invoke()
            self.assertIs(caught.exception, expected)
            self.assertIs(caught.exception.private_owner, owner)
            self.assertTrue(all(s.closes == 1 for s in self.sources))
            self.assertFalse(caught.exception.doctor_outcome.public["sourceHandlesClosed"])

    def test_final_budget_interrupt_cannot_replace_earlier_interrupt(self):
        self.fixture()
        first = KeyboardInterrupt("private")
        def runtime(_):
            self.budget.failure = SystemExit(7)
            raise first
        self.runtime = runtime
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.invoke()
        self.assertIs(caught.exception, first)

    def test_unknown_source_constructor_closure_not_claimed(self):
        self.fixture()
        def bad(*args, **kwargs):
            raise OSError("private path")
        with self.assertRaises(D.DoctorError) as caught:
            D.run(git=self.git, source_factory=bad, runtime_check=self.runtime,
                  budget=self.budget, canonical_main=True)
        self.assertFalse(caught.exception.outcome.public["sourceHandlesClosed"])

    def test_actual_connected_readiness_with_real_matchers_and_pure_filesystems(self):
        F = load("doctor_readiness_fakes", "tests/test_phase5_current_readiness.py")
        for drift in (False, True):
            self.fixture()
            helper = F.ConnectedTests()
            args = helper.fixture()
            if drift:
                args[0].nodes[F.T.path(0)]["data"] = args[0].nodes[F.T.path(0)]["data"].replace(
                    b"'never'", b"'on-request'")
            self.runtime = lambda _: helper.run_connected(args)
            if drift:
                self.rejected()
            else:
                self.assertEqual(self.invoke()["verdict"], "PASS")

    def test_main_human_json_parity_and_strict_arguments_no_native(self):
        for args in (["--json"], [], ["--git-only", "--json"]):
            outputs = []
            value = D.report(source=True, git_only=True)
            code = D.main(args, operation=lambda _: value, emit=outputs.append)
            self.assertEqual(code, 0)
            self.assertIn("GIT_ONLY_VALID", outputs[0])
        for args in (["--apply"], ["--json", "--json"], [[]], "--json"):
            outputs = []
            code = D.main(args, operation=lambda _: self.fail("native must not run"), emit=outputs.append)
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(outputs[0])["failureStage"], "arguments")

    def test_terminal_unresolved_owner_is_retained_in_numeric_exit(self):
        self.fixture()
        owner = object()
        def runtime(_):
            raise D.R.ReadinessError(private_owner=owner)
        self.runtime = runtime
        with self.assertRaises(SystemExit) as caught:
            D.main(["--json"], operation=lambda _: self.invoke(), emit=lambda _: None)
        self.assertEqual(caught.exception.code, 1)
        self.assertIs(caught.exception.private_owner, owner)
        self.assertFalse(caught.exception.doctor_outcome.public["childSettled"])

    def test_entry_failed_interrupt_never_has_successful_process_exit(self):
        for original, expected in ((SystemExit(0), 1), (SystemExit(256), 1),
                                   (SystemExit(-256), 1), (SystemExit(None), 1),
                                   (SystemExit(False), 1), (SystemExit("private"), 1),
                                   (SystemExit(9), 9), (KeyboardInterrupt(), 130)):
            outcome, owner, outputs = D.Outcome(), object(), []
            outcome.public = D.report(stage="runtime", settled=False)
            original.doctor_outcome, original.private_owner = outcome, owner
            with patch.object(D, "main", side_effect=original), \
                    patch("builtins.print", side_effect=outputs.append):
                with self.assertRaises(SystemExit) as caught:
                    D.entry()
            self.assertEqual(caught.exception.code, expected)
            self.assertEqual(json.loads(outputs[0])["verdict"], "NEEDS_REVIEW")
            self.assertIs(caught.exception.doctor_outcome, outcome)
            self.assertIs(caught.exception.private_owner, owner)
            self.assertTrue(caught.exception.settlement_failed)


class GitParsingTests(unittest.TestCase):
    def test_tree_binary_names_and_closed_kinds(self):
        git = D.NativeGit("/Users/owner", "/Users/owner/AIDev/control", Budget())
        for raw_tree in (b"100644 blob " + b"a" * 40 + b"\tx\0",
                         b"160000 commit " + b"a" * 40 + b"\tx\0",
                         b"100644 blob " + b"a" * 40 + b"\t../x\0"):
            git._read = lambda *a, value=raw_tree, **k: (0, value)
            if b"commit" in raw_tree or b"../" in raw_tree:
                with self.assertRaises(ValueError):
                    git._tree("b" * 40)
            else:
                self.assertEqual(git._tree("b" * 40), {"x": ("100644", "a" * 40)})

    def test_fixed_process_wrapper_and_read_only_environment_injected(self):
        git = D.NativeGit("/Users/owner", "/Users/owner/AIDev/control", Budget())
        calls = []
        def command(launch, budget, seconds, **kwargs):
            calls.append(launch)
            self.assertTrue(kwargs["admit_launch"](launch))
            self.assertEqual(seconds, 8)
            self.assertNotIn("CODEX_HOME", launch.environment)
            self.assertEqual(launch.environment["GIT_OPTIONAL_LOCKS"], "0")
            return D.process.CommandResult(0, b"a" * 40 + b"\n", b"")
        with patch.object(D.process, "command", command):
            self.assertEqual(git._text("rev-parse", "--verify", "HEAD"), "a" * 40)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].argv[:len(D.NativeGit.PREFIX)], D.NativeGit.PREFIX)

    def test_actual_accepted_process_owner_over_fake_git_child(self):
        F = load("doctor_catalog_fakes", "tests/test_phase5_plugin_catalog.py")
        original = D.process.command
        for unsettled in (False, True):
            world = F.World()
            world.buffers[11].extend(b"a" * 40 + b"\n")
            if unsettled:
                world.process.normal_exit = False
                world.process.ignore_term = world.process.ignore_kill = True
            budget = D.R.Budget(clock=lambda: world.now)
            git = D.NativeGit("/Users/owner", "/Users/owner/AIDev/control", budget)
            def connected(*args, **kwargs):
                kwargs.update(clock=lambda: world.now, read=world.read)
                return original(*args, **kwargs)
            with world.installed(), patch.object(D.R.catalog.subprocess, "Popen", world.popen), \
                    patch.object(D.process, "command", connected):
                if unsettled:
                    with self.assertRaises(D.process.ProbeProcessError) as caught:
                        git._text("rev-parse", "--verify", "HEAD")
                    self.assertIs(caught.exception.private_owner.process, world.process)
                    self.assertIsNot(caught.exception.child_settled, True)
                    self.assertEqual(world.process.signals, ["term", "kill"])
                else:
                    self.assertEqual(git._text("rev-parse", "--verify", "HEAD"), "a" * 40)
                    self.assertEqual(world.process.returncode, 0)
                    self.assertEqual(world.process.signals, [])
            self.assertEqual(len(world.launches), 1)
            self.assertTrue(all(stream.closed for stream in (
                world.process.stdin, world.process.stdout, world.process.stderr)))


if __name__ == "__main__":
    unittest.main()
