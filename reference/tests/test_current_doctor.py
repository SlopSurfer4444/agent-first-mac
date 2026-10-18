"""Pure injected successor tests; public committed files are fixture bytes only.

Historical bytes that differ from the current tree are materialized by a local,
read-only Git object lookup at the receipt's exact reviewed head. No hooks,
network, runtime, system inventory, private configuration or vendor child runs.
The exact historical receipt remains the production trust anchor; fixture lookup
does not patch that anchor, its hashes or the old acceptance parser.
"""

import copy
import importlib.machinery
import json
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
C = importlib.machinery.SourceFileLoader("current_doctor_test", str(ROOT / "bin/current-doctor")).load_module()
OLD_RAW = (ROOT / C.PHASE5_ACCEPTANCE).read_bytes()
OLD = C.phase5(OLD_RAW)
# Routers may be edited by the separate coordinator in this shared worktree.
# Their historical SHA values come from the exact old receipt; changed current
# bytes below are fake. No test reads evolving routing bytes as the old preimage.
SENTINEL_RAW = (ROOT / C.ACCEPTANCE).read_bytes()
SENTINEL = C.acceptance(SENTINEL_RAW)


class FixtureCustodyCliTests(unittest.TestCase):
    def test_existing_cli_fixed_status_and_retirement_dispatch_without_full_doctor(self):
        for arguments, expected in ((['--fixture-custody-status'], None),
                                    (['--retire-fixture-slot','3','--json'], 3)):
            with self.subTest(arguments=arguments):
                calls, output = [], []
                def custody(slot):
                    calls.append(slot)
                    return {'scope':'disposable-vendor-fixture-custody','outstanding':1}
                def vendor(*args, **kwargs):
                    self.fail('unrelated vendor doctor invoked')
                self.assertEqual(C.main(arguments, operation=vendor, custody_operation=custody,
                                        emit=output.append), 0)
                self.assertEqual(calls, [expected])
                self.assertEqual(json.loads(output[0])['outstanding'], 1)

    def test_invalid_slot_or_combined_lifecycle_flags_never_dispatch(self):
        for arguments in (['--retire-fixture-slot','8'], ['--retire-fixture-slot','-1'],
                          ['--retire-fixture-slot','/private/path'],
                          ['--fixture-custody-status','--git-only']):
            with self.subTest(arguments=arguments):
                self.assertEqual(C.main(arguments, custody_operation=lambda slot:self.fail('dispatched'), emit=lambda value:None), 2)

    def test_capacity_signal_redacted_and_specific(self):
        from lib.vendor_fixture_custody import CustodyError
        output = []
        def capacity(slot):
            raise CustodyError('fixture_capacity_required')
        self.assertEqual(C.main(['--fixture-custody-status'], custody_operation=capacity, emit=output.append), 1)
        self.assertEqual(json.loads(output[0])['reason'], 'fixture_capacity_required')

    def test_custody_recovery_reasons_remain_closed_specific_and_actionable(self):
        from lib.vendor_fixture_custody import CustodyError
        from lib.vendor_compatibility_probe import ProbeError
        for reason in ('fixture_metadata_pending', 'fixture_preparation_capacity',
                       'fixture_preparation_recovery_required', 'fixture_namespace_refresh_required',
                       'fixture_legacy_identity_required', 'private-path-exception'):
            with self.subTest(reason=reason):
                output = []
                def failure(slot):
                    raise CustodyError(reason)
                self.assertEqual(C.main(['--fixture-custody-status'], custody_operation=failure,
                                        emit=output.append), 1)
                value = json.loads(output[0])
                expected = 'fixture_custody_invalid' if reason == 'private-path-exception' else reason
                self.assertEqual(value['reason'], expected)
                self.assertTrue(value['nextAction'])
                if reason != 'private-path-exception':
                    self.assertIn(reason, C.REASONS)
                    self.assertEqual(ProbeError(reason).reason_class, reason)


def historical_blob(revision, path):
    result = subprocess.run(
        ("/usr/bin/git", "--no-pager", "--no-replace-objects", "-c",
         "core.hooksPath=/dev/null", "show", revision + ":" + path),
        cwd=ROOT, env={"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                       "GIT_NO_LAZY_FETCH": "1", "LC_ALL": "C"},
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=8,
    )
    if result.returncode != 0:
        raise AssertionError("historical public fixture unavailable")
    return result.stdout


def historical_public():
    """Materialize actual accepted bytes, never today's policy as old source."""
    result = {}
    for path, expected in (OLD["sources"] | OLD["evidence"]).items():
        if path in C.ROUTERS:
            continue
        data = (ROOT / path).read_bytes()
        if C.digest(data) != expected:
            data = historical_blob(OLD["reviewedHead"], path)
        if C.digest(data) != expected:
            raise AssertionError("historical Phase5 fixture hash mismatch")
        result[path] = data
    return result


PUBLIC = historical_public()


def sentinel_public():
    result = {}
    for path, item in (SENTINEL["sources"] | SENTINEL["evidence"]).items():
        if path in C.EXPOSURE_REPLACEMENTS:
            continue
        data = (ROOT / path).read_bytes()
        if C.digest(data) != item["sha256"]:
            data = historical_blob(SENTINEL["reviewedHead"], path)
        if C.digest(data) != item["sha256"]:
            raise AssertionError("historical public fixture hash mismatch")
        result[path] = data
    return result


# Replaced doctor/router bytes are not read as their historical preimages.
# Their accepted hashes and modes come from the immutable real receipt.
SENTINEL_PUBLIC = sentinel_public()


class HistoricalFixtureTests(unittest.TestCase):
    def test_changed_current_policy_uses_receipt_bound_historical_bytes(self):
        changed = {"codex/hooks/phase5-contract.py", "skills/manage-workstation/SKILL.md"}
        original = Path.read_bytes
        def read(path):
            return b"later authorized policy" if str(path.relative_to(ROOT)) in changed else original(path)
        with patch.object(Path, "read_bytes", read), patch(
                __name__ + ".historical_blob", wraps=historical_blob) as lookup:
            actual = historical_public()
        for path in changed:
            self.assertEqual(C.digest(actual[path]), OLD["sources"][path])
            self.assertIn(((OLD["reviewedHead"], path),), lookup.call_args_list)

    def test_historical_lookup_cannot_substitute_wrong_bytes(self):
        with patch.object(Path, "read_bytes", return_value=b"changed current bytes"), patch(
                __name__ + ".historical_blob", return_value=b"wrong historical bytes"):
            with self.assertRaisesRegex(AssertionError, "historical Phase5 fixture hash mismatch"):
                historical_public()


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def row(data, mode="100644"):
    return {"mode": mode, "sha256": C.digest(data)}


class Budget:
    def __init__(self):
        self.calls = 0
        self.error = None

    def check(self):
        self.calls += 1
        if self.error is not None:
            raise self.error


class Source:
    def __init__(self, data, mode, absent=False):
        self.data, self.initial, self.absent = data, data, absent
        self.digest = C.digest(data)
        self.stamp = (1, 2, 501, 20, stat.S_IFREG | (0o755 if mode == "100755" else 0o644))
        self.verifications = self.closes = 0
        self.verify_error = self.close_error = None

    def verify(self):
        self.verifications += 1
        if self.verify_error is not None:
            raise self.verify_error
        C.require(self.data == self.initial and self.closes == 0)
        return True

    def close(self):
        self.closes += 1
        if self.close_error is not None:
            raise self.close_error


class Git:
    def __init__(self, accepted=True):
        self.files = dict(PUBLIC)
        self.files[C.PHASE5_ACCEPTANCE] = OLD_RAW
        self.protected = "evidence/phase-2/protected-fake.json"
        self.files[self.protected] = b"immutable older phase fixture"
        self.modes = {}
        self.baseline = self.rows()
        for p in C.ROUTERS:
            self.baseline[p] = ("100644", "0" * 40)
            self.files[p] = ("new reviewed router " + p).encode()
        for p in C.REQUIRED:
            self.files[p] = ("new reviewed source " + p).encode()
        self.modes["bin/current-doctor"] = "100755"
        self.evidence_path = C.EVIDENCE_PREFIX + "actual-and-review.json"
        self.files[self.evidence_path] = b"bounded public fake adjudication"
        self.reviewed = self.rows()
        added = set(self.reviewed) - set(self.baseline)
        self.record = {
            "schema": 1, "kind": "POST_PHASE5_VENDOR_SENTINEL", "status": "ACCEPTED_VENDOR_SENTINEL",
            "predecessorCommit": C.BASE, "phase5AcceptanceSHA256": C.PHASE5_SHA256,
            "reviewedHead": "a" * 40,
            "sources": {p: row(self.files[p], self.reviewed[p][0]) for p in added if not p.startswith("evidence/")},
            "evidence": {p: row(self.files[p]) for p in added if p.startswith("evidence/")},
            "routers": {p: {"before": {"mode": "100644", "sha256": OLD["sources"][p]},
                            "after": row(self.files[p])} for p in C.ROUTERS},
            "checks": {role: {"status": "PASS", "evidence": self.evidence_path} for role in C.ROLES},
            "sentinelAccepted": True, **{key: False for key in C.AUTHORITY}}
        if accepted:
            self.save_record()
        self.value = {"head": "c" * 40, "branch": "main" if accepted else C.BRANCH,
                      "clean": True, "baseAncestor": True, "linear": True,
                      "tree": self.rows(), "baseTree": self.baseline}
        self.meta = {"commits": ("b" * 40,), "parents": ("a" * 40,),
                     "identity": C.D.COORDINATOR, "changes": (("A", C.ACCEPTANCE),),
                     "tree": self.reviewed}
        self.states = 0
        self.effect = None

    def rows(self):
        return {p: (self.modes.get(p, "100644"), C.oid(data)) for p, data in self.files.items()}

    def save_record(self):
        self.files[C.ACCEPTANCE] = raw(self.record)
        if hasattr(self, "value"):
            self.value["tree"] = self.rows()

    def state(self):
        self.states += 1
        if self.effect is not None:
            self.effect(self.states)
        return copy.deepcopy(self.value)

    def acceptance(self, reviewed):
        C.require(reviewed == self.record["reviewedHead"])
        return copy.deepcopy(self.meta)


class DoctorTests(unittest.TestCase):
    def fixture(self, accepted=True):
        self.git, self.budget, self.sources = Git(accepted), Budget(), []
        self.sentinel_calls = self.runtime_calls = 0
        self.source_effect = None
        self.sentinel = lambda _: {"status": "PASS", "childSettled": True, "sourceHandlesClosed": True}
        self.runtime = lambda _: C.D.R.public("ready", observed=8)

    def source(self, path, *, absent=False):
        C.require(absent == (path not in self.git.files))
        value = Source(self.git.files.get(path, b""), self.git.modes.get(path, "100644"), absent)
        self.sources.append((path, value))
        if self.source_effect is not None:
            self.source_effect(path, value)
        return value

    def invoke(self, *, with_runtime=False, **kwargs):
        def sentinel(budget, *, source_guard):
            self.assertIs(budget, self.budget)
            self.guard = source_guard
            self.sentinel_calls += 1
            return self.sentinel(budget)
        def runtime(budget):
            self.assertIs(budget, self.budget)
            self.runtime_calls += 1
            return self.runtime(budget)
        params = {"git": self.git, "source_factory": self.source, "budget": self.budget,
                  "canonical_main": True, "sentinel_check": sentinel,
                  "runtime_check": runtime if with_runtime else None, **kwargs}
        with patch.object(C.D, "run", side_effect=AssertionError("old run forbidden")), \
             patch.object(C.D, "native", side_effect=AssertionError("native forbidden")), \
             patch.object(C.D.R, "NativeRuntime", side_effect=AssertionError("native forbidden")), \
             patch.object(C.D.R.catalog.subprocess, "Popen", side_effect=AssertionError("child forbidden")):
            return C.run(**params)

    def rejected(self, **kwargs):
        with self.assertRaises(C.DoctorError) as caught:
            self.invoke(**kwargs)
        out = caught.exception.outcome
        self.assertEqual(out.public["verdict"], "NEEDS_REVIEW")
        self.assertTrue(all(s.closes == 1 for _, s in self.sources))
        self.assertNotIn("private", json.dumps(out.public))
        self.assertTrue(all(out.public[k] is False for k in C.AUTHORITY))
        return out

    def test_sentinel_only_pass_is_not_current_runtime_claim(self):
        self.fixture()
        value = self.invoke()
        self.assertEqual(value["verdict"], "PASS")
        self.assertTrue(value["historicalPhase5Accepted"] and value["phase5EngineUnchanged"])
        self.assertTrue(value["integratedMain"] and value["sentinelAccepted"] and value["currentSentinelReady"])
        self.assertFalse(value["liveRuntimeChecked"] or value["currentRuntimeReady"])
        self.assertEqual((self.sentinel_calls, self.runtime_calls, self.git.states), (1, 0, 2))
        self.assertTrue(all(s.verifications == 2 and s.closes == 1 for _, s in self.sources))

    def test_optional_exact_runtime_callback_separate_and_once(self):
        self.fixture()
        value = self.invoke(with_runtime=True)
        self.assertTrue(value["currentRuntimeReady"] and value["liveRuntimeChecked"])
        self.assertEqual((self.sentinel_calls, self.runtime_calls), (1, 1))

    def test_source_only_review_preserves_historical_acceptance(self):
        self.fixture(False)
        value = self.invoke(git_only=True)
        self.assertEqual(value["verdict"], "PREPARED_SOURCE_ONLY")
        self.assertTrue(value["historicalPhase5Accepted"] and value["phase5EngineUnchanged"])
        self.assertFalse(value["sentinelAccepted"] or value["currentSentinelReady"] or value["integratedMain"])
        self.assertEqual(self.sentinel_calls + self.runtime_calls, 0)

    def test_review_with_probe_or_acceptance_never_integrated(self):
        for accepted in (False, True):
            self.fixture(accepted)
            self.git.value["branch"] = C.BRANCH
            value = self.invoke()
            self.assertEqual(value["verdict"], "PREPARED_FOR_INDEPENDENT_REVIEW")
            self.assertFalse(value["integratedMain"])
            self.assertEqual(value["sentinelAccepted"], accepted)

    def test_git_only_skips_even_provided_callbacks(self):
        self.fixture()
        value = self.invoke(git_only=True, with_runtime=True)
        self.assertEqual(value["verdict"], "GIT_ONLY_VALID")
        self.assertFalse(value["sentinelChecked"] or value["liveRuntimeChecked"])
        self.assertEqual(self.sentinel_calls + self.runtime_calls, 0)

    def test_branch_main_location_clean_ancestry_and_linear(self):
        for key, value in (("branch", "other"), ("branch", "HEAD"), ("clean", False),
                           ("clean", 1), ("baseAncestor", False), ("linear", False)):
            self.fixture()
            self.git.value[key] = value
            self.rejected()
            self.assertEqual(self.sentinel_calls, 0)
        self.fixture()
        self.rejected(canonical_main=False)
        self.fixture(False)
        self.git.value["branch"] = "main"
        self.rejected()

    def test_historical_receipt_exact_anchor_not_self_rebound(self):
        self.fixture()
        self.git.files[C.PHASE5_ACCEPTANCE] += b"\n"
        self.git.value["tree"] = self.git.rows()
        out = self.rejected()
        self.assertFalse(out.public["historicalPhase5Accepted"])
        self.assertEqual(self.sentinel_calls, 0)

    def test_actual_predecessor_receipt_blob_required(self):
        self.fixture()
        self.git.value["baseTree"][C.PHASE5_ACCEPTANCE] = ("100644", "f" * 40)
        self.rejected()

    def test_existing_engine_and_older_receipt_mutations_and_deletion_reject(self):
        for path in ("bin/phase5-current-doctor", "bin/phase5-current-readiness", self._protected()):
            for deletion in (False, True):
                self.fixture()
                if deletion:
                    del self.git.value["tree"][path]
                else:
                    self.git.value["tree"][path] = ("100644", "f" * 40)
                self.rejected()
                self.assertEqual(self.sentinel_calls, 0)

    @staticmethod
    def _protected():
        return "evidence/phase-2/protected-fake.json"

    def test_new_unbound_code_rejected_but_new_inert_docs_evidence_allowed(self):
        for path in ("argparse.py", "bin/extra", "lib/extra.py", "tests/extra.py", "other/x.py"):
            self.fixture()
            self.git.files[path] = b"unreviewed code"
            self.git.value["tree"] = self.git.rows()
            self.rejected()
        for path in ("docs/later.md", C.EVIDENCE_PREFIX + "later.json"):
            self.fixture()
            self.git.files[path] = b"inert later note"
            self.git.value["tree"] = self.git.rows()
            self.assertEqual(self.invoke()["verdict"], "PASS")

    def test_prepared_delta_still_forbids_old_engine_edit_and_wrong_evidence_namespace(self):
        self.fixture(False)
        self.git.value["tree"]["bin/phase5-current-doctor"] = ("100644", "f" * 40)
        self.rejected(git_only=True)
        self.fixture(False)
        self.git.value["tree"]["evidence/phase-5/new-live.json"] = ("100644", "f" * 40)
        self.rejected(git_only=True)

    def test_exact_maps_cannot_omit_add_hide_extra_or_widen_router(self):
        for kind in ("missing", "extra", "router", "router-missing", "namespace"):
            self.fixture()
            if kind == "missing":
                del self.git.record["sources"]["tests/test_current_doctor.py"]
            elif kind == "extra":
                self.git.record["sources"]["extra.py"] = row(b"extra")
            elif kind == "router":
                self.git.record["routers"]["bin/phase5-current-doctor"] = copy.deepcopy(self.git.record["routers"]["README.md"])
            elif kind == "router-missing":
                del self.git.record["routers"]["README.md"]
            else:
                self.git.record["evidence"]["evidence/phase-5/new.json"] = row(b"extra")
            self.git.save_record()
            self.rejected()

    def test_router_before_after_digest_and_mode_exact(self):
        for side in ("before", "after"):
            for key, bad in (("sha256", "f" * 64), ("mode", "100755")):
                self.fixture()
                self.git.record["routers"]["README.md"][side][key] = bad
                self.git.save_record()
                self.rejected()

    def test_content_sha_and_git_oid_and_mode_all_independent(self):
        for kind in ("sha", "oid", "physical-mode", "record-mode"):
            self.fixture()
            path = "bin/current-doctor"
            if kind == "sha":
                self.git.record["sources"][path]["sha256"] = "f" * 64
                self.git.save_record()
            elif kind == "oid":
                self.git.files[path] += b"changed outside tree"
            elif kind == "physical-mode":
                self.git.modes[path] = "100644"
            else:
                self.git.record["sources"][path]["mode"] = "100644"
                self.git.save_record()
            self.rejected()

    def test_no_symlink_or_delete_for_new_owned_source(self):
        for accepted in (False, True):
            self.fixture(accepted)
            self.git.value["tree"]["bin/current-doctor"] = ("120000", "f" * 40)
            self.rejected(git_only=True)
            self.fixture(accepted)
            del self.git.value["tree"]["bin/current-doctor"]
            self.rejected(git_only=True)

    def test_acceptance_original_single_child_and_identity(self):
        for key, bad in (("commits", ("b" * 40, "c" * 40)), ("parents", (C.BASE,)),
                         ("parents", ("a" * 40, "c" * 40)), ("identity", ("private",) * 4),
                         ("changes", (("M", C.ACCEPTANCE),)),
                         ("changes", (("A", C.ACCEPTANCE), ("M", "README.md")))):
            self.fixture()
            self.git.meta[key] = bad
            self.rejected()

    def test_git_metadata_tuple_members_require_exact_strings(self):
        class PretendString:
            def __eq__(self, other):
                return True
        for key, bad in (("parents", (PretendString(),)),
                         ("identity", (PretendString(),) * 4),
                         ("changes", ((PretendString(), PretendString()),))):
            self.fixture()
            self.git.meta[key] = bad
            self.rejected()

    def test_closed_schema_exact_types_checks_and_authority(self):
        for key, bad in (("schema", True), ("sentinelAccepted", 1), ("rootAuthorized", True),
                         ("phase6Allowed", 0), ("l4Allowed", True), ("unknown", False),
                         ("predecessorCommit", "d" * 40), ("phase5AcceptanceSHA256", "e" * 64)):
            self.fixture()
            self.git.record[key] = bad
            self.git.save_record()
            self.rejected()
        self.fixture()
        del self.git.record["checks"]["finalReview"]
        self.git.save_record()
        self.rejected()

    def test_duplicate_key_and_hostile_path_before_new_source_io(self):
        self.fixture()
        self.git.files[C.ACCEPTANCE] = raw(self.git.record)[:-1] + b',"schema":1}'
        self.git.value["tree"] = self.git.rows()
        self.rejected()
        for path in ("../private", "/private", "x/../y", "x//y", "x/./y", "x\0y"):
            self.fixture()
            self.git.record["sources"][path] = row(b"not read")
            self.git.save_record()
            self.rejected()
            self.assertEqual(len(self.sources), 2)

    def test_source_creation_error_keeps_constructor_closure_unknown(self):
        self.fixture()
        error = OSError("private constructor")
        def broken(path, **kwargs):
            if path == C.ACCEPTANCE:
                raise error
            return self.source(path, **kwargs)
        out = self.rejected(source_factory=broken)
        self.assertIs(out.primary, error)
        self.assertFalse(out.public["sourceHandlesClosed"])

    def test_initial_verify_final_drift_and_close_failure_all_nonpass(self):
        for kind in ("verify", "drift", "close"):
            self.fixture()
            error = OSError("private source failure")
            def effect(path, held):
                if path == "bin/current-doctor":
                    if kind == "verify":
                        held.verify_error = error
                    elif kind == "close":
                        held.close_error = error
            self.source_effect = effect
            if kind == "drift":
                def sentinel(_):
                    next(s for p, s in self.sources if p == "bin/current-doctor").data += b"drift"
                    return {"status": "PASS", "childSettled": True, "sourceHandlesClosed": True}
                self.sentinel = sentinel
            out = self.rejected()
            self.assertFalse(out.public["currentSentinelReady"])
            if kind == "close":
                self.assertFalse(out.public["sourceHandlesClosed"])

    def test_git_final_drift_does_not_retain_pass(self):
        self.fixture()
        def effect(count):
            if count == 2:
                self.git.value["head"] = "d" * 40
        self.git.effect = effect
        out = self.rejected()
        self.assertEqual(out.public["failureStage"], "final-recheck")
        self.assertFalse(out.public["phase5EngineUnchanged"])

    def test_sentinel_attributable_shape_types_and_unknown_settlement(self):
        for value in (None, {}, {"status": "PASS", "childSettled": 1, "sourceHandlesClosed": True},
                      {"status": "PASS", "childSettled": True, "sourceHandlesClosed": 1},
                      {"status": "PASS", "childSettled": False, "sourceHandlesClosed": True},
                      {"status": "PASS", "childSettled": True, "sourceHandlesClosed": False}):
            self.fixture()
            self.sentinel = lambda _, value=value: value
            out = self.rejected()
            self.assertFalse(out.public["currentSentinelReady"])
            if out.public["childSettled"] is False:
                self.assertEqual(self.git.states, 1)

    def test_settled_sentinel_nonpass_can_close_without_losing_history(self):
        self.fixture()
        self.sentinel = lambda _: {"status": "NEEDS_REVIEW", "childSettled": True,
                                  "sourceHandlesClosed": True, "details": {"private": "retained only"}}
        out = self.rejected()
        self.assertTrue(out.public["historicalPhase5Accepted"] and out.public["sourceHandlesClosed"])
        self.assertEqual(self.git.states, 2)
        self.assertIn("private", out.sentinel_report["details"])

    def test_callback_exception_retains_owner_and_forbids_further_git_child(self):
        self.fixture()
        error = OSError("private command owner")
        error.private_owner = object()
        def broken(_):
            raise error
        self.sentinel = broken
        out = self.rejected()
        self.assertIs(out.primary, error)
        self.assertIs(out.private_owner, error.private_owner)
        self.assertFalse(out.public["childSettled"] or out.public["sourceHandlesClosed"])
        self.assertEqual(self.git.states, 1)

    def test_nested_probe_owners_survive_later_doctor_close_interruption(self):
        self.fixture()
        error = OSError("private probe cleanup")
        error.source_handles_closed = False
        error.retained_sources = (object(), object())
        error.private_diagnostics = {"private": b"not public"}
        error.private_errors = (OSError("original close"),)
        interrupt = KeyboardInterrupt()
        def broken(_):
            raise error
        self.sentinel = broken
        self.source_effect = lambda path, held: setattr(held, "close_error", interrupt) if path == "bin/current-doctor" else None
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.invoke()
        self.assertIs(caught.exception, interrupt)
        outcome = interrupt.doctor_outcome
        self.assertIn(error, outcome.errors)
        self.assertIs(outcome.errors[0].retained_sources, error.retained_sources)
        self.assertIs(outcome.errors[0].private_diagnostics, error.private_diagnostics)
        self.assertFalse(outcome.public["sourceHandlesClosed"])
        self.assertNotIn("private", json.dumps(outcome.public))
        self.assertTrue(all(s.closes == 1 for _, s in self.sources))

    def test_first_interruption_survives_all_owned_close_attempts(self):
        for interrupt in (KeyboardInterrupt(), SystemExit(0)):
            self.fixture()
            def broken(_):
                raise interrupt
            self.sentinel = broken
            self.source_effect = lambda p, s: setattr(s, "close_error", OSError("private close"))
            with self.assertRaises(type(interrupt)) as caught:
                self.invoke()
            self.assertIs(caught.exception, interrupt)
            self.assertTrue(all(s.closes == 1 for _, s in self.sources))
            self.assertFalse(interrupt.doctor_outcome.public["sourceHandlesClosed"])

    def test_runtime_fingerprint_failure_never_claimed_compatible_readiness(self):
        self.fixture()
        self.runtime = lambda _: C.D.R.public("needs-review", stage="source-bind")
        out = self.rejected(with_runtime=True)
        self.assertTrue(out.public["sentinelChecked"] and out.public["liveRuntimeChecked"])
        self.assertFalse(out.public["currentRuntimeReady"])
        self.assertEqual(out.public["failureStage"], "runtime")
        # R's nonpass report has no handle-closure proof. Be explicit about that
        # limitation instead of inventing sourceHandlesClosed on its behalf.
        self.assertFalse(out.public["sourceHandlesClosed"])

    def test_runtime_not_called_after_sentinel_failure(self):
        self.fixture()
        self.sentinel = lambda _: {"status": "NEEDS_REVIEW", "childSettled": True, "sourceHandlesClosed": True}
        self.rejected(with_runtime=True)
        self.assertEqual(self.runtime_calls, 0)

    def test_budget_expiry_after_callback_invalidates_result(self):
        self.fixture()
        error = TimeoutError("private deadline")
        def sentinel(_):
            self.budget.error = error
            return {"status": "PASS", "childSettled": True, "sourceHandlesClosed": True}
        self.sentinel = sentinel
        out = self.rejected()
        self.assertIs(out.primary, error)
        self.assertFalse(out.public["currentSentinelReady"])

    def test_cli_native_dispatch_is_mocked_and_args_are_closed(self):
        output = []
        with patch.object(C, "native", return_value=C.report(stage="arguments")) as native:
            self.assertEqual(C.main(["--json"], emit=output.append), 1)
        native.assert_called_once_with(False)
        self.assertEqual(json.loads(output.pop())["failureStage"], "arguments")
        for args in (["--apply"], ["--json", "--json"], [True], "--json"):
            self.assertEqual(C.main(args, emit=output.append), 2)
            self.assertEqual(json.loads(output.pop())["failureStage"], "arguments")

    def test_main_settled_nonpass_redacts_but_unknown_outcome_is_retained(self):
        for unknown in (False, True):
            self.fixture()
            self.sentinel = lambda _: {"status": "NEEDS_REVIEW", "childSettled": not unknown,
                                      "sourceHandlesClosed": True}
            output = []
            if unknown:
                with self.assertRaises(C.DoctorError):
                    C.main(["--json"], operation=lambda _: self.invoke(), emit=output.append)
                self.assertEqual(output, [])
            else:
                self.assertEqual(C.main(["--json"], operation=lambda _: self.invoke(), emit=output.append), 1)
                self.assertNotIn("private", output[0])

    def test_probe_reason_diagnostics_are_allowlisted_and_private_data_never_escapes(self):
        self.assertEqual(C.REASONS, C.probe.REASONS)
        for reason in (*C.REASONS, None, True, [], "private /Users/private/auth"):
            for known_type in (True, False):
                self.fixture()
                error = C.probe.ProbeError("probe_failed") if known_type else OSError("private")
                error.reason_class = reason
                error.child_settled, error.settlement_failed = True, False
                error.source_handles_closed, error.retained_sources = True, ()
                error.private_diagnostics = {"private": b"private output /Users/private/auth"}
                def broken(_):
                    raise error
                self.sentinel = broken
                output = []
                self.assertEqual(C.main(["--json"], operation=lambda _: self.invoke(), emit=output.append), 1)
                value = json.loads(output[0])
                expected = [reason] if known_type and type(reason) is str and reason in C.REASONS else []
                self.assertEqual(value["reasonCodes"], expected)
                self.assertEqual(value["failureStage"], "sentinel")
                self.assertFalse(value["currentSentinelReady"])
                self.assertNotIn("private", output[0])
                self.assertNotIn("auth", output[0])

    def test_reason_codes_cannot_rehabilitate_unknown_closure(self):
        self.fixture()
        error = C.probe.ProbeError("fixture_invalid", private_owner=object())
        error.source_handles_closed = False
        def broken(_):
            raise error
        self.sentinel = broken
        out = self.rejected()
        self.assertEqual(out.public["reasonCodes"], ["fixture_invalid"])
        self.assertFalse(out.public["currentSentinelReady"] or out.public["sourceHandlesClosed"])
        self.assertIs(out.private_owner, error.private_owner)

    def test_reason_schema_is_closed_and_success_and_git_only_have_no_reasons(self):
        for reasons in (None, True, (), {}, "fixture_invalid", [True], [[]], ["private"],
                        ["fixture_invalid", "fixture_invalid"], ["fixture_invalid"] * (len(C.REASONS) + 1)):
            value = C.report(stage="sentinel")
            value["reasonCodes"] = reasons
            with self.subTest(reasons=reasons), self.assertRaises(Exception):
                C.public_report(value)
        for kwargs in ({}, {"stage": "source"}, {"stage": "sentinel", "git_only": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(Exception):
                C.report(reasons=["fixture_invalid"], **kwargs)
        self.fixture()
        self.assertEqual(self.invoke()["reasonCodes"], [])
        self.fixture()
        self.assertEqual(self.invoke(git_only=True)["reasonCodes"], [])

    def test_human_fixture_failure_names_safe_action_without_private_details(self):
        self.fixture()
        error = C.probe.ProbeError("fixture_invalid")
        error.source_handles_closed = True
        error.private_diagnostics = "private path and output"
        def broken(_):
            raise error
        self.sentinel = broken
        output = []
        self.assertEqual(C.main([], operation=lambda _: self.invoke(), emit=output.append), 1)
        self.assertIn("failure stage=sentinel; reason=fixture_invalid", output[0])
        self.assertIn("inspect probe fixture metadata, not owner configuration", output[0])
        self.assertNotIn("private", output[0])

    def test_entry_interruptions_cannot_shell_wrap_to_success(self):
        for interrupt in (KeyboardInterrupt(), SystemExit(0), SystemExit(256), SystemExit(-256),
                          SystemExit(True), SystemExit("private"), SystemExit(2), SystemExit(255)):
            output = []
            with patch.object(C, "main", side_effect=interrupt), patch("builtins.print", side_effect=output.append):
                with self.assertRaises(SystemExit) as caught:
                    C.entry()
            self.assertIn(caught.exception.code, range(1, 256))
            self.assertEqual(json.loads(output[0])["verdict"], "NEEDS_REVIEW")
            self.assertNotIn("private", output[0])

    def test_per_command_guard_physically_checks_all_held_sources(self):
        self.fixture()
        observations = []
        def sentinel(_):
            observations.append(self.guard())
            self.assertTrue(all(s.verifications == 2 for _, s in self.sources))
            observations.append(self.guard())
            return {"status": "PASS", "childSettled": True, "sourceHandlesClosed": True}
        self.sentinel = sentinel
        self.assertEqual(self.invoke()["verdict"], "PASS")
        self.assertEqual(observations, [True, True])
        self.assertTrue(all(s.verifications == 4 for _, s in self.sources))
        self.assertEqual(self.git.states, 2)  # no recursive Git per command guard

    def test_guard_rejects_live_source_substitution_before_next_command(self):
        self.fixture()
        reached = []
        def sentinel(_):
            self.guard()
            next(s for p, s in self.sources if p == "bin/current-doctor").data += b"drift"
            self.guard()
            reached.append("command must not launch")
        self.sentinel = sentinel
        out = self.rejected()
        self.assertEqual(reached, [])
        self.assertFalse(out.public["repositoryChecksPassed"])

    def test_main_rejects_private_extra_fields_and_retains_malformed_return(self):
        self.fixture()
        returned = self.invoke()
        returned["private"] = "must not escape"
        output = []
        with self.assertRaises(C.DoctorError) as caught:
            C.main(["--json"], operation=lambda _: returned, emit=output.append)
        self.assertEqual(output, [])
        self.assertIs(caught.exception.outcome.runtime_report, returned)
        self.assertFalse(caught.exception.outcome.public["childSettled"])

    def test_main_retains_unexpected_adapter_error_owner(self):
        error = OSError("private before run")
        error.private_owner = object()
        def broken(_):
            raise error
        with self.assertRaises(C.DoctorError) as caught:
            C.main(["--json"], operation=broken, emit=lambda _: self.fail("private error emitted"))
        self.assertIs(caught.exception.private_owner, error.private_owner)
        self.assertIs(caught.exception.outcome.primary, error)

    def test_successful_main_uses_strict_public_schema(self):
        for accepted in (False, True):
            self.fixture(accepted)
            for git_only in (False, True):
                output = []
                args = ["--json", "--git-only"] if git_only else ["--json"]
                self.assertEqual(C.main(args, operation=lambda _: self.invoke(git_only=git_only),
                                        emit=output.append), 0)
                self.assertEqual(set(json.loads(output[0])), set(C.report()))

    def test_report_rejects_original_false_pass_and_unobserved_readiness(self):
        for kwargs in (
                {"source": True, "accepted": True, "integrated": True, "sentinel": True},
                {"historical": True, "source": True, "accepted": True, "integrated": True, "sentinel": True},
                {"historical": True, "source": True, "sentinel": True, "sentinel_checked": True, "runtime": True},
                {"historical": True, "source": True, "accepted": True, "git_only": True, "sentinel_checked": True}):
            with self.assertRaises(ValueError):
                C.report(**kwargs)

    def test_public_boundary_rejects_forged_status_implications(self):
        mutations = (
            ("historicalPhase5Accepted", False), ("sentinelChecked", False),
            ("childSettled", False), ("sourceHandlesClosed", False),
            ("repositoryChecksPassed", False), ("sentinelAccepted", False),
            ("integratedMain", False), ("currentSentinelReady", False),
            ("currentRuntimeReady", True), ("gitOnly", True),
            ("failureStage", "runtime"),
        )
        for key, value in mutations:
            self.fixture()
            forged = self.invoke()
            forged[key] = value
            output = []
            with self.assertRaises(C.DoctorError) as caught:
                C.main(["--json"], operation=lambda _: forged, emit=output.append)
            self.assertEqual(output, [])
            self.assertEqual(caught.exception.outcome.public["verdict"], "NEEDS_REVIEW")
            self.assertIs(caught.exception.outcome.runtime_report, forged)

    def test_public_boundary_requires_exact_requested_mode_both_directions(self):
        for requested in (False, True):
            self.fixture()
            result = self.invoke(git_only=not requested)
            args = ["--json", "--git-only"] if requested else ["--json"]
            output = []
            with self.assertRaises(C.DoctorError) as caught:
                C.main(args, operation=lambda _: result, emit=output.append)
            self.assertEqual(output, [])
            self.assertEqual(caught.exception.outcome.public["gitOnly"], requested)

    def test_nonpass_error_public_boundary_also_checks_requested_mode(self):
        for closed in (False, True):
            self.fixture()
            self.sentinel = lambda _: {"status": "NEEDS_REVIEW", "childSettled": closed, "sourceHandlesClosed": closed}
            original = self.rejected()
            error = C.DoctorError(original)
            def wrong_mode(_):
                raise error
            with self.assertRaises(C.DoctorError) as caught:
                C.main(["--json", "--git-only"], operation=wrong_mode, emit=lambda _: self.fail("wrong mode emitted"))
            self.assertIs(caught.exception.outcome.primary, error)
            self.assertTrue(caught.exception.outcome.public["gitOnly"])

    def test_pending_callback_exact_closed_error_can_settle_but_never_pass(self):
        for callback in ("sentinel", "runtime"):
            self.fixture()
            error = OSError("private known closed nonpass")
            error.child_settled = True
            error.settlement_failed = False
            error.source_handles_closed = True
            error.retained_sources = ()
            def closed_failure(_):
                raise error
            setattr(self, callback, closed_failure)
            out = self.rejected(with_runtime=callback == "runtime")
            self.assertIs(out.primary, error)
            self.assertTrue(out.public["childSettled"] and out.public["sourceHandlesClosed"])
            self.assertEqual(out.public["failureStage"], callback)
            self.assertEqual(self.git.states, 2)
            self.assertEqual(out.public["currentSentinelReady"], callback == "runtime")

    def test_closed_nonpass_error_main_emits_nonzero_without_retained_owner(self):
        self.fixture()
        error = OSError("private closed capability failure")
        error.child_settled, error.settlement_failed, error.source_handles_closed = True, False, True
        def closed_failure(_):
            raise error
        self.sentinel = closed_failure
        output = []
        self.assertEqual(C.main(["--json"], operation=lambda _: self.invoke(), emit=output.append), 1)
        value = json.loads(output[0])
        self.assertTrue(value["childSettled"] and value["sourceHandlesClosed"])
        self.assertEqual(value["verdict"], "NEEDS_REVIEW")
        self.assertNotIn("private", output[0])

    def test_retained_closed_fixture_is_diagnostic_not_live_child(self):
        for handles in ([], [object()]):
            self.fixture()
            artifact = object.__new__(C.probe.Fixture)
            artifact.handles = handles
            error = OSError("private retained fixture")
            error.child_settled, error.settlement_failed, error.source_handles_closed = True, False, True
            error.retained_sources = (artifact,)
            def closed_failure(_):
                raise error
            self.sentinel = closed_failure
            out = self.rejected()
            self.assertEqual(out.public['verdict'], 'NEEDS_REVIEW')
            self.assertEqual(out.public['childSettled'], not handles)
            self.assertEqual(out.public['sourceHandlesClosed'], not handles)
            self.assertIs(out.errors[0].retained_sources[0], artifact)

    def test_retained_fixture_public_projection_has_no_private_owner(self):
        self.fixture()
        result = self.sentinel(None)
        result['retainedFixtureCount'] = 1
        result['privateFixtureDispositions'] = ('/private/do-not-publish',)
        self.sentinel = lambda _: result
        value = self.invoke()
        self.assertEqual(value['retainedFixtureCount'], 1)
        self.assertEqual(value['fixtureDisposition'], 'manual-diagnosis-required')
        self.assertEqual(value['verdict'], 'PASS')
        self.assertNotIn('/private/do-not-publish', json.dumps(C.public_report(value)))

    def test_callback_closure_missing_wrong_type_or_retained_owner_stays_unknown(self):
        changes = (("child_settled", None), ("child_settled", 1),
                   ("settlement_failed", None), ("settlement_failed", 0), ("settlement_failed", True),
                   ("source_handles_closed", None), ("source_handles_closed", 1), ("source_handles_closed", False),
                   ("private_owner", object()), ("retained_sources", (object(),)), ("retained_sources", []))
        for key, value in changes:
            self.fixture()
            error = OSError("private contradictory closure")
            error.child_settled, error.settlement_failed, error.source_handles_closed = True, False, True
            error.retained_sources = ()
            if value is None:
                delattr(error, key)
            else:
                setattr(error, key, value)
            def failure(_):
                raise error
            self.sentinel = failure
            out = self.rejected()
            self.assertFalse(out.public["childSettled"] or out.public["sourceHandlesClosed"])
            self.assertEqual(self.git.states, 1)
            self.assertIs(out.primary, error)

    def test_later_close_metadata_cannot_rehabilitate_pending_callback_unknown(self):
        self.fixture()
        original = OSError("private unknown callback")
        later = OSError("private close metadata")
        later.child_settled, later.settlement_failed, later.source_handles_closed = True, False, True
        def broken(_):
            raise original
        self.sentinel = broken
        self.source_effect = lambda p, s: setattr(s, "close_error", later) if p == "bin/current-doctor" else None
        out = self.rejected()
        self.assertIs(out.primary, original)
        self.assertIn(later, out.errors)
        self.assertFalse(out.public["childSettled"] or out.public["sourceHandlesClosed"])

    def test_callback_proven_close_keeps_earliest_interruption_identity(self):
        for original in (KeyboardInterrupt(), SystemExit(0)):
            self.fixture()
            original.child_settled, original.settlement_failed, original.source_handles_closed = True, False, True
            def broken(_):
                raise original
            self.sentinel = broken
            with self.assertRaises(type(original)) as caught:
                self.invoke()
            self.assertIs(caught.exception, original)
            self.assertTrue(original.doctor_outcome.public["childSettled"])
            self.assertTrue(original.doctor_outcome.public["sourceHandlesClosed"])
            self.assertEqual(original.doctor_outcome.public["verdict"], "NEEDS_REVIEW")


class ExposureGit(Git):
    """Synthetic real-tree seam with the exact, unpatched fe7 receipt bytes.

Historical replacement blobs are opaque fake Git OIDs, not invented preimage
bytes. NativeGit's fixed fe7 query is independently tested below.
"""
    def __init__(self, accepted=True):
        self.files = {**PUBLIC, C.PHASE5_ACCEPTANCE: OLD_RAW}
        self.modes = {}
        self.baseline = self.rows()
        for p in C.ROUTERS:
            self.baseline[p] = ("100644", "0" * 40)
        self.files.update(SENTINEL_PUBLIC)
        prior = SENTINEL["sources"] | SENTINEL["evidence"]
        self.modes.update({p: item["mode"] for p, item in prior.items()})
        self.reviewed = self.rows()
        for p, item in SENTINEL["sources"].items():
            if p in C.EXPOSURE_REPLACEMENTS:
                self.reviewed[p] = (item["mode"], "1" * 40)
        for p, change in SENTINEL["routers"].items():
            self.reviewed[p] = (change["after"]["mode"], "2" * 40)
        self.files[C.ACCEPTANCE] = SENTINEL_RAW
        self.anchor = {**self.reviewed, C.ACCEPTANCE: ("100644", C.oid(SENTINEL_RAW))}
        self.meta = {"commits": ("3" * 40,), "parents": (SENTINEL["reviewedHead"],),
            "identity": C.D.COORDINATOR, "changes": (("A", C.ACCEPTANCE),), "tree": self.reviewed}
        for p in C.EXPOSURE_ADDITIONS | C.EXPOSURE_REPLACEMENTS:
            self.files[p] = ("exact new exposure source " + p).encode()
        self.modes["bin/aid-sessionstart"] = "100755"
        self.evidence_path = C.EXPOSURE_EVIDENCE + "review.json"
        self.files[self.evidence_path] = b"pure fake source adjudication"
        self.exposure_reviewed = self.rows()
        before = SENTINEL["sources"] | {p: v["after"] for p, v in SENTINEL["routers"].items()}
        self.record = {"schema": 1, "kind": "SESSIONSTART_EXPOSURE",
            "status": "ACCEPTED_SOURCE_READY_FOR_APPLY", "predecessorCommit": C.EXPOSURE_BASE,
            "sentinelAcceptanceSHA256": C.SENTINEL_SHA256, "reviewedHead": "4" * 40,
            "sources": {p: row(self.files[p], self.modes.get(p, "100644")) for p in C.EXPOSURE_ADDITIONS},
            "evidence": {self.evidence_path: row(self.files[self.evidence_path])},
            "replacements": {p: {"before": before[p], "after": row(self.files[p], self.modes.get(p, "100644"))}
                             for p in C.EXPOSURE_REPLACEMENTS},
            "checks": {k: {"status": "PASS", "evidence": self.evidence_path} for k in ("sourceTests", "finalReview")},
            "exposureSourceAccepted": True, **{k: False for k in C.AUTHORITY}}
        self.exposure_meta = {"commits": ("5" * 40,), "parents": (self.record["reviewedHead"],),
            "identity": C.D.COORDINATOR, "changes": (("A", C.EXPOSURE_ACCEPTANCE),),
            "tree": self.exposure_reviewed}
        if accepted:
            self.save_record()
        self.value = {"head": "6" * 40, "branch": "main" if accepted else C.EXPOSURE_BRANCH,
            "clean": True, "baseAncestor": True, "linear": True, "tree": self.rows(), "baseTree": self.baseline,
            "exposure": {"head": "6" * 40, "predecessorCommit": C.EXPOSURE_BASE,
                         "ancestor": True, "linear": True, "tree": self.anchor}}
        self.states, self.effect = 0, None

    def save_record(self):
        self.files[C.EXPOSURE_ACCEPTANCE] = raw(self.record)
        if hasattr(self, "value"):
            self.value["tree"] = self.rows()

    def acceptance(self, reviewed):
        C.require(reviewed == SENTINEL["reviewedHead"])
        return copy.deepcopy(self.meta)

    def exposure_acceptance(self, reviewed):
        C.require(reviewed == self.record["reviewedHead"])
        return copy.deepcopy(self.exposure_meta)


class ExposureTests(unittest.TestCase):
    source, invoke, rejected = DoctorTests.source, DoctorTests.invoke, DoctorTests.rejected

    def fixture(self, accepted=True):
        DoctorTests.fixture(self, accepted)
        self.git = ExposureGit(accepted)

    def test_exact_anchor_and_public_fixture_bytes_match(self):
        self.assertEqual(C.digest(SENTINEL_RAW), C.SENTINEL_SHA256)
        for p, data in SENTINEL_PUBLIC.items():
            self.assertEqual(C.digest(data), (SENTINEL["sources"] | SENTINEL["evidence"])[p]["sha256"])

    def test_preparation_retains_sentinel_acceptance_without_exposure_acceptance(self):
        self.fixture(False)
        value = self.invoke(git_only=True)
        self.assertEqual(value["verdict"], "PREPARED_SOURCE_ONLY")
        self.assertTrue(value["historicalPhase5Accepted"] and value["sentinelAccepted"])
        self.assertTrue(value["exposureSourceIncluded"])
        self.assertFalse(value["exposureSourceAccepted"] or value["exposureStateChecked"] or value["integratedMain"])
        self.assertEqual(self.sentinel_calls + self.runtime_calls, 0)
        receipt = next(s for p, s in self.sources if p == C.EXPOSURE_ACCEPTANCE)
        self.assertTrue(receipt.absent)
        self.assertEqual(receipt.closes, 1)

    def test_accepted_source_main_modes_never_claim_installation(self):
        for git_only in (False, True):
            self.fixture()
            value = self.invoke(git_only=git_only)
            self.assertEqual(value["verdict"], "GIT_ONLY_VALID" if git_only else "PASS")
            self.assertTrue(value["exposureSourceAccepted"] and value["sentinelAccepted"] and value["integratedMain"])
            self.assertFalse(value["exposureStateChecked"] or value["liveRuntimeChecked"])
            self.assertTrue(all(value[k] is False for k in C.AUTHORITY))
            self.assertIs(C.public_report(value, git_only=git_only), value)
            self.assertEqual(len(self.sources), len({p for p, _ in self.sources}))

    def test_review_branch_source_acceptance_does_not_imply_integrated(self):
        for accepted in (False, True):
            self.fixture(accepted)
            self.git.value["branch"] = C.EXPOSURE_BRANCH
            value = self.invoke()
            self.assertEqual(value["verdict"], "PREPARED_FOR_INDEPENDENT_REVIEW")
            self.assertEqual(value["exposureSourceAccepted"], accepted)
            self.assertFalse(value["integratedMain"] or value["exposureStateChecked"])

    def test_unaccepted_main_and_wrong_branch_or_location_fail_before_callback(self):
        for branch, canonical, accepted in (("main", True, False), (C.BRANCH, False, False),
                                           ("HEAD", True, True), ("other", True, True), ("main", False, True)):
            self.fixture(accepted)
            self.git.value["branch"] = branch
            self.rejected(canonical_main=canonical)
            self.assertEqual(self.sentinel_calls, 0)

    def test_fixed_predecessor_full_observation_and_final_generation(self):
        changes = (("head", "7" * 40), ("predecessorCommit", C.BASE), ("ancestor", False),
                   ("ancestor", 1), ("linear", False), ("linear", 1), ("extra", True))
        for key, value in changes:
            self.fixture()
            self.git.value["exposure"][key] = value
            self.rejected()
            self.assertEqual(self.sentinel_calls, 0)
        self.fixture()
        del self.git.value["exposure"]
        self.rejected()
        self.fixture()
        def later(count):
            if count == 2:
                self.git.value["exposure"]["tree"]["bin/current-doctor"] = ("100755", "f" * 40)
        self.git.effect = later
        out = self.rejected()
        self.assertEqual(out.public["failureStage"], "final-recheck")
        self.assertEqual(self.sentinel_calls, 1)

    def test_historical_tree_is_not_filtered_current_or_mutable_preimage(self):
        for substitute in ("current", "doctor", "receipt"):
            self.fixture()
            tree = self.git.value["exposure"]["tree"]
            if substitute == "current":
                self.git.value["exposure"]["tree"] = copy.deepcopy(self.git.value["tree"])
            elif substitute == "doctor":
                tree["bin/current-doctor"] = ("100755", "8" * 40)
            else:
                tree[C.ACCEPTANCE] = ("100644", "8" * 40)
            self.rejected()
            self.assertEqual(self.sentinel_calls, 0)

    def test_exact_old_receipt_bytes_and_unrelated_sources_remain_immutable(self):
        for path in (C.ACCEPTANCE, C.PHASE5_ACCEPTANCE, "lib/phase5_runtime_backend.py",
                     "lib/current_doctor_native.py", "config/codex/config.toml"):
            self.fixture()
            if path not in self.git.files:
                self.assertEqual(path, "config/codex/config.toml")
                path = next(p for p in PUBLIC if p.startswith("codex/"))
            self.git.files[path] += b"changed"
            self.git.value["tree"] = self.git.rows()
            self.rejected()
            self.assertEqual(self.sentinel_calls, 0)

    def test_only_exact_five_additions_and_exposure_evidence(self):
        for accepted in (False, True):
            for path in ("bin/unaccepted", "lib/unaccepted.py", "outside.py", "docs/unrelated.md", "evidence/other/result.json"):
                self.fixture(accepted)
                self.git.files[path] = b"unexpected addition"
                self.git.value["tree"] = self.git.rows()
                self.rejected()
            for path in C.EXPOSURE_ADDITIONS:
                self.fixture(accepted)
                del self.git.files[path]
                self.git.value["tree"] = self.git.rows()
                self.rejected()

    def test_no_prior_deletion_and_fixed_regular_modes(self):
        for accepted in (False, True):
            self.fixture(accepted)
            del self.git.files["lib/current_doctor_native.py"]
            self.git.value["tree"] = self.git.rows()
            self.rejected()
            for mode in ("120000", "160000"):
                self.fixture(accepted)
                p = "bin/aid-sessionstart"
                self.git.value["tree"][p] = (mode, C.oid(self.git.files[p]))
                self.rejected()

    def test_exact_before_after_source_and_mode_receipt_binding(self):
        for part in ("before-sha", "before-mode", "after-sha", "after-mode", "addition-sha", "evidence-sha"):
            self.fixture()
            entry = self.git.record["replacements"]["bin/current-doctor"]
            if part.startswith("before"):
                # Deep-copy: keep the actual prior receipt fixture immutable.
                entry["before"] = {**entry["before"], "sha256" if part.endswith("sha") else "mode":
                                   "0" * 64 if part.endswith("sha") else "100644"}
            elif part.startswith("after"):
                entry["after"]["sha256" if part.endswith("sha") else "mode"] = "0" * 64 if part.endswith("sha") else "100644"
            elif part == "addition-sha":
                self.git.record["sources"]["bin/aid-sessionstart"]["sha256"] = "0" * 64
            else:
                self.git.record["evidence"][self.git.evidence_path]["sha256"] = "0" * 64
            self.git.save_record()
            self.rejected()
            self.assertEqual(self.sentinel_calls, 0)

    def test_both_engine_replacements_mandatory_and_bound(self):
        for path in C.EXPOSURE_ENGINES:
            self.fixture()
            del self.git.record["replacements"][path]
            self.git.save_record()
            self.rejected()
            self.fixture(False)
            self.git.value["tree"][path] = self.git.anchor[path]
            self.rejected()
            self.fixture()
            self.git.files[path] += b"self-mutation"
            self.git.value["tree"] = self.git.rows()
            self.rejected()

    def test_closed_exact_receipt_schema_and_no_authority(self):
        for key, value in (("schema", True), ("predecessorCommit", C.BASE),
                           ("sentinelAcceptanceSHA256", "0" * 64), ("status", "INSTALLED"),
                           ("exposureSourceAccepted", 1), ("extra", True),
                           *((key, True) for key in C.AUTHORITY)):
            self.fixture()
            self.git.record[key] = value
            self.git.save_record()
            self.rejected()
        for changed in ("extra-replacement", "missing-source", "bad-check", "wrong-evidence-prefix"):
            self.fixture()
            if changed == "extra-replacement":
                self.git.record["replacements"]["lib/current_doctor_native.py"] = self.git.record["replacements"]["bin/current-doctor"]
            elif changed == "missing-source":
                self.git.record["sources"].pop("bin/aid-sessionstart")
            elif changed == "bad-check":
                self.git.record["checks"]["sourceTests"]["status"] = "FAIL"
            else:
                self.git.record["evidence"] = {"evidence/elsewhere.json": row(b"bad")}
            self.git.save_record()
            self.rejected()

    def test_acceptance_is_sole_coordinator_child_of_exact_reviewed_tree(self):
        for key, value in (("commits", ("5" * 40, "7" * 40)), ("parents", ("8" * 40,)),
                           ("parents", ("4" * 40, "8" * 40)), ("identity", ("wrong",) * 4),
                           ("changes", (("M", C.EXPOSURE_ACCEPTANCE),)),
                           ("changes", (("A", C.EXPOSURE_ACCEPTANCE), ("M", "bin/current-doctor")))):
            self.fixture()
            self.git.exposure_meta[key] = value
            self.rejected()
        self.fixture()
        self.git.exposure_meta["tree"][C.EXPOSURE_ACCEPTANCE] = self.git.value["tree"][C.EXPOSURE_ACCEPTANCE]
        self.rejected()

    def test_descendant_evidence_only_does_not_rewrite_accepted_generation(self):
        self.fixture()
        self.git.files[C.EXPOSURE_EVIDENCE + "later-observation.json"] = b"not source acceptance"
        self.git.value["tree"] = self.git.rows()
        self.assertEqual(self.invoke(git_only=True)["verdict"], "GIT_ONLY_VALID")
        self.fixture()
        self.git.files[self.git.evidence_path] += b"rewrite"
        self.git.value["tree"] = self.git.rows()
        self.rejected()
        self.fixture()
        self.git.value["tree"][C.EXPOSURE_EVIDENCE + "link"] = ("120000", "0" * 40)
        self.rejected()

    def test_guard_and_final_recheck_hold_new_source_and_acceptance_absence(self):
        for accepted, path in ((True, "bin/current-doctor"), (True, "bin/aid-sessionstart"),
                               (True, C.EXPOSURE_ACCEPTANCE), (False, C.EXPOSURE_ACCEPTANCE)):
            self.fixture(accepted)
            def change(_):
                held = next(s for p, s in self.sources if p == path)
                held.data += b"appearance or mutation"
                self.guard()
                self.fail("changed held source admitted")
            self.sentinel = change
            out = self.rejected()
            self.assertFalse(out.public["repositoryChecksPassed"])

    def test_new_source_acquisition_and_close_maintain_original_ownership(self):
        for path in (C.EXPOSURE_ACCEPTANCE, "bin/aid-sessionstart", "bin/current-doctor"):
            self.fixture()
            error = OSError("private closure")
            self.source_effect = lambda p, held: setattr(held, "close_error", error) if p == path else None
            out = self.rejected(git_only=True)
            self.assertIs(out.primary, error)
            self.assertFalse(out.public["sourceHandlesClosed"])
        for error in (KeyboardInterrupt(), SystemExit(0)):
            self.fixture()
            self.source_effect = lambda p, held: setattr(held, "verify_error", error) if p == "bin/aid-sessionstart" else None
            with self.assertRaises(type(error)) as caught:
                self.invoke(git_only=True)
            self.assertIs(caught.exception, error)
            self.assertTrue(all(held.closes == 1 for _, held in self.sources))
            self.assertEqual(error.doctor_outcome.public["verdict"], "NEEDS_REVIEW")

    def test_public_scope_cannot_claim_unaccepted_integration_or_installed_state(self):
        for kwargs in ({"exposure_accepted": True}, {"exposure": True},
                       {"exposure": True, "exposure_accepted": True, "accepted": False}):
            with self.assertRaises(ValueError):
                C.report(**{"historical": True, "source": True, "accepted": True, "integrated": True,
                            "sentinel": True, "sentinel_checked": True, **kwargs})
        for field in ("exposureStateChecked", "exposureSourceIncluded", "exposureSourceAccepted"):
            self.fixture()
            value = self.invoke()
            value[field] = not value[field]
            with self.assertRaises(ValueError):
                C.public_report(value)


class NativeGitSourceTests(unittest.TestCase):
    """Exercise actual new Git-vector code with fake _read, never a Git child."""
    def fixture(self):
        # The collector's actual command vectors have their own independent
        # injected tests. Here assert forwarding without extending old fixtures
        # into fabricated configuration ancestry.
        from lib import config_transition_git as G
        self.configuration_observation = {"bounded": "collector fixture"}
        collector = patch.object(G, "observe", return_value=self.configuration_observation)
        self.collector = collector.start()
        self.addCleanup(collector.stop)
        self.calls = []
        self.git = C.NativeGit("/fake/home", "/fake/repo", Budget())
        self.head, self.reviewed, self.commit = "c" * 40, "a" * 40, "b" * 40
        self.baseline = {C.PHASE5_ACCEPTANCE: ("100644", C.oid(OLD_RAW))}
        self.current = {**self.baseline, "bin/current-doctor": ("100755", "e" * 40)}
        self.overrides = {}
        def read(*args, allow_one=False):
            self.calls.append((args, allow_one))
            if args in self.overrides:
                return self.overrides[args]
            if args == ("rev-parse", "--verify", "HEAD"):
                return 0, self.head.encode() + b"\n"
            if args == ("symbolic-ref", "--quiet", "--short", "HEAD"):
                return 0, C.BRANCH.encode() + b"\n"
            if args in (("status", "--porcelain=v1", "-z", "--untracked-files=all"),
                        ("merge-base", "--is-ancestor", C.BASE, self.head),
                        ("rev-list", "--merges", C.BASE + ".." + self.head)):
                return 0, b""
            if args[:3] == ("ls-tree", "-rz", "--full-tree"):
                C.require(args[3] in (C.BASE, self.head, self.reviewed))
                tree = self.baseline if args[3] == C.BASE else self.current
                return 0, b"".join((mode + " blob " + blob + "\t" + path).encode() + b"\0"
                                   for path, (mode, blob) in tree.items())
            if args == ("log", "--format=%H", "HEAD", "--", C.ACCEPTANCE):
                return 0, self.commit.encode() + b"\n"
            if args == ("show", "-s", "--format=%P%x00%an%x00%ae%x00%cn%x00%ce", self.commit):
                return 0, "\0".join((self.reviewed, *C.D.COORDINATOR)).encode() + b"\n"
            if args == ("diff-tree", "--no-commit-id", "--name-status", "-r", "-z", self.commit):
                return 0, b"A\0" + C.ACCEPTANCE.encode() + b"\0"
            raise AssertionError(("unexpected Git vector", args))
        self.git._read = read

    def test_real_new_predecessor_queries_without_old_state_or_constants(self):
        self.fixture()
        old_base, old_acceptance = C.D.BASE, C.D.ACCEPTANCE
        with patch.object(C.D.NativeGit, "state", side_effect=AssertionError("old state forbidden")):
            value = self.git.state()
        self.assertEqual(value["baseTree"], self.baseline)
        self.assertEqual(value["tree"], self.current)
        self.assertIs(value["configuration"], self.configuration_observation)
        self.collector.assert_called_once_with(self.git, self.head, self.current)
        self.assertTrue(value["baseAncestor"] and value["linear"] and value["clean"])
        self.assertIn((("merge-base", "--is-ancestor", C.BASE, self.head), True), self.calls)
        self.assertEqual((C.D.BASE, C.D.ACCEPTANCE), (old_base, old_acceptance))
        self.assertFalse(any(old_base in arg for args, _ in self.calls for arg in args))

    def test_new_receipt_path_and_exact_child_metadata(self):
        self.fixture()
        value = self.git.acceptance(self.reviewed)
        self.assertEqual(value["parents"], (self.reviewed,))
        self.assertEqual(value["changes"], (("A", C.ACCEPTANCE),))
        self.assertEqual(value["identity"], C.D.COORDINATOR)
        self.assertIn((("log", "--format=%H", "HEAD", "--", C.ACCEPTANCE), False), self.calls)

    def test_multiple_receipt_commits_and_modified_path_reject(self):
        for kind in ("history", "change", "metadata"):
            self.fixture()
            if kind == "history":
                self.overrides[("log", "--format=%H", "HEAD", "--", C.ACCEPTANCE)] = (0, (self.commit + "\n" + self.head).encode())
            elif kind == "change":
                self.overrides[("diff-tree", "--no-commit-id", "--name-status", "-r", "-z", self.commit)] = (0, b"M\0" + C.ACCEPTANCE.encode() + b"\0")
            else:
                self.overrides[("show", "-s", "--format=%P%x00%an%x00%ae%x00%cn%x00%ce", self.commit)] = (0, b"malformed")
            with self.assertRaises(ValueError):
                self.git.acceptance(self.reviewed)

    def test_inherited_transport_keeps_exact_deadline_and_admission(self):
        git = C.NativeGit("/fake/home", "/fake/repo", Budget())
        seen = []
        def command(launch, budget, seconds, **kwargs):
            self.assertEqual(seconds, 8.0)
            self.assertEqual(launch.cwd, "/fake/repo")
            self.assertEqual(launch.argv, C.D.NativeGit.PREFIX + ("rev-parse", "--verify", "HEAD"))
            self.assertEqual(launch.environment["GIT_NO_LAZY_FETCH"], "1")
            self.assertEqual(launch.environment["GIT_CONFIG_GLOBAL"], "/dev/null")
            self.assertTrue(kwargs["admit_launch"](launch))
            seen.append(launch)
            return SimpleNamespace(returncode=0, stdout=b"fake\n", stderr=b"")
        with patch.object(C.D.process, "command", side_effect=command), \
             patch.object(C.D.R.catalog.subprocess, "Popen", side_effect=AssertionError("native forbidden")):
            self.assertEqual(git._text("rev-parse", "--verify", "HEAD"), "fake")
        self.assertEqual(len(seen), 1)

    def test_current_git_transport_accepts_only_exact_observed_temp_warning(self):
        git = C.NativeGit('/fake/home', '/fake/repo', Budget())
        def result(stderr, code=0):
            return SimpleNamespace(returncode=code, stdout=b'a'*40+b'\n', stderr=stderr)
        for count in (0, 1, 2, 4):
            with patch.object(C.D.process, 'command', return_value=result(git.TEMP_WARNING*count)):
                self.assertEqual(git._text('rev-parse', '--verify', 'HEAD'), 'a'*40)
        for stderr in (git.TEMP_WARNING*5, git.TEMP_WARNING+b'fatal: unsafe repository\n',
                       b'unknown warning\n', git.TEMP_WARNING.rstrip(b'\n'),
                       git.TEMP_WARNING.replace(b'code 5', b'code 13')):
            with self.subTest(stderr=stderr), \
                 patch.object(C.D.process, 'command', return_value=result(stderr)), self.assertRaises(ValueError):
                git._text('rev-parse', '--verify', 'HEAD')
        with patch.object(C.D.process, 'command', return_value=result(git.TEMP_WARNING, 1)):
            with self.assertRaises(ValueError): git._text('rev-parse', '--verify', 'HEAD')
            self.assertEqual(git._read('merge-base', '--is-ancestor', 'a'*40, 'b'*40, allow_one=True)[0], 1)
        # The installed/historical verifier is not modified to obtain a PASS.
        old = C.D.NativeGit('/fake/home', '/fake/repo', Budget())
        with patch.object(C.D.process, 'command', return_value=result(git.TEMP_WARNING)), self.assertRaises(ValueError):
            old._text('rev-parse', '--verify', 'HEAD')

    def test_lazy_native_wiring_uses_mock_module_exact_doctor_and_mode(self):
        for mode in (False, True):
            calls = []
            result = {"pure mocked adapter": mode}
            def native(doctor, git_only):
                calls.append((doctor, git_only))
                return result
            adapter = SimpleNamespace(native=native)
            with patch.object(C.importlib, "import_module", return_value=adapter) as loader, \
                 patch.object(C, "NativeGit", side_effect=AssertionError("real Git forbidden")):
                self.assertIs(C.native(mode), result)
            loader.assert_called_once_with("lib.current_doctor_native")
            self.assertEqual(calls, [(C, mode)])

    def test_native_rejects_nonboolean_mode_before_loading_adapter(self):
        for mode in (None, 1, 0, "--git-only"):
            with patch.object(C.importlib, "import_module", side_effect=AssertionError("adapter load forbidden")):
                with self.assertRaises(ValueError):
                    C.native(mode)

    def test_exposure_state_queries_exact_actual_fe7_without_filtering(self):
        self.fixture()
        self.overrides[("symbolic-ref", "--quiet", "--short", "HEAD")] = (0, C.EXPOSURE_BRANCH.encode() + b"\n")
        self.overrides[("merge-base", "--is-ancestor", C.EXPOSURE_BASE, self.head)] = (0, b"")
        self.overrides[("rev-list", "--merges", C.EXPOSURE_BASE + ".." + self.head)] = (0, b"")
        anchored = b"100755 blob " + b"1" * 40 + b"\tbin/current-doctor\0"
        self.overrides[("ls-tree", "-rz", "--full-tree", C.EXPOSURE_BASE)] = (0, anchored)
        with patch.object(C.D.NativeGit, "state", side_effect=AssertionError("old state forbidden")):
            state = self.git.state()
        self.assertEqual(state["exposure"], {"head": self.head, "predecessorCommit": C.EXPOSURE_BASE,
            "ancestor": True, "linear": True, "tree": {"bin/current-doctor": ("100755", "1" * 40)}})
        self.assertNotEqual(state["exposure"]["tree"], state["tree"])
        self.assertIn((("ls-tree", "-rz", "--full-tree", C.EXPOSURE_BASE), False), self.calls)
        self.assertIn((("merge-base", "--is-ancestor", C.EXPOSURE_BASE, self.head), True), self.calls)

    def test_exposure_receipt_uses_own_exact_history_and_bounded_path(self):
        self.fixture()
        self.overrides[("log", "--format=%H", "HEAD", "--", C.EXPOSURE_ACCEPTANCE)] = (0, self.commit.encode() + b"\n")
        self.overrides[("diff-tree", "--no-commit-id", "--name-status", "-r", "-z", self.commit)] = (
            0, b"A\0" + C.EXPOSURE_ACCEPTANCE.encode() + b"\0")
        meta = self.git.exposure_acceptance(self.reviewed)
        self.assertEqual(meta["changes"], (("A", C.EXPOSURE_ACCEPTANCE),))
        self.assertIn((("log", "--format=%H", "HEAD", "--", C.EXPOSURE_ACCEPTANCE), False), self.calls)
        count = len(self.calls)
        with self.assertRaises(ValueError):
            self.git._acceptance("evidence/arbitrary/acceptance.json", self.reviewed)
        self.assertEqual(len(self.calls), count)


class ConfigurationGit(ExposureGit):
    def __init__(self, accepted=True):
        super().__init__(True)
        from lib import config_transitions as F
        self.cfg_anchor = self.rows()
        for path in C.configurations.BOOTSTRAP_PATHS:
            if path not in self.files:
                self.files[path] = ("new protected bootstrap file " + path).encode()
        self.files["bin/current-doctor"] = b"generic reviewed engine"
        paths = ["evidence/config-transitions/bootstrap/" + role + ".json"
                 for role in ("validation", "review", "rollback")]
        for path in paths:
            self.files[path] = b"{}"
        reviewed = self.rows()
        record = {"schema": 1, "id": "bootstrap", "kind": "bootstrap",
            "status": "ACCEPTED_CONFIGURATION", "anchor_commit": C.configurations.ANCHOR,
            "previous_commit": C.configurations.ANCHOR, "previous_acceptance": None,
            "reviewed_commit": "7" * 40, "reviewed_tree": "8" * 40,
            "changes": F.delta(self.cfg_anchor, reviewed),
            "evidence": dict(zip(("validation", "review", "rollback"), ([p] for p in paths))),
            "coordinator": {"name": C.D.COORDINATOR[0], "email": C.D.COORDINATOR[1]}}
        pending = [{"commit": "7" * 40, "parents": [C.configurations.ANCHOR], "tree": reviewed}]
        observations = []
        accepted_commit, accepted_tree = C.configurations.ANCHOR, self.cfg_anchor
        if accepted:
            path = F.PREFIX + "bootstrap/acceptance.json"
            self.files[path] = raw(record)
            accepted_commit, accepted_tree = "9" * 40, self.rows()
            observations.append({"path": path, "raw": self.files[path],
                "acceptance_commit": accepted_commit, "acceptance_parents": ["7" * 40],
                "acceptance_identity": record["coordinator"], "reviewed_tree_id": "8" * 40,
                "base_tree": self.cfg_anchor, "reviewed_tree": reviewed,
                "accepted_tree": accepted_tree, "candidate_commits": pending})
            pending = []
        head = accepted_commit if accepted else "7" * 40
        self.value.update(head=head, branch="main" if accepted else "codex/ordinary-candidate", tree=self.rows())
        self.value["exposure"]["head"] = head
        self.value["configuration"] = {"anchorTree": self.cfg_anchor, "transitions": observations,
            "acceptedCommit": accepted_commit, "acceptedTree": accepted_tree, "pendingCommits": pending}


class ConfigurationDoctorTests(unittest.TestCase):
    source, rejected = DoctorTests.source, DoctorTests.rejected

    def fixture(self, accepted=True):
        DoctorTests.fixture(self, accepted)
        self.git = ConfigurationGit(accepted)

    def invoke(self, **kwargs):
        rules = C.configurations.policy(self.git.cfg_anchor)
        # Historical seam fixtures omit unrelated pre-Phase5 repository files.
        # Keep this fixture's closure exact; production fixed policy is tested
        # separately and the real candidate is checked without this seam.
        rules["protected_paths"] &= self.git.files.keys()
        with patch.object(C.configurations, "policy", return_value=rules):
            return DoctorTests.invoke(self, **kwargs)

    def test_real_historical_tree_and_complete_new_physical_binding_are_distinct(self):
        self.fixture()
        with patch.object(C, "verify_exposure", wraps=C.verify_exposure) as check:
            value = self.invoke()
        self.assertEqual(check.call_args.kwargs["current"], self.git.cfg_anchor)
        self.assertNotEqual(check.call_args.kwargs["current"], self.git.value["tree"])
        self.assertTrue(value["configurationSourceAccepted"] and value["currentSentinelReady"])
        self.assertEqual(value["verdict"], "PASS")
        self.assertEqual({p for p, s in self.sources if not s.absent}, set(self.git.value["tree"]))
        self.assertEqual(len(self.sources), len({p for p, s in self.sources}))
        self.assertFalse(any(value[k] for k in C.AUTHORITY))

    def test_pending_candidate_is_not_accepted_and_git_only_never_calls_live(self):
        self.fixture(False)
        self.sentinel = lambda _: self.fail("live call forbidden")
        value = self.invoke(git_only=True)
        self.assertEqual(value["verdict"], "PREPARED_SOURCE_ONLY")
        self.assertFalse(value["configurationSourceAccepted"] or value["integratedMain"]
                         or value["sentinelChecked"] or value["currentRuntimeReady"])
        self.assertTrue(value["exposureSourceAccepted"])

    def test_unreviewed_main_rejects_before_callback(self):
        self.fixture(False)
        self.git.value["branch"] = "main"
        out = self.rejected()
        self.assertEqual(out.public["failureStage"], "configuration")
        self.assertEqual(self.sentinel_calls, 0)

    def test_new_payload_drift_and_deleted_import_initializer_reappearance_revoke_pass(self):
        for target in ("docs/reviewed-config-transitions.md", "lib/__init__.py"):
            self.fixture()
            def sentinel(_):
                next(s for p, s in self.sources if p == target).verify_error = ValueError("drift")
                return {"status": "PASS", "childSettled": True, "sourceHandlesClosed": True}
            self.sentinel = sentinel
            out = self.rejected()
            self.assertFalse(out.public["currentSentinelReady"] or out.public["repositoryChecksPassed"])

    def test_git_drift_and_unknown_callback_cannot_be_accepted_live(self):
        for unknown in (False, True):
            self.fixture()
            if unknown:
                self.sentinel = lambda _: {"status": "PASS", "childSettled": False, "sourceHandlesClosed": True}
            else:
                def sentinel(_):
                    self.git.value["clean"] = False
                    return {"status": "PASS", "childSettled": True, "sourceHandlesClosed": True}
                self.sentinel = sentinel
            self.assertFalse(self.rejected().public["currentSentinelReady"])

    def test_report_rejects_accepted_configuration_without_historical_exposure(self):
        with self.assertRaises(ValueError):
            C.report(configuration=True, configuration_accepted=True)


if __name__ == "__main__":
    unittest.main()
