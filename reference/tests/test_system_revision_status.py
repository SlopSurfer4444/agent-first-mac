"""Pure hostile observations plus disposable real Git; never a native probe.

No real forced signal/deadline, installed marker, owner live root, Nix, root,
private state or source-policy mutation is used by this suite.
"""
import copy
import hashlib
import importlib.machinery
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
S = importlib.machinery.SourceFileLoader("tested_system_revision_status", str(ROOT / "bin/system-revision-status")).load_module()


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def oid(text):
    return hashlib.sha1(text.encode()).hexdigest()


def blob(content):
    return hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()


def valid_source():
    return {"schema": 1, "probe": "current-doctor", "scope": "post-phase5-vendor-sentinel",
        "verdict": "GIT_ONLY_VALID", "failureStage": None, "reasonCodes": [], "admissionMode": "historical-review",
        **{key: True for key in S.SOURCE_TRUE}, **{key: False for key in S.SOURCE_FALSE}}


def valid_marker(revision):
    return raw({"configurationRevision": revision, "darwinLabel": "fixture-label",
                "darwinRevision": oid("darwin"), "nixpkgsRevision": oid("nixpkgs")})


class Adapter:
    def __init__(self, exact=False):
        self.installed = oid("installed acceptance child")
        self.reviewed = oid("reviewed but never accepted parent")
        self.head = self.installed if exact else oid("current acceptance child")
        self.commits = (self.installed,) if exact else (self.installed, self.head)
        self.history = (self.installed,) if exact else (self.installed, self.reviewed, self.head)
        self.graph = {"flake.nix": ("100644", oid("reviewed flake imports only local darwin")),
            "flake.lock": ("100644", oid("locked dependencies")),
            "darwin/main.nix": ("100644", oid("module")),
            "darwin/automount.sh": ("100755", oid("consumed script"))}
        self.trees = {self.installed: dict(self.graph), self.head: dict(self.graph)}
        self.witness = {"schema": 1, "auditedRevision": self.installed,
            "inputs": S.projection(self.graph), "graphScopes": list(S.SCOPES), "claim": S.CLAIM}
        self.blobs = {}
        self.set_descriptor(raw(self.witness))
        self.state = {"head": self.head, "branch": "main", "clean": True,
            "canonical": True, "identity": ("fixture root inode", "fixture source hash")}
        self.response, self.code = valid_source(), 0
        self.marker_raw = valid_marker(self.installed)
        self.marker_identity = ("fixture marker inode", "fixture marker resolved path")
        self.calls = []
        self.failure = None
        self.drift = None

    def set_descriptor(self, value):
        object_id = blob(value)
        self.blobs[object_id] = value
        self.trees[self.head][S.DESCRIPTOR] = ("100644", object_id)

    def call(self, name):
        self.calls.append(name)
        if self.drift is not None:
            self.drift(self, name)

    def snapshot(self):
        self.call("snapshot")
        return copy.deepcopy(self.state)

    def source_report(self):
        self.call("source_report")
        return self.code, raw(self.response) if type(self.response) is dict else self.response

    def configuration(self, head):
        self.call("configuration")
        assert head == self.head
        return copy.deepcopy(self.trees[head]), self.commits, self.history

    def tree(self, revision):
        self.call("tree")
        return copy.deepcopy(self.trees[revision])

    def blob(self, object_id):
        self.call("blob")
        return self.blobs[object_id]

    def marker(self):
        self.call("marker")
        return self.marker_raw, self.marker_identity


class CurrentAdapter(Adapter):
    """Bounded current admission; historical IDs are checked only on demand."""
    def __init__(self, exact=False):
        super().__init__(exact=exact)
        self.response["admissionMode"] = "current-state"

    def configuration(self, head):
        self.call("configuration")
        assert head == self.head
        return copy.deepcopy(self.trees[head]), None, None

    def admitted_revision(self, commit, *, accepted):
        self.call("admitted_installed" if accepted else "admitted_witness")
        return commit in (self.commits if accepted else self.history)


class RevisionStatusTests(unittest.TestCase):
    def reject(self, adapter, reason=None):
        value = S.inspect(adapter)
        self.assertEqual(value["state"], "UNKNOWN")
        self.assertFalse(value["compatible"])
        self.assertTrue(value["readOnly"])
        self.assertFalse(value["systemMutationsPerformed"])
        if reason:
            self.assertEqual(value["reason"], reason)
        self.assertNotIn("fixture root", json.dumps(value))
        return value

    def test_exact_accepted_revision(self):
        value = S.inspect(Adapter(exact=True))
        self.assertEqual(value["state"], "CURRENT_REVISION")
        self.assertTrue(all(value[k] for k in ("compatible", "revisionExact", "sourceAccepted",
            "installedCommitAccepted", "systemInputsEqual", "childSettled", "sourceHandlesClosed")))

    def test_accepted_control_only_successor(self):
        adapter = Adapter()
        adapter.trees[adapter.head]["docs/new.md"] = ("100644", oid("docs change"))
        value = S.inspect(adapter)
        self.assertEqual(value["state"], "ACCEPTED_CONTROL_ONLY_SUCCESSOR")
        self.assertTrue(value["compatible"])
        self.assertFalse(value["revisionExact"])
        self.assertEqual(adapter.calls.count("source_report"), 2)
        self.assertEqual(adapter.calls.count("snapshot"), 3)
        self.assertEqual(adapter.calls.count("marker"), 3)

    def test_current_state_admission_is_labeled_without_independent_review_claim(self):
        for exact in (False, True):
            with self.subTest(exact=exact):
                adapter = CurrentAdapter(exact=exact)
                value = S.inspect(adapter)
                self.assertTrue(value["compatible"])
                self.assertEqual(value["sourceAdmissionMode"], "current-state")
                self.assertEqual(value["state"], "CURRENT_REVISION" if exact else "CURRENT_CONTROL_ONLY_SUCCESSOR")
                self.assertEqual(value["reason"], "exact_admitted_revision" if exact else "current_system_inputs_unchanged")
                self.assertEqual(adapter.calls.count("admitted_installed"), 1)
                self.assertEqual(adapter.calls.count("admitted_witness"), 0 if exact else 1)

    def test_current_state_installed_revision_requires_strict_acceptance(self):
        for bad in (False, 1, None, "true"):
            adapter = CurrentAdapter()
            with patch.object(adapter, "admitted_revision", return_value=bad):
                self.reject(adapter, "installed_commit_not_accepted")
        adapter = CurrentAdapter()
        adapter.marker_raw = valid_marker(adapter.reviewed)
        self.reject(adapter, "installed_commit_not_accepted")

    def test_current_state_witness_may_be_historical_candidate_only(self):
        adapter = CurrentAdapter()
        adapter.trees[adapter.reviewed] = dict(adapter.graph)
        adapter.witness["auditedRevision"] = adapter.reviewed
        adapter.set_descriptor(raw(adapter.witness))
        self.assertTrue(S.inspect(adapter)["compatible"])
        adapter.witness["auditedRevision"] = oid("foreign witness")
        adapter.set_descriptor(raw(adapter.witness))
        self.reject(adapter, "invalid_descriptor")

    def test_current_state_never_accepts_historical_tuple_as_routine_admission(self):
        adapter = Adapter()
        adapter.response["admissionMode"] = "current-state"
        self.reject(adapter, "observation_failed")
        adapter = CurrentAdapter()
        adapter.response["admissionMode"] = "historical-review"
        self.reject(adapter, "observation_failed")

    def test_current_state_public_result_cannot_claim_historical_review(self):
        current = S.inspect(CurrentAdapter())
        for update in ({"sourceAdmissionMode": "historical-review"},
                {"state": "ACCEPTED_CONTROL_ONLY_SUCCESSOR"},
                {"reason": "reviewed_system_inputs_unchanged"}, {"sourceAdmissionMode": None}):
            with self.subTest(update=update):
                with self.assertRaises(S.ObservationError):
                    S.public(dict(current, **update))

    def test_current_state_mode_drift_is_rejected_on_final_check(self):
        adapter = CurrentAdapter()
        def drift(value, name):
            if name == "source_report" and value.calls.count(name) == 2:
                value.response["admissionMode"] = "historical-review"
        adapter.drift = drift
        self.reject(adapter, "observation_drift")

    def test_source_admission_mode_is_required_and_exact(self):
        for bad in (None, True, 1, "routine", [], {}):
            adapter = Adapter()
            adapter.response["admissionMode"] = bad
            self.reject(adapter, "source_report_invalid")
        adapter = Adapter()
        del adapter.response["admissionMode"]
        self.reject(adapter, "source_report_invalid")

    def test_component_agnostic_graph_changes_are_pending(self):
        changes = (("flake.lock", ("100644", oid("new lock"))),
            ("darwin/main.nix", ("100644", oid("new module"))),
            ("darwin/automount.sh", ("100755", oid("new script"))),
            ("darwin/automount.sh", ("100644", oid("consumed script"))),
            ("modules/new.nix", ("100644", oid("new module namespace"))),
            ("darwin/new.txt", ("100644", oid("new non-nix dependency"))),
            ("darwin/main.nix", None), ("flake.nix", ("120000", oid("symlink target"))))
        for path, row in changes:
            with self.subTest(path=path, row=row):
                adapter = Adapter()
                if row is None:
                    del adapter.trees[adapter.head][path]
                else:
                    adapter.trees[adapter.head][path] = row
                value = S.inspect(adapter)
                self.assertEqual(value["state"], "PENDING_APPLY")
                self.assertEqual(value["reason"], "system_inputs_changed")
                self.assertFalse(value["compatible"] or value["systemInputsEqual"])

    def test_equal_but_unwitnessed_external_dependency_graph_is_unknown(self):
        adapter = Adapter()
        for revision in (adapter.head, adapter.installed):
            adapter.trees[revision]["flake.nix"] = ("100644", oid("imports ./outside/other.nix"))
        adapter.trees[adapter.head]["outside/other.nix"] = ("100644", oid("different external input"))
        self.reject(adapter, "unwitnessed_system_inputs")

    def test_witness_must_match_actual_audited_tree_not_just_endpoints(self):
        adapter = Adapter()
        audited = oid("separate audited acceptance")
        adapter.commits = (audited, adapter.installed, adapter.head)
        adapter.history = adapter.commits
        adapter.trees[audited] = dict(adapter.graph, **{"flake.nix": ("100644", oid("different audited flake"))})
        adapter.witness["auditedRevision"] = audited
        adapter.set_descriptor(raw(adapter.witness))
        self.reject(adapter, "unwitnessed_system_inputs")

    def test_unaccepted_audit_revision_rejected(self):
        adapter = Adapter()
        adapter.witness["auditedRevision"] = oid("foreign commit not in verified chain")
        adapter.set_descriptor(raw(adapter.witness))
        self.reject(adapter, "invalid_descriptor")

    def test_witness_may_use_verified_candidate_but_installed_may_not(self):
        adapter = Adapter()
        adapter.trees[adapter.reviewed] = dict(adapter.graph)
        adapter.witness["auditedRevision"] = adapter.reviewed
        adapter.set_descriptor(raw(adapter.witness))
        self.assertEqual(S.inspect(adapter)["state"], "ACCEPTED_CONTROL_ONLY_SUCCESSOR")
        adapter.marker_raw = valid_marker(adapter.reviewed)
        self.reject(adapter, "installed_commit_not_accepted")

    def test_installed_parent_arbitrary_ancestor_unknown_and_injection_rejected(self):
        for installed in (oid("arbitrary ancestor"), oid("reviewed but never accepted parent"), "-v", "HEAD", "a" * 40 + "\n"):
            with self.subTest(installed=installed):
                adapter = Adapter()
                adapter.marker_raw = valid_marker(installed)
                self.reject(adapter, "installed_commit_not_accepted" if S.oid(installed) else "invalid_marker")

    def test_dirty_untracked_and_noncanonical_worktree_rejected_before_doctor(self):
        for field, value, reason in (("clean", False, "dirty_source"), ("clean", 1, "dirty_source"),
                ("canonical", False, "noncanonical_source"), ("branch", "review", "noncanonical_source")):
            with self.subTest(field=field):
                adapter = Adapter()
                adapter.state[field] = value
                self.reject(adapter, reason)
                self.assertEqual(adapter.calls, ["snapshot"])

    def test_every_required_admission_boolean_is_exact(self):
        for field in S.SOURCE_TRUE:
            for bad in (False, 1, None, "true"):
                with self.subTest(field=field, bad=bad):
                    adapter = Adapter()
                    adapter.response[field] = bad
                    self.reject(adapter, "source_not_accepted" if bad is False else "source_report_invalid")
                    self.assertNotIn("marker", adapter.calls)

    def test_report_exit_zero_prepared_or_live_report_never_accepted(self):
        for field, value in (("verdict", "PREPARED_SOURCE_ONLY"), ("verdict", "PASS"),
                ("failureStage", "configuration"), ("rootAuthorized", True)):
            adapter = Adapter()
            adapter.response[field] = value
            self.reject(adapter, "source_not_accepted")
        for code in (1, True, "0"):
            adapter = Adapter()
            adapter.code = code
            self.reject(adapter, "source_not_accepted" if type(code) is int else "source_report_invalid")

    def test_strict_report_schema_and_bounded_failure_redaction(self):
        for response in (b'{"private":"/secret/private-home"}', b"not json /private", b"[]", b"{" * 1100,
                raw(valid_source())[:-1] + b',"schema":1}', b"x" * (S.MAX_JSON + 1)):
            adapter = Adapter()
            adapter.response = response
            value = self.reject(adapter, "source_report_invalid")
            self.assertFalse(value["childSettled"] or value["sourceHandlesClosed"])
            self.assertNotIn("secret", json.dumps(value))
        for alter in (lambda v: v.update(schema=True), lambda v: v.pop("gitOnly"),
                lambda v: v.update(unrecognized="private"), lambda v: v.pop("reasonCodes"),
                lambda v: v.update(reasonCodes="private"),
                lambda v: v.update(reasonCodes=["fixture_invalid"]),
                lambda v: v.update(reasonCodes=["/secret/private-home"])):
            adapter = Adapter()
            alter(adapter.response)
            self.reject(adapter, "source_report_invalid")

    def test_strict_marker_schema(self):
        base = json.loads(valid_marker(Adapter().installed))
        bad_values = [b"null", b"[]", b"not JSON", raw(base)[:-1] + b',"configurationRevision":"' + b"a" * 40 + b'"}']
        for key, value in (("configurationRevision", None), ("configurationRevision", True),
                ("configurationRevision", "a" * 39), ("darwinLabel", "private\npath"),
                ("darwinRevision", 123), ("extra", "value")):
            bad_values.append(raw(dict(base, **{key: value})))
        for value in bad_values:
            adapter = Adapter()
            adapter.marker_raw = value
            self.reject(adapter, "invalid_marker")

    def test_strict_descriptor_schema_paths_modes_and_types(self):
        mutations = [lambda v: v.update(schema=True), lambda v: v.update(extra=True),
            lambda v: v.update(claim="I promise"), lambda v: v.update(graphScopes=["darwin"]),
            lambda v: v.update(auditedRevision="HEAD"), lambda v: v.update(inputs=[]),
            lambda v: v["inputs"].pop("flake.lock"),
            lambda v: v["inputs"].update({"../external": {"mode": "100644", "oid": "a" * 40}}),
            lambda v: v["inputs"].update({"docs/external.md": {"mode": "100644", "oid": "a" * 40}}),
            lambda v: v["inputs"]["flake.nix"].update(mode="120000"),
            lambda v: v["inputs"]["flake.nix"].update(oid=True)]
        for mutate in mutations:
            adapter = Adapter(exact=True)
            mutate(adapter.witness)
            adapter.set_descriptor(raw(adapter.witness))
            self.reject(adapter, "invalid_descriptor")
        adapter = Adapter()
        adapter.set_descriptor(raw(adapter.witness)[:-1] + b',"schema":1}')
        self.reject(adapter, "invalid_descriptor")

    def test_source_root_head_clean_marker_and_final_admission_rechecked(self):
        def mutator(field, value):
            def drift(adapter, name):
                if name == "snapshot" and adapter.calls.count(name) == 2:
                    adapter.state[field] = value
            return drift
        drifts = [mutator("identity", ("replacement inode",)), mutator("head", oid("new head")),
            mutator("clean", False), mutator("canonical", False)]
        def marker_drift(adapter, name):
            if name == "marker" and adapter.calls.count(name) == 2:
                adapter.marker_identity = ("replacement marker",)
        def final_report_drift(adapter, name):
            if name == "source_report" and adapter.calls.count(name) == 2:
                adapter.response["configurationSourceAccepted"] = False
        drifts.extend((marker_drift, final_report_drift))
        for drift in drifts:
            adapter = Adapter()
            adapter.drift = drift
            value = self.reject(adapter, "observation_drift")
            self.assertFalse(value["sourceAccepted"])

    def test_failed_io_and_unsettled_owners_remain_private_and_attached(self):
        adapter = Adapter()
        private = RuntimeError("private path /secret and private stderr")
        private.child_settled = None
        private.source_handles_closed = False
        private.private_owner = object()
        with patch.object(adapter, "tree", side_effect=private):
            value = self.reject(adapter, "observation_failed")
        self.assertFalse(value["childSettled"] or value["sourceHandlesClosed"])
        self.assertIs(adapter.failure, private)
        with self.assertRaises(SystemExit) as caught:
            S.main(["--json"], operation=lambda: (_ for _ in ()).throw(S.StatusError(value, adapter)))
        self.assertIs(caught.exception.private_owner, adapter)
        self.assertEqual(caught.exception.revision_outcome, value)

    def test_deterministic_interruption_does_not_lose_owner(self):
        adapter = Adapter()
        with patch.object(adapter, "marker", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt) as caught:
                S.inspect(adapter)
        self.assertIs(caught.exception.private_owner, adapter)
        self.assertFalse(caught.exception.revision_outcome["compatible"])

    def test_cli_exact_surface_status_and_schema(self):
        for args in ([], ["--json"]):
            emitted = []
            self.assertEqual(S.main(args, operation=lambda: S.inspect(Adapter()), emit=emitted.append), 0)
            self.assertEqual(len(emitted), 1)
        for args in (["--fixture"], ["--root", "/tmp"], ["--json", "--json"], ["--apply"], "--json", [True]):
            emitted = []
            self.assertEqual(S.main(args, operation=lambda: self.fail("unexpected native operation"), emit=emitted.append), 2)
            self.assertEqual(json.loads(emitted[0])["reason"], "arguments")
        emitted = []
        self.assertEqual(S.main(["--json"], operation=lambda: {"secret": "private"}, emit=emitted.append), 1)
        self.assertNotIn("private", emitted[0])
        self.assertEqual(set(json.loads(emitted[0])), set(S.report()))

    def test_native_worktree_rejected_before_loading_native_dependencies(self):
        with patch.object(S.importlib.machinery, "SourceFileLoader", side_effect=AssertionError("must not import")):
            with self.assertRaisesRegex(S.ObservationError, "noncanonical_source"):
                S.Native()

    def test_report_schema_matches_current_doctor(self):
        doctor = importlib.machinery.SourceFileLoader("revision_fixture_current_doctor", str(ROOT / "bin/current-doctor")).load_module()
        expected = doctor.report(historical=True, source=True, accepted=True, integrated=True,
            git_only=True, exposure=True, exposure_accepted=True, configuration=True, configuration_accepted=True)
        self.assertEqual(valid_source(), expected)
        self.assertTrue(S.source_report(0, raw(expected))[1])

    def test_positive_public_results_require_consistent_booleans_revisions_and_reason(self):
        accepted = S.inspect(Adapter())
        for field, bad in (("sourceAccepted", False), ("installedCommitAccepted", False),
                ("systemInputsEqual", False), ("childSettled", False), ("sourceHandlesClosed", False),
                ("sourceRevision", None), ("revisionExact", True), ("reason", "observation_failed"),
                ("readOnly", False), ("systemMutationsPerformed", True), ("compatible", 1)):
            with self.subTest(field=field):
                with self.assertRaises(S.ObservationError):
                    S.public(dict(accepted, **{field: bad}))


class NativeBoundaryTests(unittest.TestCase):
    """Deterministic transport/file seams; no process or real marker is opened."""
    def native_file(self, *, payload=b"{}", facts=None, close_error=None):
        native = S.Native.__new__(S.Native)
        native.budget = SimpleNamespace(check=lambda: None)
        facts = facts or SimpleNamespace(st_dev=1, st_ino=2, st_uid=0, st_gid=0,
            st_mode=0o100444, st_nlink=1, st_size=len(payload), st_mtime_ns=4, st_ctime_ns=5, st_flags=0)
        patches = {"open": Mock(return_value=71), "fstat": Mock(return_value=facts),
            "stat": Mock(return_value=facts), "read": Mock(side_effect=[payload, b""]),
            "close": Mock(side_effect=close_error)}
        self.stack = []
        for name, value in patches.items():
            item = patch.object(S.os, name, value)
            item.start()
            self.addCleanup(item.stop)
        item = patch.object(S.os.path, "realpath", return_value="/nix/store/fixture/darwin-version.json")
        item.start()
        self.addCleanup(item.stop)
        return native, patches

    def test_native_configuration_uses_only_bounded_current_admission(self):
        import lib
        native = S.Native.__new__(S.Native)
        native.git = object()
        native.own_raw = b"fixture local observer"
        native.doctor = SimpleNamespace(D=SimpleNamespace(oid=blob))
        tree = {S.SELF: ("100755", blob(native.own_raw))}
        native.tree = Mock(return_value=tree)
        observation = object()
        admission = SimpleNamespace(included=Mock(return_value=True), observe=Mock(return_value=observation),
            admit=Mock(return_value={"accepted": True}), admitted_revision=Mock(return_value=True))
        collector = SimpleNamespace(observe=Mock(side_effect=AssertionError("routine replay forbidden")))
        with patch.object(lib, "current_source_admission", admission, create=True), \
                patch.object(lib, "config_transition_git", collector, create=True):
            head = oid("routine current head")
            self.assertEqual(native.configuration(head), (tree, None, None))
            admission.included.assert_called_once_with(tree)
            admission.observe.assert_called_once_with(native.git, head, tree)
            collector.observe.assert_not_called()
            admission.admit.assert_called_once_with(observation, head, tree)
            self.assertTrue(native.admitted_revision(head, accepted=True))
            admission.admitted_revision.assert_called_once_with(native.git, head, accepted=True)
            admission.admit.return_value = {"accepted": 1}
            with self.assertRaisesRegex(S.ObservationError, "source_not_accepted"):
                native.configuration(head)

    def test_native_configuration_before_migration_preserves_historical_route(self):
        import lib
        native = S.Native.__new__(S.Native)
        native.git = object()
        native.own_raw = b"fixture historical observer"
        native.doctor = SimpleNamespace(D=SimpleNamespace(oid=blob))
        tree = {S.SELF: ("100755", blob(native.own_raw))}
        native.tree = Mock(return_value=tree)
        head, reviewed = oid("accepted historical child"), oid("reviewed historical parent")
        observation = {"transitions": [{"acceptance_commit": head,
            "candidate_commits": [{"commit": reviewed}]}]}
        admission = SimpleNamespace(included=Mock(return_value=False),
            observe=Mock(side_effect=AssertionError("no migration receipt")))
        collector = SimpleNamespace(observe=Mock(return_value=observation))
        historical = SimpleNamespace(admit=Mock(return_value={"accepted": True}))
        with patch.object(lib, "current_source_admission", admission, create=True), \
                patch.object(lib, "config_transition_git", collector, create=True), \
                patch.object(lib, "config_transition_source", historical, create=True):
            self.assertEqual(native.configuration(head), (tree, (head,), (reviewed, head)))
            collector.observe.assert_called_once_with(native.git, head, tree)
            historical.admit.assert_called_once_with(observation, head, tree, review=False)
            admission.observe.assert_not_called()
            historical.admit.return_value = {"accepted": 1}
            with self.assertRaisesRegex(S.ObservationError, "source_not_accepted"):
                native.configuration(head)

    def test_native_configuration_present_invalid_migration_never_falls_back(self):
        import lib
        from lib import current_source_admission as real_admission
        native = S.Native.__new__(S.Native)
        native.git = object()
        native.own_raw = b"fixture current observer"
        native.doctor = SimpleNamespace(D=SimpleNamespace(oid=blob))
        tree = {S.SELF: ("100755", blob(native.own_raw)), real_admission.MIGRATION_PATH: ("120000", oid("invalid receipt"))}
        native.tree = Mock(return_value=tree)
        admission = SimpleNamespace(included=real_admission.included,
            observe=Mock(side_effect=ValueError("invalid migration")))
        collector = SimpleNamespace(observe=Mock(side_effect=AssertionError("fallback forbidden")))
        with patch.object(lib, "current_source_admission", admission), \
                patch.object(lib, "config_transition_git", collector, create=True):
            with self.assertRaisesRegex(ValueError, "invalid migration"):
                native.configuration(oid("current head"))
            collector.observe.assert_not_called()

    def test_marker_file_bounded_read_nofollow_and_single_close(self):
        native, calls = self.native_file()
        content, identity = native._file("/run/current-system/darwin-version.json", installed=True)
        self.assertEqual(content, b"{}")
        self.assertEqual(calls["open"].call_count, 1)
        self.assertTrue(calls["open"].call_args.args[1] & S.os.O_NOFOLLOW)
        self.assertTrue(calls["open"].call_args.args[1] & S.os.O_NONBLOCK)
        calls["close"].assert_called_once_with(71)
        self.assertEqual(identity[0], "/nix/store/fixture/darwin-version.json")

    def test_marker_file_rejects_nonregular_writable_nonroot_and_oversized(self):
        for change in ({"st_mode": 0o040755}, {"st_mode": 0o100666}, {"st_uid": 501}, {"st_size": 8193}):
            with self.subTest(change=change):
                facts = SimpleNamespace(st_mode=0o100444, st_uid=0, st_size=2)
                for name, value in change.items():
                    setattr(facts, name, value)
                native, calls = self.native_file(facts=facts)
                with self.assertRaises(S.ObservationError):
                    native._file("/run/current-system/darwin-version.json", installed=True)
                calls["read"].assert_not_called()
                calls["close"].assert_called_once_with(71)

    def test_close_failure_preserves_descriptor_without_retry(self):
        failure = OSError("private descriptor failure")
        native, calls = self.native_file(close_error=failure)
        with self.assertRaises(OSError) as caught:
            native._file("/run/current-system/darwin-version.json", installed=True)
        self.assertIs(caught.exception, failure)
        self.assertFalse(failure.source_handles_closed)
        self.assertEqual(failure.retained_fd, 71)
        calls["close"].assert_called_once_with(71)

    def test_fixed_doctor_transport_preserves_sanitized_environment_and_deadline(self):
        native = S.Native.__new__(S.Native)
        native.root = "/fixture/control"
        native.budget = SimpleNamespace(check=lambda: None)
        native.git = SimpleNamespace(environment={"PATH": "/usr/bin:/bin", "HOME": "/fixture"})
        popen = object()
        catalog = SimpleNamespace(subprocess=SimpleNamespace(Popen=popen))
        def command(launch, budget, maximum, **kwargs):
            self.assertEqual(launch.argv, ("/usr/bin/python3", "/fixture/control/bin/current-doctor", "--git-only", "--json"))
            self.assertEqual(launch.cwd, "/fixture/control")
            self.assertEqual(launch.environment, native.git.environment)
            self.assertIs(budget, native.budget)
            self.assertEqual(maximum, 180.0)
            self.assertIs(kwargs["process_factory"], popen)
            self.assertTrue(kwargs["admit_launch"](launch))
            launch.environment["UNREVIEWED"] = "value"
            with self.assertRaises(S.ObservationError):
                kwargs["admit_launch"](launch)
            return SimpleNamespace(returncode=0, stdout=raw(valid_source()), stderr=b"")
        native.doctor = SimpleNamespace(D=SimpleNamespace(process=SimpleNamespace(command=command),
            R=SimpleNamespace(catalog=catalog)))
        self.assertEqual(native.source_report(), (0, raw(valid_source())))


class RealGitRevisionTests(unittest.TestCase):
    """Actual receipt-child identities through the unchanged collector/admitter."""
    def setUp(self):
        fixtures = importlib.machinery.SourceFileLoader("revision_repository_fixtures",
            str(ROOT / "tests/test_config_transition_repository.py")).load_module()
        self.case = fixtures.RepositoryTests()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        from lib import config_transition_source as admission
        self.admission = admission
        for name, value in (("ANCHOR", self.case.anchor),
                ("policy", lambda anchor: self.case.rules), ("policy_updates", lambda anchor: {})):
            item = patch.object(admission, name, value)
            item.start()
            self.addCleanup(item.stop)
        self.case.transition("bootstrap", lambda: self.case.put("lib/engine.py", b"reviewed engine"))
        self.case.transition("payload", lambda: (
            self.case.put("flake.nix", b"fixture flake"), self.case.put("flake.lock", b"fixture lock"),
            self.case.put("darwin/main.nix", b"fixture module"),
            self.case.put("darwin/automount.sh", b"fixture shell input")))
        self.installed = self.case.previous
        witness = {"schema": 1, "auditedRevision": self.installed,
            "inputs": S.projection(self.case.git._tree(self.installed)),
            "graphScopes": S.SCOPES, "claim": S.CLAIM}
        self.reviewed, _ = self.case.transition("descriptor", lambda: self.case.put(S.DESCRIPTOR, raw(witness)))

    def adapter(self):
        case, admission, installed = self.case, self.admission, self.installed
        class Real(Adapter):
            def __init__(self):
                super().__init__()
                self.head = case.previous
                self.state["head"] = self.head
                self.marker_raw = valid_marker(installed)

            def snapshot(self):
                self.state["clean"] = case.git._read("status", "--porcelain=v1", "-z", "--untracked-files=all")[1] == b""
                return super().snapshot()

            def configuration(self, head):
                from lib import config_transition_git as collector
                tree = self.tree(head)
                value = collector.observe(case.git, head, tree)
                assert admission.admit(value, head, tree, review=False)["accepted"] is True
                accepted = tuple(t["acceptance_commit"] for t in value["transitions"])
                history = tuple(commit for t in value["transitions"]
                    for commit in (*[r["commit"] for r in t["candidate_commits"]], t["acceptance_commit"]))
                return tree, accepted, history

            def tree(self, revision):
                return case.git._tree(revision)

            def blob(self, object_id):
                return case.git._read("cat-file", "blob", object_id)[1]
        return Real()

    def test_actual_child_passes_but_reviewed_parent_never_does(self):
        value = S.inspect(self.adapter())
        self.assertEqual(value["state"], "ACCEPTED_CONTROL_ONLY_SUCCESSOR")
        adapter = self.adapter()
        adapter.marker_raw = valid_marker(self.reviewed)
        value = S.inspect(adapter)
        self.assertEqual(value["reason"], "installed_commit_not_accepted")
        self.assertFalse(value["compatible"])

    def test_real_lock_change_is_pending_and_untracked_is_unknown(self):
        self.case.transition("new-lock", lambda: self.case.put("flake.lock", b"next locked input"))
        value = S.inspect(self.adapter())
        self.assertEqual(value["state"], "PENDING_APPLY")
        self.case.put("untracked-fixture.txt", b"unreviewed")
        value = S.inspect(self.adapter())
        self.assertEqual(value["reason"], "dirty_source")

    def test_real_unreviewed_commit_is_not_promoted_by_exit_zero(self):
        self.case.put("docs/unreviewed.md", b"not accepted yet")
        self.case.previous = self.case.commit()
        value = S.inspect(self.adapter())
        self.assertEqual(value["state"], "UNKNOWN")
        self.assertFalse(value["compatible"])

    def test_real_graph_and_descriptor_refresh_in_same_accepted_transition(self):
        self.case.put("flake.nix", b"next reviewed flake")
        self.case.put("flake.lock", b"next locked graph")
        reviewed_graph = self.case.commit()
        witness = {"schema": 1, "auditedRevision": reviewed_graph,
            "inputs": S.projection(self.case.git._tree(reviewed_graph)),
            "graphScopes": S.SCOPES, "claim": S.CLAIM}
        self.case.transition("graph-refresh", lambda: self.case.put(S.DESCRIPTOR, raw(witness)))
        self.installed = self.case.previous
        self.case.transition("later-control-only", lambda: self.case.put("docs/next.md", b"ordinary control source"))
        value = S.inspect(self.adapter())
        self.assertEqual(value["state"], "ACCEPTED_CONTROL_ONLY_SUCCESSOR")


if __name__ == "__main__":
    unittest.main()
