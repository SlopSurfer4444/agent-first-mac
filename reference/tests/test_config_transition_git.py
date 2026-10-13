"""Synthetic injected transport only; no Git, subprocess or private-state access."""

import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import config_transition_git as G
from lib import config_transitions as C

BOOTSTRAP_PATHS = ("lib/config_transitions.py", "bin/current-doctor")
COORDINATOR = {"name": "Coordinator", "email": "coordinator@example.invalid"}


def oid(value):
    return hashlib.sha1(value.encode()).hexdigest()


def blob(value, mode="100644"):
    return mode, oid(value)


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class FakeGit:
    """Fail every transport call outside the explicitly observed safe surface."""

    def __init__(self):
        self.history = []
        self.calls = []
        self.blobs = {}
        self.ancestor = True
        self.listing = None
        self.head = G.ANCHOR
        self.coordinator = dict(COORDINATOR)
        self.tree = {"darwin/default.nix": blob("initial configuration"),
                     "evidence/historical/acceptance.json": blob("historical receipt")}
        self.objects = {G.ANCHOR: {"tree": dict(self.tree), "tree_id": oid("anchor tree")}}
        self.accepted_commit, self.accepted_tree = self.head, dict(self.tree)
        self.acceptances = []

    def append(self, updates=None, parents=None):
        before = self.head
        tree = dict(self.tree)
        for path, entry in (updates or {}).items():
            if entry is None:
                tree.pop(path)
            else:
                tree[path] = entry
        commit = oid("commit-" + str(len(self.history)))
        row = {"commit": commit, "parents": [before] if parents is None else parents,
               "tree": tree, "tree_id": oid("tree-" + commit),
               "author": dict(self.coordinator), "committer": dict(self.coordinator)}
        self.history.append(row)
        self.objects[commit] = row
        self.head, self.tree = commit, tree
        return row

    def accept(self, updates=None, mutate=None):
        index = len(self.acceptances)
        ident = "change-" + str(index)
        evidence = {kind: ["evidence/reviews/" + ident + "-" + kind + ".json"]
                    for kind in ("validation", "review", "rollback")}
        if updates is None:
            updates = {"lib/config_transitions.py": blob("protected engine"),
                       "bin/current-doctor": blob("protected caller", "100755")}
        updates = dict(updates)
        for paths in evidence.values():
            updates[paths[0]] = blob(paths[0])
        reviewed = self.append(updates)
        path = C.PREFIX + ident + "/acceptance.json"
        record = {"schema": 1, "id": ident,
            "kind": "bootstrap" if not index else "configuration",
            "status": "ACCEPTED_CONFIGURATION", "anchor_commit": G.ANCHOR,
            "previous_commit": self.accepted_commit,
            "previous_acceptance": self.acceptances[-1]["path"] if index else None,
            "reviewed_commit": reviewed["commit"], "reviewed_tree": reviewed["tree_id"],
            "changes": C.delta(self.accepted_tree, reviewed["tree"]),
            "evidence": evidence, "coordinator": dict(self.coordinator)}
        if mutate is not None:
            mutate(record)
        content = raw(record)
        blob_id = C.blob_oid(content)
        self.blobs[blob_id] = content
        accepted = self.append({path: ("100644", blob_id)})
        result = {"path": path, "record": record, "raw": content,
                  "reviewed": reviewed, "accepted": accepted}
        self.acceptances.append(result)
        self.accepted_commit, self.accepted_tree = self.head, dict(self.tree)
        return result

    def _read(self, *args, allow_one=False):
        self.calls.append(("read", args, allow_one))
        if args == ("merge-base", "--is-ancestor", G.ANCHOR, self.head):
            assert allow_one is True
            return (0 if self.ancestor else 1), b""
        if len(args) == 3 and args[:2] == ("cat-file", "blob"):
            assert allow_one is False and C.OID.fullmatch(args[2])
            return 0, self.blobs[args[2]]
        raise AssertionError("unexpected Git read")

    def _text(self, *args):
        self.calls.append(("text", args))
        if args == ("rev-list", "--reverse", "--topo-order", "--parents",
                    "--max-count=" + str(G.MAX_COMMITS + 1), G.ANCHOR + ".." + self.head):
            if self.listing is not None:
                return self.listing
            return "\n".join(" ".join([row["commit"], *row["parents"]]) for row in self.history)
        if len(args) == 3 and args[:2] == ("rev-parse", "--verify"):
            assert args[2].endswith("^{tree}")
            return self.objects[args[2][:-7]]["tree_id"]
        if len(args) == 4 and args[:3] == (
                "show", "-s", "--format=%P%x00%an%x00%ae%x00%cn%x00%ce"):
            row = self.objects[args[3]]
            return "\0".join([" ".join(row["parents"]), row["author"]["name"],
                row["author"]["email"], row["committer"]["name"], row["committer"]["email"]])
        raise AssertionError("unexpected Git text")

    def _tree(self, commit):
        self.calls.append(("tree", commit))
        return dict(self.objects[commit]["tree"])

    def observe(self):
        return G.observe(self, self.head, self.tree)


class ConfigTransitionGitTests(unittest.TestCase):
    def fixture(self):
        git = FakeGit()
        git.accept()
        return git

    def rejects(self, git, reason=None):
        with self.assertRaises(C.TransitionError) as caught:
            git.observe()
        if reason is not None:
            self.assertEqual(str(caught.exception), reason)
        self.assertLess(len(str(caught.exception)), 80)

    def verify(self, git, observation):
        return C.verify(G.ANCHOR, observation["anchorTree"], observation["transitions"],
            git.head, git.tree, protected_paths=BOOTSTRAP_PATHS,
            bootstrap_paths=BOOTSTRAP_PATHS, coordinator=COORDINATOR,
            tail_commits=observation["pendingCommits"])

    def test_anchor_has_no_implicit_transition(self):
        git = FakeGit()
        result = git.observe()
        self.assertEqual(result, {"anchorTree": git.tree, "transitions": [],
            "acceptedCommit": G.ANCHOR, "acceptedTree": git.tree, "pendingCommits": []})
        self.assertEqual(self.verify(git, result)["status"], "HISTORICAL_ANCHOR")

    def test_actual_predecessors_trees_and_two_successive_configuration_changes(self):
        git = self.fixture()
        git.accept({"darwin/default.nix": blob("package alpha"),
                    "manifests/alpha.json": blob("alpha ownership")})
        git.accept({"darwin/other.nix": blob("package beta"),
                    "manifests/beta.json": blob("beta ownership")})
        result = git.observe()
        self.assertEqual(result["acceptedCommit"], git.head)
        self.assertEqual(result["acceptedTree"], git.tree)
        self.assertEqual(result["pendingCommits"], [])
        prior = git.objects[G.ANCHOR]["tree"]
        for index, row in enumerate(result["transitions"]):
            self.assertEqual(row["base_tree"], prior)
            self.assertEqual(row["reviewed_tree"], git.acceptances[index]["reviewed"]["tree"])
            self.assertEqual(row["reviewed_tree_id"], git.acceptances[index]["reviewed"]["tree_id"])
            prior = git.acceptances[index]["accepted"]["tree"]
        self.assertEqual(self.verify(git, result)["transition_count"], 3)

    def test_every_intermediate_candidate_tree_is_retained(self):
        git = self.fixture()
        transient = git.append({"darwin/transient.nix": blob("temporary package")})
        reverted = git.append({"darwin/transient.nix": None})
        git.accept({"darwin/default.nix": blob("final package")})
        result = git.observe()
        rows = result["transitions"][1]["candidate_commits"]
        self.assertEqual([row["commit"] for row in rows],
                         [transient["commit"], reverted["commit"], git.acceptances[1]["reviewed"]["commit"]])
        self.assertIn("darwin/transient.nix", rows[0]["tree"])
        self.assertNotIn("darwin/transient.nix", rows[1]["tree"])

    def test_transient_historical_evidence_rewrite_reaches_policy_verification(self):
        git = self.fixture()
        path = "evidence/historical/acceptance.json"
        original = git.tree[path]
        git.append({path: blob("temporary rewrite")})
        git.append({path: original})
        git.accept({"darwin/default.nix": blob("final package")})
        result = git.observe()
        with self.assertRaisesRegex(C.TransitionError, "historical_evidence_changed"):
            self.verify(git, result)

    def test_pending_source_and_evidence_tail_remain_unaccepted(self):
        for path in ("darwin/unreviewed.nix", "evidence/later/result.json"):
            with self.subTest(path=path):
                git = self.fixture()
                accepted = git.head
                pending = git.append({path: blob("later source")})
                result = git.observe()
                self.assertEqual(result["acceptedCommit"], accepted)
                self.assertEqual(result["pendingCommits"], [{"commit": pending["commit"],
                    "parents": pending["parents"], "tree": pending["tree"]}])
                with self.assertRaisesRegex(C.TransitionError, "unreviewed_current_source"):
                    self.verify(git, result)

    def test_pending_after_anchor_remains_unaccepted(self):
        git = FakeGit()
        row = git.append({"darwin/default.nix": blob("pending")})
        result = git.observe()
        self.assertEqual(result["acceptedCommit"], G.ANCHOR)
        self.assertEqual(len(result["pendingCommits"]), 1)
        self.assertEqual(result["pendingCommits"][0]["commit"], row["commit"])

    def test_tree_ids_are_independently_read_not_receipt_claims(self):
        git = FakeGit()
        receipt = git.accept(mutate=lambda record: record.update({"reviewed_tree": oid("false tree")}))
        self.rejects(git, "reviewed_identity_mismatch")
        self.assertIn(("text", ("rev-parse", "--verify", receipt["reviewed"]["commit"] + "^{tree}")), git.calls)

    def test_receipt_commit_and_predecessor_are_not_executed_as_revisions(self):
        for field in ("previous_commit", "reviewed_commit"):
            with self.subTest(field=field):
                git = FakeGit()
                unknown = oid("off-branch commit")
                git.accept(mutate=lambda record: record.update({field: unknown}))
                self.rejects(git)
                self.assertFalse(any(unknown in str(call) for call in git.calls))

    def test_predecessor_cannot_skip_prior_accepted_configuration(self):
        git = self.fixture()
        git.accept({"darwin/default.nix": blob("second")},
                   mutate=lambda record: record.update({"previous_commit": G.ANCHOR,
                                                       "previous_acceptance": None}))
        self.rejects(git, "broken_predecessor")

    def test_rewritten_removed_and_delete_restore_receipt_rejected(self):
        for change, restore in ((None, False), (blob("rewritten"), False),
                                (None, True), (blob("rewritten"), True)):
            with self.subTest(change=change, restore=restore):
                git = self.fixture()
                path = git.acceptances[0]["path"]
                original = git.tree[path]
                git.append({path: change})
                if restore:
                    git.append({path: original})
                self.rejects(git, "git_receipt_history_changed")

    def test_unknown_receipt_cannot_disappear_before_head(self):
        git = self.fixture()
        path = C.PREFIX + "unknown/acceptance.json"
        content = b"{}"
        git.blobs[C.blob_oid(content)] = content
        git.append({"darwin/pending.nix": blob("candidate")})
        git.append({path: ("100644", C.blob_oid(content))})
        git.append({path: None})
        self.rejects(git, "invalid_schema")

    def test_invalid_reserved_receipt_path_cannot_hide_in_history(self):
        git = self.fixture()
        path = C.PREFIX + "nested/extra/acceptance.json"
        git.append({path: blob("unknown")})
        git.append({path: None})
        self.rejects(git, "invalid_receipt_path")

    def test_acceptance_commit_has_exactly_one_new_receipt(self):
        for path in ("darwin/sneaked.nix", C.PREFIX + "extra/acceptance.json"):
            with self.subTest(path=path):
                git = self.fixture()
                git.tree[path] = blob("unreviewed extra")
                self.rejects(git)

    def test_author_and_committer_both_match_the_receipt(self):
        for field in ("author", "committer"):
            with self.subTest(field=field):
                git = self.fixture()
                git.history[-1][field]["name"] = "Different coordinator"
                self.rejects(git, "coordinator_metadata_mismatch")

    def test_actual_acceptance_parent_is_rechecked_in_metadata(self):
        git = self.fixture()
        original = git._text
        def text(*args):
            result = original(*args)
            return oid("wrong parent") + result[40:] if args[0] == "show" else result
        git._text = text
        self.rejects(git, "git_acceptance_metadata_mismatch")

    def test_receipt_raw_bytes_are_bound_to_actual_blob(self):
        git = self.fixture()
        path = git.acceptances[0]["path"]
        git.blobs[git.tree[path][1]] += b"\n"
        self.rejects(git, "git_receipt_blob_mismatch")

    def test_strict_duplicate_key_parser_is_used(self):
        git = self.fixture()
        acceptance = git.acceptances[0]
        content = acceptance["raw"][:-1] + b',"schema":1}'
        git.tree[acceptance["path"]] = ("100644", C.blob_oid(content))
        git.blobs[C.blob_oid(content)] = content
        self.rejects(git, "duplicate_json_key")

    def test_actual_endpoint_must_equal_supplied_current_tree(self):
        git = self.fixture()
        supplied = dict(git.tree)
        supplied["darwin/default.nix"] = blob("fabricated endpoint")
        with self.assertRaisesRegex(C.TransitionError, "git_current_tree_mismatch"):
            G.observe(git, git.head, supplied)

    def test_nonancestor_merge_missing_parent_skipped_and_reordered_paths(self):
        cases = ("nonancestor", "merge", "missing", "skipped", "reordered", "duplicate", "truncated")
        for case in cases:
            with self.subTest(case=case):
                git = self.fixture()
                if case == "nonancestor":
                    git.ancestor = False
                elif case == "merge":
                    git.history[-1]["parents"].append(oid("merged branch"))
                elif case == "missing":
                    git.history[0]["parents"] = []
                else:
                    rows = git.history
                    if case == "skipped":
                        rows = rows[1:]
                    elif case == "reordered":
                        rows = list(reversed(rows))
                    elif case == "duplicate":
                        rows = rows + rows[-1:]
                    elif case == "truncated":
                        rows = rows[:-1]
                    git.listing = "\n".join(" ".join([row["commit"], *row["parents"]]) for row in rows)
                self.rejects(git)

    def test_unsafe_or_zero_head_is_rejected_before_transport(self):
        for head in ("--help", "HEAD", "a" * 40 + ";command", "0" * 40, None):
            with self.subTest(head=head):
                git = FakeGit()
                with self.assertRaises(C.TransitionError):
                    G.observe(git, head, git.tree)
                self.assertEqual(git.calls, [])

    def test_unsafe_history_commit_never_becomes_an_object_argument(self):
        git = self.fixture()
        git.listing = "--help " + G.ANCHOR
        self.rejects(git, "invalid_oid")
        self.assertFalse(any(call[0] == "tree" for call in git.calls))

    def test_per_call_immutable_tree_cache_and_fresh_reobservation(self):
        git = self.fixture()
        git.accept({"darwin/default.nix": blob("second")})
        expected = [G.ANCHOR] + [row["commit"] for row in git.history]
        for attempt in (1, 2):
            result = git.observe()
            tree_reads = [call[1] for call in git.calls if call[0] == "tree"]
            self.assertEqual(tree_reads, expected * attempt)
            self.assertEqual(result["acceptedTree"], git.tree)

    def test_commit_count_limit_is_requested_and_enforced(self):
        git = self.fixture()
        with patch.object(G, "MAX_COMMITS", 1):
            self.rejects(git, "git_commit_count_limit")
        self.assertTrue(any("--max-count=2" in call[1] for call in git.calls if call[0] == "text"))
        self.assertFalse(any(call[0] == "tree" for call in git.calls))

    def test_per_read_and_aggregate_size_limits(self):
        with patch.object(G, "MAX_READ_BYTES", 64):
            self.rejects(self.fixture(), "git_object_size_limit")
        with patch.object(G, "MAX_TOTAL_BYTES", 800):
            self.rejects(self.fixture(), "git_observation_size_limit")

    def test_receipt_count_limit(self):
        git = self.fixture()
        git.accept({"darwin/default.nix": blob("second")})
        with patch.object(G, "MAX_TRANSITIONS", 1):
            self.rejects(git, "git_transition_count_limit")

    def test_non_regular_receipt_and_malformed_transport_fail_closed(self):
        git = self.fixture()
        path = git.acceptances[0]["path"]
        git.tree[path] = ("100755", git.tree[path][1])
        self.rejects(git, "git_invalid_receipt_mode")
        for response in ((True, b""), (0, ""), [0, b""], (2, b"")):
            with self.subTest(response=response):
                git = FakeGit()
                git._read = lambda *args, **kwargs: response
                self.rejects(git, "invalid_git_response")

    def test_transport_interrupt_is_not_swallowed(self):
        git = FakeGit()
        def interrupted(*args, **kwargs):
            raise KeyboardInterrupt()
        git._read = interrupted
        with self.assertRaises(KeyboardInterrupt):
            git.observe()


if __name__ == "__main__":
    unittest.main()
