"""Bounded, injected observations of reviewed-configuration Git history.

This module owns no command runner, filesystem access or live-state setup. The
caller supplies the existing fixed, bounded NativeGit transport, holds the
running source, and re-observes Git after use. Returned acceptance coordinates
are observations only: config_transitions.verify must admit their full policy
chain before the caller treats them as accepted source.
"""

from lib import config_transitions as C


ANCHOR = "85ccc9a36bf5fc235002ef7681dc69f21803bd04"
MAX_COMMITS = 4096
MAX_TRANSITIONS = 1024
MAX_READ_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024


class _Objects:
    """Cache immutable object observations for exactly one observe call."""

    def __init__(self, git):
        self.git = git
        self.total = 0
        self.trees = {}
        self.tree_ids = {}

    def account(self, count):
        C.require(count <= MAX_READ_BYTES, "git_object_size_limit")
        self.total += count
        C.require(self.total <= MAX_TOTAL_BYTES, "git_observation_size_limit")

    def read(self, *args, allow_one=False):
        result = self.git._read(*args, allow_one=allow_one)
        C.require(type(result) is tuple and len(result) == 2, "invalid_git_response")
        code, raw = result
        C.require(type(code) is int and code in ((0, 1) if allow_one else (0,))
                  and type(raw) is bytes, "invalid_git_response")
        self.account(len(raw))
        return code, raw

    def text(self, *args):
        value = self.git._text(*args)
        C.require(type(value) is str, "invalid_git_response")
        try:
            count = len(value.encode("utf-8", "strict")) + 1
        except UnicodeError:
            raise C.TransitionError("invalid_git_response") from None
        self.account(count)
        return value

    def tree(self, commit):
        C._oid(commit)
        if commit not in self.trees:
            value = C._tree(self.git._tree(commit))
            # Account the ls-tree representation even though NativeGit owns its
            # bounded raw transport and returns parsed rows to this collector.
            self.account(sum(len(path.encode("utf-8")) + len(mode) + len(oid) + 8
                             for path, (mode, oid) in value.items()))
            self.trees[commit] = dict(value)
        return self.trees[commit]

    def tree_id(self, commit):
        C._oid(commit)
        if commit not in self.tree_ids:
            self.tree_ids[commit] = C._oid(self.text("rev-parse", "--verify", commit + "^{tree}"))
        return self.tree_ids[commit]


def _receipts(tree):
    paths = {path for path in tree if path.startswith(C.PREFIX)
             and path.endswith("/acceptance.json")}
    C.require(len(paths) <= MAX_TRANSITIONS, "git_transition_count_limit")
    for path in paths:
        C._receipt_path(path)
    return paths


def _history(objects, head):
    code, _ = objects.read("merge-base", "--is-ancestor", ANCHOR, head, allow_one=True)
    C.require(code == 0, "git_anchor_not_ancestor")
    history = objects.text("rev-list", "--reverse", "--topo-order", "--parents",
                           "--max-count=" + str(MAX_COMMITS + 1), ANCHOR + ".." + head)
    lines = history.splitlines()
    C.require(len(lines) <= MAX_COMMITS, "git_commit_count_limit")
    rows, seen, previous = [], {ANCHOR}, ANCHOR
    for line in lines:
        fields = line.split(" ")
        C.require(len(fields) == 2, "git_nonlinear_history")
        commit, parent = (C._oid(value) for value in fields)
        C.require(parent == previous and commit not in seen, "git_nonlinear_history")
        rows.append({"commit": commit, "parents": [parent]})
        previous = commit
        seen.add(commit)
    C.require(previous == head, "git_incomplete_history")
    return rows


def _identity(objects, commit, parent, coordinator):
    metadata = objects.text("show", "-s", "--format=%P%x00%an%x00%ae%x00%cn%x00%ce", commit)
    parts = metadata.split("\0")
    C.require(len(parts) == 5 and parts[0] == parent, "git_acceptance_metadata_mismatch")
    author = {"name": parts[1], "email": parts[2]}
    committer = {"name": parts[3], "email": parts[4]}
    C.require(author == coordinator and committer == coordinator, "coordinator_metadata_mismatch")
    return author


def observe(git, head, current_tree):
    """Collect the complete actual single-parent path from ANCHOR through head.

    Every commit contributes its actual tree, including temporary receipt or
    evidence edits later reverted. No history/path simplification is used. A
    receipt is read by its validated actual blob OID, never by a receipt-supplied
    revision. Only real commit IDs from the validated path become Git arguments.
    Pending commits are returned separately and confer no acceptance.
    """
    C._oid(head)
    C._tree(current_tree)
    objects = _Objects(git)
    history = _history(objects, head)
    anchor_tree = objects.tree(ANCHOR)
    C.require(not _receipts(anchor_tree), "git_anchor_contains_transition_receipt")
    transitions, pending = [], []
    accepted_commit, accepted_tree, previous_path = ANCHOR, anchor_tree, None
    previous_commit, previous_tree, previous_receipts = ANCHOR, anchor_tree, set()
    for row in history:
        commit = row["commit"]
        actual_tree = objects.tree(commit)
        paths = _receipts(actual_tree)
        C.require(all(path in paths and actual_tree[path] == previous_tree[path]
                      for path in previous_receipts), "git_receipt_history_changed")
        added = paths - previous_receipts
        if not added:
            pending.append({**row, "tree": actual_tree})
        else:
            C.require(len(added) == 1 and pending, "git_invalid_acceptance_child")
            C.require(len(transitions) < MAX_TRANSITIONS, "git_transition_count_limit")
            path = next(iter(added))
            mode, object_id = actual_tree[path]
            C.require(mode == "100644", "git_invalid_receipt_mode")
            C.require(C.delta(previous_tree, actual_tree) == {
                path: {"before": None, "after": {"mode": mode, "oid": object_id}}},
                "acceptance_not_sole_receipt_child")
            raw = objects.read("cat-file", "blob", C._oid(object_id))[1]
            record = C.parse(raw)
            C.require(C.blob_oid(raw) == object_id, "git_receipt_blob_mismatch")
            C.require(path == C.PREFIX + record["id"] + "/acceptance.json", "receipt_id_mismatch")
            C.require(record["anchor_commit"] == ANCHOR
                      and record["previous_commit"] == accepted_commit
                      and record["previous_acceptance"] == previous_path, "broken_predecessor")
            reviewed_tree_id = objects.tree_id(previous_commit)
            C.require(record["reviewed_commit"] == previous_commit
                      and record["reviewed_tree"] == reviewed_tree_id, "reviewed_identity_mismatch")
            identity = _identity(objects, commit, previous_commit, record["coordinator"])
            transitions.append({"path": path, "raw": raw, "acceptance_commit": commit,
                "acceptance_parents": list(row["parents"]), "acceptance_identity": identity,
                "reviewed_tree_id": reviewed_tree_id, "base_tree": accepted_tree,
                "reviewed_tree": previous_tree, "accepted_tree": actual_tree,
                "candidate_commits": pending})
            accepted_commit, accepted_tree, previous_path = commit, actual_tree, path
            pending = []
        previous_commit, previous_tree, previous_receipts = commit, actual_tree, paths
    C.require(previous_tree == current_tree, "git_current_tree_mismatch")
    return {"anchorTree": anchor_tree, "transitions": transitions,
            "acceptedCommit": accepted_commit, "acceptedTree": accepted_tree,
            "pendingCommits": pending}
