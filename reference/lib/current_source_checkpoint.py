"""Bounded post-checkpoint source proof, never runtime or reviewer authority.

The caller owns the exact checkpoint binding and policy registry in protected
reviewed source. Receipt fields cannot select that trust root or change policy.
Every post-pin commit is observed, including all merge parents; Git metadata is
adjudication provenance, not authentication of independent human judgment.
"""
import json
import re

from lib import config_transitions as F
from lib import config_transition_source as S
from lib.config_transition_git import _Objects, _identity, _receipts

MAX_COMMITS = 4096
WAVE_PATH = "evidence/config-transitions/owner-first-harness-wave/acceptance.json"


def _json(raw):
    F.require(type(raw) is bytes and 0 < len(raw) <= F.MAX_RECORD, "invalid_checkpoint_record_size")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=F._pairs,
                          parse_constant=lambda _: F.require(False, "invalid_json_number"))
    except F.TransitionError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise F.TransitionError("invalid_checkpoint_json") from None


def parse_receipt(raw, path):
    """Only the one preceding-policy wave receipt retains the legacy schema."""
    if path == WAVE_PATH:
        return F.parse(raw)
    value = _json(raw)
    F._keys(value, ("schema", "id", "kind", "status", "anchor_commit", "previous_commit",
                    "previous_acceptance", "reviewed_commit", "reviewed_tree", "changes",
                    "evidence", "coordinator"))
    F.require(type(value["schema"]) is int and value["schema"] == 2, "aggregate_schema_required")
    F.require(type(value["id"]) is str and F.SAFE_ID.fullmatch(value["id"]), "invalid_id")
    F.require(value["kind"] in ("configuration", "policy")
              and value["status"] == "ACCEPTED_CONFIGURATION", "invalid_aggregate_kind")
    for key in ("anchor_commit", "previous_commit", "reviewed_commit", "reviewed_tree"):
        F._oid(value[key])
    F._receipt_path(value["previous_acceptance"])
    changes = value["changes"]
    F.require(type(changes) is dict and 0 < len(changes) <= F.MAX_PATHS, "invalid_changes")
    for name, change in changes.items():
        F._path(name)
        F._keys(change, ("before", "after"))
        F.require(F._entry(change["before"], True) != F._entry(change["after"], True), "null_change")
    F._keys(value["evidence"], ("bundle",))
    _evidence_path(value["evidence"]["bundle"])
    F._identity(value["coordinator"])
    return value


def _evidence_path(path):
    F._path(path)
    F.require(path.startswith("evidence/") and not path.endswith("/acceptance.json"),
              "invalid_evidence_reference")


def _checks(checks):
    F.require(type(checks) is list and 0 < len(checks) <= 128, "missing_observed_checks")
    names = set()
    for check in checks:
        F._keys(check, ("id", "command", "observation"))
        ident, command = check["id"], check["command"]
        F.require(type(ident) is str and F.SAFE_ID.fullmatch(ident) and ident not in names,
                  "invalid_observed_check")
        names.add(ident)
        F.require(type(command) is list and 0 < len(command) <= 32
                  and all(type(p) is str and 0 < len(p) <= 512
                          and all(32 <= ord(c) < 127 for c in p) for p in command),
                  "invalid_observed_command")
        observed = check["observation"]
        F._keys(observed, ("completed", "exit_code", "output_sha256"))
        F.require(observed["completed"] is True and type(observed["exit_code"]) is int
                  and observed["exit_code"] == 0, "required_check_not_successful")
        F.require(type(observed["output_sha256"]) is str
                  and re.fullmatch(r"[0-9a-f]{64}", observed["output_sha256"]),
                  "invalid_observed_output_binding")


def parse_bundle(raw):
    """Recorded observations, not executable commands or authenticated judgment."""
    value = _json(raw)
    F._keys(value, ("schema", "subject_commit", "subject_tree", "validation", "review", "recovery"))
    F.require(type(value["schema"]) is int and value["schema"] == 1, "invalid_bundle_schema")
    F._oid(value["subject_commit"])
    F._oid(value["subject_tree"])
    _checks(value["validation"])
    review = value["review"]
    F._keys(review, ("subject_commit", "subject_tree", "reviewer", "decision", "unresolved_findings", "checks"))
    F.require(review["subject_commit"] == value["subject_commit"]
              and review["subject_tree"] == value["subject_tree"], "review_subject_mismatch")
    F._identity(review["reviewer"])
    F.require(review["decision"] == "ACCEPT" and type(review["unresolved_findings"]) is list
              and not review["unresolved_findings"], "unresolved_independent_review")
    _checks(review["checks"])
    recovery = value["recovery"]
    F._keys(recovery, ("plan", "checks"))
    F._path(recovery["plan"])
    _checks(recovery["checks"])
    return value


def _binding(binding):
    F._keys(binding, ("commit", "tree", "receipt", "blob", "reviewed", "reviewed_tree",
                      "previous", "previous_receipt"))
    for key in ("commit", "tree", "blob", "reviewed", "reviewed_tree", "previous"):
        F._oid(binding[key])
    F._receipt_path(binding["receipt"])
    F._receipt_path(binding["previous_receipt"])


def observe(git, head, current, binding):
    """Read the exact trusted pin and bounded actual descendants, not migration."""
    _binding(binding)
    F._oid(head)
    F._tree(current)
    o = _Objects(git)
    pin = binding["commit"]
    F.require(o.read("merge-base", "--is-ancestor", pin, head, allow_one=True)[0] == 0,
              "checkpoint_not_ancestor")
    tree = o.tree(pin)
    F.require(o.tree_id(pin) == binding["tree"]
              and tree.get(binding["receipt"]) == ("100644", binding["blob"]),
              "checkpoint_binding_mismatch")
    raw = o.read("cat-file", "blob", binding["blob"])[1]
    _identity(o, pin, binding["reviewed"], S.COORDINATOR)
    reviewed = o.tree(binding["reviewed"])
    F.require(o.tree_id(binding["reviewed"]) == binding["reviewed_tree"],
              "checkpoint_binding_mismatch")
    lines = o.text("rev-list", "--reverse", "--topo-order", "--parents",
                   "--max-count=" + str(MAX_COMMITS + 1), pin + ".." + head).splitlines()
    F.require(len(lines) <= MAX_COMMITS, "checkpoint_history_limit")
    rows, trees = [], {pin: tree}
    for line in lines:
        fields = line.split(" ")
        F.require(2 <= len(fields) <= 17, "invalid_checkpoint_topology")
        commit, parents = F._oid(fields[0]), [F._oid(p) for p in fields[1:]]
        F.require(commit not in trees and len(set(parents)) == len(parents)
                  and all(p in trees for p in parents), "unknown_checkpoint_predecessor")
        candidate = o.tree(commit)
        added = _receipts(candidate) - set().union(*(_receipts(trees[p]) for p in parents))
        F.require(len(added) <= 1, "invalid_checkpoint_receipt_child")
        receipt = None
        if added:
            F.require(len(parents) == 1, "invalid_checkpoint_receipt_child")
            path = added.pop()
            F.require(candidate[path][0] == "100644", "invalid_checkpoint_receipt_mode")
            content = o.read("cat-file", "blob", candidate[path][1])[1]
            identity = _identity(o, commit, parents[0], S.COORDINATOR)
            record = parse_receipt(content, path)
            bundle = None
            if record["schema"] == 2:
                bundle_path = record["evidence"]["bundle"]
                entry = trees[parents[0]].get(bundle_path)
                F.require(entry is not None and entry[0] == "100644", "checkpoint_evidence_missing")
                bundle_raw = o.read("cat-file", "blob", entry[1])[1]
                evidence = parse_bundle(bundle_raw)
                subject = evidence["subject_commit"]
                F.require(subject in trees, "evidence_subject_not_in_checkpoint_history")
                bundle = {"raw": bundle_raw, "subjectTreeId": o.tree_id(subject)}
            receipt = {"path": path, "raw": content, "identity": identity,
                       "reviewedTreeId": o.tree_id(parents[0]), "bundle": bundle}
        rows.append({"commit": commit, "parents": parents, "tree": candidate, "receipt": receipt})
        trees[commit] = candidate
    F.require(head in trees and trees[head] == current, "checkpoint_current_tree_mismatch")
    return {"checkpointVersion": 1, "head": head, "pinTree": tree,
            "pinReviewedTree": reviewed, "pinRaw": raw, "rows": rows}


def _evidence(tree):
    return {p: row for p, row in tree.items() if p.startswith("evidence/")}


def admit(observation, head, current, binding, rules, updates):
    """Validate all DAG branches and advance only genuine reviewed checkpoints.

    Pending evidence is append-only but never routine admission. An aggregate
    receipt covers its complete predecessor-to-reviewed delta; only a registered
    policy transition may change protected policy. Receipt-free merges require
    the same accepted checkpoint on every parent and equivalent protected history.
    """
    _binding(binding)
    F._keys(observation, ("checkpointVersion", "head", "pinTree", "pinReviewedTree", "pinRaw", "rows"))
    F.require(type(observation["checkpointVersion"]) is int and observation["checkpointVersion"] == 1
              and observation["head"] == head, "invalid_checkpoint_observation")
    F._oid(head)
    F._tree(current)
    pin = binding["commit"]
    tree = F._tree(observation["pinTree"])
    reviewed = F._tree(observation["pinReviewedTree"])
    record = F.parse(observation["pinRaw"])
    F.require(F.blob_oid(observation["pinRaw"]) == binding["blob"]
              and tree.get(binding["receipt"]) == ("100644", binding["blob"])
              and record["reviewed_commit"] == binding["reviewed"]
              and record["reviewed_tree"] == binding["reviewed_tree"]
              and record["previous_commit"] == binding["previous"]
              and record["previous_acceptance"] == binding["previous_receipt"]
              and record["anchor_commit"] == S.ANCHOR
              and record["coordinator"] == S.COORDINATOR
              and binding["receipt"] == F.PREFIX + record["id"] + "/acceptance.json",
              "checkpoint_binding_mismatch")
    F.require(F.delta(reviewed, tree) == {binding["receipt"]: {"before": None,
              "after": {"mode": "100644", "oid": binding["blob"]}}},
              "acceptance_not_sole_receipt_child")
    F._policy(**rules)
    F._updates(updates)
    rows = observation["rows"]
    F.require(type(rows) is list and len(rows) <= MAX_COMMITS, "checkpoint_history_limit")
    trees, states = {pin: tree}, {pin: (pin, binding["receipt"], rules)}
    admitted = {pin}
    for row in rows:
        F._keys(row, ("commit", "parents", "tree", "receipt"))
        commit, parents, candidate = F._oid(row["commit"]), row["parents"], F._tree(row["tree"])
        F.require(type(parents) is list and 1 <= len(parents) <= 16
                  and all(type(p) is str and F.OID.fullmatch(p) is not None for p in parents)
                  and len(set(parents)) == len(parents) and commit not in trees
                  and all(p in trees for p in parents), "unknown_checkpoint_predecessor")
        state = states[parents[0]]
        F.require(all(states[p] == state for p in parents), "merge_checkpoint_mismatch")
        previous, previous_path, active_rules = state
        # Only caller-owned registered transitions whose receipt is actually in
        # this final tree may stage policy deltas. They MUST close at that receipt.
        registered = [(p, u) for p, u in updates.items()
                      if u["previous_commit"] == previous and p in current and p not in trees[previous]]
        # Schema-2 policy reviews use the same exact aggregate/bundle proof as
        # root-target review. The immutable legacy registry remains for old
        # schema-1 decisions; future policy repairs need no named code entry.
        # A record only opens candidate staging here, NEVER routine admission.
        # Its exact delta, observed review/recovery bundle and sole child are
        # still independently verified below before advancing the checkpoint.
        generic = []
        for future in rows:
            future_receipt = future["receipt"]
            if future_receipt is None or future_receipt["path"] in updates:
                continue
            decision = parse_receipt(future_receipt["raw"], future_receipt["path"])
            if (decision["schema"] == 2 and decision["kind"] == "policy"
                    and decision["previous_commit"] == previous):
                changed = set(decision["changes"])
                F.require(any(p in active_rules["protected_paths"]
                    or p.startswith(active_rules["protected_prefixes"]) for p in changed),
                    "policy_review_requires_protected_delta")
                generic.append((future_receipt["path"], {
                    "previous_commit": previous, "paths": changed, "after": active_rules}))
        registered += generic
        F.require(len(registered) <= 1, "ambiguous_checkpoint_policy")
        kind = "policy" if registered else "configuration"
        scope = dict(active_rules, bootstrap_paths=registered[0][1]["paths"]) if registered else active_rules
        added = _receipts(candidate) - set().union(*(_receipts(trees[p]) for p in parents))
        receipt = row["receipt"]
        if receipt is None:
            F.require(not added, "missing_checkpoint_receipt_observation")
            F.require(not registered or len(parents) == 1, "nonlinear_policy_candidate")
            for parent in parents:
                F.validate_candidate(trees[parent], candidate, kind, **scope)
                S.import_scope(trees[parent], candidate)
            if (all(parent in admitted for parent in parents)
                    and _evidence(candidate) == _evidence(trees[previous])):
                # A later policy receipt must not retroactively demote a valid
                # routine prefix. Prove each edge independently under ORIGINAL
                # configuration rules, never the registered policy exception.
                # Once staging taints a parent, a revert cannot restore routine
                # admission; only the genuine receipt below resets that lineage.
                try:
                    for parent in parents:
                        F.validate_candidate(trees[parent], candidate, "configuration", **active_rules)
                        S.import_scope(trees[parent], candidate)
                except F.TransitionError:
                    pass  # Valid policy candidate, but not a routine revision.
                else:
                    admitted.add(commit)
        else:
            F._keys(receipt, ("path", "raw", "identity", "reviewedTreeId", "bundle"))
            path = F._receipt_path(receipt["path"])
            F.require(len(parents) == 1 and added == {path}, "invalid_checkpoint_receipt_child")
            parent = parents[0]
            before = trees[parent]
            record = parse_receipt(receipt["raw"], path)
            F.require(record["kind"] == kind and (not registered or path == registered[0][0]),
                      "unregistered_checkpoint_policy")
            F.require(record["previous_commit"] == previous and record["previous_acceptance"] == previous_path
                      and record["anchor_commit"] == S.ANCHOR, "broken_checkpoint_predecessor")
            F.require(path == F.PREFIX + record["id"] + "/acceptance.json"
                      and record["reviewed_commit"] == parent
                      and record["reviewed_tree"] == F._oid(receipt["reviewedTreeId"]),
                      "checkpoint_reviewed_identity_mismatch")
            F.require(record["coordinator"] == S.COORDINATOR and receipt["identity"] == S.COORDINATOR,
                      "coordinator_metadata_mismatch")
            F.require(F.delta(trees[previous], before) == record["changes"], "checkpoint_change_scope_mismatch")
            F.validate_candidate(trees[previous], before, kind, **scope)
            S.import_scope(trees[previous], before)
            if record["schema"] == 1:
                F.require(receipt["bundle"] is None and all(p in before and before[p][0] == "100644"
                          for paths in record["evidence"].values() for p in paths), "checkpoint_evidence_missing")
            else:
                _admit_bundle(receipt["bundle"], record, previous, parent, before, trees, rows)
            F.require(F.delta(before, candidate) == {path: {"before": None,
                      "after": {"mode": "100644", "oid": F.blob_oid(receipt["raw"])}}},
                      "acceptance_not_sole_receipt_child")
            after_rules = registered[0][1]["after"] if registered else active_rules
            F.require(set(after_rules["protected_paths"]) <= candidate.keys(), "protected_policy_missing")
            state = (commit, path, after_rules)
            admitted.add(commit)
        trees[commit], states[commit] = candidate, state
    F.require(head in trees and trees[head] == current, "checkpoint_current_tree_mismatch")
    ancestors, remaining = {head}, [head]
    parent_rows = {row["commit"]: row["parents"] for row in rows}
    while remaining:
        for parent in parent_rows.get(remaining.pop(), ()):
            if parent not in ancestors:
                ancestors.add(parent)
                remaining.append(parent)
    F.require(ancestors == trees.keys(), "checkpoint_unrelated_observation")
    checkpoint, path, active_rules = states[head]
    F.require(_evidence(current) == _evidence(trees[checkpoint]), "unreviewed_checkpoint_evidence")
    F.require(head in admitted, "unaccepted_checkpoint_policy")
    return {"accepted": True, "checkpoint": checkpoint, "checkpointTree": trees[checkpoint],
            "receipt": path, "rules": active_rules, "admittedRevisions": frozenset(admitted),
            "candidateRevisions": frozenset(trees)}


def _admit_bundle(observation, record, previous, parent, reviewed, trees, rows):
    F._keys(observation, ("raw", "subjectTreeId"))
    bundle = parse_bundle(observation["raw"])
    path, subject = record["evidence"]["bundle"], bundle["subject_commit"]
    F.require(reviewed.get(path) == ("100644", F.blob_oid(observation["raw"])),
              "evidence_bundle_blob_mismatch")
    F.require(subject in trees and observation["subjectTreeId"] == bundle["subject_tree"],
              "evidence_subject_mismatch")
    parent_rows = {row["commit"]: row["parents"] for row in rows}
    def ancestry(commit):
        ancestors, pending = {commit}, [commit]
        while pending:
            for ancestor in parent_rows.get(pending.pop(), ()):
                if ancestor not in ancestors:
                    ancestors.add(ancestor); pending.append(ancestor)
        return ancestors
    ancestors, subject_ancestors = ancestry(parent), ancestry(subject)
    F.require(subject in ancestors, "evidence_subject_not_ancestor")
    F.require(previous in subject_ancestors, "evidence_subject_before_checkpoint")
    # Evidence publication may follow checks; no source byte can change after
    # the observed subject, including a temporary edit later restored.
    for row in rows:
        if row["commit"] in ancestors - subject_ancestors:
            for name, change in F.delta(trees[subject], row["tree"]).items():
                F.require(name.startswith("evidence/") and change["before"] is None,
                          "source_changed_after_evidence_subject")
    F.require(path not in trees[subject], "evidence_subject_mismatch")
    plan = bundle["recovery"]["plan"]
    F.require(trees[subject].get(plan, (None,))[0] == "100644"
              and reviewed.get(plan) == trees[subject][plan], "recovery_plan_not_source_bound")
