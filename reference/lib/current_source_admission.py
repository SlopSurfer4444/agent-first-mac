"""Current-state admission after one independently reviewed migration.

The fixed migration receipt selects a real sole-child checkpoint. Its original
policy slice is checked; earlier accepted history is not replayed. Git metadata
records adjudication, not cryptographic reviewer authentication. The reviewed
local verifier remains the bootstrap boundary. Nothing here grants apply/trust.
"""
from lib import config_transitions as F
from lib import config_transition_source as S
from lib import current_source_checkpoint as K
from lib.config_transition_git import _Objects, _identity

MIGRATION_PREVIOUS = "60daf6e2a82b818630acbe3282ca507fb99b7013"
MIGRATION_PATH = "evidence/config-transitions/global-harness-simplification/acceptance.json"
PREVIOUS_RECEIPT = "evidence/config-transitions/wine-operation-readiness/acceptance.json"
MAX_MIGRATION_COMMITS = 128
OWNER_FIRST_WAVE_PATH = "evidence/config-transitions/owner-first-harness-wave/acceptance.json"
# Existing accepted Git objects, not a pin to this still-unaccepted candidate.
# Activation additionally requires the separately registered and reviewed wave
# transition. A present malformed receipt never falls back to migration replay.
CHECKPOINT_BINDING = {
    "commit": "94e0e1999c208aaf4112b611bbfa5c8b65111419",
    "tree": "897033ec4fc445fd8c53efdbe0dec61987bc6a8c",
    "receipt": MIGRATION_PATH,
    "blob": "fc48b8bff18ed15be8790466149f065f694784ee",
    "reviewed": "77df451b1222d3a5cda5a31d5165f32de89e211d",
    "reviewed_tree": "c227276d8f3d8f868c6adbc89db64d2fd98c50a8",
    "previous": MIGRATION_PREVIOUS,
    "previous_receipt": PREVIOUS_RECEIPT,
}
CURRENT_CORE = frozenset(("bin/system-revision-status", "tests/test_system_revision_status.py",
    "tests/test_current_source_admission.py", "tests/test_current_source_doctor.py",
    "tests/test_current_source_checkpoint.py",
    "tests/test_prepare_productivity_apply.py", "tests/test_project_context_boundary.py",
    "docs/current-source-admission.md", "docs/harness-operations.md"))


def included(tree):
    return MIGRATION_PATH in tree


def observe(git, head, current):
    """Read only fixed migration objects plus the actual current tree identity."""
    if OWNER_FIRST_WAVE_PATH in current:
        return K.observe(git, head, current, CHECKPOINT_BINDING)
    F._oid(head)
    F._tree(current)
    o = _Objects(git)
    F.require(included(current), "migration_not_registered")
    history = o.text("log", "--full-history", "--format=%H", "--max-count=2",
                     head, "--", MIGRATION_PATH).splitlines()
    F.require(len(history) == 1, "migration_receipt_history_changed")
    checkpoint = F._oid(history[0])
    tree = o.tree(checkpoint)
    F.require(tree.get(MIGRATION_PATH) == current[MIGRATION_PATH]
              and tree[MIGRATION_PATH][0] == "100644", "migration_receipt_changed")
    raw = o.read("cat-file", "blob", tree[MIGRATION_PATH][1])[1]
    F.require(F.blob_oid(raw) == tree[MIGRATION_PATH][1], "migration_blob_mismatch")
    record = F.parse(raw)
    reviewed = record["reviewed_commit"]
    _identity(o, checkpoint, reviewed, S.COORDINATOR)
    F.require(o.read("merge-base", "--is-ancestor", checkpoint, head, allow_one=True)[0] == 0,
              "checkpoint_not_ancestor")
    F.require(o.read("rev-list", "--merges", "--max-count=1", checkpoint + ".." + head)[1] == b"",
              "nonlinear_current_history")
    rows = o.text("rev-list", "--reverse", "--topo-order", "--parents",
                  "--max-count=" + str(MAX_MIGRATION_COMMITS + 1),
                  MIGRATION_PREVIOUS + ".." + reviewed).splitlines()
    F.require(0 < len(rows) <= MAX_MIGRATION_COMMITS, "migration_candidate_limit")
    candidates = []
    previous = MIGRATION_PREVIOUS
    for line in rows:
        fields = line.split(" ")
        F.require(len(fields) == 2 and fields[1] == previous, "migration_nonlinear")
        commit = F._oid(fields[0])
        candidates.append({"commit": commit, "parents": [previous], "tree": o.tree(commit)})
        previous = commit
    F.require(previous == reviewed, "migration_history_incomplete")
    return {"checkpoint": checkpoint, "checkpointTree": tree, "raw": raw,
            "baseTree": o.tree(MIGRATION_PREVIOUS), "candidates": candidates,
            "reviewedTreeId": o.tree_id(reviewed), "head": head,
            "ancestor": True}


def admit(observation, head, current):
    if OWNER_FIRST_WAVE_PATH in current:
        result = checkpoint_admission(observation, head, current)
        return dict(_admit_tree(result["checkpointTree"], current, result["rules"]),
                    headReviewed=head == result["checkpoint"], checkpoint=result["checkpoint"])
    F._keys(observation, ("checkpoint", "checkpointTree", "raw", "baseTree",
                          "candidates", "reviewedTreeId", "head", "ancestor"))
    F.require(observation["head"] == head and observation["ancestor"] is True,
              "checkpoint_not_ancestor")
    F._oid(head)
    F._oid(observation["checkpoint"])
    base, checkpoint = F._tree(observation["baseTree"]), F._tree(observation["checkpointTree"])
    record = F.parse(observation["raw"])
    # Registration is trusted source owned by the integration coordinator, not
    # arbitrary checkpoint IDs or policy fields supplied by a receipt/caller.
    registration = S.policy_updates(base).get(MIGRATION_PATH)
    F.require(registration is not None and registration["previous_commit"] == MIGRATION_PREVIOUS,
              "migration_not_registered")
    F.require(record["id"] == "global-harness-simplification" and record["kind"] == "policy"
              and record["anchor_commit"] == S.ANCHOR
              and record["previous_commit"] == MIGRATION_PREVIOUS
              and record["previous_acceptance"] == PREVIOUS_RECEIPT and PREVIOUS_RECEIPT in base
              and record["coordinator"] == S.COORDINATOR, "invalid_migration_record")
    rules = dict(S.policy_v2(base), bootstrap_paths=registration["paths"])
    rows = observation["candidates"]
    F.require(type(rows) is list and 0 < len(rows) <= MAX_MIGRATION_COMMITS, "migration_candidate_limit")
    F.require(F._linear([{k: row[k] for k in ("commit", "parents")} for row in rows],
                        MIGRATION_PREVIOUS) == record["reviewed_commit"], "migration_nonlinear")
    before = base
    for row in rows:
        F._keys(row, ("commit", "parents", "tree"))
        F.validate_candidate(before, row["tree"], "policy", **rules)
        S.import_scope(before, row["tree"])
        before = row["tree"]
    F.require(observation["reviewedTreeId"] == record["reviewed_tree"]
              and F.delta(base, before) == record["changes"], "migration_source_mismatch")
    F.require(all(p in before and before[p][0] == "100644"
                  for paths in record["evidence"].values() for p in paths), "migration_evidence_missing")
    F.require(F.delta(before, checkpoint) == {MIGRATION_PATH: {"before": None,
              "after": {"mode": "100644", "oid": F.blob_oid(observation["raw"])}}},
              "acceptance_not_sole_receipt_child")
    return admit_tree(checkpoint, current)


def admit_tree(checkpoint, current):
    """Current endpoint scope; deliberately no independent-review claim."""
    registration = S.policy_updates(checkpoint).get(MIGRATION_PATH)
    F.require(registration is not None and registration["previous_commit"] == MIGRATION_PREVIOUS,
              "migration_not_registered")
    rules = registration["after"]
    return _admit_tree(checkpoint, current, rules)


def _admit_tree(checkpoint, current, rules):
    rules = dict(rules, protected_paths=rules["protected_paths"] | (CURRENT_CORE & checkpoint.keys()))
    F.validate_candidate(checkpoint, current, "configuration", **rules)
    S.import_scope(checkpoint, current)
    # Evidence is frozen, including additions (Nix may read any extension).
    F.require({p: v for p, v in checkpoint.items() if p.startswith("evidence/")}
              == {p: v for p, v in current.items() if p.startswith("evidence/")},
              "historical_evidence_changed")
    absent = set(S.IMPORT_ABSENCES)
    directories = {"/".join(p.split("/")[:i]) for p in current
                   for i in range(1, len(p.split("/")))}
    for path in checkpoint.keys() - current.keys():
        parts = path.split("/")
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            if prefix in current:
                break
            if prefix not in directories:
                absent.add(prefix)
                break
    F.require(not absent.intersection(current), "unexpected_import_initializer")
    return {"accepted": True, "absent": tuple(sorted(absent))}


def checkpoint_admission(observation, head, current):
    """Source-only proof shared by doctor, reviewed-root preparation and witnesses."""
    F.require(OWNER_FIRST_WAVE_PATH in current, "checkpoint_successor_not_present")
    pin = observation.get("pinTree", {}) if type(observation) is dict else {}
    updates = S.policy_updates(pin)
    F.require(OWNER_FIRST_WAVE_PATH in updates
              and updates[OWNER_FIRST_WAVE_PATH]["previous_commit"] == CHECKPOINT_BINDING["commit"],
              "checkpoint_successor_not_registered")
    registration = updates.get(MIGRATION_PATH)
    F.require(registration is not None, "migration_not_registered")
    rules = registration["after"]
    rules = dict(rules, protected_paths=rules["protected_paths"] | (CURRENT_CORE & pin.keys()))
    return K.admit(observation, head, current, CHECKPOINT_BINDING, rules, updates)


def reviewed_target(git, head, current):
    """Require exact independently reviewed aggregate HEAD, not a routine tail."""
    result = checkpoint_admission(observe(git, head, current), head, current)
    F.require(result["checkpoint"] == head, "root_target_requires_independent_review")
    return True


def admitted_revision(git, commit, *, accepted=True):
    """On-demand marker/witness check without replaying historical transitions."""
    F._oid(commit)
    F.require(type(accepted) is bool, "invalid_revision_mode")
    head = git._text("rev-parse", "--verify", "HEAD")
    current = git._tree(head)
    observation = observe(git, head, current)
    admit(observation, head, current)
    if OWNER_FIRST_WAVE_PATH in current:
        result = checkpoint_admission(observation, head, current)
        if commit in result["candidateRevisions"]:
            F.require(not accepted or commit in result["admittedRevisions"], "revision_not_accepted")
            return True
        # Pre-pin history retains the exact historical sole-receipt witness.
        observation = {"checkpoint": CHECKPOINT_BINDING["commit"],
                       "checkpointTree": observation["pinTree"]}
    checkpoint = observation["checkpoint"]
    F.require(git._read("merge-base", "--is-ancestor", commit, head, allow_one=True)[0] == 0,
              "revision_not_ancestor")
    if git._read("merge-base", "--is-ancestor", checkpoint, commit, allow_one=True)[0] == 0:
        admit_tree(observation["checkpointTree"], git._tree(commit))
        return True
    F.require(git._read("merge-base", "--is-ancestor", S.ANCHOR, commit, allow_one=True)[0] == 0,
              "revision_before_anchor")
    F.require(git._read("merge-base", "--is-ancestor", commit, checkpoint, allow_one=True)[0] == 0,
              "revision_outside_checkpoint_history")
    if not accepted:
        return True
    # A precheckpoint installed commit must be a real immutable sole receipt
    # child. Its review authority was established at migration, not re-created.
    o = _Objects(git)
    change = o.read("diff-tree", "--no-commit-id", "--name-status", "-r", "-z", commit)[1].split(b"\0")
    F.require(len(change) == 3 and change[0] == b"A" and change[2] == b"", "revision_not_accepted")
    path = change[1].decode("ascii")
    F._receipt_path(path)
    tree = o.tree(commit)
    F.require(tree.get(path) == observation["checkpointTree"].get(path), "revision_receipt_changed")
    raw = o.read("cat-file", "blob", tree[path][1])[1]
    record = F.parse(raw)
    F.require(F.blob_oid(raw) == tree[path][1], "revision_receipt_changed")
    _identity(o, commit, record["reviewed_commit"], S.COORDINATOR)
    return True
