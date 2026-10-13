"""Pure, fail-closed source-admission policy; observations are not authentication.

The native caller must obtain actual Git objects, prove a clean/current source,
validate the historical anchor and supply its trusted policy dependency paths.
This module never reads files, invokes commands, or grants apply/runtime authority.
Coordinator metadata describes adjudication; matching Git metadata is not proof
of the human's identity or independence. Evidence content is always inert here.
"""

import hashlib
import json
import re


PREFIX = "evidence/config-transitions/"
MAX_RECORD = 2 * 1024 * 1024
MAX_PATHS = 100000
MAX_TRANSITIONS = 1024
MAX_COMMITS = 100000
OID = re.compile(r"[0-9a-f]{40}\Z")
SAFE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,95}\Z")
COMPONENT = re.compile(r"[A-Za-z0-9_.-]+\Z")


class TransitionError(ValueError):
    """Bounded public reason, never an echo of untrusted source content."""


def require(value, reason):
    if not value:
        raise TransitionError(reason)


def _keys(value, keys):
    require(type(value) is dict and value.keys() == set(keys), "invalid_schema")


def _oid(value):
    require(type(value) is str and OID.fullmatch(value) is not None
            and value != "0" * 40, "invalid_oid")
    return value


def _path(value):
    require(type(value) is str and 0 < len(value) <= 1024, "invalid_path")
    require(all(COMPONENT.fullmatch(p) and p not in (".", "..")
                and p.lower() != ".git" for p in value.split("/")), "invalid_path")
    return value


def _identity(value):
    _keys(value, ("name", "email"))
    for part in value.values():
        require(type(part) is str and 0 < len(part) <= 256
                and part.strip() == part and all(32 <= ord(c) < 127 for c in part),
                "invalid_identity_metadata")


def _entry(value, nullable=False):
    if nullable and value is None:
        return None
    _keys(value, ("mode", "oid"))
    require(type(value["mode"]) is str and value["mode"] in ("100644", "100755"),
            "unsupported_mode")
    _oid(value["oid"])
    return (value["mode"], value["oid"])


def _tree(tree):
    require(type(tree) is dict and len(tree) <= MAX_PATHS, "invalid_tree")
    folded_paths = set()
    directories = {}
    for path, entry in tree.items():
        _path(path)
        require(path.lower() not in folded_paths, "tree_path_collision")
        folded_paths.add(path.lower())
        require(type(entry) is tuple and len(entry) == 2, "invalid_tree_entry")
        _entry({"mode": entry[0], "oid": entry[1]})
        # A flattened Git tree cannot contain both a blob and its descendant.
        parts = path.split("/")
        for i in range(1, len(parts)):
            directory = "/".join(parts[:i])
            require(directories.setdefault(directory.lower(), directory) == directory,
                    "tree_path_collision")
        require(all("/".join(parts[:i]) not in tree for i in range(1, len(parts))),
                "tree_path_collision")
    require(not folded_paths.intersection(directories), "tree_path_collision")
    return tree


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def parse(raw):
    """Parse a strict receipt; successful parsing alone is never admission."""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_RECORD, "invalid_record_size")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: require(False, "invalid_json_number"))
    except TransitionError:
        raise
    except (UnicodeError, ValueError, RecursionError):
        raise TransitionError("invalid_json") from None
    _keys(value, ("schema", "id", "kind", "status", "anchor_commit", "previous_commit",
                  "previous_acceptance", "reviewed_commit", "reviewed_tree", "changes",
                  "evidence", "coordinator"))
    require(type(value["schema"]) is int and value["schema"] == 1, "invalid_schema_version")
    require(type(value["id"]) is str and SAFE_ID.fullmatch(value["id"]), "invalid_id")
    require(type(value["kind"]) is str and value["kind"] in ("bootstrap", "configuration", "policy"),
            "invalid_kind")
    require(value["status"] == "ACCEPTED_CONFIGURATION", "invalid_status")
    for key in ("anchor_commit", "previous_commit", "reviewed_commit", "reviewed_tree"):
        _oid(value[key])
    if value["previous_acceptance"] is not None:
        _receipt_path(value["previous_acceptance"])
    changes = value["changes"]
    require(type(changes) is dict and 0 < len(changes) <= MAX_PATHS, "invalid_changes")
    for path, change in changes.items():
        _path(path)
        _keys(change, ("before", "after"))
        require(_entry(change["before"], True) != _entry(change["after"], True),
                "null_change")
    _keys(value["evidence"], ("validation", "review", "rollback"))
    seen = set()
    for paths in value["evidence"].values():
        require(type(paths) is list and 0 < len(paths) <= MAX_PATHS, "invalid_evidence")
        for path in paths:
            _path(path)
            require(path.startswith("evidence/") and not path.endswith("/acceptance.json")
                    and path not in seen, "invalid_evidence_reference")
            seen.add(path)
    _identity(value["coordinator"])
    return value


def _receipt_path(path):
    _path(path)
    require(path.startswith(PREFIX) and path.endswith("/acceptance.json"), "invalid_receipt_path")
    ident = path[len(PREFIX):-len("/acceptance.json")]
    require(SAFE_ID.fullmatch(ident) is not None, "invalid_receipt_path")
    return path


def blob_oid(raw):
    """Git SHA-1 blob identity for already bounded receipt bytes."""
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def delta(before, after):
    """Exact file delta including deletion and executable-bit-only changes."""
    def entry(row):
        return None if row is None else {"mode": row[0], "oid": row[1]}
    return {p: {"before": entry(before.get(p)), "after": entry(after.get(p))}
            for p in sorted(before.keys() | after.keys()) if before.get(p) != after.get(p)}


def _immutable_evidence(before, after):
    require(all(after.get(p) == row for p, row in before.items() if p.startswith("evidence/")),
            "historical_evidence_changed")


def _linear(rows, previous):
    require(type(rows) in (list, tuple) and 0 < len(rows) <= MAX_COMMITS,
            "invalid_candidate_chain")
    seen = {previous}
    for row in rows:
        _keys(row, ("commit", "parents"))
        _oid(row["commit"])
        require(type(row["parents"]) in (list, tuple) and list(row["parents"]) == [previous]
                and row["commit"] not in seen, "nonlinear_candidate")
        previous = row["commit"]
        seen.add(previous)
    return previous


def _policy(protected_paths, protected_prefixes, allowed_paths, allowed_prefixes,
            bootstrap_paths, coordinator):
    _identity(coordinator)
    require(type(bootstrap_paths) in (set, frozenset, list, tuple) and bootstrap_paths
            and len(bootstrap_paths) <= MAX_PATHS, "invalid_bootstrap_policy")
    bootstrap = {_path(p) for p in bootstrap_paths}
    require(len(bootstrap) == len(bootstrap_paths), "duplicate_bootstrap_path")
    require(type(protected_paths) in (set, frozenset, list, tuple) and protected_paths
            and len(protected_paths) <= MAX_PATHS, "invalid_protected_policy")
    protected = {_path(p) for p in protected_paths}
    require(len(protected) == len(protected_paths), "duplicate_protected_path")

    def prefixes(values):
        require(type(values) in (list, tuple) and len(values) <= MAX_PATHS,
                "invalid_policy_prefixes")
        for value in values:
            require(type(value) is str and value.endswith("/"), "invalid_policy_prefix")
            _path(value[:-1])
        require(len(set(values)) == len(values), "duplicate_policy_prefix")
        return tuple(values)

    protected_prefixes = prefixes(protected_prefixes)
    allowed_prefixes = prefixes(allowed_prefixes)
    require(type(allowed_paths) in (set, frozenset, list, tuple)
            and len(allowed_paths) <= MAX_PATHS, "invalid_allowed_paths")
    allowed = {_path(p) for p in allowed_paths}
    require(len(allowed) == len(allowed_paths), "duplicate_allowed_path")
    return protected, protected_prefixes, allowed, allowed_prefixes, bootstrap


def _scope(before, after, kind, policy):
    protected, protected_prefixes, allowed, allowed_prefixes, bootstrap = policy
    changes = delta(before, after)
    _immutable_evidence(before, after)
    require(all(not p.startswith(PREFIX) or not p.endswith("/acceptance.json") or p in before
                for p in after), "candidate_acceptance_record")
    if kind == "configuration":
        require(not any(p in protected or p.startswith(protected_prefixes)
                        or any(p == prefix[:-1] for prefix in protected_prefixes)
                        for p in changes), "protected_policy_changed")
        require(all(p.startswith("evidence/") or p in allowed
                    or p.startswith(allowed_prefixes) for p in changes),
                "unsupported_source_surface")
    else:
        require(all(p in bootstrap or (p.startswith("evidence/") and p not in before)
                    for p in changes), "unsupported_bootstrap_surface")
    return changes


def validate_candidate(base_tree, current_tree, kind, *, protected_paths, bootstrap_paths, coordinator,
                       protected_prefixes=("lib/", "vendor/"),
                       allowed_paths=("flake.nix", "flake.lock"),
                       allowed_prefixes=("darwin/", "manifests/", "bin/", "docs/", "tests/")):
    """Scope-only preview, NOT source acceptance or a substitute for chain review.

    Native callers must separately check each intermediate candidate tree against
    its predecessor, clean source binding, and actual Git ancestry. This helper
    checks endpoint scope only and intentionally consumes no review receipt.
    A policy preview uses the caller's exact bootstrap_paths as its repair scope;
    this preview does not authorize a policy update or select successor rules.
    """
    require(type(kind) is str and kind in ("bootstrap", "configuration", "policy"), "invalid_kind")
    policy = _policy(protected_paths, protected_prefixes, allowed_paths, allowed_prefixes,
                     bootstrap_paths, coordinator)
    changes = _scope(_tree(base_tree), _tree(current_tree), kind, policy)
    require(policy[0] <= current_tree.keys(), "protected_policy_missing")
    return {"status": "UNACCEPTED_CONFIGURATION_CANDIDATE", "changes": changes,
            "apply_authorized": False, "installed_state_verified": False,
            "phase_acceptance_granted": False}


def _updates(registry):
    """Normalize only caller-owned policy decisions, never receipt content."""
    require(type(registry) is dict and len(registry) <= MAX_TRANSITIONS, "invalid_policy_registry")
    updates = {}
    for path, entry in registry.items():
        _receipt_path(path)
        _keys(entry, ("previous_commit", "paths", "after"))
        _oid(entry["previous_commit"])
        after = entry["after"]
        _keys(after, ("protected_paths", "protected_prefixes", "allowed_paths", "allowed_prefixes",
                      "bootstrap_paths", "coordinator"))
        successor = _policy(**after)
        # Reuse the strict exact-path validator; the repair whitelist is separate
        # from both historical bootstrap and successor ordinary-configuration rules.
        scope = _policy(after["protected_paths"], after["protected_prefixes"],
                        after["allowed_paths"], after["allowed_prefixes"],
                        entry["paths"], after["coordinator"])[4]
        updates[path] = (entry["previous_commit"], scope, successor, dict(after["coordinator"]))
    return updates


def verify(anchor_commit, anchor_tree, transitions, current_commit, current_tree,
           *, protected_paths, bootstrap_paths, coordinator, protected_prefixes=("lib/", "vendor/"),
           allowed_paths=("flake.nix", "flake.lock"),
           allowed_prefixes=("darwin/", "manifests/", "bin/", "docs/", "tests/"),
           tail_commits=(), policy_updates=None):
    """Validate ordered native observations and return source-only state.

    bootstrap_paths and coordinator are mandatory trusted caller policy, never
    receipt choices. The initial transition can touch only exact bootstrap paths
    and append evidence; every other anchor file stays exact at every commit.
    Coordinator metadata is constrained, not cryptographically authenticated.
    protected_paths is trusted caller policy, NOT a receipt field. Freeze these
    paths after the sole first/bootstrap transition, including all verifier code,
    imports, admission rules and entry-point wiring. The native caller must also
    keep its own running implementation bound to those verified source objects.
    Protected prefixes also reject new dependency/import files. Ordinary source
    changes must fit the trusted generic allowed paths/prefixes (evidence is
    separately append-only); receipt data cannot widen these namespaces.
    Candidate ancestry observations cover every base-exclusive Git commit.
    Current source must be the exact acceptance endpoint. Even added evidence can
    influence Nix evaluation; no evidence-only tail has inertness authority.
    Optional caller-owned policy_updates register exact predecessor/path-bound
    policy successors. They never reinterpret earlier transitions. A successor
    rule set activates only after that policy receipt's verified sole-file child.
    """
    _oid(anchor_commit)
    _oid(current_commit)
    _tree(anchor_tree)
    _tree(current_tree)
    require(type(transitions) in (list, tuple) and len(transitions) <= MAX_TRANSITIONS,
            "invalid_transition_count")
    policy = _policy(protected_paths, protected_prefixes, allowed_paths, allowed_prefixes,
                     bootstrap_paths, coordinator)
    updates = _updates({} if policy_updates is None else policy_updates)
    used_updates = set()
    require(type(tail_commits) in (list, tuple) and len(tail_commits) <= MAX_COMMITS,
            "invalid_tail")
    require(not tail_commits, "unreviewed_current_source")
    previous, previous_path, tree = anchor_commit, None, anchor_tree
    seen_commits = {anchor_commit}
    for index, observation in enumerate(transitions):
        _keys(observation, ("path", "raw", "acceptance_commit", "acceptance_parents",
                           "acceptance_identity", "reviewed_tree_id", "base_tree",
                           "reviewed_tree", "accepted_tree", "candidate_commits"))
        path = _receipt_path(observation["path"])
        record = parse(observation["raw"])
        require(path == PREFIX + record["id"] + "/acceptance.json", "receipt_id_mismatch")
        update = None
        scope_policy = policy
        if record["kind"] == "policy":
            require(index > 0 and path in updates, "unregistered_policy_transition")
            require(path not in used_updates, "replayed_policy_transition")
            update = updates[path]
            require(previous == update[0], "policy_predecessor_mismatch")
            scope_policy = policy[:4] + (update[1],)
        else:
            require(path not in updates
                    and record["kind"] == ("bootstrap" if index == 0 else "configuration"),
                    "unexpected_transition_kind")
        require(record["anchor_commit"] == anchor_commit and record["previous_commit"] == previous
                and record["previous_acceptance"] == previous_path, "broken_predecessor")
        base = _tree(observation["base_tree"])
        reviewed = _tree(observation["reviewed_tree"])
        accepted = _tree(observation["accepted_tree"])
        require(base == tree, "base_tree_mismatch")
        candidates = observation["candidate_commits"]
        require(type(candidates) in (list, tuple) and 0 < len(candidates) <= MAX_COMMITS,
                "invalid_candidate_chain")
        for commit in candidates:
            _keys(commit, ("commit", "parents", "tree"))
        reviewed_commit = _linear([{"commit": c["commit"], "parents": c["parents"]}
                                   for c in candidates], previous)
        intermediate = base
        for commit in candidates:
            require(commit["commit"] not in seen_commits, "repeated_commit")
            seen_commits.add(commit["commit"])
            candidate_tree = _tree(commit["tree"])
            _scope(intermediate, candidate_tree, record["kind"], scope_policy)
            intermediate = candidate_tree
        require(intermediate == reviewed, "reviewed_tree_mismatch")
        require(reviewed_commit == record["reviewed_commit"]
                and _oid(observation["reviewed_tree_id"]) == record["reviewed_tree"],
                "reviewed_identity_mismatch")
        require(delta(base, reviewed) == record["changes"], "change_scope_mismatch")
        _scope(base, reviewed, record["kind"], scope_policy)
        require(path not in reviewed, "candidate_acceptance_record")
        required_policy = update[2] if update is not None else policy
        require(required_policy[0] <= reviewed.keys(), "protected_policy_missing")
        for paths in record["evidence"].values():
            require(all(p in reviewed and reviewed[p][0] == "100644" for p in paths),
                    "evidence_not_tracked_regular")
        acceptance = _oid(observation["acceptance_commit"])
        require(type(observation["acceptance_parents"]) in (list, tuple)
                and list(observation["acceptance_parents"]) == [reviewed_commit]
                and acceptance not in seen_commits, "invalid_acceptance_topology")
        _identity(observation["acceptance_identity"])
        require(observation["acceptance_identity"] == coordinator
                and record["coordinator"] == coordinator, "coordinator_metadata_mismatch")
        require(delta(reviewed, accepted) == {
            path: {"before": None, "after": {"mode": "100644", "oid": blob_oid(observation["raw"])}}},
            "acceptance_not_sole_receipt_child")
        previous, previous_path, tree = acceptance, path, accepted
        seen_commits.add(acceptance)
        if update is not None:
            policy, coordinator = update[2], update[3]
            used_updates.add(path)
    accepted_commit = previous
    require(previous == current_commit and tree == current_tree, "unreviewed_current_source")
    return {"status": "ACCEPTED_CONFIGURATION" if transitions else "HISTORICAL_ANCHOR",
            "accepted_commit": accepted_commit, "current_commit": current_commit,
            "transition_count": len(transitions), "evidence_tail_count": len(tail_commits),
            "apply_authorized": False, "installed_state_verified": False,
            "phase_acceptance_granted": False}
