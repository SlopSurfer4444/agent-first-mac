"""Pure synthetic Git-observation tests; no Git/process/private-state access."""

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import config_transitions as C

BOOTSTRAP_PATHS = ("lib/config_transitions.py", "bin/current-doctor", "docs/config-transitions.md")
COORDINATOR = {"name": "Coordinator", "email": "coordinator@example.invalid"}


def oid(label):
    return hashlib.sha1(label.encode()).hexdigest()


def blob(label, mode="100644"):
    return (mode, oid(label))


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class Chain:
    def __init__(self):
        self.anchor = oid("anchor")
        self.anchor_tree = {"evidence/history/acceptance.json": blob("history"),
                            "darwin/default.nix": blob("initial package"),
                            "manifests/old.json": blob("removable config")}
        self.tree = dict(self.anchor_tree)
        self.commit = self.anchor
        self.transitions = []
        self.tail = []

    def add(self, updates=None, count=2):
        index = len(self.transitions)
        ident = "change-" + str(index)
        reviewed = dict(self.tree)
        updates = updates if updates is not None else {
            "lib/config_transitions.py": blob("engine"),
            "bin/current-doctor": blob("wiring", "100755"),
            "docs/config-transitions.md": blob("contract")}
        for path, entry in updates.items():
            if entry is None:
                reviewed.pop(path)
            else:
                reviewed[path] = entry
        evidence = {key: ["evidence/reviews/" + ident + "-" + key + ".json"]
                    for key in ("validation", "review", "rollback")}
        for paths in evidence.values():
            reviewed[paths[0]] = blob(paths[0])
        candidates, parent = [], self.commit
        for n in range(count):
            commit = oid(ident + "-candidate-" + str(n))
            candidates.append({"commit": commit, "parents": [parent], "tree": dict(reviewed)})
            parent = commit
        path = C.PREFIX + ident + "/acceptance.json"
        record = {"schema": 1, "id": ident,
                  "kind": "configuration" if index else "bootstrap",
                  "status": "ACCEPTED_CONFIGURATION", "anchor_commit": self.anchor,
                  "previous_commit": self.commit,
                  "previous_acceptance": self.transitions[-1]["path"] if index else None,
                  "reviewed_commit": parent, "reviewed_tree": oid(ident + "-tree"),
                  "changes": C.delta(self.tree, reviewed), "evidence": evidence,
                  "coordinator": {"name": "Coordinator", "email": "coordinator@example.invalid"}}
        accepted = dict(reviewed)
        accepted[path] = ("100644", C.blob_oid(raw(record)))
        acceptance = oid(ident + "-accepted")
        observation = {"path": path, "raw": raw(record), "acceptance_commit": acceptance,
                       "acceptance_parents": [parent], "acceptance_identity": dict(record["coordinator"]),
                       "reviewed_tree_id": record["reviewed_tree"], "base_tree": dict(self.tree),
                       "reviewed_tree": reviewed, "accepted_tree": accepted,
                       "candidate_commits": candidates}
        self.transitions.append(observation)
        self.tree, self.commit = accepted, acceptance
        return observation

    def reseal(self, index, mutate):
        observation = self.transitions[index]
        record = json.loads(observation["raw"])
        mutate(record)
        observation["raw"] = raw(record)
        observation["accepted_tree"][observation["path"]] = ("100644", C.blob_oid(observation["raw"]))
        if index == len(self.transitions) - 1:
            self.tree = observation["accepted_tree"]

    def append_tail(self, updates):
        tree = dict(self.tree)
        for path, entry in updates.items():
            if entry is None:
                tree.pop(path)
            else:
                tree[path] = entry
        commit = oid("tail-" + str(len(self.tail)))
        self.tail.append({"commit": commit, "parents": [self.commit], "tree": tree})
        self.tree, self.commit = tree, commit

    def verify(self, **kwargs):
        policy = {"protected_paths": BOOTSTRAP_PATHS,
                  "bootstrap_paths": BOOTSTRAP_PATHS, "coordinator": COORDINATOR}
        policy.update(kwargs)
        return C.verify(self.anchor, self.anchor_tree, self.transitions, self.commit, self.tree,
                        tail_commits=self.tail, **policy)


class ConfigTransitionsTests(unittest.TestCase):
    def fixture(self):
        chain = Chain()
        chain.add()
        return chain

    def rejects(self, chain, reason=None):
        with self.assertRaises(C.TransitionError) as context:
            chain.verify()
        if reason:
            self.assertEqual(str(context.exception), reason)

    def test_anchor_and_bootstrap_are_source_only(self):
        for chain, status in ((Chain(), "HISTORICAL_ANCHOR"),
                              (self.fixture(), "ACCEPTED_CONFIGURATION")):
            result = chain.verify()
            self.assertEqual(result["status"], status)
            for field in ("apply_authorized", "installed_state_verified", "phase_acceptance_granted"):
                self.assertIs(result[field], False)

    def test_two_successive_unrelated_packages_without_checker_edit(self):
        chain = self.fixture()
        engine = chain.tree["lib/config_transitions.py"]
        chain.add({"darwin/default.nix": blob("package alpha"),
                   "manifests/alpha.json": blob("alpha owner")})
        chain.add({"darwin/second.nix": blob("package beta"),
                   "manifests/beta.json": blob("beta owner"), "manifests/old.json": None})
        self.assertEqual(chain.verify()["transition_count"], 3)
        self.assertEqual(chain.tree["lib/config_transitions.py"], engine)
        self.assertNotIn("manifests/old.json", chain.tree)

    def test_mode_only_normal_source_change(self):
        chain = self.fixture()
        chain.add({"bin/alpha": blob("script")})
        chain.add({"bin/alpha": blob("script", "100755")})
        self.assertEqual(chain.verify()["transition_count"], 3)

    def test_unreviewed_source_or_unknown_head(self):
        for mutation in (lambda c: c.tree.update({"darwin/unreviewed.nix": blob("drift")}),
                         lambda c: setattr(c, "commit", oid("unknown"))):
            with self.subTest(mutation=mutation):
                chain = self.fixture()
                mutation(chain)
                self.rejects(chain)

    def test_exact_delta_missing_extra_wrong_and_noop(self):
        for mutation in (lambda r: r["changes"].pop("bin/current-doctor"),
                         lambda r: r["changes"].update({"darwin/fake.nix": {
                             "before": None, "after": {"mode": "100644", "oid": oid("fake")}}}),
                         lambda r: r["changes"]["bin/current-doctor"]["after"].update({"oid": oid("wrong")}),
                         lambda r: r["changes"].update({"darwin/noop.nix": {"before": None, "after": None}})):
            with self.subTest(mutation=mutation):
                chain = self.fixture()
                chain.reseal(0, mutation)
                self.rejects(chain)

    def test_historical_evidence_change_and_removal_rejected_even_reviewed(self):
        for entry in (blob("rewrite"), None, blob("history", "100755")):
            with self.subTest(entry=entry):
                chain = self.fixture()
                chain.add({"evidence/history/acceptance.json": entry})
                self.rejects(chain, "historical_evidence_changed")

    def test_prior_transition_receipt_is_immutable(self):
        chain = self.fixture()
        chain.add({chain.transitions[0]["path"]: blob("rewritten receipt")})
        self.rejects(chain, "historical_evidence_changed")

    def test_protected_engine_and_new_import_files_rejected(self):
        for path in ("lib/config_transitions.py", "bin/current-doctor", "docs/config-transitions.md",
                     "lib/__init__.py", "vendor/__init__.py", "lib/new_dependency.py"):
            for removal in (False, True) if path == "lib/config_transitions.py" else (False,):
                with self.subTest(path=path, removal=removal):
                    chain = self.fixture()
                    chain.add({path: None if removal else blob("unreviewed policy")})
                    self.rejects(chain)

    def test_root_import_injection_and_unsupported_surface(self):
        for path in ("json.py", "os/__init__.py", "sitecustomize.py", ".codex/config.toml"):
            with self.subTest(path=path):
                chain = self.fixture()
                chain.add({path: blob("injection")})
                self.rejects(chain, "unsupported_source_surface")

    def test_trusted_additional_generic_surface(self):
        chain = self.fixture()
        chain.add({"modules/new.nix": blob("module")})
        self.assertEqual(chain.verify(allowed_prefixes=("modules/",))["transition_count"], 2)

    def test_bad_predecessor_and_kind(self):
        for field, value in (("previous_commit", oid("fake")),
                             ("previous_acceptance", None), ("anchor_commit", oid("other")),
                             ("kind", "bootstrap")):
            with self.subTest(field=field):
                chain = self.fixture()
                chain.add({"darwin/default.nix": blob("update")})
                chain.reseal(1, lambda r: r.update({field: value}))
                self.rejects(chain)

    def test_skipped_or_merge_candidate_and_acceptance(self):
        for mutation in (lambda o: o["candidate_commits"][0].update({"parents": [oid("fake")]}),
                         lambda o: o["candidate_commits"].pop(0),
                         lambda o: o["candidate_commits"][1]["parents"].append(oid("merge")),
                         lambda o: o.update({"acceptance_parents": [oid("wrong")]}),
                         lambda o: o["acceptance_parents"].append(oid("merge")),
                         lambda o: o.update({"reviewed_tree_id": oid("fake tree")}),
                         lambda o: o["base_tree"].update({"darwin/ghost.nix": blob("ghost")})):
            with self.subTest(mutation=mutation):
                chain = self.fixture()
                mutation(chain.transitions[0])
                self.rejects(chain)

    def test_acceptance_child_missing_extra_or_raw_unbound(self):
        for mutation in (lambda o: o["accepted_tree"].pop(o["path"]),
                         lambda o: o["accepted_tree"].update({"docs/extra.md": blob("extra")}),
                         lambda o: o["accepted_tree"].update({o["path"]: blob("fake raw")}),
                         lambda o: o.update({"raw": o["raw"] + b"\n"}),
                         lambda o: o["acceptance_identity"].update({"name": "Not coordinator"})):
            with self.subTest(mutation=mutation):
                chain = self.fixture()
                mutation(chain.transitions[0])
                self.rejects(chain)

    def test_candidate_cannot_preauthorize_receipt(self):
        chain = self.fixture()
        chain.add({C.PREFIX + "invented/acceptance.json": blob("fake authority")})
        self.rejects(chain, "candidate_acceptance_record")

    def test_invalid_evidence_reference(self):
        for value in (["docs/not-evidence.md"], [], ["evidence/missing.json"],
                      [C.PREFIX + "change-0/acceptance.json"],
                      ["evidence/reviews/change-0-validation.json"]):
            with self.subTest(value=value):
                chain = self.fixture()
                chain.reseal(0, lambda r: r["evidence"].update({"review": value}))
                self.rejects(chain)

    def test_executable_evidence_rejected(self):
        chain = self.fixture()
        observation = chain.transitions[0]
        path = "evidence/reviews/change-0-review.json"
        observation["reviewed_tree"][path] = blob("review", "100755")
        for candidate in observation["candidate_commits"]:
            candidate["tree"][path] = blob("review", "100755")
        observation["accepted_tree"][path] = blob("review", "100755")
        chain.reseal(0, lambda r: r.update({"changes": C.delta(observation["base_tree"], observation["reviewed_tree"])}))
        self.rejects(chain, "evidence_not_tracked_regular")

    def test_all_evidence_tails_are_unreviewed_source(self):
        for accepted in (True, False):
            with self.subTest(accepted=accepted):
                chain = self.fixture() if accepted else Chain()
                chain.append_tail({"evidence/runtime/fresh.json": blob("observation")})
                self.rejects(chain, "unreviewed_current_source")
        self.assertEqual(self.fixture().verify()["evidence_tail_count"], 0)

    def test_tail_rejects_source_exec_policy_deletion_receipts_or_merges(self):
        for update in ({"docs/new.md": blob("policy")}, {"evidence/code.py": blob("code")},
                       {"evidence/new.json": blob("executable", "100755")},
                       {C.PREFIX + "fake/acceptance.json": blob("receipt")},
                       {"evidence/history/acceptance.json": None},
                       {"evidence/history/acceptance.json": blob("rewritten")}, {}):
            with self.subTest(update=update):
                chain = self.fixture()
                chain.append_tail(update)
                self.rejects(chain)
        chain = self.fixture()
        chain.append_tail({"evidence/new.json": blob("new")})
        chain.tail[0]["parents"].append(oid("merge"))
        self.rejects(chain)

    def test_parser_duplicate_keys_exact_types_and_unknown_fields(self):
        original = json.loads(self.fixture().transitions[0]["raw"])
        for field, value in (("schema", True), ("schema", 1.0), ("status", "PASS"),
                             ("id", "../escape"), ("kind", "unknown-policy"),
                             ("apply_authorized", False), ("reviewed_commit", "0" * 40)):
            with self.subTest(field=field, value=value):
                record = copy.deepcopy(original)
                record[field] = value
                with self.assertRaises(C.TransitionError):
                    C.parse(raw(record))
        for invalid in (b'{"schema":1,"schema":1}', b'{"x":{"mode":1,"mode":2}}',
                        b"NaN", b"\xff", b"[]", b"[" * 2000, b" " * (C.MAX_RECORD + 1)):
            with self.subTest(invalid=invalid[:50]):
                with self.assertRaises(C.TransitionError):
                    C.parse(invalid)

    def test_unsafe_paths_symlinks_and_gitlinks(self):
        for path in ("../evil", "/absolute", "a//b", "a/./b", ".git/config", "a/.GiT/config",
                     "a\\b", "a\nb", "a ", "a/../b"):
            with self.subTest(path=path):
                chain = self.fixture()
                chain.tree[path] = blob("evil")
                self.rejects(chain)
        for mode in ("120000", "160000", "100664", 100644, True):
            with self.subTest(mode=mode):
                chain = self.fixture()
                chain.tree["darwin/default.nix"] = blob("bad mode", mode)
                self.rejects(chain)

    def test_flattened_tree_path_collision(self):
        for path in ("darwin", "DARWIN", "darwin/DEFAULT.nix", "Darwin/new.nix"):
            with self.subTest(path=path):
                chain = self.fixture()
                chain.tree[path] = blob("ambiguous path")
                self.rejects(chain, "tree_path_collision")

    def test_policy_and_observation_exactness(self):
        chain = self.fixture()
        for kwargs in ({"protected_paths": []}, {"protected_prefixes": ["../lib/"]},
                       {"protected_prefixes": ["lib"]}, {"allowed_paths": ["../escape"]}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(C.TransitionError):
                    chain.verify(**kwargs)
        chain.transitions[0]["arbitrary"] = True
        self.rejects(chain, "invalid_schema")

    def test_intermediate_rewrite_restored_before_review_is_rejected(self):
        for path, reason, bootstrap in (
                ("evidence/history/acceptance.json", "historical_evidence_changed", True),
                ("evidence/history/acceptance.json", "historical_evidence_changed", False),
                ("lib/config_transitions.py", "protected_policy_changed", False),
                ("lib/__init__.py", "protected_policy_changed", False),
                ("json.py", "unsupported_source_surface", False)):
            with self.subTest(path=path, bootstrap=bootstrap):
                chain = self.fixture()
                if not bootstrap:
                    chain.add({"darwin/default.nix": blob("ordinary update")})
                chain.transitions[-1]["candidate_commits"][0]["tree"][path] = blob("temporary bad state")
                self.rejects(chain, reason)

    def test_candidate_preview_never_accepts(self):
        chain = self.fixture()
        result = C.validate_candidate(chain.anchor_tree, chain.transitions[0]["reviewed_tree"],
                                      "bootstrap", protected_paths=("lib/config_transitions.py",),
                                      bootstrap_paths=BOOTSTRAP_PATHS, coordinator=COORDINATOR)
        self.assertEqual(result["status"], "UNACCEPTED_CONFIGURATION_CANDIDATE")
        self.assertIs(result["apply_authorized"], False)
        current = dict(chain.tree)
        current["lib/__init__.py"] = blob("injected")
        with self.assertRaisesRegex(C.TransitionError, "protected_policy_changed"):
            C.validate_candidate(chain.tree, current, "configuration",
                                 protected_paths=("lib/config_transitions.py",),
                                 bootstrap_paths=BOOTSTRAP_PATHS, coordinator=COORDINATOR)

    def test_bootstrap_cannot_tamper_with_existing_unlisted_surfaces(self):
        for path in ("vendor/legacy.py", "lib/old_phase_engine.py", "policy/aid-admin.json",
                     "codex/hooks.json", "darwin/default.nix", "manifests/old.json"):
            for restored in (False, True):
                with self.subTest(path=path, restored=restored):
                    chain = Chain()
                    chain.anchor_tree[path] = blob("historical source")
                    chain.tree = dict(chain.anchor_tree)
                    updates = {p: blob("bootstrap source " + p) for p in BOOTSTRAP_PATHS}
                    if not restored:
                        updates[path] = blob("unauthorized replacement")
                    observation = chain.add(updates)
                    if restored:
                        observation["candidate_commits"][0]["tree"][path] = blob("temporary replacement")
                    self.rejects(chain, "unsupported_bootstrap_surface")

    def test_bootstrap_cannot_delete_unlisted_anchor_file_or_add_unlisted_source(self):
        for path, entry in (("darwin/default.nix", None),
                            ("lib/new_unlisted.py", blob("engine extension")),
                            ("bin/unlisted-tool", blob("tool")),
                            ("darwin/package.nix", blob("package"))):
            with self.subTest(path=path):
                chain = Chain()
                updates = {p: blob("bootstrap source " + p) for p in BOOTSTRAP_PATHS}
                updates[path] = entry
                chain.add(updates)
                self.rejects(chain, "unsupported_bootstrap_surface")

    def test_bootstrap_scope_and_coordinator_are_mandatory_trusted_policy(self):
        chain = self.fixture()
        for kwargs in ({"bootstrap_paths": []}, {"bootstrap_paths": ["../escape"]},
                       {"bootstrap_paths": [BOOTSTRAP_PATHS[0]] * 2},
                       {"coordinator": {}}, {"coordinator": {"name": True, "email": "x"}}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(C.TransitionError):
                    chain.verify(**kwargs)

    def test_colluding_receipt_and_observed_metadata_cannot_choose_coordinator(self):
        chain = self.fixture()
        alternate = {"name": "Other actor", "email": "other@example.invalid"}
        chain.reseal(0, lambda r: r.update({"coordinator": alternate}))
        chain.transitions[0]["acceptance_identity"] = alternate
        self.rejects(chain, "coordinator_metadata_mismatch")


class PolicyUpdateTests(unittest.TestCase):
    LEGACY = ("bin/check-alpha", "bin/check-beta")

    def fixture(self, policy=True):
        chain = Chain()
        chain.anchor_tree.update({p: blob("historical " + p, "100755") for p in self.LEGACY})
        chain.tree = dict(chain.anchor_tree)
        chain.add()
        previous = chain.commit
        after = {"protected_paths": BOOTSTRAP_PATHS, "protected_prefixes": ("lib/", "vendor/"),
                 "allowed_paths": ("flake.nix", "flake.lock"),
                 "allowed_prefixes": ("darwin/", "manifests/", "bin/", "docs/", "tests/"),
                 "bootstrap_paths": BOOTSTRAP_PATHS, "coordinator": COORDINATOR}
        registry = {C.PREFIX + "change-1/acceptance.json": {
            "previous_commit": previous, "paths": ("lib/config_transitions.py",), "after": after}}
        if policy:
            chain.add({"lib/config_transitions.py": blob("reviewed v2 engine")})
            chain.reseal(1, lambda r: r.update({"kind": "policy"}))
        return chain, registry

    def verify(self, chain, registry=None):
        return chain.verify(protected_paths=BOOTSTRAP_PATHS + self.LEGACY, policy_updates=registry)

    def rejects(self, chain, registry, reason=None):
        with self.assertRaises(C.TransitionError) as caught:
            self.verify(chain, registry)
        if reason:
            self.assertEqual(str(caught.exception), reason)

    def test_registered_policy_then_two_ordinary_validator_updates(self):
        chain, registry = self.fixture()
        chain.add({"bin/check-alpha": blob("alpha validator v2", "100755"),
                   "darwin/alpha.nix": blob("alpha package v2")})
        chain.add({"bin/check-beta": blob("beta validator v2", "100755"),
                   "darwin/beta.nix": blob("beta package v2")})
        result = self.verify(chain, registry)
        self.assertEqual(result["transition_count"], 4)
        self.assertIs(result["apply_authorized"], False)
        self.assertIs(result["phase_acceptance_granted"], False)

    def test_policy_parse_is_not_admission_without_caller_registry(self):
        chain, _ = self.fixture()
        self.assertEqual(C.parse(chain.transitions[-1]["raw"])["kind"], "policy")
        self.rejects(chain, None, "unregistered_policy_transition")
        self.rejects(chain, {}, "unregistered_policy_transition")

    def test_unused_registry_does_not_reinterpret_original_v1_chain(self):
        chain, registry = self.fixture(False)
        self.assertEqual(self.verify(chain), self.verify(chain, registry))
        chain.add({"bin/check-alpha": blob("too early validator change", "100755")})
        other_registry = {C.PREFIX + "future/acceptance.json": next(iter(registry.values()))}
        self.rejects(chain, other_registry, "protected_policy_changed")

    def test_policy_cannot_relax_history_before_its_predecessor(self):
        chain, _ = self.fixture(False)
        chain.add({"bin/check-alpha": blob("unreviewed under v1", "100755")})
        previous = chain.commit
        chain.add({"lib/config_transitions.py": blob("v2 engine")})
        chain.reseal(2, lambda r: r.update({"kind": "policy"}))
        _, template = self.fixture()
        decision = copy.deepcopy(next(iter(template.values())))
        decision["previous_commit"] = previous
        registry = {chain.transitions[2]["path"]: decision}
        self.rejects(chain, registry, "protected_policy_changed")

    def test_unknown_policy_id_wrong_predecessor_and_kind_rejected(self):
        for mutation, reason in (
                (lambda r: {C.PREFIX + "other/acceptance.json": next(iter(r.values()))},
                 "unregistered_policy_transition"),
                (lambda r: {p: dict(v, previous_commit=oid("wrong")) for p, v in r.items()},
                 "policy_predecessor_mismatch")):
            chain, registry = self.fixture()
            self.rejects(chain, mutation(registry), reason)
        chain, registry = self.fixture()
        chain.reseal(1, lambda r: r.update({"kind": "configuration"}))
        self.rejects(chain, registry, "unexpected_transition_kind")

    def test_policy_cannot_be_first_bootstrap(self):
        chain, registry = self.fixture(False)
        chain.reseal(0, lambda r: r.update({"kind": "policy"}))
        decision = next(iter(registry.values()))
        decision["previous_commit"] = chain.anchor
        self.rejects(chain, {chain.transitions[0]["path"]: decision}, "unregistered_policy_transition")

    def test_policy_scope_rejects_unlisted_and_restored_changes(self):
        for path in ("lib/other_engine.py", "bin/check-alpha", "darwin/default.nix",
                     "evidence/history/acceptance.json"):
            for restored in (False, True):
                with self.subTest(path=path, restored=restored):
                    chain, registry = self.fixture()
                    row = chain.transitions[1]
                    targets = [row["candidate_commits"][0]["tree"]] if restored else [
                        row["reviewed_tree"], row["accepted_tree"],
                        *(c["tree"] for c in row["candidate_commits"])]
                    for tree in targets:
                        tree[path] = blob("outside repair scope")
                    if not restored:
                        chain.reseal(1, lambda r: r.update({"changes": C.delta(row["base_tree"], row["reviewed_tree"])}))
                    self.rejects(chain, registry)

    def test_core_is_still_protected_after_policy_acceptance(self):
        chain, registry = self.fixture()
        chain.add({"lib/config_transitions.py": blob("unauthorized next engine")})
        self.rejects(chain, registry, "protected_policy_changed")

    def test_registered_policy_receipt_cannot_be_replayed(self):
        chain, registry = self.fixture()
        original_path = chain.transitions[1]["path"]
        original_id = C.parse(chain.transitions[1]["raw"])["id"]
        chain.add({"lib/config_transitions.py": blob("second policy attempt")})
        chain.transitions[2]["path"] = original_path
        chain.reseal(2, lambda r: r.update({"kind": "policy", "id": original_id}))
        self.rejects(chain, registry, "replayed_policy_transition")

    def test_receipt_cannot_supply_successor_rules(self):
        chain, registry = self.fixture()
        chain.reseal(1, lambda r: r.update({"policy_updates": {}}))
        self.rejects(chain, registry, "invalid_schema")

    def test_malformed_trusted_registry_rejected(self):
        for mutation in (lambda v: v.update({"paths": []}),
                         lambda v: v.update({"paths": ["../escape"]}),
                         lambda v: v.update({"extra": True}),
                         lambda v: v["after"].pop("coordinator"),
                         lambda v: v["after"].update({"arbitrary": True}),
                         lambda v: v.update({"previous_commit": "bad"})):
            with self.subTest(mutation=mutation):
                chain, registry = self.fixture()
                mutation(next(iter(registry.values())))
                self.rejects(chain, registry)

    def test_policy_still_requires_prepolicy_coordinator_and_sole_receipt_child(self):
        for collusion in (False, True):
            chain, registry = self.fixture()
            if collusion:
                other = {"name": "Other", "email": "other@example.invalid"}
                next(iter(registry.values()))["after"]["coordinator"] = other
                chain.reseal(1, lambda r: r.update({"coordinator": other}))
                chain.transitions[1]["acceptance_identity"] = other
            else:
                chain.transitions[1]["accepted_tree"]["docs/extra.md"] = blob("extra child source")
            self.rejects(chain, registry)

    def test_policy_preview_only_checks_exact_repair_scope(self):
        chain, registry = self.fixture()
        row = chain.transitions[1]
        kwargs = dict(next(iter(registry.values()))["after"])
        kwargs["bootstrap_paths"] = ("lib/config_transitions.py",)
        result = C.validate_candidate(row["base_tree"], row["reviewed_tree"], "policy", **kwargs)
        self.assertEqual(result["status"], "UNACCEPTED_CONFIGURATION_CANDIDATE")
        self.assertIs(result["apply_authorized"], False)
        row["reviewed_tree"]["darwin/extra.nix"] = blob("outside scope")
        with self.assertRaises(C.TransitionError):
            C.validate_candidate(row["base_tree"], row["reviewed_tree"], "policy", **kwargs)


if __name__ == "__main__":
    unittest.main()
