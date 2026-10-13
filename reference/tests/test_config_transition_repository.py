"""Real disposable Git objects; no native doctor, network or machine writes.

The only processes are fixed Git vectors in a freshly created test repository.
Production anchor is never patched in production files. A test-only anchor is
necessary to exercise genuine object identities without rewriting real history.
"""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lib import config_transition_git as G
from lib import config_transitions as F
from lib import config_transition_source as S


class LocalGit:
    def __init__(self, root):
        self.root = root
        self.env = {"PATH": "/usr/bin:/bin", "HOME": str(root), "LANG": "C", "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0", "GIT_AUTHOR_NAME": "Fixture Coordinator",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid", "GIT_COMMITTER_NAME": "Fixture Coordinator",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}

    def _read(self, *args, allow_one=False):
        result = subprocess.run(("/usr/bin/git", "--no-pager", "--no-optional-locks",
            "--no-replace-objects", "-c", "core.hooksPath=/dev/null", *args),
            cwd=self.root, env=self.env, capture_output=True, timeout=8, check=False)
        if result.returncode not in ((0, 1) if allow_one else (0,)):
            raise AssertionError("fixture Git command failed")
        return result.returncode, result.stdout

    def _text(self, *args):
        return self._read(*args)[1].decode().rstrip("\n")

    def _tree(self, commit):
        tree = {}
        for entry in self._read("ls-tree", "-rz", "--full-tree", commit)[1].split(b"\0"):
            if entry:
                header, path = entry.split(b"\t")
                mode, kind, oid = header.decode().split()
                assert kind == "blob"
                tree[path.decode()] = (mode, oid)
        return tree


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aid-config-transition-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git = LocalGit(self.root)
        self.git._read("init", "--quiet")
        self.put("lib/engine.py", b"original engine")
        self.put("evidence/historical.json", b"{}")
        self.anchor = self.commit()
        self.previous, self.previous_path = self.anchor, None
        self.rules = {"protected_paths": {"lib/engine.py"}, "bootstrap_paths": {"lib/engine.py"},
            "coordinator": {"name": "Fixture Coordinator", "email": "fixture@example.invalid"}}
        self.policy_updates = {}
        anchor_patch = patch.object(G, "ANCHOR", self.anchor)
        anchor_patch.start()
        self.addCleanup(anchor_patch.stop)

    def put(self, path, raw):
        full = self.root / path
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(raw)

    def commit(self):
        self.git._read("add", "--all")  # disposable fixture, never user's repo
        self.git._read("commit", "--quiet", "-m", "bounded fixture")
        return self.git._text("rev-parse", "HEAD")

    def transition(self, ident, mutation, *, kind=None, amend_record=None):
        base = self.git._tree(self.previous)
        mutation()
        evidence = {}
        for role in ("validation", "review", "rollback"):
            path = F.PREFIX + ident + "/" + role + ".json"
            self.put(path, b"{}")
            evidence[role] = [path]
        reviewed = self.commit()
        tree = self.git._tree(reviewed)
        record = {"schema": 1, "id": ident,
            "kind": kind or ("bootstrap" if self.previous_path is None else "configuration"),
            "status": "ACCEPTED_CONFIGURATION", "anchor_commit": self.anchor,
            "previous_commit": self.previous, "previous_acceptance": self.previous_path,
            "reviewed_commit": reviewed, "reviewed_tree": self.git._text("rev-parse", reviewed + "^{tree}"),
            "changes": F.delta(base, tree), "evidence": evidence,
            "coordinator": {"name": "Fixture Coordinator", "email": "fixture@example.invalid"}}
        if amend_record is not None:
            amend_record(record)
        path = F.PREFIX + ident + "/acceptance.json"
        self.put(path, json.dumps(record, sort_keys=True).encode())
        self.previous, self.previous_path = self.commit(), path
        return reviewed, record

    def verify(self):
        head = self.git._text("rev-parse", "HEAD")
        tree = self.git._tree(head)
        observation = G.observe(self.git, head, tree)
        result = F.verify(self.anchor, observation["anchorTree"], observation["transitions"], head,
                          tree, tail_commits=observation["pendingCommits"],
                          policy_updates=self.policy_updates, **self.rules)
        return result, observation

    def bootstrap_v1(self):
        self.rules["protected_paths"].add("bin/check-productivity")
        self.rules["bootstrap_paths"].add("bin/check-productivity")
        return self.transition("bootstrap-v1", lambda: (
            self.put("lib/engine.py", b"reviewed engine v1"),
            self.put("bin/check-productivity", b"reviewed validator v1")))

    def register_policy_v2(self, ident="policy-v2", predecessor=None):
        # This trusted registry is supplied by the test caller, not discovered
        # from a receipt or inferred from the current repository's payloads.
        path = F.PREFIX + ident + "/acceptance.json"
        self.policy_updates[path] = {
            "previous_commit": self.previous if predecessor is None else predecessor,
            "paths": {"lib/engine.py"},
            "after": {"protected_paths": {"lib/engine.py"},
                "protected_prefixes": ("lib/", "vendor/"),
                "allowed_paths": ("flake.nix", "flake.lock"),
                "allowed_prefixes": ("darwin/", "manifests/", "bin/", "docs/", "tests/"),
                "bootstrap_paths": {"lib/engine.py", "bin/check-productivity"},
                "coordinator": {"name": "Fixture Coordinator", "email": "fixture@example.invalid"}}}
        return path

    def policy_v2(self):
        self.register_policy_v2()
        return self.transition("policy-v2", lambda: self.put("lib/engine.py", b"reviewed engine v2"),
                               kind="policy")

    def test_real_two_additions_then_removal_without_engine_changes(self):
        self.transition("bootstrap", lambda: self.put("lib/engine.py", b"reviewed general engine"))
        engine = self.git._tree(self.previous)["lib/engine.py"]
        self.transition("first-payload", lambda: self.put("darwin/first.nix", b"first package"))
        self.transition("second-payload", lambda: self.put("manifests/second.json", b"{}"))
        self.transition("remove-first", lambda: (self.root / "darwin/first.nix").unlink())
        result, observation = self.verify()
        self.assertEqual(result["transition_count"], 4)
        self.assertEqual(observation["acceptedTree"]["lib/engine.py"], engine)
        self.assertNotIn("darwin/first.nix", observation["acceptedTree"])
        self.assertFalse(result["apply_authorized"] or result["installed_state_verified"])

    def test_real_rewritten_then_restored_historical_evidence_rejects(self):
        self.transition("bootstrap", lambda: self.put("lib/engine.py", b"reviewed engine"))
        self.put("evidence/historical.json", b"tampered")
        self.commit()
        self.put("evidence/historical.json", b"{}")
        self.commit()
        self.transition("payload", lambda: self.put("darwin/payload.nix", b"ordinary"))
        with self.assertRaisesRegex(F.TransitionError, "historical_evidence_changed"):
            self.verify()

    def test_real_receipt_rewrite_is_not_hidden_by_restored_endpoint(self):
        self.transition("bootstrap", lambda: self.put("lib/engine.py", b"reviewed engine"))
        path = self.previous_path
        saved = (self.root / path).read_bytes()
        self.put(path, b"{}")
        self.commit()
        self.put(path, saved)
        self.commit()
        with self.assertRaisesRegex(F.TransitionError, "git_receipt_history_changed"):
            self.verify()

    def test_real_parent_tree_identity_cannot_stand_for_acceptance_child_commit(self):
        reviewed, record = self.transition("bootstrap", lambda: self.put("lib/engine.py", b"reviewed engine"))
        result, observation = self.verify()
        self.assertNotEqual(reviewed, observation["acceptedCommit"])
        self.assertNotEqual(record["reviewed_tree"], self.git._text("rev-parse", self.previous + "^{tree}"))
        self.assertEqual(result["accepted_commit"], self.previous)

    def test_real_policy_successor_then_validator_setting_and_package_add_remove(self):
        self.bootstrap_v1()
        bootstrap_commit, bootstrap_path = self.previous, self.previous_path
        bootstrap_receipt = (self.root / bootstrap_path).read_bytes()
        historical = self.git._tree(self.previous)["evidence/historical.json"]
        validator_v1 = self.git._tree(self.previous)["bin/check-productivity"]
        self.assertEqual(self.verify()[0]["transition_count"], 1)

        policy_reviewed, policy_record = self.policy_v2()
        policy_commit, policy_path = self.previous, self.previous_path
        result, observed_policy = self.verify()
        self.assertEqual(result["transition_count"], 2)
        self.assertEqual(policy_record["previous_commit"], bootstrap_commit)
        self.assertEqual(policy_record["previous_acceptance"], bootstrap_path)
        self.assertEqual(self.git._text("rev-parse", policy_reviewed + "^"), bootstrap_commit)
        self.assertEqual(self.git._text("rev-parse", policy_commit + "^"), policy_reviewed)
        self.assertEqual(observed_policy["transitions"][-1]["reviewed_tree_id"],
                         self.git._text("rev-parse", policy_reviewed + "^{tree}"))
        engine_v2 = observed_policy["acceptedTree"]["lib/engine.py"]
        policy_receipt = (self.root / policy_path).read_bytes()
        self.assertEqual(set(policy_record), {"schema", "id", "kind", "status", "anchor_commit",
            "previous_commit", "previous_acceptance", "reviewed_commit", "reviewed_tree",
            "changes", "evidence", "coordinator"})

        self.transition("validator-and-setting", lambda: (
            self.put("bin/check-productivity", b"reviewed validator v2"),
            self.put("darwin/productivity.nix", b"{ setting = true; }")))
        self.transition("add-another-package", lambda: self.put("manifests/second-package.json", b"{}"))
        self.transition("remove-another-package", lambda: (self.root / "manifests/second-package.json").unlink())
        result, observation = self.verify()
        self.assertEqual(result["transition_count"], 5)
        self.assertEqual(observation["pendingCommits"], [])
        self.assertNotEqual(observation["acceptedTree"]["bin/check-productivity"], validator_v1)
        self.assertIn("darwin/productivity.nix", observation["acceptedTree"])
        self.assertNotIn("manifests/second-package.json", observation["acceptedTree"])
        for transition in observation["transitions"][2:]:
            self.assertEqual(transition["base_tree"]["lib/engine.py"], engine_v2)
            for commit in transition["candidate_commits"]:
                self.assertEqual(commit["tree"]["lib/engine.py"], engine_v2)
            self.assertEqual(transition["accepted_tree"]["lib/engine.py"], engine_v2)
        self.assertEqual(observation["acceptedTree"]["evidence/historical.json"], historical)
        self.assertEqual((self.root / bootstrap_path).read_bytes(), bootstrap_receipt)
        self.assertEqual((self.root / policy_path).read_bytes(), policy_receipt)
        self.assertFalse(result["apply_authorized"] or result["installed_state_verified"]
                         or result["phase_acceptance_granted"])

    def test_real_unknown_policy_receipt_has_no_registry_authority(self):
        self.bootstrap_v1()
        self.transition("unknown-policy", lambda: self.put("lib/engine.py", b"unknown engine"), kind="policy")
        with self.assertRaisesRegex(F.TransitionError, "unregistered_policy_transition"):
            self.verify()

    def test_real_policy_registry_requires_its_exact_predecessor(self):
        self.bootstrap_v1()
        self.register_policy_v2(predecessor=self.anchor)
        self.transition("policy-v2", lambda: self.put("lib/engine.py", b"reviewed engine v2"), kind="policy")
        with self.assertRaisesRegex(F.TransitionError, "policy_predecessor_mismatch"):
            self.verify()

    def test_real_policy_receipt_replay_is_rejected_in_actual_history(self):
        self.bootstrap_v1()
        self.policy_v2()
        self.assertEqual(self.verify()[0]["transition_count"], 2)
        self.transition("policy-v2", lambda: self.put("lib/engine.py", b"replayed policy engine"), kind="policy")
        with self.assertRaisesRegex(F.TransitionError, "git_receipt_history_changed"):
            self.verify()

    def test_real_renamed_policy_cannot_reuse_spent_predecessor(self):
        self.bootstrap_v1()
        predecessor = self.previous
        self.policy_v2()
        self.assertEqual(self.verify()[0]["transition_count"], 2)
        self.register_policy_v2("renamed-policy", predecessor=predecessor)
        self.transition("renamed-policy", lambda: self.put("lib/engine.py", b"replayed policy engine"),
                        kind="policy")
        with self.assertRaisesRegex(F.TransitionError, "policy_predecessor_mismatch"):
            self.verify()

    def test_real_pre_policy_protected_mutation_restoration_uses_v1_rules(self):
        self.bootstrap_v1()
        original = (self.root / "bin/check-productivity").read_bytes()
        self.put("bin/check-productivity", b"prematurely changed validator")
        changed_commit = self.commit()
        self.put("bin/check-productivity", original)
        restored_commit = self.commit()
        self.transition("before-policy", lambda: self.put("darwin/setting.nix", b"ordinary setting"))
        self.policy_v2()
        self.assertNotEqual(self.git._tree(changed_commit)["bin/check-productivity"],
                            self.git._tree(restored_commit)["bin/check-productivity"])
        with self.assertRaisesRegex(F.TransitionError, "protected_policy_changed"):
            self.verify()

    def test_real_policy_candidate_does_not_preactivate_successor_rules(self):
        self.bootstrap_v1()
        self.register_policy_v2()
        original = (self.root / "bin/check-productivity").read_bytes()
        self.put("bin/check-productivity", b"not in exact policy repair paths")
        self.commit()
        self.put("bin/check-productivity", original)
        self.commit()
        self.transition("policy-v2", lambda: self.put("lib/engine.py", b"reviewed engine v2"), kind="policy")
        with self.assertRaisesRegex(F.TransitionError, "unsupported_bootstrap_surface"):
            self.verify()

    def test_real_policy_registry_fields_are_not_valid_receipt_fields(self):
        self.bootstrap_v1()
        self.register_policy_v2()
        self.transition("policy-v2", lambda: self.put("lib/engine.py", b"reviewed engine v2"), kind="policy",
            amend_record=lambda record: record.update({"policy_updates": {}}))
        with self.assertRaisesRegex(F.TransitionError, "invalid_schema"):
            self.verify()

    def test_real_post_policy_engine_mutation_remains_protected(self):
        self.bootstrap_v1()
        self.policy_v2()
        self.transition("unreviewed-policy", lambda: self.put("lib/engine.py", b"ordinary payload spoof"))
        with self.assertRaisesRegex(F.TransitionError, "protected_policy_changed"):
            self.verify()

    def selected_trust_predecessor(self):
        registry = "manifests/trusted-repos.json"
        hook = "codex/hooks/phase5-contract.py"
        self.rules["protected_paths"].add(registry)
        self.rules["bootstrap_paths"].update((registry, hook))
        self.transition("bootstrap-trust-fixture", lambda: (
            self.put("lib/engine.py", b"reviewed engine v1"),
            self.put(registry, b'{"schema":1,"repositories":["control-fixture"]}'),
            self.put(hook, b"unchanged historical router")))
        v2_path = self.register_policy_v2()
        v2 = self.policy_updates[v2_path]["after"]
        v2["protected_paths"].add(registry)
        self.transition("policy-v2", lambda: self.put("lib/engine.py", b"reviewed engine v2"), kind="policy")
        self.transition("github-cli", lambda: self.put("darwin/github-cli.nix", b"reviewed gh fixture"))
        path = S.SELECTED_REPO_TRUST_PATH
        self.policy_updates[path] = {"previous_commit": self.previous,
            "paths": S.SELECTED_REPO_TRUST_PATHS, "after": dict(v2)}
        return registry, hook, path

    def accept_selected_trust(self, registry):
        return self.transition("selected-repo-trust", lambda: self.put(
            registry, b'{"schema":1,"repositories":["control-fixture","selected-fixture","worktree-fixture"]}'),
            kind="policy")

    def test_real_v2_package_then_selected_trust_keeps_core_and_rules(self):
        registry, hook, path = self.selected_trust_predecessor()
        previous = self.previous
        historical = self.git._tree(previous)["evidence/historical.json"]
        before_hook = self.git._tree(previous)[hook]
        reviewed, record = self.accept_selected_trust(registry)
        result, observation = self.verify()
        self.assertEqual(result["transition_count"], 4)
        self.assertEqual(record["previous_commit"], previous)
        self.assertEqual(observation["transitions"][-1]["acceptance_parents"], [reviewed])
        self.assertEqual(observation["acceptedTree"][hook], before_hook)
        self.assertEqual(observation["acceptedTree"]["evidence/historical.json"], historical)
        self.assertEqual(self.policy_updates[path]["after"], self.policy_updates[F.PREFIX + "policy-v2/acceptance.json"]["after"])
        self.assertFalse(result["apply_authorized"] or result["installed_state_verified"])

    def test_real_selected_trust_wrong_predecessor_rejected(self):
        registry, _, path = self.selected_trust_predecessor()
        self.policy_updates[path]["previous_commit"] = self.anchor
        self.accept_selected_trust(registry)
        with self.assertRaisesRegex(F.TransitionError, "policy_predecessor_mismatch"):
            self.verify()

    def test_real_selected_trust_receipt_cannot_be_replayed(self):
        registry, _, _ = self.selected_trust_predecessor()
        self.accept_selected_trust(registry)
        self.transition("selected-repo-trust", lambda: self.put(registry, b"different replayed registry"),
                        kind="policy")
        with self.assertRaisesRegex(F.TransitionError, "git_receipt_history_changed"):
            self.verify()

    def test_real_selected_trust_later_ordinary_registry_edit_rejected(self):
        registry, _, _ = self.selected_trust_predecessor()
        self.accept_selected_trust(registry)
        self.transition("unapproved-next-repository", lambda: self.put(registry, b"another repository"))
        with self.assertRaisesRegex(F.TransitionError, "protected_policy_changed"):
            self.verify()

    def test_real_selected_trust_rejects_restored_hook_mutation(self):
        registry, hook, _ = self.selected_trust_predecessor()
        before = (self.root / hook).read_bytes()
        self.put(hook, b"forbidden temporary hook mutation")
        self.commit()
        self.put(hook, before)
        self.commit()
        self.accept_selected_trust(registry)
        with self.assertRaisesRegex(F.TransitionError, "unsupported_bootstrap_surface"):
            self.verify()

    def test_real_selected_trust_rejects_restored_historical_evidence(self):
        registry, _, _ = self.selected_trust_predecessor()
        self.put("evidence/historical.json", b"forbidden replacement")
        self.commit()
        self.put("evidence/historical.json", b"{}")
        self.commit()
        self.accept_selected_trust(registry)
        with self.assertRaisesRegex(F.TransitionError, "historical_evidence_changed"):
            self.verify()

    def windows_skill_predecessor(self):
        registry, hook, trust_path = self.selected_trust_predecessor()
        # Keep production namespace protection in both preceding policy steps;
        # their bootstrap fixture remains deliberately smaller than production.
        for update in self.policy_updates.values():
            update["after"]["protected_prefixes"] = S.PROTECTED_PREFIXES
        self.accept_selected_trust(registry)
        path = S.WINDOWS_HOST_SKILL_PATH
        self.policy_updates[path] = {"previous_commit": self.previous,
            "paths": S.WINDOWS_HOST_SKILL_PATHS,
            "after": dict(self.policy_updates[trust_path]["after"])}
        return registry, hook, path

    def accept_windows_skill(self, extra=None):
        def mutation():
            self.put("skills/manage-windows-host/SKILL.md", b"reviewed Windows guidance")
            if extra is not None:
                extra()
        return self.transition("windows-host-skill", mutation, kind="policy")

    def test_real_third_policy_windows_skill_preserves_history_and_v2(self):
        registry, hook, path = self.windows_skill_predecessor()
        previous = self.previous
        before = self.git._tree(previous)
        reviewed, record = self.accept_windows_skill()
        result, observation = self.verify()
        self.assertEqual(result["transition_count"], 5)
        self.assertEqual(record["previous_commit"], previous)
        self.assertEqual(observation["transitions"][-1]["acceptance_parents"], [reviewed])
        self.assertIn("skills/manage-windows-host/SKILL.md", observation["acceptedTree"])
        for protected in (registry, hook, "lib/engine.py", "evidence/historical.json"):
            self.assertEqual(observation["acceptedTree"][protected], before[protected])
        self.assertEqual(self.policy_updates[path]["after"],
                         self.policy_updates[F.PREFIX + "policy-v2/acceptance.json"]["after"])
        self.assertFalse(result["apply_authorized"] or result["installed_state_verified"])
        self.transition("ordinary-after-skill", lambda: self.put("docs/ordinary.md", b"reviewed payload"))
        self.assertEqual(self.verify()[0]["transition_count"], 6)

    def test_real_windows_skill_wrong_predecessor_rejected(self):
        _, _, path = self.windows_skill_predecessor()
        self.policy_updates[path]["previous_commit"] = self.anchor
        self.accept_windows_skill()
        with self.assertRaisesRegex(F.TransitionError, "policy_predecessor_mismatch"):
            self.verify()

    def test_real_windows_skill_receipt_replay_rejected(self):
        self.windows_skill_predecessor()
        self.accept_windows_skill()
        self.assertEqual(self.verify()[0]["transition_count"], 5)
        self.accept_windows_skill(lambda: self.put("docs/windows-host-skill.md", b"replay attempt"))
        with self.assertRaisesRegex(F.TransitionError, "git_receipt_history_changed"):
            self.verify()

    def test_real_windows_skill_rejects_other_skill(self):
        self.windows_skill_predecessor()
        self.accept_windows_skill(lambda: self.put("skills/other/SKILL.md", b"unapproved skill"))
        with self.assertRaisesRegex(F.TransitionError, "unsupported_bootstrap_surface"):
            self.verify()

    def test_real_windows_skill_rejects_hook_mutation(self):
        _, hook, _ = self.windows_skill_predecessor()
        self.accept_windows_skill(lambda: self.put(hook, b"unapproved hook"))
        with self.assertRaisesRegex(F.TransitionError, "unsupported_bootstrap_surface"):
            self.verify()

    def test_real_windows_skill_rejects_trust_mutation(self):
        registry, _, _ = self.windows_skill_predecessor()
        self.accept_windows_skill(lambda: self.put(registry, b"unapproved trust"))
        with self.assertRaisesRegex(F.TransitionError, "unsupported_bootstrap_surface"):
            self.verify()

    def test_real_windows_skill_rejects_restored_intermediate_hook(self):
        _, hook, _ = self.windows_skill_predecessor()
        before = (self.root / hook).read_bytes()
        self.put(hook, b"temporary unapproved hook")
        self.commit()
        self.put(hook, before)
        self.commit()
        self.accept_windows_skill()
        with self.assertRaisesRegex(F.TransitionError, "unsupported_bootstrap_surface"):
            self.verify()

    def test_real_later_ordinary_windows_skill_edit_stays_protected(self):
        self.windows_skill_predecessor()
        self.accept_windows_skill()
        self.transition("unapproved-skill-update", lambda: self.put(
            "skills/manage-windows-host/SKILL.md", b"unapproved ordinary edit"))
        with self.assertRaisesRegex(F.TransitionError, "protected_policy_changed"):
            self.verify()

    def current_doctor_diagnostics_predecessor(self):
        paths = S.CURRENT_DOCTOR_DIAGNOSTICS_PATHS
        forbidden = {"codex/hooks/phase5-contract.py", "manifests/trusted-repos.json",
                     "policy/aid-admin-policy.json", "lib/config_transitions.py"}
        self.rules = {
            "protected_paths": {"lib/engine.py"} | (paths - {
                "bin/system-revision-status", "tests/test_system_revision_status.py"}) | forbidden,
            "protected_prefixes": S.PROTECTED_PREFIXES,
            "allowed_paths": ("flake.nix", "flake.lock"),
            "allowed_prefixes": S.ALLOWED_PREFIXES,
            "bootstrap_paths": {"lib/engine.py"} | paths | forbidden,
            "coordinator": self.rules["coordinator"]}

        def bootstrap():
            self.put("lib/engine.py", b"reviewed fixture engine")
            for path in paths | forbidden:
                self.put(path, ("historical fixture " + path).encode())

        self.transition("bootstrap-diagnostics-fixture", bootstrap)
        self.policy_updates[S.CURRENT_DOCTOR_DIAGNOSTICS_PATH] = {
            "previous_commit": self.previous, "paths": paths, "after": dict(self.rules)}
        return forbidden

    def accept_current_doctor_diagnostics(self, extra=None):
        def mutation():
            self.put("bin/current-doctor", b"reviewed historical source binding")
            self.put("lib/vendor_compatibility_probe.py", b"bounded public diagnostic reasons")
            if extra is not None:
                extra()
        return self.transition("current-doctor-diagnostics", mutation, kind="policy")

    def admit_current_doctor_diagnostics(self, review=False):
        head = self.git._text("rev-parse", "HEAD")
        tree = self.git._tree(head)
        observation = G.observe(self.git, head, tree)
        with patch.object(S, "ANCHOR", self.anchor), \
                patch.object(S, "policy", return_value=self.rules), \
                patch.object(S, "policy_updates", return_value=self.policy_updates):
            return S.admit(observation, head, tree, review=review)

    def test_real_current_doctor_diagnostics_preview_not_main_or_acceptance(self):
        self.current_doctor_diagnostics_predecessor()
        self.put("bin/current-doctor", b"candidate source fixture repair")
        self.put("lib/vendor_compatibility_probe.py", b"candidate bounded diagnostics")
        self.commit()
        self.assertIs(self.admit_current_doctor_diagnostics(True)["accepted"], False)
        with self.assertRaisesRegex(F.TransitionError, "unreviewed_main_source"):
            self.admit_current_doctor_diagnostics()

    def test_real_current_doctor_diagnostics_acceptance_keeps_history_and_rules(self):
        forbidden = self.current_doctor_diagnostics_predecessor()
        before = self.git._tree(self.previous)
        predecessor = self.previous
        reviewed, record = self.accept_current_doctor_diagnostics()
        result, observation = self.verify()
        self.assertIs(self.admit_current_doctor_diagnostics()["accepted"], True)
        self.assertEqual(record["previous_commit"], predecessor)
        self.assertEqual(observation["transitions"][-1]["acceptance_parents"], [reviewed])
        self.assertEqual(self.policy_updates[S.CURRENT_DOCTOR_DIAGNOSTICS_PATH]["after"], self.rules)
        for path in (*forbidden, "lib/engine.py", "evidence/historical.json"):
            self.assertEqual(observation["acceptedTree"][path], before[path])
        self.assertFalse(result["apply_authorized"] or result["installed_state_verified"]
                         or result["phase_acceptance_granted"])
        self.transition("later-doctor-edit", lambda: self.put(
            "bin/current-doctor", b"unapproved ordinary doctor mutation"))
        with self.assertRaisesRegex(F.TransitionError, "protected_policy_changed"):
            self.verify()

    def test_real_current_doctor_diagnostics_wrong_predecessor_rejected(self):
        self.current_doctor_diagnostics_predecessor()
        self.policy_updates[S.CURRENT_DOCTOR_DIAGNOSTICS_PATH]["previous_commit"] = self.anchor
        self.accept_current_doctor_diagnostics()
        with self.assertRaisesRegex(F.TransitionError, "policy_predecessor_mismatch"):
            self.verify()

    def test_real_current_doctor_diagnostics_receipt_replay_rejected(self):
        self.current_doctor_diagnostics_predecessor()
        self.accept_current_doctor_diagnostics()
        self.assertIs(self.admit_current_doctor_diagnostics()["accepted"], True)
        self.accept_current_doctor_diagnostics(lambda: self.put(
            "docs/post-phase5-sentinel.md", b"replayed source repair"))
        with self.assertRaisesRegex(F.TransitionError, "git_receipt_history_changed"):
            self.verify()

    def test_real_current_doctor_diagnostics_unexpected_protected_change_rejected(self):
        self.current_doctor_diagnostics_predecessor()
        self.accept_current_doctor_diagnostics(lambda: self.put(
            "manifests/trusted-repos.json", b"unapproved trust registry"))
        with self.assertRaisesRegex(F.TransitionError, "unsupported_bootstrap_surface"):
            self.verify()

    def test_real_current_doctor_diagnostics_restored_hook_change_rejected(self):
        self.current_doctor_diagnostics_predecessor()
        path = "codex/hooks/phase5-contract.py"
        original = (self.root / path).read_bytes()
        self.put(path, b"temporary unapproved hook")
        self.commit()
        self.put(path, original)
        self.commit()
        self.accept_current_doctor_diagnostics()
        with self.assertRaisesRegex(F.TransitionError, "unsupported_bootstrap_surface"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
