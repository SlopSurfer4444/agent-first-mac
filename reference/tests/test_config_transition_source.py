"""Pure current-source routing tests: synthetic Git objects, no native access."""

import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib import config_transition_source as S
from lib import config_transitions as F
from test_config_transitions import Chain, blob, oid, BOOTSTRAP_PATHS, COORDINATOR


RULES = {
    "bootstrap_paths": (*BOOTSTRAP_PATHS, "docs/intent.md"), "coordinator": COORDINATOR,
    "protected_paths": frozenset(("bin/current-doctor", "lib/config_transitions.py",
                                  "docs/config-transitions.md")),
    "protected_prefixes": ("lib/", "vendor/"),
    "allowed_paths": ("flake.nix", "flake.lock"),
    "allowed_prefixes": ("darwin/", "modules/", "manifests/", "bin/", "docs/", "tests/"),
}


def fixture(accepted=True):
    chain = Chain()
    chain.anchor = chain.commit = S.ANCHOR
    chain.anchor_tree["bin/current-doctor"] = blob("historical doctor", "100755")
    chain.tree = dict(chain.anchor_tree)
    if accepted:
        chain.add()
    return chain


def observation(chain):
    last = chain.transitions[-1] if chain.transitions else None
    return {"anchorTree": chain.anchor_tree, "transitions": chain.transitions,
            "acceptedCommit": last["acceptance_commit"] if last else chain.anchor,
            "acceptedTree": last["accepted_tree"] if last else chain.anchor_tree,
            "pendingCommits": chain.tail}


def route(chain, review=False, updates=None, rules=None):
    with patch.object(S, "policy", return_value=RULES if rules is None else rules), \
            patch.object(S, "policy_updates", return_value=updates or {}):
        return S.admit(observation(chain), chain.commit, chain.tree, review=review)


def policy_fixture():
    chain = fixture()
    after = dict(RULES)
    # A payload validator was mistakenly classified as core in this fixture.
    after["protected_paths"] = RULES["protected_paths"] - {"docs/config-transitions.md"}
    path = S.POLICY_V2_PATH
    updates = {path: {"previous_commit": chain.commit,
                     "paths": {"lib/config_transitions.py"}, "after": after}}
    return chain, updates


def append_policy(chain, path=S.POLICY_V2_PATH, mutation=None):
    item = chain.add({"lib/config_transitions.py": blob("reviewed policy correction")}
                     if mutation is None else mutation)
    old_path = item["path"]
    record = json.loads(item["raw"])
    record.update(kind="policy", id=path.split("/")[-2])
    item["path"] = path
    item["raw"] = json.dumps(record, sort_keys=True).encode()
    del item["accepted_tree"][old_path]
    item["accepted_tree"][item["path"]] = ("100644", F.blob_oid(item["raw"]))
    chain.tree = item["accepted_tree"]
    return item


class ConfigTransitionSourceTests(unittest.TestCase):
    def rejects(self, chain, reason=None, review=True):
        with self.assertRaises(F.TransitionError) as caught:
            route(chain, review)
        if reason:
            self.assertEqual(str(caught.exception), reason)

    def test_actual_policy_freezes_authority_and_import_surfaces(self):
        anchor = {"bin/check-existing": blob("check"), "bin/phase5-legacy": blob("legacy"),
                  "tests/test_phase5_existing.py": blob("tests"),
                  "darwin/ordinary.nix": blob("configuration")}
        rules = S.policy(anchor)
        self.assertTrue(S.FIXED <= rules["protected_paths"])
        for path in ("bin/check-existing", "bin/phase5-legacy", "tests/test_phase5_existing.py",
                     "bin/current-doctor", "ARCHITECTURE.md", "AGENTS.md", "README.md",
                     "lib/config_transition_source.py", "lib/config_transition_git.py",
                     "manifests/sessionstart-exposure.json", "tests/test_config_transition_source.py"):
            self.assertIn(path, rules["protected_paths"])
        self.assertNotIn("darwin/ordinary.nix", rules["protected_paths"])
        for prefix in ("lib/", "vendor/", "policy/", "Sources/", "codex/", "skills/"):
            self.assertIn(prefix, rules["protected_prefixes"])
        self.assertEqual(set(rules["allowed_paths"]), {"flake.nix", "flake.lock"})
        self.assertIn("modules/", rules["allowed_prefixes"])
        for path in ("json.py", "sitecustomize.py", ".codex/config.toml"):
            self.assertNotIn(path, rules["allowed_paths"])
            self.assertFalse(path.startswith(rules["allowed_prefixes"]))
        self.assertEqual(set(S.IMPORT_ABSENCES), {"lib/__init__.py", "vendor/__init__.py"})

    def test_v2_boundary_preserves_v1_but_allows_payload_validation(self):
        anchor = {p: blob(p) for p in (
            "bin/check-productivity-baseline", "bin/check-example-payload",
            "bin/check-phase2a", "bin/check-phase4-final-probes", "bin/phase5-preflight")}
        v1, v2 = S.policy(anchor), S.policy_v2(anchor)
        for p in ("bin/check-productivity-baseline", "bin/check-example-payload",
                  *S.PAYLOAD_DOCTORS):
            self.assertIn(p, v1["protected_paths"])
            self.assertNotIn(p, v2["protected_paths"])
        for p in ("bin/check-phase2a", "bin/check-phase4-final-probes", "bin/phase5-preflight",
                  "bin/prepare-productivity-apply", "bin/current-doctor", "ARCHITECTURE.md",
                  "manifests/trusted-repos.json", "lib/config_transition_source.py"):
            self.assertIn(p, v2["protected_paths"])
        self.assertEqual(v1["protected_prefixes"], v2["protected_prefixes"])
        self.assertEqual(S.policy_updates(anchor), {S.POLICY_V2_PATH: {
            "previous_commit": S.POLICY_V2_PREVIOUS, "paths": S.POLICY_V2_PATHS, "after": v2},
            S.SELECTED_REPO_TRUST_PATH: {"previous_commit": S.SELECTED_REPO_TRUST_PREVIOUS,
                "paths": S.SELECTED_REPO_TRUST_PATHS, "after": v2},
            S.WINDOWS_HOST_SKILL_PATH: {"previous_commit": S.WINDOWS_HOST_SKILL_PREVIOUS,
                "paths": S.WINDOWS_HOST_SKILL_PATHS, "after": v2},
            S.FEATURE_NAMES_PATH: {"previous_commit": S.FEATURE_NAMES_PREVIOUS,
                "paths": S.FEATURE_NAMES_PATHS, "after": v2},
            S.CLI_LAYOUT_PATH: {"previous_commit": S.CLI_LAYOUT_PREVIOUS,
                "paths": S.CLI_LAYOUT_PATHS, "after": v2},
            S.CURRENT_DOCTOR_DIAGNOSTICS_PATH: {
                "previous_commit": S.CURRENT_DOCTOR_DIAGNOSTICS_PREVIOUS,
                "paths": S.CURRENT_DOCTOR_DIAGNOSTICS_PATHS, "after": v2},
            S.GLOBAL_HARNESS_PATH: {"previous_commit": S.GLOBAL_HARNESS_PREVIOUS,
                "paths": S.GLOBAL_HARNESS_PATHS, "after": S.global_harness_policy(anchor)},
            S.OWNER_FIRST_WAVE_PATH: {"previous_commit": S.OWNER_FIRST_WAVE_PREVIOUS,
                "paths": S.OWNER_FIRST_WAVE_PATHS, "after": S.owner_first_wave_policy(anchor)},
            S.VENDOR_FIXTURE_CUSTODY_REPAIR_PATH: {
                "previous_commit": S.VENDOR_FIXTURE_CUSTODY_REPAIR_PREVIOUS,
                "paths": S.VENDOR_FIXTURE_CUSTODY_REPAIR_PATHS, "after": S.owner_first_wave_policy(anchor)},
            S.SCHEDULER_DESCRIPTOR_REPAIR_PATH: {
                "previous_commit": S.SCHEDULER_DESCRIPTOR_REPAIR_PREVIOUS,
                "paths": S.SCHEDULER_DESCRIPTOR_REPAIR_PATHS, "after": S.owner_first_wave_policy(anchor)},
            S.PRODUCT_SURFACE_PATH: {
                "previous_commit": S.PRODUCT_SURFACE_PREVIOUS,
                "paths": S.PRODUCT_SURFACE_PATHS, "after": S.owner_first_wave_policy(anchor)},
            S.WINE_ARCHIVE_CHAIN_PATH: {
                "previous_commit": S.WINE_ARCHIVE_CHAIN_PREVIOUS,
                "paths": S.WINE_ARCHIVE_CHAIN_PATHS, "after": S.owner_first_wave_policy(anchor)},
            S.CUSTODY_NAMESPACE_PATH: {
                "previous_commit": S.CUSTODY_NAMESPACE_PREVIOUS,
                "paths": S.CUSTODY_NAMESPACE_PATHS, "after": S.owner_first_wave_policy(anchor)},
            S.SCOPED_READINESS_PATH: {
                "previous_commit": S.SCOPED_READINESS_PREVIOUS,
                "paths": S.SCOPED_READINESS_PATHS, "after": S.owner_first_wave_policy(anchor)},
            S.NATIVE_LAUNCH_PATH: {
                "previous_commit": S.NATIVE_LAUNCH_PREVIOUS,
                "paths": S.NATIVE_LAUNCH_PATHS, "after": S.owner_first_wave_policy(anchor)},
            S.NATIVE_SERVER_ALIAS_PATH: {
                "previous_commit": S.NATIVE_SERVER_ALIAS_PREVIOUS,
                "paths": S.NATIVE_SERVER_ALIAS_PATHS, "after": S.owner_first_wave_policy(anchor)}})

    def test_scoped_readiness_scope_preserves_game_closure_and_authority(self):
        self.assertEqual(S.SCOPED_READINESS_PREVIOUS, 'ab3763f701974c2262a8fb2e579ed426f5bce0dd')
        self.assertEqual(S.SCOPED_READINESS_PATH, 'evidence/config-transitions/scoped-readiness/acceptance.json')
        rules = S.owner_first_wave_policy({})
        self.assertEqual(S.policy_updates({})[S.SCOPED_READINESS_PATH]['after'], rules)
        before = {p: blob(p) for p in rules['protected_paths']}
        before[S.CUSTODY_NAMESPACE_PATH] = blob('immutable custody acceptance')
        candidate = dict(before, **{p: blob('scoped ' + p) for p in S.SCOPED_READINESS_PATHS})
        scope = dict(rules, bootstrap_paths=S.SCOPED_READINESS_PATHS)
        F.validate_candidate(before, candidate, 'policy', **scope)
        for path in ('lib/current_source_checkpoint.py', 'lib/operation_readiness.py',
                     'bin/current-doctor', 'manifests/games-hub.json', 'manifests/trusted-repos.json',
                     'manifests/workstation-guidance-delivery.json'):
            with self.subTest(path=path), self.assertRaisesRegex(F.TransitionError, 'unsupported_bootstrap_surface'):
                F.validate_candidate(before, dict(candidate, **{path: blob('extra')}), 'policy', **scope)
        with self.assertRaisesRegex(F.TransitionError, 'historical_evidence_changed'):
            F.validate_candidate(before, dict(candidate, **{S.CUSTODY_NAMESPACE_PATH: blob('changed')}),
                                 'policy', **scope)

    def test_custody_namespace_scope_preserves_authority_and_prior_evidence(self):
        self.assertEqual(S.CUSTODY_NAMESPACE_PREVIOUS, "f96b6a78f68a58635f018dbca8271ca8981d47a1")
        self.assertEqual(S.CUSTODY_NAMESPACE_PATH, "evidence/config-transitions/custody-namespace/acceptance.json")
        rules = S.owner_first_wave_policy({})
        self.assertEqual(S.policy_updates({})[S.CUSTODY_NAMESPACE_PATH]['after'], rules)
        before = {p: blob(p) for p in rules['protected_paths']}
        before[S.WINE_ARCHIVE_CHAIN_PATH] = blob('immutable wine acceptance')
        candidate = dict(before, **{p: blob('namespace ' + p) for p in S.CUSTODY_NAMESPACE_PATHS})
        scope = dict(rules, bootstrap_paths=S.CUSTODY_NAMESPACE_PATHS)
        F.validate_candidate(before, candidate, 'policy', **scope)
        for path in ('lib/current_source_checkpoint.py', 'lib/operation_readiness.py',
                     'bin/current-doctor', 'ARCHITECTURE.md', 'manifests/trusted-repos.json'):
            with self.subTest(path=path), self.assertRaisesRegex(F.TransitionError, 'unsupported_bootstrap_surface'):
                F.validate_candidate(before, dict(candidate, **{path: blob('extra')}), 'policy', **scope)
        with self.assertRaisesRegex(F.TransitionError, 'historical_evidence_changed'):
            F.validate_candidate(before, dict(candidate, **{S.WINE_ARCHIVE_CHAIN_PATH: blob('changed')}),
                                 'policy', **scope)

    def test_wine_archive_chain_scope_preserves_protected_contract_and_receipts(self):
        self.assertEqual(S.WINE_ARCHIVE_CHAIN_PREVIOUS, "db9629b187e0dbfd2ae0e0deb341249283965717")
        self.assertEqual(S.WINE_ARCHIVE_CHAIN_PATH, "evidence/config-transitions/wine-archive-chain/acceptance.json")
        expected = {"bin/game-launch-reliability-update", "tests/test_game_delivery_order.py",
                    "manifests/games-hub.json", "manifests/wine-runtime-overlay.json", "manifests/wine-runtime-update.json",
                    "lib/config_transition_source.py", "tests/test_config_transition_source.py",
                    "tests/test_current_source_checkpoint.py", "docs/wine-archive-chain-admission.md"}
        self.assertEqual(S.WINE_ARCHIVE_CHAIN_PATHS, expected)
        rules = S.owner_first_wave_policy({})
        self.assertEqual(S.policy_updates({})[S.WINE_ARCHIVE_CHAIN_PATH]['after'], rules)
        self.assertIn('tests/test_game_delivery_order.py', rules['protected_paths'])
        before = {p: blob(p) for p in rules['protected_paths']}
        before[S.PRODUCT_SURFACE_PATH] = blob('immutable prior acceptance')
        candidate = dict(before, **{p: blob('wine chain ' + p) for p in expected})
        scope = dict(rules, bootstrap_paths=expected)
        F.validate_candidate(before, candidate, 'policy', **scope)
        with self.assertRaisesRegex(F.TransitionError, 'protected_policy_changed'):
            F.validate_candidate(before, dict(before, **{'tests/test_game_delivery_order.py': blob('changed')}),
                                 'configuration', **rules)
        for path in ('lib/current_source_checkpoint.py', 'lib/game_delivery_bridge.py', 'bin/current-doctor',
                     'bin/ds3-runtime', 'bin/games-runtime-update', 'manifests/game-launch-reliability.json'):
            with self.subTest(path=path), self.assertRaisesRegex(F.TransitionError, 'unsupported_bootstrap_surface'):
                F.validate_candidate(before, dict(candidate, **{path: blob('extra')}), 'policy', **scope)
        with self.assertRaisesRegex(F.TransitionError, 'historical_evidence_changed'):
            F.validate_candidate(before, dict(candidate, **{S.PRODUCT_SURFACE_PATH: blob('changed')}),
                                 'policy', **scope)

    def test_product_surface_scope_preserves_runtime_and_previous_acceptance(self):
        self.assertEqual(S.PRODUCT_SURFACE_PREVIOUS, "fac9dd5d7925695c7d0a8b5a3f8af536ef71c3dd")
        self.assertEqual(S.PRODUCT_SURFACE_PATH, "evidence/config-transitions/product-surface/acceptance.json")
        expected = {"README.md", "docs/index.md", "docs/usage.md", "docs/installation.md",
                    "docs/recovery.md", "docs/history/index.md", "bin/aid", "tests/test_aid.py", "docs/aid.md",
                    "lib/config_transition_source.py", "tests/test_config_transition_source.py",
                    "tests/test_current_source_checkpoint.py", "tests/test_product_surface.py",
                    "docs/product-surface-admission.md"}
        self.assertEqual(S.PRODUCT_SURFACE_PATHS, expected)
        rules = S.owner_first_wave_policy({})
        self.assertEqual(S.policy_updates({})[S.PRODUCT_SURFACE_PATH]['after'], rules)
        before = {p: blob(p) for p in rules['protected_paths']}
        before[S.SCHEDULER_DESCRIPTOR_REPAIR_PATH] = blob('immutable scheduler receipt')
        candidate = dict(before, **{p: blob('product ' + p) for p in expected})
        scope = dict(rules, bootstrap_paths=expected)
        F.validate_candidate(before, candidate, 'policy', **scope)
        for path in ('lib/current_source_checkpoint.py', 'lib/workstation_maintenance_delivery.py',
                     'manifests/workstation-maintenance.json', 'bin/current-doctor', 'bin/game-launch-reliability-update'):
            with self.subTest(path=path), self.assertRaisesRegex(F.TransitionError, 'unsupported_bootstrap_surface'):
                F.validate_candidate(before, dict(candidate, **{path: blob('extra')}), 'policy', **scope)
        with self.assertRaisesRegex(F.TransitionError, 'historical_evidence_changed'):
            F.validate_candidate(before, dict(candidate, **{S.SCHEDULER_DESCRIPTOR_REPAIR_PATH: blob('changed')}),
                                 'policy', **scope)

    def test_scheduler_descriptor_scope_is_exact_and_keeps_prior_policy(self):
        self.assertEqual(S.SCHEDULER_DESCRIPTOR_REPAIR_PREVIOUS,
                         "6e8d675db89af967e4375e75ef0ab5563e4b9208")
        self.assertEqual(S.SCHEDULER_DESCRIPTOR_REPAIR_PATH,
                         "evidence/config-transitions/scheduler-descriptor-repair/acceptance.json")
        expected = {"lib/workstation_maintenance_delivery.py",
                    "tests/test_workstation_maintenance_delivery.py", "lib/config_transition_source.py",
                    "tests/test_config_transition_source.py", "tests/test_current_source_checkpoint.py",
                    "docs/scheduler-descriptor-repair.md"}
        self.assertEqual(S.SCHEDULER_DESCRIPTOR_REPAIR_PATHS, expected)
        rules = S.owner_first_wave_policy({})
        self.assertEqual(S.policy_updates({})[S.SCHEDULER_DESCRIPTOR_REPAIR_PATH]['after'], rules)
        before = {p: blob(p) for p in rules['protected_paths']}
        before[S.VENDOR_FIXTURE_CUSTODY_REPAIR_PATH] = blob('immutable prior receipt')
        candidate = dict(before, **{p: blob('repair ' + p) for p in expected})
        scope = dict(rules, bootstrap_paths=expected)
        F.validate_candidate(before, candidate, 'policy', **scope)
        for path in ('lib/current_source_checkpoint.py', 'lib/vendor_fixture_custody.py',
                     'manifests/workstation-maintenance.json', 'bin/current-doctor',
                     'bin/game-launch-reliability-update', 'tests/test_game_delivery_order.py'):
            with self.subTest(path=path), self.assertRaisesRegex(F.TransitionError, 'unsupported_bootstrap_surface'):
                F.validate_candidate(before, dict(candidate, **{path: blob('extra')}), 'policy', **scope)
        with self.assertRaisesRegex(F.TransitionError, 'historical_evidence_changed'):
            F.validate_candidate(before, dict(candidate, **{S.VENDOR_FIXTURE_CUSTODY_REPAIR_PATH: blob('changed')}),
                                 'policy', **scope)

    def test_fixture_custody_correction_is_exact_without_reopening_wave(self):
        self.assertEqual(S.VENDOR_FIXTURE_CUSTODY_REPAIR_PREVIOUS,
                         "207e8f3fa2acfc70a588337ef129fb9a91699b1e")
        self.assertEqual(S.VENDOR_FIXTURE_CUSTODY_REPAIR_PATH,
                         "evidence/config-transitions/vendor-fixture-custody-repair/acceptance.json")
        expected = {"lib/vendor_fixture_custody.py", "lib/vendor_compatibility_probe.py",
                    "tests/test_vendor_fixture_custody.py", "tests/test_vendor_compatibility_probe.py",
                    "lib/config_transition_source.py", "tests/test_config_transition_source.py",
                    "tests/test_current_source_checkpoint.py", "docs/vendor-fixture-custody-repair.md"}
        self.assertEqual(S.VENDOR_FIXTURE_CUSTODY_REPAIR_PATHS, expected)
        rules = S.owner_first_wave_policy({})
        self.assertEqual(S.policy_updates({})[S.VENDOR_FIXTURE_CUSTODY_REPAIR_PATH]['after'], rules)
        self.assertEqual(len(S.OWNER_FIRST_WAVE_PATHS), 180)
        before = {p: blob(p) for p in rules['protected_paths']}
        before[S.OWNER_FIRST_WAVE_PATH] = blob('immutable accepted wave')
        candidate = dict(before, **{p: blob('repair ' + p) for p in expected})
        preview = dict(rules, bootstrap_paths=expected)
        F.validate_candidate(before, candidate, 'policy', **preview)
        for path in ('lib/current_source_checkpoint.py', 'bin/current-doctor',
                     'policy/aid-admin-policy.json', 'lib/vendor_fixture_custody_extra.py'):
            with self.subTest(path=path), self.assertRaisesRegex(F.TransitionError, 'unsupported_bootstrap_surface'):
                F.validate_candidate(before, dict(candidate, **{path: blob('extra')}), 'policy', **preview)
        with self.assertRaisesRegex(F.TransitionError, 'historical_evidence_changed'):
            F.validate_candidate(before, dict(candidate, **{S.OWNER_FIRST_WAVE_PATH: blob('replayed')}), 'policy', **preview)

    def test_fresh_combined_wave_has_no_sibling_checkpoint_dependency(self):
        self.assertEqual(S.OWNER_FIRST_WAVE_PREVIOUS,
                         "94e0e1999c208aaf4112b611bbfa5c8b65111419")
        updates = S.policy_updates({})
        self.assertNotIn("evidence/config-transitions/owner-first-delivery/acceptance.json", updates)
        self.assertFalse(any(u["previous_commit"] == "849a241f9592e1faf3b9a2a9dc2107d6b93ac46a"
                             for u in updates.values()))
        self.assertLessEqual(S.OWNER_FIRST_WAVE_DELIVERY_PATHS, S.OWNER_FIRST_WAVE_PATHS)
        self.assertLessEqual(S.OWNER_FIRST_WAVE_DELIVERY_PROTECTED,
                             S.owner_first_wave_policy({})["protected_paths"])
        self.assertIn("manifests/windows-host-ssh-client.json", S.OWNER_FIRST_WAVE_PATHS)
        self.assertNotIn(S.OWNER_FIRST_WAVE_PATH, S.OWNER_FIRST_WAVE_PATHS)
        self.assertNotIn("lib/current_source_checkpoint.py", S.OWNER_FIRST_WAVE_DELIVERY_PATHS)
        for ordinary in ("bin/ds3-runtime", "bin/games-runtime-update", "bin/wine-runtime-overlay",
                         "docs/wine-runtime-overlay.md", "manifests/wine-runtime-update.schema.json"):
            self.assertIn(ordinary, S.OWNER_FIRST_WAVE_PATHS)
            self.assertNotIn(ordinary, S.OWNER_FIRST_WAVE_DELIVERY_PROTECTED)

    def test_combined_scope_rejects_unregistered_source_and_historical_evidence_edits(self):
        old = S.global_harness_policy({})
        before = {p: blob(p) for p in old["protected_paths"]}
        before["evidence/previous.json"] = blob("immutable")
        rules = dict(old, bootstrap_paths=S.OWNER_FIRST_WAVE_PATHS)
        candidate = dict(before, **{p: blob("combined " + p) for p in S.OWNER_FIRST_WAVE_PATHS})
        F.validate_candidate(before, candidate, "policy", **rules)
        with self.assertRaisesRegex(F.TransitionError, "unsupported_bootstrap_surface"):
            F.validate_candidate(before, dict(candidate, **{"lib/unregistered.py": blob("extra")}), "policy", **rules)
        with self.assertRaisesRegex(F.TransitionError, "historical_evidence_changed"):
            F.validate_candidate(before, dict(candidate, **{"evidence/previous.json": blob("changed")}), "policy", **rules)

    def test_guidance_delivery_scope_and_authority_boundary_are_exact(self):
        expected = {"bin/workstation-guidance-delivery", "lib/workstation_guidance_delivery.py",
                    "tests/test_workstation_guidance_delivery.py",
                    "manifests/workstation-guidance-delivery.json", "docs/workstation-guidance-delivery.md"}
        observed = {p for p in S.OWNER_FIRST_WAVE_PATHS
                    if "workstation-guidance-delivery" in p or "workstation_guidance_delivery" in p}
        self.assertEqual(observed, expected)
        old, after = S.global_harness_policy({}), S.owner_first_wave_policy({})
        for path in expected:
            self.assertTrue(path in after["protected_paths"] or path.startswith(after["protected_prefixes"]))
        before = {p: blob(p) for p in old["protected_paths"]}
        candidate = dict(before, **{p: blob("guidance " + p) for p in expected})
        rules = dict(old, bootstrap_paths=S.OWNER_FIRST_WAVE_PATHS)
        F.validate_candidate(before, candidate, "policy", **rules)
        for outside in ("bin/workstation-guidance-delivery-extra", "lib/workstation_guidance_delivery_extra.py",
                        "manifests/workstation-guidance-delivery-extra.json", "skills/unrelated/SKILL.md"):
            with self.subTest(path=outside), self.assertRaisesRegex(F.TransitionError, "unsupported_bootstrap_surface"):
                F.validate_candidate(before, dict(candidate, **{outside: blob("outside")}), "policy", **rules)

    def test_current_doctor_diagnostics_registry_is_exact_and_keeps_v2(self):
        self.assertEqual(S.CURRENT_DOCTOR_DIAGNOSTICS_PREVIOUS,
                         "8ac981e93c4720c9f4725315632ff1b7f2e05b76")
        self.assertEqual(S.CURRENT_DOCTOR_DIAGNOSTICS_PATH,
                         "evidence/config-transitions/current-doctor-diagnostics/acceptance.json")
        self.assertEqual(S.CURRENT_DOCTOR_DIAGNOSTICS_PATHS, {
            "lib/config_transition_source.py", "tests/test_config_transition_source.py",
            "tests/test_config_transition_repository.py", "docs/reviewed-config-transitions.md",
            "bin/current-doctor", "tests/test_current_doctor.py",
            "docs/post-phase5-sentinel-admission.md", "lib/vendor_compatibility_probe.py",
            "tests/test_vendor_compatibility_probe.py", "docs/post-phase5-sentinel.md",
            "bin/system-revision-status", "tests/test_system_revision_status.py"})
        rules = S.policy_v2({})
        self.assertEqual(S.policy_updates({})[S.CURRENT_DOCTOR_DIAGNOSTICS_PATH]["after"], rules)
        for path in ("bin/current-doctor", "tests/test_current_doctor.py",
                     "docs/post-phase5-sentinel-admission.md", "docs/post-phase5-sentinel.md",
                     "lib/config_transition_source.py", "tests/test_config_transition_source.py",
                     "tests/test_config_transition_repository.py", "docs/reviewed-config-transitions.md",
                     "tests/test_vendor_compatibility_probe.py"):
            self.assertIn(path, rules["protected_paths"])
        self.assertIn("lib/", rules["protected_prefixes"])
        for path in ("bin/system-revision-status", "tests/test_system_revision_status.py"):
            self.assertNotIn(path, rules["protected_paths"])
        for path in ("lib/config_transitions.py", "lib/config_transition_git.py",
                     "lib/vendor_compatibility_policy.py", "bin/phase5-current-doctor",
                     "codex/hooks/phase5-contract.py", "manifests/trusted-repos.json",
                     "policy/aid-admin-policy.json", "ARCHITECTURE.md"):
            self.assertNotIn(path, S.CURRENT_DOCTOR_DIAGNOSTICS_PATHS)

    def test_cli_layout_repair_is_exact_and_keeps_v2(self):
        self.assertEqual(S.CLI_LAYOUT_PREVIOUS, "0e0576966e53295f929de0eba7be3567b366ad52")
        self.assertEqual(S.CLI_LAYOUT_PATH, "evidence/config-transitions/vendor-cli-layout/acceptance.json")
        self.assertEqual(S.CLI_LAYOUT_PATHS, {
            "lib/config_transition_source.py", "tests/test_config_transition_source.py",
            "lib/vendor_compatibility_probe.py", "tests/test_vendor_compatibility_probe.py",
            "docs/reviewed-config-transitions.md"})
        self.assertEqual(S.policy_updates({})[S.CLI_LAYOUT_PATH]["after"], S.policy_v2({}))

    def test_feature_names_repair_is_exact_and_keeps_v2(self):
        self.assertEqual(S.FEATURE_NAMES_PREVIOUS, "6a7b560e8b81af03b5ed685cf761e7b695878618")
        self.assertEqual(S.FEATURE_NAMES_PATH, "evidence/config-transitions/feature-names/acceptance.json")
        self.assertEqual(S.FEATURE_NAMES_PATHS, {
            "lib/config_transition_source.py", "tests/test_config_transition_source.py",
            "lib/vendor_compatibility_policy.py", "tests/test_vendor_compatibility_policy.py",
            "docs/reviewed-config-transitions.md", "tests/test_current_doctor.py"})
        self.assertEqual(S.policy_updates({})[S.FEATURE_NAMES_PATH]["after"], S.policy_v2({}))
        for path in ("bin/current-doctor", "lib/vendor_compatibility_probe.py",
                     "lib/config_transitions.py", "manifests/trusted-repos.json",
                     "codex/hooks/phase5-contract.py", "policy/root.json"):
            self.assertNotIn(path, S.FEATURE_NAMES_PATHS)

    def test_windows_skill_registry_is_exact_and_preserves_protection(self):
        self.assertEqual(S.WINDOWS_HOST_SKILL_PREVIOUS, "a44faa509993ee6df841e31d0cba97e20e1ae4c9")
        self.assertEqual(S.WINDOWS_HOST_SKILL_PATH,
                         "evidence/config-transitions/windows-host-skill/acceptance.json")
        self.assertEqual(S.WINDOWS_HOST_SKILL_PATHS, {
            "lib/config_transition_source.py", "tests/test_config_transition_source.py",
            "tests/test_config_transition_repository.py", "docs/reviewed-config-transitions.md",
            "skills/manage-windows-host/SKILL.md", "manifests/windows-host-skill.json",
            "docs/windows-host-skill.md", "docs/maintenance.md", "bin/windows-host-skill",
            "tests/test_windows_host_skill.py"})
        rules = S.policy_v2({})
        self.assertEqual(S.policy_updates({})[S.WINDOWS_HOST_SKILL_PATH]["after"], rules)
        self.assertIn("skills/", rules["protected_prefixes"])
        for path in ("skills/manage-workstation/SKILL.md", "skills/manage-windows-host/extra.md",
                     "codex/hooks/phase5-contract.py", "manifests/trusted-repos.json",
                     "lib/config_transitions.py", "ARCHITECTURE.md", "bin/current-doctor"):
            self.assertNotIn(path, S.WINDOWS_HOST_SKILL_PATHS)

    def test_selected_trust_registry_is_exact_and_keeps_v2_rules(self):
        self.assertEqual(S.SELECTED_REPO_TRUST_PREVIOUS, "9faf4aa1ce5132a9e799ccd9bf4ea005a14a6818")
        self.assertEqual(S.SELECTED_REPO_TRUST_PATH,
                         "evidence/config-transitions/selected-repo-trust/acceptance.json")
        self.assertEqual(S.SELECTED_REPO_TRUST_PATHS, {
            "ARCHITECTURE.md", "README.md", "docs/reviewed-config-transitions.md",
            "docs/repo-trust-adoption.md", "manifests/trusted-repos.json",
            "lib/config_transition_source.py", "tests/test_config_transition_source.py",
            "tests/test_config_transition_repository.py", "bin/check-repo-trust", "tests/test_repo_trust.py"})
        rules = S.policy_v2({})
        self.assertEqual(S.policy_updates({})[S.SELECTED_REPO_TRUST_PATH]["after"], rules)
        self.assertIn("manifests/trusted-repos.json", rules["protected_paths"])
        for path in ("codex/hooks/phase5-contract.py", "manifests/trusted-repos.schema.json",
                     "manifests/codex-contract.json", "lib/config_transitions.py", "bin/current-doctor"):
            self.assertNotIn(path, S.SELECTED_REPO_TRUST_PATHS)

    def test_exact_policy_preview_is_preparation_only_and_narrow(self):
        chain, updates = policy_fixture()
        chain.append_tail({"lib/config_transitions.py": blob("reviewed repair")})
        self.assertFalse(route(chain, True, updates)["accepted"])
        with self.assertRaisesRegex(F.TransitionError, "unreviewed_main_source"):
            route(chain, False, updates)
        for p in ("bin/current-doctor", "darwin/also-change-setting.nix", "lib/__init__.py"):
            bad, updates = policy_fixture()
            bad.append_tail({p: blob("outside repair")})
            with self.subTest(path=p), self.assertRaises(F.TransitionError):
                route(bad, True, updates)

    def test_policy_only_changes_rules_after_verified_acceptance(self):
        chain, updates = policy_fixture()
        append_policy(chain)
        self.assertTrue(route(chain, False, updates)["accepted"])
        chain.add({"docs/config-transitions.md": blob("now mutable payload validator")})
        self.assertTrue(route(chain, False, updates)["accepted"])
        chain.append_tail({"docs/config-transitions.md": blob("next prepared revision")})
        self.assertFalse(route(chain, True, updates)["accepted"])
        chain.append_tail({"lib/config_transitions.py": blob("unapproved engine update")})
        with self.assertRaises(F.TransitionError):
            route(chain, True, updates)

    def test_v2_cannot_reinterpret_old_segment_or_accept_unknown_policy(self):
        chain, updates = policy_fixture()
        chain.add({"docs/config-transitions.md": blob("still protected before policy")})
        with self.assertRaises(F.TransitionError):
            route(chain, False, updates)
        chain, updates = policy_fixture()
        append_policy(chain)
        with self.assertRaises(F.TransitionError):
            route(chain, False)
        with self.assertRaises(F.TransitionError):
            route(chain, False, {S.POLICY_V2_PATH: dict(updates[S.POLICY_V2_PATH],
                previous_commit=oid("wrong predecessor"))})

    def test_policy_preview_does_not_hide_temporary_out_of_scope_change(self):
        chain, updates = policy_fixture()
        original = chain.tree["bin/current-doctor"]
        chain.append_tail({"bin/current-doctor": blob("temporary corruption")})
        chain.append_tail({"bin/current-doctor": original,
                           "lib/config_transitions.py": blob("otherwise valid repair")})
        with self.assertRaises(F.TransitionError):
            route(chain, True, updates)

    def test_historical_anchor_is_not_configuration_transition_acceptance(self):
        result = route(fixture(False))
        self.assertIs(result["accepted"], False)
        self.assertTrue(set(S.IMPORT_ABSENCES) <= set(result["absent"]))

    def test_accepted_chain_is_not_apply_or_installed_authority(self):
        result = route(fixture())
        self.assertIs(result["accepted"], True)
        self.assertEqual(set(result), {"accepted", "absent"})
        self.assertNotIn("apply_authorized", result)
        self.assertNotIn("installed_state_verified", result)

    def test_pending_source_allowed_only_on_review_branch(self):
        chain = fixture()
        chain.append_tail({"modules/new-package.nix": blob("ordinary package")})
        self.assertIs(route(chain, True)["accepted"], False)
        self.rejects(chain, "unreviewed_main_source", review=False)

    def test_bootstrap_can_add_policy_in_separate_commits(self):
        chain = fixture(False)
        chain.append_tail({"docs/intent.md": blob("bootstrap intent")})
        chain.append_tail({"lib/config_transitions.py": blob("engine"),
                           "docs/config-transitions.md": blob("contract")})
        self.assertIs(route(chain, True)["accepted"], False)
        self.rejects(chain, "unreviewed_main_source", review=False)

    def test_incomplete_bootstrap_fails_closed(self):
        chain = fixture(False)
        chain.append_tail({"docs/intent.md": blob("intent only")})
        self.rejects(chain, "protected_policy_missing")

    def test_evidence_tail_is_unaccepted_even_when_file_is_json(self):
        chain = fixture()
        chain.append_tail({"evidence/after/fresh.json": blob("observation")})
        chain.append_tail({"evidence/after/fresh-two.json": blob("second observation")})
        self.rejects(chain, "unreviewed_main_source", review=False)
        self.assertIs(route(chain, True)["accepted"], False)

    def test_evidence_tail_does_not_hide_later_unreviewed_source(self):
        chain = fixture()
        chain.append_tail({"evidence/after/fresh.json": blob("observation")})
        chain.append_tail({"modules/unreviewed.nix": blob("source")})
        self.rejects(chain, "unreviewed_main_source", review=False)
        self.assertIs(route(chain, True)["accepted"], False)

    def test_protected_import_root_and_historical_evidence_mutations_rejected(self):
        for path in ("lib/config_transitions.py", "lib/__init__.py", "vendor/__init__.py",
                     "bin/current-doctor", "docs/config-transitions.md", "json.py",
                     "evidence/history/acceptance.json"):
            with self.subTest(path=path):
                chain = fixture()
                chain.append_tail({path: blob("changed")})
                self.rejects(chain)

    def test_temporary_protected_or_evidence_rewrite_cannot_be_restored_away(self):
        for path in ("lib/config_transitions.py", "bin/current-doctor",
                     "evidence/history/acceptance.json"):
            with self.subTest(path=path):
                chain = fixture()
                original = chain.tree[path]
                chain.append_tail({path: blob("temporary invalid state")})
                chain.append_tail({path: original, "modules/normal.nix": blob("ordinary change")})
                self.rejects(chain)

    def test_bootstrap_cannot_rewrite_historical_evidence(self):
        chain = fixture(False)
        original = chain.tree["evidence/history/acceptance.json"]
        chain.append_tail({"evidence/history/acceptance.json": blob("rewritten")})
        chain.append_tail({"evidence/history/acceptance.json": original,
                           "lib/config_transitions.py": blob("engine"),
                           "docs/config-transitions.md": blob("contract")})
        self.rejects(chain, "historical_evidence_changed")

    def test_accepted_and_pending_deletion_hold_nearest_missing_subtree(self):
        chain = fixture()
        chain.add({"modules/removed/sub/config.nix": blob("to remove"),
                   "modules/retained/old.nix": blob("to remove beside sibling"),
                   "modules/retained/keep.nix": blob("keep")})
        chain.add({"modules/removed/sub/config.nix": None,
                   "modules/retained/old.nix": None})
        result = route(chain)
        self.assertIn("modules/removed", result["absent"])
        self.assertIn("modules/retained/old.nix", result["absent"])
        self.assertNotIn("modules/removed/sub/config.nix", result["absent"])
        chain.append_tail({"modules/retained/keep.nix": None})
        result = route(chain, True)
        self.assertIn("modules", result["absent"])
        self.assertNotIn("modules/retained/keep.nix", result["absent"])

    def test_pending_created_then_deleted_source_is_held_absent(self):
        chain = fixture()
        chain.append_tail({"modules/transient/deep.nix": blob("temporary reviewed source")})
        chain.append_tail({"modules/transient/deep.nix": None})
        self.assertIn("modules", route(chain, True)["absent"])

    def test_bootstrap_import_initializer_cannot_be_claimed_current(self):
        chain = fixture(False)
        chain.append_tail({"lib/config_transitions.py": blob("engine"),
                           "docs/config-transitions.md": blob("contract"),
                           "lib/__init__.py": blob("import injection")})
        self.rejects(chain, "unsupported_bootstrap_surface")

    def test_script_directory_import_shadows_rejected_but_helpers_remain_usable(self):
        for path in ("bin/secrets.py", "bin/secrets/__init__.py", "bin/selectors.pyc",
                     "bin/plistlib.cpython-312-darwin.so", "bin/JSON.PY"):
            chain = fixture()
            chain.add({path: blob("import shadow")})
            self.rejects(chain, "script_directory_import_shadow")
            chain = fixture()
            chain.append_tail({path: blob("pending import shadow")})
            self.rejects(chain, "script_directory_import_shadow")
        chain = fixture()
        chain.add({"bin/ordinary-check": blob("#!/usr/bin/python3\n", "100755")})
        self.assertTrue(route(chain)["accepted"])

    def test_actual_bootstrap_policy_excludes_old_engines_broker_hooks_and_payloads(self):
        rules = S.policy({})
        for path in ("bin/phase5-current-readiness", "policy/aid-admin-policy.json",
                     "codex/hooks.json", "darwin/unrelated.nix"):
            self.assertNotIn(path, rules["bootstrap_paths"])
        self.assertEqual(rules["coordinator"], S.COORDINATOR)

    def test_regular_file_replacing_old_directory_is_held_instead_of_impossible_absent_child(self):
        chain = fixture()
        chain.add({"modules/old/deep.nix": blob("old nested module")})
        chain.add({"modules/old/deep.nix": None, "modules/old": blob("regular source")})
        self.assertNotIn("modules/old/deep.nix", route(chain)["absent"])

    def test_source_observation_and_current_tree_binding(self):
        chain = fixture()
        for review in (1, None, "yes"):
            with self.subTest(review=review):
                self.rejects(chain, "invalid_source_observation", review=review)
        for key in ("anchorTree", "acceptedCommit", "acceptedTree"):
            broken = copy.deepcopy(observation(chain))
            if key == "acceptedCommit":
                broken[key] = oid("wrong accepted")
            else:
                broken[key]["darwin/ghost.nix"] = blob("ghost")
            with self.subTest(key=key), patch.object(S, "policy", return_value=RULES):
                with self.assertRaises(F.TransitionError):
                    S.admit(broken, chain.commit, chain.tree, review=True)
        chain.tree = dict(chain.tree)
        chain.tree["darwin/unknown.nix"] = blob("unknown")
        self.rejects(chain, "unreviewed_current_source")

    def test_falsy_invalid_pending_collections_rejected(self):
        chain = fixture()
        for value in ({}, "", None, False, 0):
            with self.subTest(value=value), patch.object(S, "policy", return_value=RULES):
                broken = observation(chain)
                broken["pendingCommits"] = value
                with self.assertRaises(F.TransitionError):
                    S.admit(broken, chain.commit, chain.tree, review=False)

    def test_pending_chain_rejects_missing_merge_wrong_and_repeated_ancestors(self):
        for mutation in (
                lambda rows: rows[1].update({"parents": [oid("wrong")]}),
                lambda rows: rows[1]["parents"].append(oid("merge")),
                lambda rows: rows[1].update({"commit": "not-a-git-oid"}),
                lambda rows: rows[1].update({"commit": rows[0]["parents"][0]})):
            with self.subTest(mutation=mutation):
                chain = fixture()
                chain.append_tail({"modules/first.nix": blob("first")})
                chain.append_tail({"modules/second.nix": blob("second")})
                chain.append_tail({"modules/third.nix": blob("third")})
                mutation(chain.tail)
                chain.tail[2]["parents"] = [chain.tail[1]["commit"]]
                self.rejects(chain)


class SelectedTrustSourceTests(unittest.TestCase):
    REGISTRY = "manifests/trusted-repos.json"
    HOOK = "codex/hooks/phase5-contract.py"

    def fixture(self):
        chain = fixture(False)
        chain.anchor_tree.update({self.REGISTRY: blob("original control-only registry"),
                                  self.HOOK: blob("unchanged router")})
        chain.tree = dict(chain.anchor_tree)
        chain.add()
        rules = dict(RULES, protected_paths=RULES["protected_paths"] | {self.REGISTRY})
        v2 = dict(rules, protected_paths=rules["protected_paths"] - {"docs/config-transitions.md"})
        updates = {S.POLICY_V2_PATH: {"previous_commit": chain.commit,
            "paths": {"lib/config_transitions.py"}, "after": v2}}
        append_policy(chain)
        chain.add({"darwin/github-cli.nix": blob("owner-authorized gh package")})
        updates[S.SELECTED_REPO_TRUST_PATH] = {"previous_commit": chain.commit,
            "paths": S.SELECTED_REPO_TRUST_PATHS, "after": v2}
        return chain, rules, updates

    def accept(self, chain):
        return append_policy(chain, S.SELECTED_REPO_TRUST_PATH,
                             {self.REGISTRY: blob("control plus exact selected roots")})

    def test_v2_then_ordinary_package_then_exact_trust_delta(self):
        chain, rules, updates = self.fixture()
        historical = chain.tree["evidence/history/acceptance.json"]
        hook = chain.tree[self.HOOK]
        self.accept(chain)
        self.assertEqual(len(chain.transitions), 4)
        result = route(chain, updates=updates, rules=rules)
        self.assertIs(result["accepted"], True)
        self.assertEqual(chain.tree[self.HOOK], hook)
        self.assertEqual(chain.tree["evidence/history/acceptance.json"], historical)
        self.assertEqual(updates[S.SELECTED_REPO_TRUST_PATH]["after"], updates[S.POLICY_V2_PATH]["after"])

    def test_trust_preview_is_scoped_unaccepted_and_never_main(self):
        chain, rules, updates = self.fixture()
        chain.append_tail({self.REGISTRY: blob("exact selected root additions")})
        self.assertIs(route(chain, True, updates, rules)["accepted"], False)
        with self.assertRaisesRegex(F.TransitionError, "unreviewed_main_source"):
            route(chain, False, updates, rules)

    def test_later_ordinary_registry_edits_stay_protected(self):
        chain, rules, updates = self.fixture()
        self.accept(chain)
        chain.add({self.REGISTRY: blob("another unapproved repository")})
        with self.assertRaisesRegex(F.TransitionError, "protected_policy_changed"):
            route(chain, updates=updates, rules=rules)

    def test_wrong_trust_predecessor_and_unknown_receipt_rejected(self):
        chain, rules, updates = self.fixture()
        self.accept(chain)
        for altered in (
                {S.POLICY_V2_PATH: updates[S.POLICY_V2_PATH]},
                dict(updates, **{S.SELECTED_REPO_TRUST_PATH: dict(
                    updates[S.SELECTED_REPO_TRUST_PATH], previous_commit=oid("wrong predecessor"))})):
            with self.subTest(registry=tuple(altered)), self.assertRaises(F.TransitionError):
                route(chain, updates=altered, rules=rules)

    def test_selected_policy_replay_rejected(self):
        chain, rules, updates = self.fixture()
        self.accept(chain)
        self.accept(chain)
        with self.assertRaisesRegex(F.TransitionError, "replayed_policy_transition"):
            route(chain, updates=updates, rules=rules)

    def test_forbidden_hook_or_old_evidence_restore_cannot_hide_in_preview(self):
        for path in (self.HOOK, "evidence/history/acceptance.json", "lib/config_transitions.py"):
            chain, rules, updates = self.fixture()
            original = chain.tree[path]
            chain.append_tail({path: blob("forbidden temporary mutation")})
            chain.append_tail({path: original, self.REGISTRY: blob("selected roots")})
            with self.subTest(path=path), self.assertRaises(F.TransitionError):
                route(chain, True, updates, rules)


class WindowsHostSkillSourceTests(unittest.TestCase):
    SKILL = "skills/manage-windows-host/SKILL.md"
    FORBIDDEN = ("skills/manage-workstation/SKILL.md", "skills/other/SKILL.md",
                 "skills/manage-windows-host/extra.md", "codex/hooks/phase5-contract.py",
                 "manifests/trusted-repos.json", "policy/aid-admin-policy.json",
                 "lib/config_transitions.py")

    def fixture(self):
        trust = SelectedTrustSourceTests()
        chain, rules, updates = trust.fixture()
        trust.accept(chain)
        # Exercise the actual protected namespace boundary in the synthetic
        # chain while retaining its deliberately small bootstrap path fixture.
        rules["protected_prefixes"] = S.PROTECTED_PREFIXES
        for update in updates.values():
            update["after"]["protected_prefixes"] = S.PROTECTED_PREFIXES
        updates[S.WINDOWS_HOST_SKILL_PATH] = {"previous_commit": chain.commit,
            "paths": S.WINDOWS_HOST_SKILL_PATHS,
            "after": dict(updates[S.SELECTED_REPO_TRUST_PATH]["after"])}
        return chain, rules, updates

    def accept(self, chain, extra=None):
        return append_policy(chain, S.WINDOWS_HOST_SKILL_PATH,
                             {self.SKILL: blob("reviewed Windows host guidance"), **(extra or {})})

    def test_third_policy_adds_only_exact_skill_and_keeps_v2(self):
        chain, rules, updates = self.fixture()
        historical = dict(chain.tree)
        self.accept(chain)
        self.assertIs(route(chain, updates=updates, rules=rules)["accepted"], True)
        self.assertEqual(len(chain.transitions), 5)
        self.assertEqual(updates[S.WINDOWS_HOST_SKILL_PATH]["after"],
                         updates[S.POLICY_V2_PATH]["after"])
        for path in ("evidence/history/acceptance.json", "codex/hooks/phase5-contract.py",
                     "manifests/trusted-repos.json", "lib/config_transitions.py"):
            self.assertEqual(chain.tree[path], historical[path])
        chain.add({"docs/ordinary-next-payload.md": blob("ordinary reviewed update")})
        self.assertIs(route(chain, updates=updates, rules=rules)["accepted"], True)

    def test_exact_windows_preview_is_unaccepted_and_not_main(self):
        chain, rules, updates = self.fixture()
        chain.append_tail({self.SKILL: blob("candidate guidance")})
        self.assertIs(route(chain, True, updates, rules)["accepted"], False)
        with self.assertRaisesRegex(F.TransitionError, "unreviewed_main_source"):
            route(chain, False, updates, rules)

    def test_windows_policy_and_preview_reject_other_authority_paths(self):
        for path in self.FORBIDDEN:
            for preview in (False, True):
                chain, rules, updates = self.fixture()
                if preview:
                    chain.append_tail({self.SKILL: blob("guidance"), path: blob("forbidden")})
                else:
                    self.accept(chain, {path: blob("forbidden")})
                with self.subTest(path=path, preview=preview), self.assertRaisesRegex(
                        F.TransitionError, "unsupported_bootstrap_surface"):
                    route(chain, preview, updates, rules)

    def test_windows_policy_rejects_restored_intermediate_authority_drift(self):
        for path in self.FORBIDDEN:
            chain, rules, updates = self.fixture()
            before = chain.tree.get(path)
            chain.append_tail({path: blob("temporary forbidden mutation")})
            chain.append_tail({path: before, self.SKILL: blob("otherwise valid guidance")})
            with self.subTest(path=path), self.assertRaisesRegex(
                    F.TransitionError, "unsupported_bootstrap_surface"):
                route(chain, True, updates, rules)

    def test_later_skill_hooks_and_trust_edits_remain_protected(self):
        for path in (self.SKILL, *self.FORBIDDEN):
            chain, rules, updates = self.fixture()
            self.accept(chain)
            chain.add({path: blob("unapproved ordinary edit")})
            with self.subTest(path=path), self.assertRaises(F.TransitionError):
                route(chain, updates=updates, rules=rules)

    def test_windows_wrong_predecessor_unknown_receipt_and_replay_rejected(self):
        chain, rules, updates = self.fixture()
        self.accept(chain)
        wrong = copy.deepcopy(updates)
        wrong[S.WINDOWS_HOST_SKILL_PATH]["previous_commit"] = oid("wrong predecessor")
        with self.assertRaisesRegex(F.TransitionError, "policy_predecessor_mismatch"):
            route(chain, updates=wrong, rules=rules)
        unknown = {path: value for path, value in updates.items() if path != S.WINDOWS_HOST_SKILL_PATH}
        with self.assertRaisesRegex(F.TransitionError, "unregistered_policy_transition"):
            route(chain, updates=unknown, rules=rules)
        self.accept(chain)
        with self.assertRaisesRegex(F.TransitionError, "replayed_policy_transition"):
            route(chain, updates=updates, rules=rules)


class CliLayoutSourceTests(unittest.TestCase):
    TARGET = "lib/vendor_compatibility_probe.py"

    def fixture(self):
        chain = fixture()
        updates = {S.CLI_LAYOUT_PATH: {"previous_commit": chain.commit,
            "paths": S.CLI_LAYOUT_PATHS, "after": dict(RULES)}}
        return chain, updates

    def accept(self, chain):
        return append_policy(chain, S.CLI_LAYOUT_PATH,
                             {self.TARGET: blob("reviewed direct native CLI")})

    def test_exact_repair_preserves_protection_after_acceptance(self):
        chain, updates = self.fixture()
        self.accept(chain)
        self.assertIs(route(chain, updates=updates)["accepted"], True)
        chain.add({self.TARGET: blob("unapproved later change")})
        with self.assertRaises(F.TransitionError):
            route(chain, updates=updates)

    def test_review_preview_is_not_main_acceptance(self):
        chain, updates = self.fixture()
        chain.append_tail({self.TARGET: blob("candidate direct binary path")})
        self.assertIs(route(chain, True, updates)["accepted"], False)
        with self.assertRaisesRegex(F.TransitionError, "unreviewed_main_source"):
            route(chain, False, updates)

    def test_wrong_predecessor_unknown_registration_and_replay_reject(self):
        chain, updates = self.fixture()
        self.accept(chain)
        wrong = copy.deepcopy(updates)
        wrong[S.CLI_LAYOUT_PATH]["previous_commit"] = oid("wrong predecessor")
        with self.assertRaisesRegex(F.TransitionError, "policy_predecessor_mismatch"):
            route(chain, updates=wrong)
        with self.assertRaisesRegex(F.TransitionError, "unregistered_policy_transition"):
            route(chain)
        self.accept(chain)
        with self.assertRaisesRegex(F.TransitionError, "replayed_policy_transition"):
            route(chain, updates=updates)

    def test_restored_out_of_scope_intermediate_change_rejects(self):
        for path in ("lib/config_transitions.py", "bin/current-doctor",
                     "codex/hooks/phase5-contract.py", "manifests/trusted-repos.json"):
            chain, updates = self.fixture()
            original = chain.tree.get(path)
            chain.append_tail({path: blob("temporary forbidden change")})
            chain.append_tail({path: original, self.TARGET: blob("candidate native path")})
            with self.subTest(path=path), self.assertRaises(F.TransitionError):
                route(chain, True, updates)


class CurrentDoctorDiagnosticsSourceTests(unittest.TestCase):
    DOCTOR = "bin/current-doctor"
    PROBE = "lib/vendor_compatibility_probe.py"
    PAYLOAD_CONSUMERS = {"bin/system-revision-status", "tests/test_system_revision_status.py"}
    FORBIDDEN = ("lib/config_transitions.py", "lib/config_transition_git.py",
                 "lib/vendor_compatibility_policy.py", "bin/phase5-current-doctor",
                 "codex/hooks/phase5-contract.py", "manifests/trusted-repos.json",
                 "policy/aid-admin-policy.json")

    def fixture(self):
        chain = fixture(False)
        for path in S.CURRENT_DOCTOR_DIAGNOSTICS_PATHS | set(self.FORBIDDEN):
            chain.anchor_tree.setdefault(path, blob("historical " + path))
        chain.tree = dict(chain.anchor_tree)
        chain.add()
        rules = dict(RULES, protected_prefixes=S.PROTECTED_PREFIXES,
                     protected_paths=RULES["protected_paths"] |
                     (S.CURRENT_DOCTOR_DIAGNOSTICS_PATHS - self.PAYLOAD_CONSUMERS))
        updates = {S.CURRENT_DOCTOR_DIAGNOSTICS_PATH: {
            "previous_commit": chain.commit, "paths": S.CURRENT_DOCTOR_DIAGNOSTICS_PATHS,
            "after": dict(rules)}}
        return chain, rules, updates

    def accept(self, chain, extra=None):
        return append_policy(chain, S.CURRENT_DOCTOR_DIAGNOSTICS_PATH, {
            self.DOCTOR: blob("reviewed fixture binding", "100755"),
            self.PROBE: blob("bounded diagnostic reasons"), **(extra or {})})

    def test_exact_review_preview_is_unaccepted_and_not_main(self):
        chain, rules, updates = self.fixture()
        chain.append_tail({p: blob("reviewed candidate " + p)
                           for p in S.CURRENT_DOCTOR_DIAGNOSTICS_PATHS})
        self.assertIs(route(chain, True, updates, rules)["accepted"], False)
        with self.assertRaisesRegex(F.TransitionError, "unreviewed_main_source"):
            route(chain, False, updates, rules)
        wrong = copy.deepcopy(updates)
        wrong[S.CURRENT_DOCTOR_DIAGNOSTICS_PATH]["previous_commit"] = oid("wrong predecessor")
        with self.assertRaisesRegex(F.TransitionError, "protected_policy_changed"):
            route(chain, True, wrong, rules)

    def test_acceptance_preserves_history_and_does_not_relax_later_protection(self):
        chain, rules, updates = self.fixture()
        before = dict(chain.tree)
        self.accept(chain)
        self.assertIs(route(chain, updates=updates, rules=rules)["accepted"], True)
        self.assertEqual(updates[S.CURRENT_DOCTOR_DIAGNOSTICS_PATH]["after"], rules)
        for path in (*self.FORBIDDEN, "evidence/history/acceptance.json"):
            self.assertEqual(chain.tree[path], before[path])
        accepted = copy.deepcopy(chain)
        for path in S.CURRENT_DOCTOR_DIAGNOSTICS_PATHS - self.PAYLOAD_CONSUMERS:
            bad = copy.deepcopy(accepted)
            bad.add({path: blob("unapproved later change")})
            with self.subTest(path=path), self.assertRaisesRegex(
                    F.TransitionError, "protected_policy_changed"):
                route(bad, updates=updates, rules=rules)

    def test_wrong_predecessor_unknown_registration_and_replay_reject(self):
        chain, rules, updates = self.fixture()
        self.accept(chain)
        wrong = copy.deepcopy(updates)
        wrong[S.CURRENT_DOCTOR_DIAGNOSTICS_PATH]["previous_commit"] = oid("wrong predecessor")
        with self.assertRaisesRegex(F.TransitionError, "policy_predecessor_mismatch"):
            route(chain, updates=wrong, rules=rules)
        with self.assertRaisesRegex(F.TransitionError, "unregistered_policy_transition"):
            route(chain, rules=rules)
        self.accept(chain)
        with self.assertRaisesRegex(F.TransitionError, "replayed_policy_transition"):
            route(chain, updates=updates, rules=rules)

    def test_unexpected_protected_and_restored_intermediate_changes_reject(self):
        for path in (*self.FORBIDDEN, "evidence/history/acceptance.json"):
            chain, rules, updates = self.fixture()
            self.accept(chain, {path: blob("unexpected protected mutation")})
            with self.subTest(path=path, accepted=True), self.assertRaises(F.TransitionError):
                route(chain, updates=updates, rules=rules)
            chain, rules, updates = self.fixture()
            original = chain.tree[path]
            chain.append_tail({path: blob("temporary forbidden change")})
            chain.append_tail({path: original, self.DOCTOR: blob("candidate fixture repair")})
            with self.subTest(path=path, accepted=False), self.assertRaises(F.TransitionError):
                route(chain, True, updates, rules)


class GlobalHarnessSourceTests(unittest.TestCase):
    TARGET = "codex/hooks/phase5-contract.py"
    FORBIDDEN = ("lib/config_transitions.py", "bin/phase5-current-doctor",
                 "manifests/trusted-repos.json", "policy/aid-admin-policy.json")

    def fixture(self):
        chain = fixture(False)
        for path in S.GLOBAL_HARNESS_PATHS | set(self.FORBIDDEN):
            chain.anchor_tree.setdefault(path, blob("historical " + path))
        chain.tree = dict(chain.anchor_tree)
        chain.add()
        rules = dict(RULES, protected_prefixes=S.PROTECTED_PREFIXES,
                     protected_paths=RULES["protected_paths"] | S.GLOBAL_HARNESS_PATHS
                     | set(self.FORBIDDEN))
        updates = {S.GLOBAL_HARNESS_PATH: {
            "previous_commit": chain.commit, "paths": S.GLOBAL_HARNESS_PATHS,
            "after": dict(rules)}}
        return chain, rules, updates

    def accept(self, chain):
        return append_policy(chain, S.GLOBAL_HARNESS_PATH,
                             {self.TARGET: blob("nonblocking startup context")})

    def test_exact_preview_is_not_main_acceptance(self):
        chain, rules, updates = self.fixture()
        chain.append_tail({p: blob("candidate " + p) for p in S.GLOBAL_HARNESS_PATHS})
        self.assertIs(route(chain, True, updates, rules)["accepted"], False)
        with self.assertRaisesRegex(F.TransitionError, "unreviewed_main_source"):
            route(chain, False, updates, rules)

    def test_acceptance_preserves_protection(self):
        chain, rules, updates = self.fixture()
        self.accept(chain)
        self.assertIs(route(chain, updates=updates, rules=rules)["accepted"], True)
        for path in (*S.GLOBAL_HARNESS_PATHS, *self.FORBIDDEN):
            bad = copy.deepcopy(chain)
            bad.add({path: blob("unapproved later edit")})
            with self.subTest(path=path), self.assertRaises(F.TransitionError):
                route(bad, updates=updates, rules=rules)

    def test_wrong_predecessor_unknown_registration_and_replay_reject(self):
        chain, rules, updates = self.fixture()
        self.accept(chain)
        wrong = copy.deepcopy(updates)
        wrong[S.GLOBAL_HARNESS_PATH]["previous_commit"] = oid("wrong predecessor")
        with self.assertRaisesRegex(F.TransitionError, "policy_predecessor_mismatch"):
            route(chain, updates=wrong, rules=rules)
        with self.assertRaisesRegex(F.TransitionError, "unregistered_policy_transition"):
            route(chain, rules=rules)
        self.accept(chain)
        with self.assertRaisesRegex(F.TransitionError, "replayed_policy_transition"):
            route(chain, updates=updates, rules=rules)

    def test_restored_out_of_scope_intermediate_edit_rejects(self):
        for path in (*self.FORBIDDEN, "evidence/history/acceptance.json"):
            chain, rules, updates = self.fixture()
            original = chain.tree[path]
            chain.append_tail({path: blob("temporary forbidden edit")})
            chain.append_tail({path: original, self.TARGET: blob("startup fix")})
            with self.subTest(path=path), self.assertRaises(F.TransitionError):
                route(chain, True, updates, rules)

    def test_production_registration_keeps_v2_boundary(self):
        self.assertEqual(S.GLOBAL_HARNESS_PREVIOUS,
                         "60daf6e2a82b818630acbe3282ca507fb99b7013")
        update = S.policy_updates({})[S.GLOBAL_HARNESS_PATH]
        expected = S.policy_v2({})
        self.assertNotIn("tests/test_project_context_boundary.py", expected["protected_paths"])
        self.assertNotIn("tests/test_project_context_boundary.py", S.policy({})["protected_paths"])
        expected["protected_paths"] |= {
            "tests/test_project_context_boundary.py", "bin/system-revision-status",
            "tests/test_system_revision_status.py", "tests/test_current_source_admission.py",
            "tests/test_current_source_doctor.py", "tests/test_prepare_productivity_apply.py",
            "docs/current-source-admission.md", "docs/harness-operations.md"}
        self.assertEqual(update["after"], expected)
        self.assertIn("tests/test_project_context_boundary.py",
                      update["after"]["protected_paths"])
        self.assertNotIn("manifests/trusted-repos.json", update["paths"])


class OwnerFirstWaveSourceTests(unittest.TestCase):
    RETIRED = frozenset((
        "Sources/AidAdminCore/RecoveryReceipt.swift", "bin/root-operation-recovery-observe",
        "lib/root_operation_recovery.py", "tests/test_root_operation_recovery.py",
    ))

    def fixture(self):
        chain = fixture(False)
        before = S.global_harness_policy(chain.anchor_tree)
        for path in before["protected_paths"]:
            chain.anchor_tree.setdefault(path, blob("historical " + path))
        chain.tree = dict(chain.anchor_tree)
        chain.add()
        # Keep the synthetic bootstrap contract while using the real production
        # before/after protection, exact delta list, and policy selector.
        before = dict(before, bootstrap_paths=RULES["bootstrap_paths"], coordinator=COORDINATOR)
        after = dict(S.owner_first_wave_policy(chain.anchor_tree),
                     bootstrap_paths=RULES["bootstrap_paths"], coordinator=COORDINATOR)
        updates = {S.OWNER_FIRST_WAVE_PATH: {"previous_commit": chain.commit,
                   "paths": S.OWNER_FIRST_WAVE_PATHS, "after": after}}
        return chain, before, updates

    def accept(self, chain):
        return append_policy(chain, S.OWNER_FIRST_WAVE_PATH,
            {path: blob("reviewed wave " + path) for path in S.OWNER_FIRST_WAVE_PATHS - self.RETIRED})

    def test_fixed_registration_and_monotonic_successor_protection(self):
        self.assertEqual(S.OWNER_FIRST_WAVE_PREVIOUS,
                         "94e0e1999c208aaf4112b611bbfa5c8b65111419")
        self.assertEqual(S.OWNER_FIRST_WAVE_PATH,
                         "evidence/config-transitions/owner-first-harness-wave/acceptance.json")
        before, after = S.global_harness_policy({}), S.owner_first_wave_policy({})
        self.assertLessEqual(before["protected_paths"], after["protected_paths"])
        self.assertEqual(before["protected_prefixes"], after["protected_prefixes"])
        self.assertEqual(before["allowed_paths"], after["allowed_paths"])
        self.assertEqual(before["allowed_prefixes"], after["allowed_prefixes"])
        for path in ("bin/aid-harness-offramp", "manifests/harness-hook-retirement.json",
                     "tests/test_current_source_checkpoint.py", "tests/test_operation_readiness.py",
                     "tests/test_harness_offramp.py", "tests/test_project_context_boundary.py",
                     "tests/test_aid.py", "tests/test_sessionstart_exposure.py",
                     "tests/test_prepared_receipt.py", "tests/test_root_resume_module_guards.py",
                     "tests/test_root_bundle_successor.py",
                     "tests/AidAdminResumeHomeManagerTests/AidAdminResumeHomeManagerTests.swift",
                     "tests/AidAdminResumeLaunchdTests/AidAdminResumeLaunchdTests.swift",
                     "manifests/workstation-maintenance.json",
                     "bin/workstation-maintenance-cycle", "tests/test_workstation_maintenance_cycle.py",
                     "tests/test_workstation_maintenance_delivery.py",
                     "tests/test_vendor_fixture_custody.py",
                     "manifests/quarantine-boundary-successor.json",
                     "tests/test_quarantine_boundary_successor.py",
                     "tests/fixtures/phase5-quarantine-before-current-cli.zsh",
                     "tests/fixtures/phase5-quarantine-before-temp-deny.config.toml",
                     "docs/post-phase5-sentinel.md",
                     "docs/current-source-admission.md", "docs/operation-readiness.md",
                     "docs/harness-operations.md", "docs/wave-offramp.md"):
            with self.subTest(path=path):
                self.assertIn(path, S.OWNER_FIRST_WAVE_PATHS)
                self.assertIn(path, after["protected_paths"])
        for path in ("darwin/productivity.nix", "manifests/productivity-baseline.json",
                     "bin/productivity-doctor", "bin/check-productivity-baseline",
                     "bin/games-play", "bin/cs2-play", "bin/game-app-launchers",
                     "docs/wave-games.md", "docs/wave-owner-freedom.md",
                     "docs/wave-recovery-coverage.md", "bin/workstation-drift-snapshot",
                     "docs/maintenance.md"):
            self.assertNotIn(path, after["protected_paths"])
        self.assertIn("lib/", after["protected_prefixes"])
        for path in ("Sources/AidAdminCore/ResumeLaunchd.swift",
                     "Sources/AidAdminCore/ResumeHomeManager.swift",
                     "lib/workstation_maintenance_delivery.py", "lib/vendor_fixture_custody.py"):
            self.assertIn(path, S.OWNER_FIRST_WAVE_PATHS)
            self.assertTrue(path.startswith(after["protected_prefixes"]))
        for path in ("manifests/game-launch-reliability.json", "manifests/games-hub.json",
                     "manifests/wine-runtime-overlay.json", "manifests/wine-runtime-update.json",
                     "bin/wine-runtime-overlay", "docs/wine-runtime-overlay.md",
                     "manifests/wine-runtime-overlay.schema.json",
                     "manifests/wine-runtime-update.schema.json",
                     "tests/test_ds3_window_repair.py", "tests/test_wine_runtime_extended.py",
                     "darwin/windows-app.nix", "darwin/rustdesk-controller.nix"):
            self.assertIn(path, S.OWNER_FIRST_WAVE_PATHS)
            self.assertNotIn(path, after["protected_paths"])
            self.assertFalse(path.startswith(after["protected_prefixes"]))
        self.assertLessEqual(self.RETIRED, S.OWNER_FIRST_WAVE_PATHS)
        self.assertFalse(self.RETIRED & after["protected_paths"])
        for path in ("policy/aid-admin-policy.json", "manifests/trusted-repos.json",
                     S.OWNER_FIRST_WAVE_PATH, "evidence/history/acceptance.json"):
            self.assertNotIn(path, S.OWNER_FIRST_WAVE_PATHS)

    def test_preview_remains_unaccepted_and_independent_receipt_required(self):
        chain, before, updates = self.fixture()
        chain.append_tail({path: blob("candidate " + path) for path in S.OWNER_FIRST_WAVE_PATHS})
        self.assertFalse(route(chain, True, updates, before)["accepted"])
        with self.assertRaisesRegex(F.TransitionError, "unreviewed_main_source"):
            route(chain, False, updates, before)

    def test_wave_acceptance_preserves_history_and_payload_freedom(self):
        chain, before, updates = self.fixture()
        history = chain.tree["evidence/history/acceptance.json"]
        self.accept(chain)
        self.assertTrue(route(chain, updates=updates, rules=before)["accepted"])
        self.assertEqual(chain.tree["evidence/history/acceptance.json"], history)
        chain.add({"manifests/productivity-baseline.json": blob("next reviewed preferences"),
                   "bin/games-play": blob("ordinary payload wrapper update"),
                   "docs/wave-games.md": blob("descriptive evidence update")})
        self.assertTrue(route(chain, updates=updates, rules=before)["accepted"])

    def test_new_protected_temporary_edit_restore_cannot_evade_after_rules(self):
        chain, before, updates = self.fixture()
        self.accept(chain)
        for path in sorted(S.OWNER_FIRST_WAVE_PROTECTED - before["protected_paths"]):
            bad = copy.deepcopy(chain)
            original = bad.tree[path]
            bad.append_tail({path: blob("temporary unreviewed authority")})
            bad.append_tail({path: original})
            self.assertEqual(bad.tree, chain.tree)
            with self.subTest(path=path), self.assertRaisesRegex(
                    F.TransitionError, "protected_policy_changed"):
                route(bad, True, updates, before)

    def test_retired_scaffold_history_requires_scope_but_not_final_presence(self):
        chain, before, updates = self.fixture()
        item = self.accept(chain)
        first = item["candidate_commits"][0]["tree"]
        first.update({path: blob("intermediate scaffold " + path) for path in self.RETIRED})
        self.assertFalse(self.RETIRED & chain.tree.keys())
        self.assertTrue(route(chain, updates=updates, rules=before)["accepted"])
        endpoint_only = copy.deepcopy(updates)
        endpoint_only[S.OWNER_FIRST_WAVE_PATH]["paths"] -= self.RETIRED
        with self.assertRaisesRegex(F.TransitionError, "unsupported_bootstrap_surface"):
            route(chain, updates=endpoint_only, rules=before)

    def test_wrong_predecessor_and_unregistered_wave_reject(self):
        chain, before, updates = self.fixture()
        self.accept(chain)
        wrong = copy.deepcopy(updates)
        wrong[S.OWNER_FIRST_WAVE_PATH]["previous_commit"] = oid("wrong predecessor")
        with self.assertRaisesRegex(F.TransitionError, "policy_predecessor_mismatch"):
            route(chain, updates=wrong, rules=before)
        with self.assertRaisesRegex(F.TransitionError, "unregistered_policy_transition"):
            route(chain, rules=before)



class NativeLaunchAdmissionScope(unittest.TestCase):
    def test_actual_post_checkpoint_edges_match_the_exact_registration(self):
        import subprocess
        root = Path(__file__).resolve().parents[1]
        def git(*args):
            return subprocess.check_output(['git', '-C', str(root), *args])
        def tree(commit):
            result = {}
            for row in git('ls-tree', '-rz', commit).split(b'\0'):
                if row:
                    meta, name = row.split(b'\t', 1)
                    mode, kind, identity = meta.decode().split(' ')
                    self.assertEqual(kind, 'blob')
                    result[name.decode()] = (mode, identity)
            return result
        tip = '96db584aa8a6f90630941e09e1a033883cfcafae'
        before = tree(S.NATIVE_LAUNCH_PREVIOUS)
        rules = S.owner_first_wave_policy(before)
        paths = set()
        rows = git('rev-list', '--reverse', '--parents', S.NATIVE_LAUNCH_PREVIOUS + '..' + tip).decode().splitlines()
        self.assertEqual(len(rows), 7)
        for row in rows:
            commit, parent = row.split()
            old, new = tree(parent), tree(commit)
            paths.update(F.delta(old, new))
            F.validate_candidate(old, new, 'policy', **dict(rules, bootstrap_paths=S.NATIVE_LAUNCH_PATHS))
            S.import_scope(old, new)
        self.assertEqual(paths | {'lib/config_transition_source.py', 'tests/test_config_transition_source.py',
                                 'docs/native-launch-source-admission.md', 'tests/test_ds3_virtual_fullscreen.py'}, S.NATIVE_LAUNCH_PATHS)
        with self.assertRaisesRegex(F.TransitionError, 'protected_policy_changed'):
            F.validate_candidate(tree('64fdb5d1fc98b4d97ff1943c49650ff977f586b8'), tree(tip), 'configuration', **rules)

    def test_exact_registered_transition_preserves_all_successor_rules(self):
        expected = {
            'bin/cs2-play',
            'bin/ds3-runtime',
            'bin/game-launch-admission',
            'bin/game-native-admission-plan',
            'bin/game-native-admission-update',
            'bin/games-play',
            'bin/rustdesk-ssh-tunnel',
            'docs/ds3-native-renderer.md',
            'docs/game-native-launch-admission.md',
            'docs/native-launch-source-admission.md',
            'docs/rustdesk-ssh-tunnel.md',
            'lib/config_transition_source.py',
            'lib/game_launch_native/BUILD.md',
            'lib/game_launch_native/README.md',
            'lib/game_launch_native/binding/native_launch_binding.py',
            'lib/game_launch_native/native-identity/native_identity.py',
            'lib/game_launch_native/native-identity/prefix_identity.py',
            'lib/game_launch_native/native-identity/prefix_probe.c',
            'lib/game_launch_native/native-identity/probe.c',
            'lib/game_native_admission_assets.py',
            'lib/game_native_admission_bridge.py',
            'lib/game_native_admission_capability.py',
            'lib/game_native_admission_transaction.py',
            'manifests/ds3-renderer-update.json',
            'manifests/game-native-launch-admission.json',
            'manifests/rustdesk-ssh-tunnel.json',
            'manifests/wine-runtime-update.json',
            'tests/test_config_transition_source.py',
            'tests/test_ds3_native_renderer.py',
            'tests/test_ds3_virtual_fullscreen.py',
            'tests/test_game_native_admission_assets.py',
            'tests/test_game_native_admission_bridge.py',
            'tests/test_game_native_admission_capability.py',
            'tests/test_game_native_admission_transaction.py',
            'tests/test_game_native_admission_update.py',
            'tests/test_native_admission.py',
            'tests/test_native_admission_layout.py',
            'tests/test_native_admission_plan.py',
            'tests/test_rustdesk_ssh_tunnel.py',
}
        self.assertEqual(S.NATIVE_LAUNCH_PREVIOUS, "a0bd1e9af3d1bf2ba5426762ede54b4bee3e4445")
        self.assertEqual(S.NATIVE_LAUNCH_PATH, "evidence/config-transitions/native-launch-admission/acceptance.json")
        self.assertEqual(S.NATIVE_LAUNCH_PATHS, expected)
        rules = S.owner_first_wave_policy({})
        registration = S.policy_updates({})[S.NATIVE_LAUNCH_PATH]
        self.assertEqual(registration, {'previous_commit': S.NATIVE_LAUNCH_PREVIOUS, 'paths': expected, 'after': rules})
        before = {p: blob(p) for p in rules['protected_paths']}
        candidate = dict(before, **{p: blob('native source ' + p) for p in expected})
        F.validate_candidate(before, candidate, 'policy', **dict(rules, bootstrap_paths=expected))
        with self.assertRaisesRegex(F.TransitionError, 'protected_policy_changed'):
            F.validate_candidate(before, candidate, 'configuration', **rules)
        for path in ('lib/operation_readiness.py', 'bin/current-doctor', 'lib/current_source_checkpoint.py', 'policy/root.json', 'skills/unrelated/SKILL.md'):
            with self.subTest(path=path), self.assertRaisesRegex(F.TransitionError, 'unsupported_bootstrap_surface'):
                F.validate_candidate(before, dict(candidate, **{path: blob('unrelated')}), 'policy', **dict(rules, bootstrap_paths=expected))
        for path in ('lib/game_native_admission_transaction.py', 'lib/game_launch_native/binding/native_launch_binding.py'):
            with self.subTest(future_path=path), self.assertRaisesRegex(F.TransitionError, 'protected_policy_changed'):
                F.validate_candidate(candidate, dict(candidate, **{path: blob('later ordinary edit')}), 'configuration', **rules)


class NativeServerAliasScope(unittest.TestCase):
    def test_exact_transition_keeps_successor_protection(self):
        expected = {
            'bin/cs2-play',
            'bin/ds3-runtime',
            'bin/game-launch-admission',
            'bin/game-native-admission-plan',
            'bin/game-native-admission-update',
            'bin/games-play',
            'docs/game-native-launch-admission.md',
            'lib/config_transition_source.py',
            'lib/game_launch_native/binding/native_launch_binding.py',
            'lib/game_native_admission_assets.py',
            'lib/game_native_admission_bridge.py',
            'lib/game_native_admission_transaction.py',
            'manifests/game-native-launch-admission.json',
            'manifests/wine-runtime-update.json',
            'tests/test_config_transition_source.py',
            'tests/test_game_native_admission_assets.py',
            'tests/test_game_native_admission_bridge.py',
            'tests/test_game_native_admission_update.py',
            'tests/test_native_admission.py',
            'tests/test_native_admission_layout.py',
            'tests/test_native_admission_plan.py',
        }
        self.assertEqual(len(expected), 21)
        self.assertEqual(S.NATIVE_SERVER_ALIAS_PREVIOUS, '46e3a690096b6f89f2ca09a23e8c9e668fb6bbc0')
        self.assertEqual(S.NATIVE_SERVER_ALIAS_PATH, 'evidence/config-transitions/native-server-alias/acceptance.json')
        self.assertEqual(S.NATIVE_SERVER_ALIAS_PATHS, expected)
        rules = S.owner_first_wave_policy({})
        self.assertEqual(S.policy_updates({})[S.NATIVE_SERVER_ALIAS_PATH],
                         {'previous_commit': S.NATIVE_SERVER_ALIAS_PREVIOUS, 'paths': expected, 'after': rules})
        before = {p: blob(p) for p in rules['protected_paths']}
        after = dict(before, **{p: blob('successor ' + p) for p in expected})
        F.validate_candidate(before, after, 'policy', **dict(rules, bootstrap_paths=expected))
        with self.assertRaisesRegex(F.TransitionError, 'protected_policy_changed'):
            F.validate_candidate(before, after, 'configuration', **rules)
        for path in ('lib/operation_readiness.py', 'lib/current_source_checkpoint.py', 'bin/current-doctor', 'policy/root.json'):
            with self.subTest(path=path), self.assertRaisesRegex(F.TransitionError, 'unsupported_bootstrap_surface'):
                F.validate_candidate(before, dict(after, **{path: blob('unrelated')}), 'policy', **dict(rules, bootstrap_paths=expected))
        with self.assertRaisesRegex(F.TransitionError, 'protected_policy_changed'):
            F.validate_candidate(after, dict(after, **{'lib/game_native_admission_bridge.py': blob('later edit')}), 'configuration', **rules)


if __name__ == "__main__":
    unittest.main()
