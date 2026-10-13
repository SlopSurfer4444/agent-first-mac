"""Trusted configuration-admission policy and pure current-source routing.

Historical verifiers still consume real anchor trees. This module only admits
source membership; it never grants execution, installed convergence or trust.
"""
from lib import config_transitions as F

ANCHOR = "85ccc9a36bf5fc235002ef7681dc69f21803bd04"
PROTECTED_PREFIXES = ("lib/", "vendor/", "policy/", "Sources/", "install-bundles/",
                      "codex/", "skills/")
ALLOWED_PREFIXES = ("darwin/", "modules/", "manifests/", "bin/", "docs/", "tests/")
FIXED = frozenset((
    ".gitignore", "AGENTS.md", "ARCHITECTURE.md", "README.md", "Package.swift",
    "bin/current-doctor", "bin/aid-sessionstart", "bin/codex-quarantine",
    "bin/phase2-doctor", "bin/prepare-productivity-apply",
    "bin/prepare-phase4-build-only-target", "bin/amnezia-desktop-doctor",
    "bin/productivity-doctor", "bin/rustdesk-mac-controller-doctor",
    "bin/tailscale-windows-host-doctor", "bin/windows-app-rdp-client-doctor",
    "manifests/codex-contract.json", "manifests/phase5-apply-bundle.json",
    "manifests/phase5-trusted-probe.json", "manifests/sessionstart-exposure.json",
    "manifests/trusted-repos.json", "manifests/trusted-repos.schema.json",
    "docs/phase-5-current-doctor.md", "docs/phase-5-current-integration-sources.md",
    "docs/post-phase5-sentinel.md", "docs/post-phase5-sentinel-admission.md",
    "docs/vendor-sentinel-sessionstart.md", "docs/vendor-sentinel-sessionstart-admission.md",
    "docs/reviewed-config-transitions.md", "tests/test_current_doctor.py",
    "tests/test_current_doctor_native.py", "tests/test_vendor_compatibility_policy.py",
    "tests/test_vendor_compatibility_probe.py", "tests/test_config_transitions.py",
    "tests/test_config_transition_source.py", "tests/test_config_transition_git.py",
    "tests/test_config_transition_repository.py",
    "lib/config_transitions.py", "lib/config_transition_source.py", "lib/config_transition_git.py",
))
EXISTING_PREFIXES = ("bin/check-", "bin/phase3-", "bin/phase4-", "bin/phase5-",
                     "bin/build-phase4-", "tests/test_phase5_", "tests/AidAdmin",
                     "tests/fixtures/phase5-")
IMPORT_ABSENCES = ("lib/__init__.py", "vendor/__init__.py")
BOOTSTRAP_PATHS = frozenset((
    "AGENTS.md", "ARCHITECTURE.md", "README.md", "bin/current-doctor",
    "tests/test_current_doctor.py", "docs/reviewed-config-transitions.md",
    "lib/config_transitions.py", "lib/config_transition_source.py", "lib/config_transition_git.py",
    "tests/test_config_transitions.py", "tests/test_config_transition_source.py",
    "tests/test_config_transition_git.py", "tests/test_config_transition_repository.py",
))
COORDINATOR = {"name": "Agent-First Mac Coordinator", "email": "coordinator@agent-first-mac.invalid"}
# V1 is deliberately retained above: historical receipts must keep their
# original policy. The sole reviewed V2 upgrade is selected by trusted source,
# never by rule fields supplied in a receipt.
POLICY_V2_PREVIOUS = "85304696c4bf1c35a76c70361850f2e9ccbd4a1a"
POLICY_V2_PATH = "evidence/config-transitions/payload-policy-v2/acceptance.json"
POLICY_V2_PATHS = frozenset((
    "ARCHITECTURE.md", "docs/reviewed-config-transitions.md",
    "lib/config_transitions.py", "lib/config_transition_source.py",
    "tests/test_config_transitions.py", "tests/test_config_transition_source.py",
    "tests/test_config_transition_repository.py",
))
# This owner-authorized trust addition is an exact, one-time policy delta.
# It does not relax V2 protection or admit later repository registrations.
SELECTED_REPO_TRUST_PREVIOUS = "9faf4aa1ce5132a9e799ccd9bf4ea005a14a6818"
SELECTED_REPO_TRUST_PATH = "evidence/config-transitions/selected-repo-trust/acceptance.json"
SELECTED_REPO_TRUST_PATHS = frozenset((
    "ARCHITECTURE.md", "README.md", "docs/reviewed-config-transitions.md",
    "docs/repo-trust-adoption.md", "manifests/trusted-repos.json",
    "lib/config_transition_source.py", "tests/test_config_transition_source.py",
    "tests/test_config_transition_repository.py", "bin/check-repo-trust", "tests/test_repo_trust.py",
))
# The Windows-host guidance is a single owner-authorized skills exception.
# Its acceptance retains the complete V2 policy, including the skills prefix.
WINDOWS_HOST_SKILL_PREVIOUS = "a44faa509993ee6df841e31d0cba97e20e1ae4c9"
WINDOWS_HOST_SKILL_PATH = "evidence/config-transitions/windows-host-skill/acceptance.json"
WINDOWS_HOST_SKILL_PATHS = frozenset((
    "lib/config_transition_source.py", "tests/test_config_transition_source.py",
    "tests/test_config_transition_repository.py", "docs/reviewed-config-transitions.md",
    "skills/manage-windows-host/SKILL.md", "manifests/windows-host-skill.json",
    "docs/windows-host-skill.md", "docs/maintenance.md", "bin/windows-host-skill",
    "tests/test_windows_host_skill.py",
))
FEATURE_NAMES_PREVIOUS = "6a7b560e8b81af03b5ed685cf761e7b695878618"
FEATURE_NAMES_PATH = "evidence/config-transitions/feature-names/acceptance.json"
FEATURE_NAMES_PATHS = frozenset((
    "lib/config_transition_source.py", "tests/test_config_transition_source.py",
    "lib/vendor_compatibility_policy.py", "tests/test_vendor_compatibility_policy.py",
    "docs/reviewed-config-transitions.md", "tests/test_current_doctor.py",
))
# Owner-authorized repair for the signed app's nested native CLI layout.
# This grants no lasting exception to the protected vendor/admission sources.
CLI_LAYOUT_PREVIOUS = "0e0576966e53295f929de0eba7be3567b366ad52"
CLI_LAYOUT_PATH = "evidence/config-transitions/vendor-cli-layout/acceptance.json"
CLI_LAYOUT_PATHS = frozenset((
    "lib/config_transition_source.py", "tests/test_config_transition_source.py",
    "lib/vendor_compatibility_probe.py", "tests/test_vendor_compatibility_probe.py",
    "docs/reviewed-config-transitions.md",
))
# A single owner-authorized source-fixture and bounded diagnostic repair.
# This does not make doctor or compatibility sources ordinary mutable payloads.
CURRENT_DOCTOR_DIAGNOSTICS_PREVIOUS = "8ac981e93c4720c9f4725315632ff1b7f2e05b76"
CURRENT_DOCTOR_DIAGNOSTICS_PATH = "evidence/config-transitions/current-doctor-diagnostics/acceptance.json"
CURRENT_DOCTOR_DIAGNOSTICS_PATHS = frozenset((
    "lib/config_transition_source.py", "tests/test_config_transition_source.py",
    "tests/test_config_transition_repository.py", "docs/reviewed-config-transitions.md",
    "bin/current-doctor", "tests/test_current_doctor.py",
    "docs/post-phase5-sentinel-admission.md", "lib/vendor_compatibility_probe.py",
    "tests/test_vendor_compatibility_probe.py", "docs/post-phase5-sentinel.md",
    "bin/system-revision-status", "tests/test_system_revision_status.py",
))
# One explicit global simplification successor; no permanent exception for
# protected hook/admission changes or grant of native trust.
GLOBAL_HARNESS_PREVIOUS = "60daf6e2a82b818630acbe3282ca507fb99b7013"
GLOBAL_HARNESS_PATH = "evidence/config-transitions/global-harness-simplification/acceptance.json"
GLOBAL_HARNESS_PATHS = frozenset((
    'AGENTS.md',
    'manifests/harness-simplification.json',
    'tests/test_current_doctor.py',
    'ARCHITECTURE.md',
    'README.md',
    'docs/reviewed-config-transitions.md',
    'docs/project-context-boundary.md',
    'docs/current-source-admission.md',
    'docs/harness-operations.md',
    'docs/history/control-agent-routing-before-simplification.md',
    'skills/manage-workstation/SKILL.md',
    'codex/hooks/phase5-contract.py',
    'tests/test_repo_trust.py',
    'tests/test_project_context_boundary.py',
    'lib/config_transition_source.py',
    'tests/test_config_transition_source.py',
    'bin/current-doctor',
    'lib/current_doctor_native.py',
    'lib/current_source_admission.py',
    'bin/prepare-productivity-apply',
    'bin/system-revision-status',
    'bin/productivity-doctor',
    'bin/amnezia-desktop-doctor',
    'bin/tailscale-windows-host-doctor',
    'tests/test_system_revision_status.py',
    'tests/test_component_revision_status.py',
    'tests/test_amnezia_revision_status.py',
    'tests/test_amnezia_absent.py',
    'tests/test_current_source_admission.py',
    'tests/test_current_source_doctor.py',
    'tests/test_prepare_productivity_apply.py',
))
# Payload doctors report the current reviewed manifest; they are not source
# admission, broker or trust authorities. Their July versions are history,
# not a permanent constraint on future reviewed app versions/preferences.
PAYLOAD_DOCTORS = frozenset((
    "bin/amnezia-desktop-doctor", "bin/productivity-doctor",
    "bin/rustdesk-mac-controller-doctor", "bin/tailscale-windows-host-doctor",
    "bin/windows-app-rdp-client-doctor",
))
V2_EXISTING_PREFIXES = ("bin/check-phase", *EXISTING_PREFIXES[1:])


def policy(anchor):
    """Only trusted code and the fixed anchor select protection, never a receipt."""
    return {"protected_paths": FIXED | {p for p in anchor if p.startswith(EXISTING_PREFIXES)},
            "protected_prefixes": PROTECTED_PREFIXES,
            "allowed_paths": ("flake.nix", "flake.lock"), "allowed_prefixes": ALLOWED_PREFIXES,
            "bootstrap_paths": BOOTSTRAP_PATHS, "coordinator": COORDINATOR}


def policy_v2(anchor):
    rules = dict(policy(anchor))
    rules["protected_paths"] = ((FIXED - PAYLOAD_DOCTORS)
                                | {p for p in anchor if p.startswith(V2_EXISTING_PREFIXES)})
    return rules


def global_harness_policy(anchor):
    # Introduced only at this successor: earlier accepted trees do not contain
    # this test and must not retroactively require it.
    rules = dict(policy_v2(anchor))
    rules["protected_paths"] = rules["protected_paths"] | {
        "tests/test_project_context_boundary.py", "bin/system-revision-status",
        "tests/test_system_revision_status.py", "tests/test_current_source_admission.py",
        "tests/test_current_source_doctor.py", "tests/test_prepare_productivity_apply.py",
        "docs/current-source-admission.md", "docs/harness-operations.md"}
    return rules


def policy_updates(anchor):
    return {POLICY_V2_PATH: {"previous_commit": POLICY_V2_PREVIOUS,
                            "paths": POLICY_V2_PATHS, "after": policy_v2(anchor)},
            SELECTED_REPO_TRUST_PATH: {"previous_commit": SELECTED_REPO_TRUST_PREVIOUS,
                                      "paths": SELECTED_REPO_TRUST_PATHS, "after": policy_v2(anchor)},
            WINDOWS_HOST_SKILL_PATH: {"previous_commit": WINDOWS_HOST_SKILL_PREVIOUS,
                                     "paths": WINDOWS_HOST_SKILL_PATHS, "after": policy_v2(anchor)},
            FEATURE_NAMES_PATH: {"previous_commit": FEATURE_NAMES_PREVIOUS,
                                 "paths": FEATURE_NAMES_PATHS, "after": policy_v2(anchor)},
            CLI_LAYOUT_PATH: {"previous_commit": CLI_LAYOUT_PREVIOUS,
                              "paths": CLI_LAYOUT_PATHS, "after": policy_v2(anchor)},
            CURRENT_DOCTOR_DIAGNOSTICS_PATH: {
                "previous_commit": CURRENT_DOCTOR_DIAGNOSTICS_PREVIOUS,
                "paths": CURRENT_DOCTOR_DIAGNOSTICS_PATHS, "after": policy_v2(anchor)},
            GLOBAL_HARNESS_PATH: {
                "previous_commit": GLOBAL_HARNESS_PREVIOUS,
                "paths": GLOBAL_HARNESS_PATHS, "after": global_harness_policy(anchor)}}


def import_scope(before, after):
    # Direct shebang invocation puts bin/ on Python's import search path too.
    # Ordinary executable helpers (including extensionless Python scripts) are
    # fine, but module/package/bytecode/extension additions there are not.
    F.require(not any(path.startswith("bin/") and path.lower().endswith(
        (".py", ".pyc", ".pyo", ".so", ".pyd", ".dylib"))
        for path in F.delta(before, after)), "script_directory_import_shadow")


def admit(observation, head, current, *, review):
    F.require(type(review) is bool and type(observation) is dict and set(observation) == {
        "anchorTree", "transitions", "acceptedCommit", "acceptedTree", "pendingCommits"},
        "invalid_source_observation")
    anchor, transitions = observation["anchorTree"], observation["transitions"]
    previous, accepted_tree = observation["acceptedCommit"], observation["acceptedTree"]
    pending = observation["pendingCommits"]
    F.require(type(pending) in (list, tuple) and len(pending) <= F.MAX_COMMITS,
              "invalid_candidate_chain")
    rules, updates = policy(anchor), policy_updates(anchor)
    # First validate the chain at its ACTUAL last accepted commit/tree. A pending
    # candidate is never supplied to a historical verifier as a pretend anchor.
    F.verify(ANCHOR, anchor, transitions, previous, accepted_tree,
             policy_updates=updates, **rules)
    # Only a fully verified policy acceptance child changes subsequent rules.
    for transition in transitions:
        if F.parse(transition["raw"])["kind"] == "policy":
            rules = updates[transition["path"]]["after"]
    for transition in transitions:
        intermediate = transition["base_tree"]
        for row in transition["candidate_commits"]:
            import_scope(intermediate, row["tree"])
            intermediate = row["tree"]
    accepted = bool(transitions)
    if pending:
        # Even new evidence can be read by Nix: no extension-based "inert"
        # exception. Post-apply observations may remain outside the control
        # source tree until the next ordinary reviewed transition consumes them.
        F.require(review, "unreviewed_main_source")
        kind = "configuration" if transitions else "bootstrap"
        # Bounded review preparation of an exact separately authorized delta.
        # This never accepts source or grants execution, even on a review branch.
        preview = next((item for item in updates.values()
                        if item["previous_commit"] == previous), None)
        if preview is not None:
            kind = "policy"
            rules = dict(rules, bootstrap_paths=preview["paths"])
        tree = accepted_tree
        partial_rules = dict(rules)
        seen = {ANCHOR}
        for transition in transitions:
            seen.add(transition["acceptance_commit"])
            seen.update(row["commit"] for row in transition["candidate_commits"])
        if not transitions:
            partial_rules["protected_paths"] = rules["protected_paths"] & anchor.keys()
        for row in pending:
            F.require(type(row) is dict and set(row) == {"commit", "parents", "tree"}
                      and type(row["parents"]) in (list, tuple)
                      and list(row["parents"]) == [previous], "nonlinear_candidate")
            F._oid(row["commit"])
            F.require(row["commit"] not in seen, "repeated_commit")
            seen.add(row["commit"])
            F.validate_candidate(tree, row["tree"], kind, **partial_rules)
            import_scope(tree, row["tree"])
            previous, tree = row["commit"], row["tree"]
        F.require(previous == head and tree == current, "unreviewed_current_source")
        F.validate_candidate(accepted_tree, current, kind, **rules)
        accepted = False
    else:
        F.require(previous == head and accepted_tree == current, "unreviewed_current_source")
    # Hold physical absence for deletions, including a removed parent directory.
    # SourceFile needs an existing parent; choose the first missing component.
    historical_paths = set(anchor)
    for item in transitions:
        for name in ("base_tree", "reviewed_tree", "accepted_tree"):
            historical_paths.update(item[name])
        for row in item["candidate_commits"]:
            historical_paths.update(row["tree"])
    for row in pending:
        historical_paths.update(row["tree"])
    absent = set(IMPORT_ABSENCES)
    directories = {"/".join(p.split("/")[:i]) for p in current
                   for i in range(1, len(p.split("/")))}
    for path in historical_paths - current.keys():
        parts = path.split("/")
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            if prefix in current:
                # A held regular file at this prefix already proves there can
                # be no descendant; do not try to open it as a parent directory.
                break
            if prefix not in current and prefix not in directories:
                absent.add(prefix)
                break
    F.require(not (absent & current.keys()), "unexpected_import_initializer")
    return {"accepted": accepted, "absent": tuple(sorted(absent))}
