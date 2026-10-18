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
# Preparation snapshot of the owner-authorized wave, not acceptance evidence.
# Refresh against the union of every intermediate delta and the final candidate,
# not just endpoint differences: added-then-retired scaffolds remain in scope.
# Never discover authorization paths dynamically from a working tree or receipt.
OWNER_FIRST_WAVE_PREVIOUS = "94e0e1999c208aaf4112b611bbfa5c8b65111419"
OWNER_FIRST_WAVE_PATH = "evidence/config-transitions/owner-first-harness-wave/acceptance.json"
OWNER_FIRST_WAVE_PATHS = frozenset((
    "AGENTS.md",
    "ARCHITECTURE.md",
    "Package.swift",
    "Sources/AidAdmin/main.swift",
    "Sources/AidAdminApply/main.swift",
    "Sources/AidAdminBootstrapCore/AidAdminBootstrapCore.swift",
    "Sources/AidAdminCore/AidAdminCore.swift",
    "Sources/AidAdminCore/OperationJournal.swift",
    "Sources/AidAdminCore/RecoveryReceipt.swift",
    "Sources/AidAdminCore/ResumeHomeManager.swift",
    "Sources/AidAdminCore/ResumeLaunchd.swift",
    "Sources/AidAdminEmergencyAction/main.swift",
    "Sources/AidAdminEmergencyCore/AidAdminEmergencyCore.swift",
    "Sources/AidAdminRuntime/BoundedProcess.swift",
    "bin/aid",
    "bin/aid-harness-offramp",
    "bin/build-phase4-emergency-bundle",
    "bin/build-phase4-install-bundle",
    "bin/check-codex-windows-host-ssh-app-server-holder",
    "bin/check-productivity-baseline",
    "bin/codex-windows-host-ssh-app-server-holder",
    "bin/codex-windows-host-ssh-stdio-compat",
    "bin/codex-quarantine",
    "bin/cs2-play",
    "bin/cs2-standalone",
    "bin/current-doctor",
    "bin/ds3-runtime",
    "bin/game-app-launcher-update",
    "bin/game-app-launchers",
    "bin/game-launch-admission",
    "bin/game-launch-reliability-update",
    "bin/games-hub",
    "bin/games-play",
    "bin/games-runtime-update",
    "bin/windows-host-ssh-client",
    "bin/phase5-config-transaction",
    "bin/phase5-preflight",
    "bin/phase5-trusted-probe",
    "bin/prepare-productivity-apply",
    "bin/productivity-doctor",
    "bin/root-operation-recovery-observe",
    "bin/shell-nofile",
    "bin/wine-runtime-overlay",
    "bin/workstation-drift-snapshot",
    "bin/workstation-maintenance-cycle",
    "codex/hooks.json",
    "codex/hooks/phase5-contract.py",
    "codex/quarantine.config.toml",
    "darwin/productivity.nix",
    "darwin/rustdesk-controller.nix",
    "darwin/windows-app.nix",
    "docs/aid.md",
    "docs/codex-windows-host-ssh-app-server-holder.md",
    "docs/codex-windows-host-ssh-stdio-compat.md",
    "docs/current-source-admission.md",
    "docs/windows-host-ssh-client.md",
    "docs/harness-operations.md",
    "docs/maintenance.md",
    "docs/operation-readiness.md",
    "docs/post-phase5-sentinel.md",
    "docs/project-context-boundary.md",
    "docs/shell-nofile.md",
    "docs/wave-games.md",
    "docs/wave-offramp.md",
    "docs/wave-owner-freedom.md",
    "docs/wave-quarantine-boundary.md",
    "docs/wave-recovery-coverage.md",
    "docs/wave-root-recovery.md",
    "docs/wave-shell-legacy.md",
    "docs/wave-ssh.md",
    "docs/wave-vendor-correctness.md",
    "docs/wine-runtime-overlay.md",
    "lib/config_transition_source.py",
    "lib/current_doctor_native.py",
    "lib/current_source_admission.py",
    "lib/current_source_checkpoint.py",
    "lib/game_operation_readiness.py",
    "lib/harness_offramp.py",
    "lib/operation_readiness.py",
    "lib/prepared_receipt.py",
    "lib/productivity_ownership.py",
    "lib/root_operation_recovery.py",
    "lib/vendor_compatibility_policy.py",
    "lib/vendor_compatibility_probe.py",
    "lib/vendor_fixture_custody.py",
    "lib/workstation_maintenance_delivery.py",
    "manifests/codex-windows-host-ssh-app-server-holder.json",
    "manifests/codex-windows-host-ssh-stdio-compat.json",
    "manifests/game-launch-reliability.json",
    "manifests/games-hub.json",
    "manifests/harness-hook-retirement.json",
    "manifests/productivity-baseline.json",
    "manifests/quarantine-boundary-successor.json",
    "manifests/wine-runtime-overlay.json",
    "manifests/wine-runtime-overlay.schema.json",
    "manifests/wine-runtime-update.json",
    "manifests/wine-runtime-update.schema.json",
    "manifests/workstation-maintenance.json",
    "skills/manage-workstation/SKILL.md",
    "tests/AidAdminBootstrapTests/AidAdminBootstrapTests.swift",
    "tests/AidAdminCoreTests/AidAdminCoreTests.swift",
    "tests/AidAdminEmergencyTests/AidAdminEmergencyTests.swift",
    "tests/AidAdminResumeHomeManagerTests/AidAdminResumeHomeManagerTests.swift",
    "tests/AidAdminResumeLaunchdTests/AidAdminResumeLaunchdTests.swift",
    "tests/AidAdminRuntimeTests/AidAdminRuntimeTests.swift",
    "tests/fixtures/harness-hooks-pre-retirement.json",
    "tests/fixtures/phase5-quarantine-before-current-cli.zsh",
    "tests/fixtures/phase5-quarantine-before-temp-deny.config.toml",
    "tests/test_aid.py",
    "tests/test_codex_windows-host_ssh_app_server_holder.py",
    "tests/test_codex_windows-host_ssh_stdio_compat.py",
    "tests/test_config_transition_source.py",
    "tests/test_current_doctor.py",
    "tests/test_current_doctor_native.py",
    "tests/test_current_source_checkpoint.py",
    "tests/test_ds3_lifecycle_recovery.py",
    "tests/test_ds3_runtime.py",
    "tests/test_ds3_window_repair.py",
    "tests/test_game_launch_admission.py",
    "tests/test_game_launch_reliability_update.py",
    "tests/test_game_operation_readiness.py",
    "tests/test_games_runtime_update.py",
    "tests/test_windows-host_ssh_client.py",
    "tests/test_harness_offramp.py",
    "tests/test_operation_readiness.py",
    "tests/test_phase5_current_quarantine.py",
    "tests/test_phase5_quarantine_fixture.py",
    "tests/test_phase5_quarantine_launcher_outer.py",
    "tests/test_phase5_quarantine_outer.py",
    "tests/test_phase5_vendor_floor.py",
    "tests/test_prepare_productivity_apply.py",
    "tests/test_prepared_receipt.py",
    "tests/test_productivity_owner_freedom.py",
    "tests/test_productivity_power_policy.py",
    "tests/test_project_context_boundary.py",
    "tests/test_quarantine_boundary_successor.py",
    "tests/test_root_bundle_successor.py",
    "tests/test_root_operation_recovery.py",
    "tests/test_root_resume_module_guards.py",
    "tests/test_sessionstart_exposure.py",
    "tests/test_vendor_compatibility_policy.py",
    "tests/test_vendor_compatibility_probe.py",
    "tests/test_vendor_fixture_custody.py",
    "tests/test_wave_recovery_coverage.py",
    "tests/test_wave_shell_legacy.py",
    "tests/test_wave_ssh_exchange.py",
    "tests/test_wave_ssh_lifecycle.py",
    "tests/test_wave_ssh_protocol.py",
    "tests/test_wave_trusted_version.py",
    "tests/test_wine_runtime_extended.py",
    "tests/test_workstation_drift_snapshot.py",
    "tests/test_workstation_maintenance_cycle.py",
    "tests/test_workstation_maintenance_delivery.py",
))
# Lasting protection is intentionally separate from the one-time mutation list.
# lib/, Sources/, codex/ and skills/ remain protected by existing prefixes; normal
# payload wrappers, app preferences, observation tools and descriptive wave docs
# do not become authorities merely because this wave changed them.
OWNER_FIRST_WAVE_PROTECTED = frozenset((
    # Direct operation/custody adapters and their authority declarations.
    "bin/aid-harness-offramp", "bin/codex-windows-host-ssh-app-server-holder",
    "bin/codex-windows-host-ssh-stdio-compat", "bin/shell-nofile",
    "bin/workstation-maintenance-cycle",
    "manifests/harness-hook-retirement.json",
    "manifests/codex-windows-host-ssh-app-server-holder.json",
    "manifests/codex-windows-host-ssh-stdio-compat.json",
    "manifests/workstation-maintenance.json",
    # Acceptance-critical source, authority and receipt/recovery regressions.
    "manifests/quarantine-boundary-successor.json",
    "tests/test_quarantine_boundary_successor.py",
    "tests/fixtures/phase5-quarantine-before-current-cli.zsh",
    "tests/fixtures/phase5-quarantine-before-temp-deny.config.toml",
    "tests/test_current_source_checkpoint.py", "tests/test_operation_readiness.py",
    "tests/test_harness_offramp.py", "tests/test_prepared_receipt.py",
    "tests/test_root_resume_module_guards.py", "tests/test_game_operation_readiness.py",
    "tests/test_codex_windows-host_ssh_app_server_holder.py",
    "tests/test_codex_windows-host_ssh_stdio_compat.py",
    "tests/test_wave_shell_legacy.py", "tests/test_wave_ssh_lifecycle.py",
    "tests/test_wave_ssh_protocol.py", "tests/test_wave_ssh_exchange.py",
    "tests/test_aid.py", "tests/test_sessionstart_exposure.py",
    "tests/test_project_context_boundary.py",
    "tests/test_root_bundle_successor.py",
    "tests/test_workstation_maintenance_delivery.py",
    "tests/test_workstation_maintenance_cycle.py",
    "tests/test_vendor_fixture_custody.py",
    "tests/AidAdminResumeHomeManagerTests/AidAdminResumeHomeManagerTests.swift",
    "tests/AidAdminResumeLaunchdTests/AidAdminResumeLaunchdTests.swift",
    "tests/AidAdminRuntimeTests/AidAdminRuntimeTests.swift",
    "tests/fixtures/harness-hooks-pre-retirement.json",
    # Normative admission/operation/off-ramp contracts, not descriptive reports.
    "docs/current-source-admission.md", "docs/harness-operations.md",
    "docs/operation-readiness.md", "docs/wave-offramp.md",
))

# Fresh unaccepted candidate on canonical 97ce4ae, not a descendant of the
# independently accepted 849a241 sibling. Preserve that sibling and its receipt;
# this lineage must publish its own genuine wave receipt after combined review.
# Component scope is provisional until the integration owner freezes all paths.
OWNER_FIRST_WAVE_DELIVERY_PATHS = frozenset((
    "lib/config_transition_source.py", "tests/test_config_transition_source.py",
    "tests/test_current_source_checkpoint.py", "docs/current-source-admission.md",
    "docs/owner-first-delivery-recovery.md", "manifests/windows-host-ssh-client.json",
    "lib/game_delivery_bridge.py", "tests/test_game_delivery_bridge.py",
    "tests/test_game_delivery_order.py", "docs/wave-games.md",
    "tests/test_game_operation_readiness.py",
    "bin/quarantine-delivery", "lib/quarantine_delivery.py",
    "tests/test_quarantine_delivery.py", "docs/quarantine-delivery.md",
    "manifests/root-runtime-release.json", "lib/root_delivery.py",
    "bin/root-delivery", "tests/test_root_delivery.py", "docs/root-runtime-delivery.md",
    "lib/root_runtime_health.py", "bin/root-runtime-doctor", "tests/test_root_runtime_health.py",
    "bin/aid", "manifests/aid-catalog.json", "tests/test_aid.py", "docs/aid.md",
    "bin/ds3-policy-source-bootstrap", "bin/ds3-runtime", "bin/games-runtime-update",
    "bin/wine-runtime-overlay", "docs/wine-runtime-overlay.md",
    "manifests/wine-runtime-update.schema.json", "tests/test_ds3_policy_source_bootstrap.py",
    "tests/test_games_installed_policy.py", "tests/test_wine_installed_policy.py",
    "bin/workstation-guidance-delivery", "lib/workstation_guidance_delivery.py",
    "tests/test_workstation_guidance_delivery.py", "manifests/workstation-guidance-delivery.json",
    "docs/workstation-guidance-delivery.md",
))
# New authorities and acceptance-critical contracts only. Ordinary Wine payload
# wrappers/schema documentation do not become protected merely by changing here.
# lib/ is already protected by the unchanged inherited prefix.
OWNER_FIRST_WAVE_DELIVERY_PROTECTED = frozenset((
    "bin/quarantine-delivery", "tests/test_quarantine_delivery.py", "docs/quarantine-delivery.md",
    "bin/root-delivery", "bin/root-runtime-doctor", "manifests/root-runtime-release.json",
    "tests/test_root_delivery.py", "tests/test_root_runtime_health.py", "docs/root-runtime-delivery.md",
    "bin/ds3-policy-source-bootstrap", "tests/test_ds3_policy_source_bootstrap.py",
    "tests/test_games_installed_policy.py", "tests/test_wine_installed_policy.py",
    "docs/owner-first-delivery-recovery.md",
    "tests/test_game_delivery_bridge.py", "tests/test_game_delivery_order.py",
    "bin/workstation-guidance-delivery", "tests/test_workstation_guidance_delivery.py",
    "manifests/workstation-guidance-delivery.json", "docs/workstation-guidance-delivery.md",
))
# Explicit union; retain the original reviewed scope, including its four retired
# scaffolds, without claiming that those commits occur on this new lineage.
OWNER_FIRST_WAVE_PATHS = OWNER_FIRST_WAVE_PATHS | OWNER_FIRST_WAVE_DELIVERY_PATHS
OWNER_FIRST_WAVE_PROTECTED = OWNER_FIRST_WAVE_PROTECTED | OWNER_FIRST_WAVE_DELIVERY_PROTECTED

# Narrow correction after the real integrated wave; historical wave scope and
# protections stay immutable. This registration alone is not source acceptance.
VENDOR_FIXTURE_CUSTODY_REPAIR_PREVIOUS = "207e8f3fa2acfc70a588337ef129fb9a91699b1e"
VENDOR_FIXTURE_CUSTODY_REPAIR_PATH = "evidence/config-transitions/vendor-fixture-custody-repair/acceptance.json"
VENDOR_FIXTURE_CUSTODY_REPAIR_PATHS = frozenset((
    "lib/vendor_fixture_custody.py", "lib/vendor_compatibility_probe.py",
    "tests/test_vendor_fixture_custody.py", "tests/test_vendor_compatibility_probe.py",
    "lib/config_transition_source.py", "tests/test_config_transition_source.py",
    "tests/test_current_source_checkpoint.py", "docs/vendor-fixture-custody-repair.md",
))

SCHEDULER_DESCRIPTOR_REPAIR_PREVIOUS = "6e8d675db89af967e4375e75ef0ab5563e4b9208"
SCHEDULER_DESCRIPTOR_REPAIR_PATH = "evidence/config-transitions/scheduler-descriptor-repair/acceptance.json"
SCHEDULER_DESCRIPTOR_REPAIR_PATHS = frozenset((
    "lib/workstation_maintenance_delivery.py", "tests/test_workstation_maintenance_delivery.py",
    "lib/config_transition_source.py", "tests/test_config_transition_source.py",
    "tests/test_current_source_checkpoint.py", "docs/scheduler-descriptor-repair.md",
))

PRODUCT_SURFACE_PREVIOUS = "fac9dd5d7925695c7d0a8b5a3f8af536ef71c3dd"
PRODUCT_SURFACE_PATH = "evidence/config-transitions/product-surface/acceptance.json"
PRODUCT_SURFACE_PATHS = frozenset((
    "README.md", "docs/index.md", "docs/usage.md", "docs/installation.md",
    "docs/recovery.md", "docs/history/index.md", "bin/aid", "tests/test_aid.py", "docs/aid.md",
    "lib/config_transition_source.py", "tests/test_config_transition_source.py",
    "tests/test_current_source_checkpoint.py", "tests/test_product_surface.py",
    "docs/product-surface-admission.md",
))

# Exact aggregate successor: the ordinary Wave5 pins precede a protected
# regression-test update. Admission preserves all prior protections and receipts.
WINE_ARCHIVE_CHAIN_PREVIOUS = "db9629b187e0dbfd2ae0e0deb341249283965717"
WINE_ARCHIVE_CHAIN_PATH = "evidence/config-transitions/wine-archive-chain/acceptance.json"
WINE_ARCHIVE_CHAIN_PATHS = frozenset((
    "bin/game-launch-reliability-update", "tests/test_game_delivery_order.py",
    "manifests/games-hub.json", "manifests/wine-runtime-overlay.json", "manifests/wine-runtime-update.json",
    "lib/config_transition_source.py", "tests/test_config_transition_source.py",
    "tests/test_current_source_checkpoint.py", "docs/wine-archive-chain-admission.md",
))

# Durable namespace identity: aggregate the unchanged routine Wine prefix,
# then admit only the separately reviewed custody and admission source delta.
CUSTODY_NAMESPACE_PREVIOUS = "f96b6a78f68a58635f018dbca8271ca8981d47a1"
CUSTODY_NAMESPACE_PATH = "evidence/config-transitions/custody-namespace/acceptance.json"
CUSTODY_NAMESPACE_PATHS = frozenset((
    "lib/vendor_fixture_custody.py", "tests/test_custody_namespace.py",
    "docs/custody-namespace.md", "docs/custody-namespace-admission.md",
    "lib/config_transition_source.py", "tests/test_config_transition_source.py",
    "tests/test_current_source_checkpoint.py",
    "bin/ds3-runtime", "bin/game-launch-reliability-update", "bin/games-runtime-update",
    "bin/wine-runtime-overlay", "docs/wine-runtime-overlay.md",
    "manifests/ds3-renderer-update.json", "manifests/game-launch-reliability.json",
    "manifests/games-hub.json", "manifests/wine-runtime-overlay.json",
    "manifests/wine-runtime-update.json", "tests/test_ds3_native_borderless_launch.py",
    "tests/test_ds3_renderer.py", "tests/test_game_archive_renderer.py",
    "tests/test_game_archive_schema4.py", "tests/test_renderer_launch_bridge.py",
))

SCOPED_READINESS_PREVIOUS = "ab3763f701974c2262a8fb2e579ed426f5bce0dd"
SCOPED_READINESS_PATH = "evidence/config-transitions/scoped-readiness/acceptance.json"
SCOPED_READINESS_PATHS = frozenset((
    "docs/games-hub.md", "docs/game-launch-reliability-update.md",
    "docs/wine-runtime-overlay.md", "docs/windows-host-ssh-client.md",
    "AGENTS.md",
    "ARCHITECTURE.md",
    "bin/workstation-guidance-successor",
    "docs/harness-operations.md",
    "docs/maintenance.md",
    "docs/operation-readiness.md",
    "docs/owner-first-delivery-recovery.md",
    "docs/quarantine-delivery.md",
    "docs/root-runtime-delivery.md",
    "docs/scoped-readiness-admission.md",
    "docs/shell-nofile.md",
    "docs/wave-games.md",
    "docs/wave-offramp.md",
    "docs/wave-ssh.md",
    "docs/workstation-guidance-delivery.md",
    "lib/config_transition_source.py",
    "lib/quarantine_delivery.py",
    "lib/root_delivery.py",
    "lib/workstation_guidance_delivery.py",
    "lib/workstation_maintenance_delivery.py",
    "manifests/harness-hook-retirement.json",
    "manifests/workstation-guidance-successor.json",
    "skills/manage-workstation/SKILL.md",
    "skills/manage-workstation/recovery/owner-first-v1.md",
    "tests/test_config_transition_source.py",
    "tests/test_current_source_checkpoint.py",
    "tests/test_operation_readiness.py",
    "tests/test_quarantine_delivery.py",
    "tests/test_root_delivery.py",
    "tests/test_workstation_guidance_delivery.py",
    "tests/test_workstation_maintenance_delivery.py",
))

# Exact native launch source admission; namespace protection is unchanged.
# Includes every actual post-checkpoint edge, retaining the already admitted
# RustDesk/renderer prefix rather than pretending 64fdb5d was a checkpoint.
NATIVE_LAUNCH_PREVIOUS = "a0bd1e9af3d1bf2ba5426762ede54b4bee3e4445"
NATIVE_LAUNCH_PATH = "evidence/config-transitions/native-launch-admission/acceptance.json"
NATIVE_LAUNCH_PATHS = frozenset((
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
))

NATIVE_SERVER_ALIAS_PREVIOUS = "46e3a690096b6f89f2ca09a23e8c9e668fb6bbc0"
NATIVE_SERVER_ALIAS_PATH = "evidence/config-transitions/native-server-alias/acceptance.json"
NATIVE_SERVER_ALIAS_PATHS = frozenset((
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


def owner_first_wave_policy(anchor):
    # Never retroactively require successor files in historical accepted trees.
    rules = dict(global_harness_policy(anchor))
    rules["protected_paths"] = rules["protected_paths"] | OWNER_FIRST_WAVE_PROTECTED
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
                "paths": GLOBAL_HARNESS_PATHS, "after": global_harness_policy(anchor)},
            OWNER_FIRST_WAVE_PATH: {
                "previous_commit": OWNER_FIRST_WAVE_PREVIOUS,
                "paths": OWNER_FIRST_WAVE_PATHS, "after": owner_first_wave_policy(anchor)},
            VENDOR_FIXTURE_CUSTODY_REPAIR_PATH: {
                "previous_commit": VENDOR_FIXTURE_CUSTODY_REPAIR_PREVIOUS,
                "paths": VENDOR_FIXTURE_CUSTODY_REPAIR_PATHS, "after": owner_first_wave_policy(anchor)},
            SCHEDULER_DESCRIPTOR_REPAIR_PATH: {
                "previous_commit": SCHEDULER_DESCRIPTOR_REPAIR_PREVIOUS,
                "paths": SCHEDULER_DESCRIPTOR_REPAIR_PATHS, "after": owner_first_wave_policy(anchor)},
            PRODUCT_SURFACE_PATH: {
                "previous_commit": PRODUCT_SURFACE_PREVIOUS,
                "paths": PRODUCT_SURFACE_PATHS, "after": owner_first_wave_policy(anchor)},
            WINE_ARCHIVE_CHAIN_PATH: {
                "previous_commit": WINE_ARCHIVE_CHAIN_PREVIOUS,
                "paths": WINE_ARCHIVE_CHAIN_PATHS, "after": owner_first_wave_policy(anchor)},
            CUSTODY_NAMESPACE_PATH: {
                "previous_commit": CUSTODY_NAMESPACE_PREVIOUS,
                "paths": CUSTODY_NAMESPACE_PATHS, "after": owner_first_wave_policy(anchor)},
            SCOPED_READINESS_PATH: {
                "previous_commit": SCOPED_READINESS_PREVIOUS,
                "paths": SCOPED_READINESS_PATHS, "after": owner_first_wave_policy(anchor)},
            NATIVE_LAUNCH_PATH: {
                "previous_commit": NATIVE_LAUNCH_PREVIOUS,
                "paths": NATIVE_LAUNCH_PATHS, "after": owner_first_wave_policy(anchor)},
            NATIVE_SERVER_ALIAS_PATH: {
                "previous_commit": NATIVE_SERVER_ALIAS_PREVIOUS,
                "paths": NATIVE_SERVER_ALIAS_PATHS, "after": owner_first_wave_policy(anchor)}}


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
