# Source map

These are reference sources, not instructions to activate them on your Mac.

| Component | Starting points |
| --- | --- |
| Read-only front door | [aid](../reference/bin/aid) |
| Bounded monitoring | [cycle](../reference/bin/workstation-maintenance-cycle), [snapshot](../reference/bin/workstation-drift-snapshot), [delivery](../reference/lib/workstation_maintenance_delivery.py) |
| Owner freedom | [ownership](../reference/lib/productivity_ownership.py), [readiness](../reference/lib/operation_readiness.py) |
| Source admission | [admission](../reference/lib/current_source_admission.py), [transitions](../reference/lib/config_transitions.py) |
| Affected user-helper source | [closure](../reference/lib/scoped_source_admission.py), [dependency checks](../reference/lib/operation_checks.py), [user readiness](../reference/lib/user_operation_readiness.py) |
| Vendor compatibility | [doctor](../reference/bin/current-doctor), [policy](../reference/lib/vendor_compatibility_policy.py) |
| Advisory project context | [hook](../reference/codex/hooks/phase5-contract.py) |
| Quarantine pair | [delivery](../reference/lib/quarantine_delivery.py) |
| Typed administrator | [core](../reference/Sources/AidAdminCore/AidAdminCore.swift), [delivery](../reference/lib/root_delivery.py) |
| Privilege-separated Git observation | [implementation](../reference/Sources/AidAdminCore/GitObservation.swift) |
| Bounded helper processes | [command custody](../reference/lib/bounded_command.py), [regressions](../reference/tests/test_bounded_command.py) |
| Bound executable source | [execution regressions](../reference/tests/test_scoped_execution.py), [delivery closure regressions](../reference/tests/test_delivery_source_closure.py) |
| Optional launcher file scope | [shared file operations](../reference/lib/game_app_files.py), [routes](../reference/lib/game_app_routes.json) |
| Harness off-ramp | [implementation](../reference/lib/harness_offramp.py) |
| Optional games | [hub](../reference/bin/games-hub), [updater](../reference/bin/games-runtime-update) |
| Optional Windows | [client](../reference/bin/windows-host-ssh-client) |
| Scoped delivery consumers | [guidance successor](../reference/bin/workstation-guidance-successor), [guidance delivery](../reference/lib/workstation_guidance_delivery.py), [schedule delivery](../reference/lib/workstation_maintenance_delivery.py) |
| Custody across reboot | [custody](../reference/lib/vendor_fixture_custody.py), [namespace tests](../reference/tests/test_custody_namespace.py) |
| Optional remote desktop tunnel | [tunnel](../reference/bin/rustdesk-ssh-tunnel), [mocked tests](../reference/tests/test_rustdesk_ssh_tunnel.py) |
| Optional native game admission | [plan](../reference/bin/game-native-admission-plan), [transaction](../reference/lib/game_native_admission_transaction.py), [source closure](../reference/lib/game_launch_native/README.md) |

Historical Phase modules remain because current modules import them and because
they explain recovery/admission behavior. Live manifests, original Git ancestry,
historical acceptance packets and installed state are missing deliberately.
Unresolved runtime references must not be repaired with invented hashes or PASS
receipts. Human-facing docs are separate from private operating history.
