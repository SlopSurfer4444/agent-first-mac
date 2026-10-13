---
name: manage-workstation
description: Manage workstation-level install, adopt, update, remove, repair, relocation, or ownership changes for macOS apps, global CLIs and runtimes, services, VPNs, Codex plugins, MCP servers, apps, and agent tools. Use for machine lifecycle requests; do not use for repo-local dependencies already governed by the repository contract, lockfile, mise, uv, or its package manager.
---

# Manage workstation lifecycle

1. Classify the request. Keep repo-local runtimes and dependencies inside the
   closest repository contract; ordinary editing, tests, diagnostics, review
   and commits need no workstation gate. Route machine-wide state through
   `$HOME/AIDev/control`. Start with that control root's
   `docs/harness-operations.md`; apply its authoritative architecture and the
   affected lifecycle contract.
2. Read the control `ARCHITECTURE.md` and relevant manifest. Inventory and
   attest existing state before changing it. Adopt canonical existing payloads
   before reinstalling or relocating them.
3. Require one primary installation/update owner, one manifest entry, a stable
   resolver, version policy, capabilities, data boundary, smoke test, removal,
   and rollback for every payload. Stop on owner collisions or untrusted input.
4. Prepare a task branch/worktree. Validate source and provenance, then
   evaluate, dry-run, or build before applying. Never place secrets, auth state,
   profiles, raw environments, recovery material, or stable identifiers in Git
   or evidence.
5. Commit atomic control intent and follow the current source-admission route.
   Before any workstation mutation, require a fresh full accepted canonical
   `$HOME/AIDev/control/bin/current-doctor --json` PASS: accepted current source,
   ready sentinel, settled children and closed handles. Exit0, preparation,
   Git-only, component checks and an old PASS are not readiness. Failure pauses
   that mutation, not ordinary repo work or authorized offline repair.
6. `aid` is read-only inventory, plan guidance and doctor dispatch, not an apply
   executor. Use the reviewed user-level adapter named by the payload lifecycle.
   When root is required, use only the existing typed `aid-admin` operation.
   System activation requires reviewed source integration, a build of the exact
   integrated apply commit and its bound receipt before `apply-system`.
   Never invoke an ad-hoc privileged installer or arbitrary root command.
7. Run the affected functional smoke test and doctor, save bounded redacted
   evidence, and verify idempotence. Match checks to the change; retain separate
   protected root/trust/security review and native consent gates. Source,
   installed and operational acceptance remain separate. On failure use the
   existing scoped recovery path; preserve evidence and accepted history.
8. If a login, consent, license, TCC grant, physical action, or other irreducible
   owner boundary remains, request one bounded action with its expected result
   and exact verification probe.
