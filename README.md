# Agent-First Mac

A source reference for an agent-managed Mac: desired state in Git, bounded
privileged operations, quarantine for unknown projects, diagnostics, and
recoverable configuration changes.

**This is a sanitized source release, not a one-command installer.** It contains
the implementation developed for one workstation, not that workstation's private
history, credentials, trust decisions, recovery records, or installed binaries.
It has not been validated as a bootstrap for a fresh Mac.

## What is here

- `reference/bin/aid`: the command facade and its diagnostic/lifecycle tools.
- `reference/lib/`: configuration transitions, Git source admission, compatibility
  checks, runtime discovery, and recovery logic.
- `reference/Sources/`: Swift source for bounded administrator operations.
- `reference/darwin/`, `reference/flake.nix`, `reference/flake.lock`: Nix/Darwin
  configuration source and pinned inputs.
- `reference/codex/hooks/` and `reference/skills/`: context and workstation/SSH
  operating guidance. These are source material, not auto-installed instructions.
- `reference/tests/`: implementation tests, including disposable Git fixtures.
- `reference/examples/manifests/`: explicitly wrapped, sanitized historical
  examples; **not live configuration**.

## Start safely

Read [ARCHITECTURE.md](ARCHITECTURE.md) and [PUBLIC-RELEASE.md](PUBLIC-RELEASE.md).
To run the selected portable logic tests, with Python 3.11+ and Git available:

```sh
python3 tools/test_reference.py
```

These tests use mocks and disposable directories. They do not install the
harness, run privileged operations, configure VPNs, or touch games.
The full historical test suite is **not** the public acceptance suite: some
tests intentionally depend on private receipts, omitted manifests, or the
original Git ancestry.

There is no supported installation command for this release. Do not copy its
sudoers, hook configuration, system policies, or Nix modules into your machine
without reviewing and adapting them. Removing executable bits reduces accidental
execution; it is not a security sandbox. Interpreters can still execute scripts.

## Why build this?

The goal is to make an agent useful beyond editing one repository without giving
every task unrestricted ownership of the workstation: explicit installation
owners, ordinary development that stays ordinary, narrow system changes, and
evidence-based recovery when something fails.

This release shares the actual implementation and its trade-offs. Personal
operating notes and incident history are omitted. Turning it
into a portable product requires a new host configuration and locally established
trust and acceptance, not replaying somebody else's successful checks.

## License

Original project code: [MIT](LICENSE). Vendored Tomli retains its own MIT
copyright and license; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
No Apple, Microsoft, game, or Wine binaries are distributed.
