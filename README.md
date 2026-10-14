# Agent-First Mac

A workstation harness that helps an agent manage a Mac without making the owner
ask permission to use it. Ordinary development stays ordinary; persistent machine
changes get scoped checks, explicit ownership and recoverable execution.

**Public source reference, not a fresh-Mac installer.** No credentials, live trust
configuration, private history, recovery records or installed binaries are included.

## Start here

- [Product guide](docs/product-guide.md): benefits, boundaries and everyday use.
- [Source map](docs/source-map.md): find implementation by task.
- [Example workstation skill](examples/skills/manage-workstation/SKILL.md) and
  [illustrative lifecycle](examples/component-lifecycle.json): reusable guidance,
  not active configuration.
- [Validation](VALIDATION.md), [export workflow](docs/export.md) and
  [release boundary](PUBLIC-RELEASE.md).

## What the design buys you

- A read-only `aid` front door for declared inventory, routing and scoped doctors.
- Bounded deterministic metadata observation, separate from health and repair.
- Component-specific changes instead of replaying bootstrap for every edit.
- Explicit quarantine, native consent and typed administrator boundaries.
- Optional Windows and game integration separate from ordinary development.

Historical implementation modules remain where current code depends on them.
Their names are not instructions to rerun old live trials. Optional game source
is not a game distribution or a supported Wine installation.

## Safe first command

With Python 3.11+ and Git:

```sh
python3 tools/test_reference.py
```

This selected suite uses mocks and disposable fixtures. Do not run the entire
historical suite or installers against your workstation just because it passes.
Read [ARCHITECTURE.md](ARCHITECTURE.md) before adapting the implementation.

Original code: [MIT](LICENSE). [Third-party notices](THIRD-PARTY-NOTICES.md)
remain intact. No Apple, Microsoft, game or Wine binaries are distributed.
