# Public validation

Current export validation (2026-10-19 review snapshot): 14 exporter tests passed;
the selected reference suite ran 329 tests with 325 passing and four explicit
skips. Structure/provenance checks passed for 359 text files, including 340
exported sources. The exact source
revision is recorded in `export-provenance.json`; these are source-release results,
not installed-workstation acceptance.

Run in this public checkout:

```sh
python3 -B tools/test_export_reference.py
python3 -B tools/check_release.py
python3 -B tools/test_reference.py
git diff --check
```

Exporter fixtures exercise refusal, fresh destination behavior, private redaction
rules, exact exceptions, public-path mapping and deterministic output. Structural
validation checks text/non-executable files, source syntax, guide links, the exact
exported file set and hashes, and the allowlist digest. Neither proves privacy.

The selected macOS suite covers transitions, disposable Git admission,
advisory project context, compatibility-policy logic, mocked remote-desktop tunnel
behavior, affected-source closure and bound execution, bounded child commands,
and disposable custody namespace, durable-record
and interrupted-transaction fixtures. The custody fixtures use Darwin's native
filesystem provider, so this combined runner requires macOS, Python 3.11+ and Git.
Two explicitly named tests
are reported SKIPPED: one reads deliberately omitted operational
`codex/hooks.json`; the other compares deliberately omitted private Git
predecessor objects. Two additional bounded-command tests reported a native
`EPERM` while observing their own child process groups in this test environment;
they retain UNKNOWN rather than claiming process-group settlement. Native
settlement coverage for those cases is therefore incomplete here.
No authority-bearing file or Git ancestry is fabricated.
The version-floor test compares source constants instead of a private observed
version manifest. These differences are part of the public test scope.

The exported Swift Git-observer implementation and root-broker tests are available
for review but are not executed by this Python runner. Likewise, the optional
game-successor and actual delivery-closure tests require omitted operational
inputs or the private repository layout; they are exported for inspection, not
included in the selected suite. This publication
does not claim a rebuilt or newly installed privileged broker or game runtime.

The entire historical test suite is not a portable acceptance suite. These tests
do not install the harness, exercise native consent, certify a fresh Mac, prove
root policy, establish Windows connectivity or verify running games. Tests and
structural checks must run on the final export, not a preceding candidate.

Publication additionally requires independent review of the actual full tree
and diff, including authored guides and export tools, for private identifiers,
credential patterns, personal narratives, source completeness and licensing.
Pattern scanning alone cannot guarantee absence of sensitive data.
