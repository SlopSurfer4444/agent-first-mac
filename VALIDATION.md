# Public validation

Current export validation (2026-10-18): 14 exporter tests passed; the selected reference suite
ran 256 tests with 254 passing and two explicit skips. Structure/provenance checks
passed for 340 text files, including 321 exported sources. The exact source
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
behavior and disposable custody namespace fixtures. The custody fixtures use Darwin's native
filesystem provider, so this combined runner requires macOS, Python 3.11+ and Git.
Two explicitly named tests
are reported SKIPPED: one reads deliberately omitted operational
`codex/hooks.json`; the other compares deliberately omitted private Git
predecessor objects. No authority-bearing file or Git ancestry is fabricated.
The version-floor test compares source constants instead of a private observed
version manifest. These differences are part of the public test scope.

The entire historical test suite is not a portable acceptance suite. These tests
do not install the harness, exercise native consent, certify a fresh Mac, prove
root policy, establish Windows connectivity or verify running games. Tests and
structural checks must run on the final export, not a preceding candidate.

Publication additionally requires independent review of the actual full tree
and diff, including authored guides and export tools, for private identifiers,
credential patterns, personal narratives, source completeness and licensing.
Pattern scanning alone cannot guarantee absence of sensitive data.
