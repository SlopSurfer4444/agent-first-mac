# Public validation

Current export validation: 14 exporter tests passed; the selected reference suite
ran 218 tests with 217 passing and one explicit skip. Structure/provenance checks
passed for 301 text files, including 282 exported sources. The exact source
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

The selected portable suite covers transitions, disposable Git admission,
advisory project context and compatibility-policy logic. One explicitly named
project-context test is reported SKIPPED because it reads deliberately omitted
operational `codex/hooks.json`; no authority-bearing file is fabricated for it.
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
