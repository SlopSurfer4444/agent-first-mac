# Public export validation

Checks performed on the sanitized source candidate before initial publication:

- `python3 tools/test_reference.py`: **199 tests passed**. This selected suite
  covers configuration transitions, disposable Git admission, project context
  boundaries and compatibility-policy logic. It does not invoke installation.
- AST parsing: **190 Python source files** parsed successfully.
- JSON parsing: **41 JSON files** parsed successfully.
- `git diff --cached --check`: passed.
- Six vendored Tomli files compared byte-for-byte with the source snapshot:
  unchanged, including license and provenance.
- Actual export independently inspected for credential patterns, original
  user/host/project identifiers, saved private evidence, binaries, symlinks and
  licensing boundaries. Identified personal narratives and labels were removed.

These are bounded source-release checks, not an audit guarantee or acceptance
of a fresh-machine installation. See PUBLIC-RELEASE.md for omitted components
and the distinction between portable tests and historical integration tests.
