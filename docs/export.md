# Refreshing the public reference

The public repository has its own history. Never push a private control branch,
bundle or history into it. Export selected committed text into a new scratch
directory, review the resulting candidate, then integrate that source snapshot
into a task branch of this public repository.

```sh
python3 tools/export_reference.py --source /absolute/source/repository \
  --commit FULL_40_CHARACTER_COMMIT --destination /private/tmp/new-export-stage \
  --redactions /absolute/private/redaction-policy.json
```

The destination must not exist. The exporter does not overlay, delete, install,
activate, push or copy source Git history. An interrupted staging directory is
retained; inspect it and select a different fresh destination, never use it as
a completed export. Arguments are examples, not a host installation procedure.

`tools/export-files.json` is an explicit per-file public-path allowlist. New upstream files
do not enter a release automatically. Each addition needs content/privacy and
dependency review. Only selected source categories are accepted: no operating
history, private evidence, runtime manifests, host policy, profiles or bundles.
Vendor source and its notices remain byte-identical. Exported payload files are
non-executable text; this is accident prevention, not a sandbox.

Private redaction rules remain outside the public repository; only their digest
is recorded. The public tools and fixtures contain invented identifiers, never
the original values being removed. Known personal path aliases are replaced. Credential-shaped strings and stable
identifier patterns cause refusal rather than silent credential redaction.
Scanning is incomplete: arbitrary personal narratives and identifiers require
human/independent source review. Do not weaken a detector to make a candidate
pass without identifying and testing the precise false-positive case.

The exporter retains historical commit/hash constants as implementation, not
fabricated trust. The one public test adaptation compares source version-floor
constants instead of loading an omitted private observation manifest. It is an
exact guarded transformation, not a general test-rewriting facility.

`export-provenance.json` records the explicit source commit, allowlist digest and
exported output hashes, not the private source path or machine observations.
Top-level public guides and authored examples are maintained independently; do
not replace them with upstream private README or operational notes.

Before publication, inspect the entire candidate and diff, validate local guide
links, run exporter fixtures and the selected public suite, parse text formats,
check vendor/license equality, and verify there are no symlinks, binary or
executable payloads. Recorded old test counts are not current acceptance.
Push only after the owner-authorized publication conditions are satisfied.
