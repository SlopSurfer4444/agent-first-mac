# Scope and limitations

This publication is a separate repository with clean history. The original
workstation repository and installed configuration were not modified to create it.

Included: implementation source, tests, generic schemas, sanitized example
contracts, pinned dependency metadata, and a public architecture overview.

Excluded: original Git history; all saved acceptance/observation evidence;
installation bundles and compiled binaries; private trust registry; workstation
inventory/acceptance manifest; Codex inventory and live hook/preset configuration;
recovery/closure snapshots; original operating/incident and coordination notes; experimental Wine
patch/build packets and their logs. The Wine/launcher integration source remains,
but neither games nor an operational Wine installation is included.

Personal user and host aliases were replaced in paths and contents. Example
manifests are wrapped and relocated, not silently represented as ready-to-install
state. Owner authorization/decision and recovery/observation fields are removed
from example manifests; they are illustrative data shapes, not complete runtime
inputs. Original checksum/commit anchors are not recomputed into fabricated trust.
References to omitted files are expected in historical source and documentation.

The portable test runner checks selected logic only. It does not certify the
whole historical suite, root broker installation, a new Mac, compatibility with
future Codex versions, or a working Windows bridge. No timing or live PASS from
the original machine is a result for this public checkout.

The public version-comparator regression compares the two implementation source
constants instead of reading an omitted private observed-version manifest.
That comparison does not assert an installed CLI version.

Before publishing, the exported files are inspected for recognizable credential
patterns and personal identifiers, with an independent review of the actual
candidate. Pattern scanning is not a mathematical guarantee against all secrets.
Do not put sensitive data into an issue when reporting a suspected leak.
