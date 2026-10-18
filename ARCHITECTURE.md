# Public reference architecture

This file governs the public reference release, not any installed workstation.

The implementation separates desired configuration, observations, authorization,
and mutation. The `aid` facade routes work; doctors inspect state; reviewed
configuration transitions bind changes to source; typed Swift administrator
operations limit privileged actions. Unknown code receives bounded inspection
and isolation before execution; ordinary project editing does not require a
custom trust registry, workstation doctor or harness adoption. Skills and context hooks guide agents but
are not a security boundary by themselves.

The intended live layout separates `~/AIDev/control` (desired-state source) from
repositories, temporary work, observations, and application-owned data. Existing
applications remain in canonical macOS locations. Each payload has one primary
installation/update owner. Secrets and recovery material stay outside ordinary
Git. Public reference files confer no permission to change a host.

## Public release boundary

`reference/` preserves implementation source with personal names and aliases
replaced. It is deliberately not the accepted control repository. Private Git
history, acceptance evidence, installation bundles and selected host manifests
are absent. Authored public examples live outside runtime discovery and are not
installation inputs. Historical fixed hashes and
cross-references may be unresolved; they must not be replaced with invented PASS
records. Original operating notes and incident history are not distributed.

No automatic activation, privilege grant, trust import, or system update occurs
when cloning this repository or running the selected public tests.

Contributions should distinguish unit-tested logic, a built program, and a
validated installation. A future portable bootstrap needs its own reviewed
configuration, acceptance criteria and rollback tests. Keep machine identifiers,
credentials, raw observations and private history out of contributions.
