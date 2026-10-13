"""Pure successor classification; never execution admission or config rewriting.

Callers supply independently admitted *private* plugin/MCP projections, never
projections copied automatically from the current candidate. Project path
checks are lexical only: they prove neither filesystem identity nor trust.
Descriptor/identity checks, signed-runtime attestation, integration review,
managed-file checks and per-operation custody remain caller responsibilities.
No parsed private values or parser diagnostics escape the public result.
"""

import re

from vendor.tomli import TOMLDecodeError, loads


MAX_CONFIG_BYTES = 1024 * 1024
HOOK_SLOTS = frozenset(("session_start:0:0", "pre_tool_use:0:0", "stop:0:0"))


class ContractError(ValueError):
    """A fixed, redacted policy failure (never a TOML parser exception)."""


def _path(value):
    if type(value) is not str or not value.startswith("/"):
        return False
    if any(ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
        return False
    return all(part not in ("", ".", "..") for part in value[1:].split("/"))


def _same(left, right):
    """Type-exact comparison: booleans are not integers; mapping order matters.

Preserving table/key order also preserves the previously exact integration
ordering boundary. No TOML reserialization is used for this comparison.
"""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return (list(left) == list(right)
                and all(_same(left[key], right[key]) for key in left))
    if type(left) is list:
        return len(left) == len(right) and all(_same(a, b) for a, b in zip(left, right))
    return left == right


def _result(verdict, reasons, count=None):
    return {
        "schema": 1,
        "verdict": verdict,
        "reasonCodes": reasons,
        "projectCount": count,
        "executionAdmission": False,
        "configMutationAuthorized": False,
        "trustMutationAuthorized": False,
    }


def _admission(control_root, hook_source, hook_records, plugins, mcp):
    if not _path(control_root) or not _path(hook_source):
        return False
    if type(hook_records) is not dict or set(hook_records) != HOOK_SLOTS:
        return False
    if any(type(value) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
           for value in hook_records.values()):
        return False
    return all(value is None or type(value) is dict for value in (plugins, mcp))


def classify(config_bytes, *, control_root, hook_source, hook_records,
             admitted_plugins, admitted_mcp):
    """Classify in-memory TOML without authorizing execution or changing bytes.

``hook_records`` maps the three HOOK_SLOTS to independently reviewed hashes.
Integration arguments are full parsed ``plugins``/``mcp_servers`` mappings;
``None`` means no admission exists. Even empty mappings need explicit admission.
An absent projects table is a valid zero-project collection. Each present
project must contain exactly one trusted/untrusted trust_level value; that
observed value is preserved, never promoted or interpreted as execution rights.
Unknown non-managed settings remain opaque and must be preserved byte-exactly.
"""
    if not _admission(control_root, hook_source, hook_records,
                      admitted_plugins, admitted_mcp):
        return _result("invalid", ["admission_contract_invalid"])
    if type(config_bytes) is not bytes or not 0 < len(config_bytes) <= MAX_CONFIG_BYTES:
        return _result("invalid", ["config_bytes_invalid"])
    try:
        document = loads(config_bytes.decode("utf-8", "strict"))
    except (TOMLDecodeError, UnicodeError, ValueError, RecursionError, OverflowError):
        # Do not chain, return, log, or interpolate parser diagnostics.
        return _result("invalid", ["config_toml_invalid"])
    if (type(document.get("approval_policy")) is not str
            or document.get("approval_policy") != "never"
            or type(document.get("sandbox_mode")) is not str
            or document.get("sandbox_mode") != "danger-full-access"):
        return _result("invalid", ["managed_scalars_invalid"])
    hooks = document.get("hooks")
    expected_hooks = {hook_source + ":" + slot: {"trusted_hash": hook_records[slot]}
                      for slot in ("session_start:0:0", "pre_tool_use:0:0", "stop:0:0")}
    # No executable inline hook, extra state entry or trust-bypass field is allowed.
    if (type(hooks) is not dict or set(hooks) != {"state"}
            or type(hooks["state"]) is not dict
            or set(hooks["state"]) != set(expected_hooks)
            or any(not _same(hooks["state"][key], expected_hooks[key])
                   for key in expected_hooks)):
        return _result("invalid", ["hook_contract_invalid"])
    projects = document.get("projects", {})
    if type(projects) is not dict:
        return _result("invalid", ["project_records_invalid"])
    for identity, record in projects.items():
        if (not _path(identity) or identity == control_root or type(record) is not dict
                or set(record) != {"trust_level"}
                or type(record["trust_level"]) is not str
                or record["trust_level"] not in ("trusted", "untrusted")):
            return _result("invalid", ["project_records_invalid"])
    reasons = []
    try:
        for key, admitted, reason in (
                ("plugins", admitted_plugins, "plugins_need_review"),
                ("mcp_servers", admitted_mcp, "mcp_need_review")):
            observed = document.get(key, {})
            if (type(observed) is not dict
                    or any(type(name) is not str or not name or type(row) is not dict
                           for name, row in observed.items())):
                return _result("invalid", ["integration_records_invalid"])
            if admitted is None or not _same(observed, admitted):
                reasons.append(reason)
    except RecursionError:
        return _result("invalid", ["admission_contract_invalid"])
    return _result("needs-review" if reasons else "ready", reasons, len(projects))


def assert_preserved(before, after):
    """Require exact operation-local bytes, including comments and whitespace.

This does not verify file metadata/identity or confer admission. Callers retain
the original observations privately; no digest or private value is returned.
"""
    if type(before) is not bytes or type(after) is not bytes:
        raise ContractError("preservation_bytes_invalid") from None
    if before != after:
        raise ContractError("config_bytes_changed") from None
