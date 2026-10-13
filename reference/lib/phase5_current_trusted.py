"""Pure current trusted-task/discovery contracts; no transport or entry point.

Every function requires independently admitted legacy definitions. Never import
the historical runner here or call its live_snapshot, real_run, manifest gate,
owner-layout, temporary-file or process helpers. Root owns fresh physical source
bindings, schema/result files, process settlement and the one-request limit.

Discovery preserves the legacy app-server argv, explicit cwd and clean env. It
does NOT claim exec's ignore-user-config/ignore-rules/ephemeral flags are present
or supported on that transport. Only the separate exec builder preserves those
task flags. Discovery/task output never proves hook execution, model cognition,
mutation absence, a native event-ID join, or any new authority.
"""

from dataclasses import dataclass, field
import functools
import math
from pathlib import Path
import re


MAX_BYTES = 4 * 1024 * 1024
SOURCE_IDS = frozenset(("hooks-definition", "hook-router", "skill-definition", "skill-metadata"))
SOURCE_EVENTS = {"session_start:0:0": "SessionStart", "pre_tool_use:0:0": "PreToolUse", "stop:0:0": "Stop"}


class TrustedError(ValueError):
    pass


def _require(value):
    if value is not True:
        raise TrustedError("current_trusted_contract_required") from None


def _redacted(function):
    @functools.wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception:
            raise TrustedError("current_trusted_contract_required") from None
    return checked


def _plain(definitions, value):
    if type(value) is bytes:
        _require(len(value) <= MAX_BYTES)
        value = definitions.strict_json_text(value.decode("utf-8", "strict"), "trusted_input")
    budget = [40000, MAX_BYTES]
    def copy(item, depth=0):
        budget[0] -= 1
        _require(depth <= 16 and budget[0] >= 0)
        kind = type(item)
        if kind is str:
            budget[1] -= len(item.encode("utf-8"))
            _require(budget[1] >= 0)
            return item
        if kind in (bool, type(None)):
            return item
        if kind is int:
            _require(item.bit_length() <= 64)
            return item
        if kind is float:
            _require(math.isfinite(item))
            return item
        if kind is list:
            return [copy(child, depth + 1) for child in item]
        _require(kind is dict and all(type(key) is str for key in item))
        return {copy(key, depth + 1): copy(child, depth + 1) for key, child in item.items()}
    return copy(value)


def _path(definitions, value):
    _require(type(value) is str and 1 < len(value) <= 1024 and str(Path(value)) == value)
    _require(definitions.safe_dynamic(value, "trusted_path") == value)
    return Path(value)


def _layout(definitions, home, control, hook_hashes):
    home, control = _path(definitions, home), _path(definitions, control)
    _require(control == home / "AIDev/control")
    hashes = _plain(definitions, hook_hashes)
    _require(type(hashes) is dict and set(hashes) == set(SOURCE_EVENTS)
             and all(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
                     for value in hashes.values()) and hashes == definitions.HASHES)
    _require(definitions.EVENTS == {"session_start:0:0": "sessionStart", "pre_tool_use:0:0": "preToolUse", "stop:0:0": "stop"})
    return home, home / ".codex", control, hashes


@dataclass(frozen=True, repr=False)
class Launch:
    argv: tuple = field(repr=False)
    environment: dict = field(repr=False)
    cwd: str = field(repr=False)


def _same_launch(launch, expected):
    _require(type(launch) is Launch and type(launch.argv) is tuple
             and all(type(arg) is str for arg in launch.argv)
             and type(launch.environment) is dict
             and all(type(key) is str and type(value) is str for key, value in launch.environment.items())
             and type(launch.cwd) is str and launch.argv == expected.argv
             and launch.environment == expected.environment and launch.cwd == expected.cwd)


@_redacted
def discovery_launch(definitions, *, home, control, hook_hashes):
    home, codex_home, control, _ = _layout(definitions, home, control, hook_hashes)
    return Launch(tuple(definitions.app_server_command(home, control)),
                  definitions.clean_environment(home, codex_home), str(control))


@_redacted
def discovery_command_contract(definitions, launch, *, home, control, hook_hashes):
    expected = discovery_launch(definitions, home=home, control=control, hook_hashes=hook_hashes)
    _same_launch(launch, expected)
    return True


def _entry(value, control, collection):
    _require(type(value) is dict and type(value.get("data")) is list and len(value["data"]) == 1)
    entry = value["data"][0]
    _require(type(entry) is dict and entry.get("cwd") == str(control)
             and entry.get("errors") == [] and type(entry.get(collection)) is list)
    _require(entry.get("warnings", []) == [])
    return entry


def _expected_hooks(definitions, sources):
    document = _plain(definitions, sources["hooks-definition"])
    _require(type(document) is dict and set(document) == {"hooks"}
             and set(document["hooks"]) == set(SOURCE_EVENTS.values()))
    expected = {}
    for slot, event in SOURCE_EVENTS.items():
        groups = document["hooks"][event]
        _require(type(groups) is list and len(groups) == 1 and type(groups[0]) is dict)
        group = groups[0]
        _require(set(group) <= {"matcher", "hooks"} and type(group.get("hooks")) is list and len(group["hooks"]) == 1)
        handler = group["hooks"][0]
        _require(type(handler) is dict and set(handler) <= {"type", "command", "timeout", "statusMessage", "async"}
                 and handler.get("type") == "command" and type(handler.get("command")) is str
                 and type(handler.get("timeout")) is int and 0 < handler["timeout"] < 2 ** 64
                 and handler.get("async", False) is False)
        _require(group.get("matcher") is None or type(group["matcher"]) is str)
        _require(handler.get("statusMessage") is None or type(handler["statusMessage"]) is str)
        expected[slot] = {"command": handler["command"], "timeoutSec": handler["timeout"],
                          "matcher": group.get("matcher"), "statusMessage": handler.get("statusMessage")}
    return expected


def _skill_shape(definitions, skill):
    _require(type(skill) is dict and {"name", "description", "enabled", "path", "scope"} <= set(skill)
             and type(skill["name"]) is str and type(skill["description"]) is str
             and type(skill["enabled"]) is bool and skill["scope"] in ("user", "repo", "system", "admin"))
    _path(definitions, skill["path"])
    for key in ("pluginId", "shortDescription"):
        _require(skill.get(key) is None or type(skill[key]) is str)
    interface = skill.get("interface")
    if interface is not None:
        _require(type(interface) is dict)
        for key in ("brandColor", "defaultPrompt", "displayName", "iconLarge", "iconLargeUrl",
                    "iconSmall", "iconSmallUrl", "shortDescription"):
            _require(interface.get(key) is None or type(interface[key]) is str)
        for key in ("iconLarge", "iconSmall"):
            if interface.get(key) is not None:
                _path(definitions, interface[key])
    dependencies = skill.get("dependencies")
    if dependencies is not None:
        _require(type(dependencies) is dict and type(dependencies.get("tools")) is list)
        for tool in dependencies["tools"]:
            _require(type(tool) is dict and type(tool.get("type")) is str and type(tool.get("value")) is str)
            _require(all(tool.get(key) is None or type(tool[key]) is str
                         for key in ("command", "description", "transport", "url")))


@_redacted
def validate_discovery(definitions, hooks_result, skills_result, *, home, control,
                       hook_hashes, expected_sources, installed_hashes):
    """Expected bytes are independently admitted source, never copied live input.

installed_hashes must come from root's fresh held physical observations. List
responses carry no skill-file hash and cannot establish that physical binding.
Only the current reviewed single-line skill front matter is interpreted here.
Unknown bounded descriptive response fields are inert, not new capabilities.
"""
    home, codex_home, control, hashes = _layout(definitions, home, control, hook_hashes)
    _require(type(expected_sources) is dict and set(expected_sources) == SOURCE_IDS
             and type(installed_hashes) is dict and set(installed_hashes) == SOURCE_IDS)
    _require(all(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES for raw in expected_sources.values())
             and sum(map(len, expected_sources.values())) <= MAX_BYTES)
    for identity, raw in expected_sources.items():
        digest = installed_hashes[identity]
        _require(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
                 and definitions.sha256_bytes(raw) == digest)
    expected = _expected_hooks(definitions, expected_sources)
    hooks = _entry(_plain(definitions, hooks_result), control, "hooks")
    _require(hooks.get("warnings") == [] and len(hooks["hooks"]) == 3)
    source_path, observed = str(codex_home / "hooks.json"), set()
    required = {"currentHash", "displayOrder", "enabled", "eventName", "isManaged", "key",
                "source", "sourcePath", "timeoutSec", "trustStatus", "handlerType", "command"}
    for hook in hooks["hooks"]:
        _require(type(hook) is dict and required <= set(hook))
        slot = next((slot for slot in expected if hook["key"] == source_path + ":" + slot), None)
        _require(slot is not None and slot not in observed)
        _require(hook["enabled"] is True and hook["isManaged"] is False and hook["handlerType"] == "command"
                 and hook["source"] == "user" and hook["sourcePath"] == source_path
                 and hook["trustStatus"] == "trusted" and hook["currentHash"] == hashes[slot]
                 and hook["eventName"] == definitions.EVENTS[slot] and hook.get("async", False) is False
                 and hook.get("pluginId") is None)
        _require(type(hook["displayOrder"]) is int and -2 ** 63 <= hook["displayOrder"] < 2 ** 63
                 and type(hook["timeoutSec"]) is int)
        # Current admitted source omits this configured nullable-uint threshold.
        # Omission/null means the 2,500-token default; a numeric 2500 is still an
        # explicit configuration, not the schema's absent/default representation.
        _require(hook.get("additionalContextLimit") is None)
        _require(all(hook.get(key) == value for key, value in expected[slot].items()))
        _require(not {"server", "tool", "prompt", "agent"}.intersection(hook))
        observed.add(slot)
    skills = _entry(_plain(definitions, skills_result), control, "skills")["skills"]
    _require(len(skills) <= 2048)
    path = str(codex_home / "skills/manage-workstation/SKILL.md")
    selected, identities = [], set()
    for skill in skills:
        _skill_shape(definitions, skill)
        identity = (skill["scope"], skill["path"])
        _require(identity not in identities)
        identities.add(identity)
        if skill["name"] == "manage-workstation" or skill["path"] == path:
            selected.append(skill)
    _require(len(selected) == 1)
    skill = selected[0]
    _require(skill["name"] == "manage-workstation" and skill["path"] == path and skill["scope"] == "user"
             and skill["enabled"] is True and skill.get("pluginId") is None
             and (skill.get("dependencies") is None or skill["dependencies"] == {"tools": []}))
    lines = expected_sources["skill-definition"].decode("utf-8", "strict").splitlines()
    _require(lines[0] == "---")
    header = lines[1:lines.index("---", 1)]
    names = [line[6:] for line in header if line.startswith("name: ")]
    descriptions = [line[13:] for line in header if line.startswith("description: ")]
    _require(names == ["manage-workstation"] and descriptions == [skill["description"]])
    return {"verdict": "matched", "hookCount": 3, "selectedSkillCount": 1,
            "hookExecutionProven": False, "skillUseProven": False, "modelRequestAuthorized": False,
            "executionAdmission": False, "phase5Accepted": False, "phase6Allowed": False}


@_redacted
def task_material(definitions):
    schema = _plain(definitions, definitions.canonical_schema())
    _require(definitions.audit_schema(schema) is True and type(definitions.FIXED_TASK) is str)
    return {"prompt": definitions.FIXED_TASK, "schema": schema, "maximumRequests": 1,
            "model": "gpt-5.6-sol", "reasoningEffort": "max", "modelRequestAuthorized": False}


@_redacted
def exec_launch(definitions, *, home, control, hook_hashes, schema_path, result_path):
    home, codex_home, control, _ = _layout(definitions, home, control, hook_hashes)
    schema_path, result_path = _path(definitions, schema_path), _path(definitions, result_path)
    _require(schema_path != result_path)
    command = definitions.build_exec_command(home, codex_home, control, schema_path, result_path)
    _require(definitions.command_contract(command, home, codex_home, control, schema_path, result_path) is True)
    return Launch(tuple(command), definitions.clean_environment(home, codex_home), str(control))


@_redacted
def exec_command_contract(definitions, launch, **parameters):
    expected = exec_launch(definitions, **parameters)
    _same_launch(launch, expected)
    return True


@_redacted
def validate_task_output(definitions, value):
    """Same strict schema/constants; JSON object ordering is not semantic.

Reject duplicate keys before normalizing only object order for the historical
validator. List order, exact scalar types and constant checks are unchanged.
"""
    schema, value = task_material(definitions)["schema"], _plain(definitions, value)
    def ordered(node, item):
        if node["type"] != "object":
            return item
        _require(type(item) is dict and set(item) == set(node["properties"]))
        return {key: ordered(child, item[key]) for key, child in node["properties"].items()}
    _require(definitions.validate_output(ordered(schema, value)) is True)
    return {"verdict": "schema-valid", "supportingEvidenceOnly": True,
            "hookExecutionProven": False, "skillUseProven": False, "phase5Accepted": False}
