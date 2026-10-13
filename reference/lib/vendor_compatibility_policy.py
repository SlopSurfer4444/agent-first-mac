"""Pure, bounded interpretation of caller-owned offline capability observations.

No I/O, imports of operational callers, discovery, process ownership or admission.
This checks a small documented generated-schema subset, not JSON Schema in general.
Unknown schema shapes remain unproven. Compatible means only this source interface;
signature, profile semantics, runtime state and successful child settlement belong
to the caller. Input dictionaries must originate from duplicate-rejecting parsing.
"""

import json
import math
import re


MINIMUM_VERSION = "codex-cli 0.145.0-alpha.18"
MAX_TEXT_BYTES = 256 * 1024
MAX_SCHEMA_BYTES = 4 * 1024 * 1024
FEATURE_KEYS = (
    "apps", "browser_use", "browser_use_external", "browser_use_full_cdp_access",
    "computer_use", "in_app_browser", "plugins", "remote_plugin",
    "skill_mcp_dependency_install",
)
EXEC_FLAGS = frozenset((
    "--strict-config", "--ignore-user-config", "--ignore-rules", "--ephemeral",
    "--json", "--profile", "--cd", "--sandbox", "--model", "--config",
    "--output-schema", "--output-last-message",
))
APP_SERVER_FLAGS = frozenset(("--strict-config", "--listen", "--config"))
REASON_CODES = frozenset((
    "version_input_invalid", "version_below_floor", "exec_help_unproven",
    "mcp_help_unproven", "app_server_help_unproven", "features_unproven",
    "schema_input_invalid", "schema_shape_unproven", "schema_contract_changed",
))
_ANNOTATIONS = frozenset(("$schema", "$id", "$comment", "title", "description", "default", "examples", "deprecated"))
_KEYS = _ANNOTATIONS | frozenset((
    "$ref", "type", "properties", "required", "additionalProperties", "items",
    "enum", "const", "oneOf", "anyOf", "allOf", "format", "minimum", "maximum",
    "minItems", "maxItems", "minLength", "maxLength",
))
_JSON_TYPES = frozenset(("object", "array", "string", "integer", "number", "boolean", "null"))
_INTEGER_FORMATS = {"int64": (-2 ** 63, 2 ** 63 - 1),
                    "uint64": (0, 2 ** 64 - 1), "uint": (0, None)}
_ENVELOPE_KEYS = frozenset(("id", "method", "params", "result", "error", "jsonrpc"))


class PolicyError(ValueError):
    def __init__(self, reason="schema_input_invalid"):
        self.reason = reason if reason in REASON_CODES else "schema_input_invalid"
        super().__init__(self.reason)


def _need(condition, reason="schema_contract_changed"):
    if condition is not True:
        raise PolicyError(reason)


def _plain(value):
    """Reject custom containers, cycles, excessive input and bool-as-number traps."""
    budget = [250000, MAX_SCHEMA_BYTES]
    def visit(item, depth):
        budget[0] -= 1
        _need(depth <= 64 and budget[0] >= 0, "schema_input_invalid")
        kind = type(item)
        if kind is str:
            budget[1] -= len(item.encode("utf-8", "strict"))
            _need(budget[1] >= 0, "schema_input_invalid")
        elif kind in (bool, type(None)):
            pass
        elif kind is int:
            _need(item.bit_length() <= 128, "schema_input_invalid")
        elif kind is float:
            _need(math.isfinite(item), "schema_input_invalid")
        elif kind is list:
            for child in item:
                visit(child, depth + 1)
        elif kind is dict:
            for key, child in item.items():
                _need(type(key) is str, "schema_input_invalid")
                visit(key, depth + 1)
                visit(child, depth + 1)
        else:
            raise PolicyError()
    visit(value, 0)
    _need(type(value) is dict, "schema_input_invalid")


def parse_schema(raw):
    """Strict JSON entry for adapters; errors contain only a fixed reason code."""
    def pairs(items):
        result = {}
        for key, value in items:
            _need(key not in result, "schema_input_invalid")
            result[key] = value
        return result
    def constant(_):
        raise PolicyError()
    def integer(token):
        _need(len(token) <= 40, "schema_input_invalid")
        return int(token)
    result = None
    try:
        _need(type(raw) is bytes and 0 < len(raw) <= MAX_SCHEMA_BYTES, "schema_input_invalid")
        result = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                            parse_constant=constant, parse_int=integer)
        _plain(result)
    except Exception:
        failed = True
    else:
        failed = False
    # Raise outside the except block: even formatted tracebacks have no raw context.
    if failed:
        raise PolicyError() from None
    return result


def _text(raw):
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_TEXT_BYTES)
    value = raw.decode("utf-8", "strict")
    _need(all(ord(char) >= 32 or char in "\n\r\t" for char in value))
    return value


def _version_at_or_above(observed, floor=MINIMUM_VERSION):
    # Same floor ordering as the accepted phase5-trusted-probe pure comparator.
    pattern = r"codex-cli ([0-9]+(?:\.[0-9]+)+(?:-[0-9A-Za-z.]+)?)"
    a, b = re.fullmatch(pattern, observed), re.fullmatch(pattern, floor)
    if a is None or b is None:
        return False
    def parts(value):
        number, _, suffix = value.partition("-")
        return tuple(int(item) for item in number.split(".")), suffix
    an, ap = parts(a.group(1))
    bn, bp = parts(b.group(1))
    width = max(len(an), len(bn))
    an, bn = an + (0,) * (width - len(an)), bn + (0,) * (width - len(bn))
    if an != bn:
        return an > bn
    if not ap or not bp:
        return not ap
    def pre(value):
        if any(not item for item in value.split(".")):
            return None
        return tuple((0, int(item)) if item.isdecimal() else (1, item)
                     for item in value.split("."))
    av, bv = pre(ap), pre(bp)
    return av is not None and bv is not None and av >= bv


def _flags(raw, required):
    text = _text(raw)
    found = set(re.findall(r"^[ \t]*(?:-[A-Za-z],[ \t]+)?(--[a-z][a-z0-9-]*)(?=[ \t,=<]|$)",
                           text, re.MULTILINE))
    _need(required <= found)


def _features(raw):
    found = {}
    for line in _text(raw).splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*)[ \t]+([A-Za-z][A-Za-z0-9_ -]*?)[ \t]+(true|false)", line.strip())
        _need(match is not None and match.group(1) not in found)
        found[match.group(1)] = match.group(3)
    _need(all(found.get(key) == "false" for key in FEATURE_KEYS))


class _Schema:
    """Small structural queries and fixed-request checks; never remote $ref I/O."""
    def __init__(self, root):
        _plain(root)
        _need(root.get("$schema") == "http://json-schema.org/draft-07/schema#"
              and type(root.get("definitions")) is dict, "schema_shape_unproven")
        self.root = root
        self.steps = 20000
        self.defs = root["definitions"]
        self.v2 = self.defs.get("v2", self.defs)
        _need(type(self.v2) is dict, "schema_shape_unproven")

    def node(self, value, trail=()):
        self.steps -= 1
        _need(self.steps >= 0 and len(trail) <= 32 and type(value) is dict,
              "schema_shape_unproven")
        _need(set(value) <= _KEYS, "schema_shape_unproven")
        if "$ref" in value:
            ref = value["$ref"]
            _need(set(value) <= _ANNOTATIONS | {"$ref"} and type(ref) is str
                  and ref.startswith("#/definitions/") and ref not in trail,
                  "schema_shape_unproven")
            target = self.root
            for key in ref[2:].split("/"):
                _need(type(target) is dict and key in target and "~" not in key,
                      "schema_shape_unproven")
                target = target[key]
            return self.node(target, trail + (ref,))
        if "allOf" in value:
            rows = value["allOf"]
            _need(set(value) <= _ANNOTATIONS | {"allOf"} and type(rows) is list
                  and len(rows) == 1, "schema_shape_unproven")
            return self.node(rows[0], trail + ("allOf",))
        for key in ("minimum", "maximum"):
            if key in value:
                _need(type(value[key]) in (int, float) and math.isfinite(value[key]),
                      "schema_shape_unproven")
        for key in ("minItems", "maxItems", "minLength", "maxLength"):
            if key in value:
                _need(type(value[key]) is int and value[key] >= 0, "schema_shape_unproven")
        if "format" in value:
            _need(type(value["format"]) is str and value["format"] in _INTEGER_FORMATS,
                  "schema_shape_unproven")
            kinds = value.get("type")
            kinds = kinds if type(kinds) is list else [kinds]
            _need(all(type(kind) is str for kind in kinds) and "integer" in kinds
                  and set(kinds) <= {"integer", "null"}, "schema_shape_unproven")
        if "additionalProperties" in value:
            _need(type(value["additionalProperties"]) in (bool, dict), "schema_shape_unproven")
        return value

    def types(self, value):
        node = self.node(value)
        if "type" in node:
            kinds = node["type"] if type(node["type"]) is list else [node["type"]]
            _need(bool(kinds) and all(type(x) is str and x in _JSON_TYPES for x in kinds)
                  and len(kinds) == len(set(kinds)), "schema_shape_unproven")
            result = set(kinds)
            # HookMetadata has object-level variants. Primitive intersections
            # need a broader schema interpreter, which this policy does not own.
            _need(not ({"oneOf", "anyOf"} & set(node)) or result == {"object"},
                  "schema_shape_unproven")
        else:
            key = "anyOf" if "anyOf" in node else "oneOf"
            rows = node.get(key)
            _need(set(node) <= _ANNOTATIONS | {key} and type(rows) is list
                  and 1 <= len(rows) <= 32, "schema_shape_unproven")
            result = set().union(*(self.types(row) for row in rows))
        if "enum" in node:
            rows = node["enum"]
            _need(type(rows) is list and rows and all(self.kind(row) in result
                  and self.formatted(node, row) for row in rows),
                  "schema_shape_unproven")
        if "const" in node:
            _need(self.kind(node["const"]) in result and self.formatted(node, node["const"]),
                  "schema_shape_unproven")
        return result

    @staticmethod
    def kind(value):
        return {str: "string", bool: "boolean", int: "integer", float: "number",
                dict: "object", list: "array", type(None): "null"}.get(type(value))

    @staticmethod
    def formatted(node, value):
        if "format" not in node or value is None:
            return True
        lower, upper = _INTEGER_FORMATS[node["format"]]
        return type(value) is int and value >= lower and (upper is None or value <= upper)

    def typed(self, value, kinds):
        _need(self.types(value) == set(kinds.split("|")))

    def obj(self, value, required=()):
        node = self.node(value)
        self.typed(node, "object")
        fields = node.get("properties", {})
        needed = node.get("required", [])
        _need(type(fields) is dict and type(needed) is list
              and all(type(key) is str for key in needed)
              and len(needed) == len(set(needed)), "schema_shape_unproven")
        _need(set(required) <= set(needed))
        return fields

    def fields(self, value, specification, required=()):
        fields = self.obj(value, required)
        for key, kinds in specification.items():
            _need(key in fields)
            self.typed(fields[key], kinds)
        return fields

    def array(self, value):
        node = self.node(value)
        self.typed(node, "array")
        _need(type(node.get("items")) is dict, "schema_shape_unproven")
        return node["items"]

    def enum_has(self, value, expected):
        node = self.node(value)
        self.typed(node, "string")
        _need(type(node.get("enum")) is list and set(expected) <= set(node["enum"]))
        _need("const" not in node or all(node["const"] == value for value in expected))

    def nonnull(self, value):
        node = self.node(value)
        rows = node.get("anyOf")
        _need(set(node) <= _ANNOTATIONS | {"anyOf"} and type(rows) is list
              and len(rows) == 2, "schema_shape_unproven")
        selected = [row for row in rows if self.types(row) != {"null"}]
        _need(len(selected) == 1 and any(self.types(row) == {"null"} for row in rows),
              "schema_shape_unproven")
        return selected[0]

    def accepts(self, raw, value, depth=0):
        _need(depth <= 32, "schema_shape_unproven")
        if type(raw) is bool:
            return raw  # Generated wire payload slots explicitly use true schemas.
        node = self.node(raw)
        if self.kind(value) not in self.types(node):
            return False
        for key in ("enum", "const"):
            if key in node:
                candidates = node[key] if key == "enum" else [node[key]]
                if not any(type(value) is type(x) and value == x for x in candidates):
                    return False
        for key in ("oneOf", "anyOf"):
            if key in node:
                rows = node[key]
                _need(type(rows) is list and 1 <= len(rows) <= 32, "schema_shape_unproven")
                hits = sum(self.accepts(row, value, depth + 1) for row in rows)
                if (key == "oneOf" and hits != 1) or (key == "anyOf" and hits == 0):
                    return False
        if "type" not in node:
            return True  # The supported union's branches supplied all constraints.
        if type(value) is dict:
            fields = self.obj({**node, "type": "object"})
            if not set(node.get("required", [])) <= set(value):
                return False
            additional = node.get("additionalProperties", True)
            _need(type(additional) is bool, "schema_shape_unproven")
            for key, child in value.items():
                if key not in fields:
                    if not additional:
                        return False
                elif not self.accepts(fields[key], child, depth + 1):
                    return False
        if type(value) is list:
            item = self.array({**node, "type": "array"})
            if not all(self.accepts(item, child, depth + 1) for child in value):
                return False
        if type(value) in (str, list):
            lo, hi = ("minLength", "maxLength") if type(value) is str else ("minItems", "maxItems")
            if len(value) < node.get(lo, 0) or len(value) > node.get(hi, MAX_SCHEMA_BYTES):
                return False
        if type(value) in (int, float):
            if value < node.get("minimum", -math.inf) or value > node.get("maximum", math.inf):
                return False
            if not self.formatted(node, value):
                return False
        return True

    def method(self, collection, name):
        node = self.node(self.defs.get(collection))
        rows = node.get("oneOf")
        _need(set(node) <= _ANNOTATIONS | {"oneOf"} and type(rows) is list
              and 1 <= len(rows) <= 1000, "schema_shape_unproven")
        found = []
        for row in rows:
            _need(type(row) is dict and type(row.get("properties")) is dict,
                  "schema_shape_unproven")
            method = self.node(row["properties"].get("method"))
            values = method.get("enum")
            _need(type(values) is list and len(values) == 1
                  and self.types(method) == {"string"}, "schema_shape_unproven")
            if values == [name]:
                found.append(row)
        _need(len(found) == 1)
        return found[0]


def _request_samples():
    client = {"name": "phase5_plugin_catalog_observer", "title": "Phase 5 Plugin Catalog Observer", "version": "1.0.0"}
    return (
        (0, "initialize", {"clientInfo": client}),
        (1, "initialize", {"clientInfo": {"name": "phase5-trusted-probe-validator", "version": "1"},
                        "capabilities": {"experimentalApi": True}}),
        (2, "hooks/list", {"cwds": ["/fixture/cwd"]}),
        (3, "skills/list", {"cwds": ["/fixture/cwd"], "forceReload": False}),
        (1, "plugin/installed", {"cwds": [], "installSuggestionPluginNames": []}),
        (2, "plugin/list", {"cwds": [], "forceRefetch": False, "marketplaceKinds": ["vertical"]}),
    )


def _schema_contract(schema):
    s = _Schema(schema)
    for identity, method, params in _request_samples():
        node = s.method("ClientRequest", method)
        s.obj(node, ("id", "method", "params"))
        _need(s.accepts(node, {"id": identity, "method": method, "params": params}))
    _need(s.accepts(s.method("ClientNotification", "initialized"),
                    {"method": "initialized", "params": {}}))
    s.obj(s.defs.get("InitializeResponse"))
    for response, collection in (("HooksListResponse", "hooks"), ("SkillsListResponse", "skills")):
        fields = s.obj(s.v2.get(response), ("data",))
        row = s.array(fields.get("data"))
        entries = s.fields(row, {"cwd": "string", "errors": "array", collection: "array"},
                           ("cwd", "errors", collection))
        if collection == "hooks":
            s.fields(row, {"warnings": "array"}, ("warnings",))
            s.typed(s.array(entries["warnings"]), "string")
        s.array(entries["errors"])
        metadata = s.array(entries[collection])
        if collection == "skills":
            fields = s.fields(metadata, {"name": "string", "description": "string", "enabled": "boolean",
                                "path": "string", "scope": "string", "pluginId": "string|null",
                                "shortDescription": "string|null", "interface": "object|null",
                                "dependencies": "object|null"},
                     ("name", "description", "enabled", "path", "scope"))
            s.enum_has(fields["scope"], ("user", "repo", "system", "admin"))
            _need(set(s.node(fields["scope"])["enum"]) == {"user", "repo", "system", "admin"})
            for key, expected in (("name", "manage-workstation"), ("enabled", True),
                                  ("scope", "user"), ("pluginId", None)):
                _need(s.accepts(fields[key], expected))
            _need(s.accepts(fields["dependencies"], None)
                  or s.accepts(fields["dependencies"], {"tools": []}))
            s.fields(s.nonnull(fields["interface"]), {key: "string|null" for key in (
                "brandColor", "defaultPrompt", "displayName", "iconLarge", "iconLargeUrl",
                "iconSmall", "iconSmallUrl", "shortDescription")})
            tools = s.obj(s.nonnull(fields["dependencies"]), ("tools",))
            s.fields(s.array(tools.get("tools")), {
                "type": "string", "value": "string", "command": "string|null",
                "description": "string|null", "transport": "string|null", "url": "string|null",
            }, ("type", "value"))
        else:
            fields = s.fields(metadata, {
                "currentHash": "string", "displayOrder": "integer", "enabled": "boolean",
                "eventName": "string", "isManaged": "boolean", "key": "string", "source": "string",
                "sourcePath": "string", "timeoutSec": "integer", "trustStatus": "string",
                "additionalContextLimit": "integer|null", "matcher": "string|null",
                "statusMessage": "string|null", "pluginId": "string|null",
            }, ("currentHash", "displayOrder", "enabled", "eventName", "isManaged", "key",
                "source", "sourcePath", "timeoutSec", "trustStatus"))
            s.enum_has(fields["eventName"], ("sessionStart", "preToolUse", "stop"))
            s.enum_has(fields["source"], ("user",))
            s.enum_has(fields["trustStatus"], ("trusted",))
            for key, expected in (("enabled", True), ("isManaged", False),
                                  ("additionalContextLimit", None), ("pluginId", None)):
                _need(s.accepts(fields[key], expected))
            _need(s.node(fields["additionalContextLimit"]).get("default") is None)
            hook = s.node(metadata)
            variants = hook.get("oneOf")
            _need(type(variants) is list and 1 <= len(variants) <= 32, "schema_shape_unproven")
            command = [item for item in variants if s.node(item).get("properties", {}).get("handlerType", {}).get("enum") == ["command"]]
            _need(len(command) == 1)
            s.fields(command[0], {"handlerType": "string", "command": "string", "async": "boolean"},
                     ("handlerType", "command"))
            _need(s.accepts(s.obj(command[0])["async"], False))
    for response in ("PluginInstalledResponse", "PluginListResponse"):
        fields = s.obj(s.v2.get(response), ("marketplaces",))
        s.array(fields.get("marketplaceLoadErrors"))
        market = s.array(fields.get("marketplaces"))
        fields = s.fields(market, {"name": "string", "path": "string|null", "plugins": "array"},
                          ("name", "plugins"))
        plugin = s.array(fields["plugins"])
        fields = s.fields(plugin, {"authPolicy": "string", "enabled": "boolean", "id": "string",
                          "installPolicy": "string", "installed": "boolean", "name": "string",
                          "source": "object", "remotePluginId": "string|null",
                          "version": "string|null", "localVersion": "string|null"},
                 ("authPolicy", "enabled", "id", "installPolicy", "installed", "name", "source"))
        source = s.node(fields["source"])
        variants = source.get("oneOf")
        _need(type(variants) is list and len(variants) == 4, "schema_shape_unproven")
        by_kind = {}
        for row in variants:
            props = s.obj(row, ("type",))
            tag = s.node(props.get("type"))
            s.typed(tag, "string")
            values = tag.get("enum")
            _need(type(values) is list and len(values) == 1 and values[0] not in by_kind)
            by_kind[values[0]] = row
        _need(set(by_kind) == {"local", "git", "npm", "remote"})
        s.fields(by_kind["local"], {"path": "string"}, ("path",))
        s.fields(by_kind["git"], {"url": "string", "path": "string|null",
                                 "refName": "string|null", "sha": "string|null"}, ("url",))
        s.fields(by_kind["npm"], {"package": "string", "registry": "string|null",
                                 "version": "string|null"}, ("package",))
        _need(set(s.obj(by_kind["remote"])) == {"type"})


def _envelope_contract(envelopes):
    """Inspect the separate emitted JSONRPCMessage.json, never merged definitions.

    The generic ID domain can include strings, but our exact clients use integers.
    Non-reserved output metadata is ignored, as in catalog._Session._line. Every
    reserved field remains associated with exactly one supported message kind.
    """
    _need(type(envelopes) is dict, "schema_shape_unproven")
    s = _Schema(envelopes)
    names = ("JSONRPCRequest", "JSONRPCNotification", "JSONRPCResponse", "JSONRPCError")
    branches = envelopes.get("anyOf")
    expected = {"#/definitions/" + name for name in names}
    _need(set(envelopes) <= _ANNOTATIONS | {"definitions", "anyOf"}
          and type(branches) is list and len(branches) == len(names), "schema_shape_unproven")
    _need(all(type(row) is dict and set(row) == {"$ref"} and type(row["$ref"]) is str
              for row in branches), "schema_shape_unproven")
    _need({row["$ref"] for row in branches} == expected, "schema_shape_unproven")
    shapes = {
        "JSONRPCRequest": ({"id", "method", "params"}, {"id", "method"},
                           {"id": 0, "method": "initialize", "params": {"clientInfo": {"name": "sentinel", "version": "1"}}}),
        "JSONRPCNotification": ({"method", "params"}, {"method"},
                                {"method": "initialized", "params": {}}),
        "JSONRPCResponse": ({"id", "result"}, {"id", "result"}, {"id": 0, "result": {}}),
        "JSONRPCError": ({"id", "error"}, {"id", "error"},
                         {"id": 0, "error": {"code": -32603, "message": "protocol error"}}),
    }
    for name, (core, required, sample) in shapes.items():
        node = s.node(s.defs.get(name))
        properties = s.obj(node, required)
        _need(set(properties) & _ENVELOPE_KEYS == core)
        if "id" in core:
            kinds = s.types(properties["id"])
            _need("integer" in kinds and kinds <= {"integer", "string"})
            _need(all(s.accepts(properties["id"], identity) for identity in range(4)))
        if "method" in core:
            s.typed(properties["method"], "string")
        if name in ("JSONRPCResponse", "JSONRPCError", "JSONRPCNotification"):
            # Added output metadata can be required by the vendor and still be
            # inert to our parser. Do not strip/ignore any reserved envelope key.
            query = {**node, "properties": {key: properties[key] for key in core},
                     "required": [key for key in node.get("required", []) if key in core]}
            _need(s.accepts(query, sample))
        else:
            for identity, method, params in _request_samples():
                _need(s.accepts(node, {"id": identity, "method": method, "params": params}))
    # The same notification schema must accept our outgoing acknowledgement,
    # without a newly mandatory metadata field that this client never sends.
    _need(s.accepts(s.defs["JSONRPCNotification"], shapes["JSONRPCNotification"][2]))


def assess_capabilities(*, version, exec_help, mcp_list_help, app_server_help, features, schema, envelopes=None):
    """Interpret only captured outputs, never command success, identity or authority."""
    checks, reasons = {}, []
    def run(name, reason, callback):
        try:
            callback()
        except Exception as error:
            checks[name] = False
            selected = reason
            if type(error) is PolicyError and (name == "schema" or
                    (name == "version" and error.reason == "version_input_invalid")):
                selected = error.reason
            if selected not in reasons:
                reasons.append(selected)
        else:
            checks[name] = True
    def version_check():
        try:
            value = _text(version).strip()
            _need(len(value) <= 256, "version_input_invalid")
        except Exception:
            raise PolicyError("version_input_invalid") from None
        _need(_version_at_or_above(value))
    run("version", "version_below_floor", version_check)
    run("execFlags", "exec_help_unproven", lambda: _flags(exec_help, EXEC_FLAGS))
    run("mcpFlags", "mcp_help_unproven", lambda: _flags(mcp_list_help, {"--json"}))
    run("appServerFlags", "app_server_help_unproven", lambda: _flags(app_server_help, APP_SERVER_FLAGS))
    run("features", "features_unproven", lambda: _features(features))
    def schema_check():
        _schema_contract(schema)
        _envelope_contract(envelopes)
    run("schema", "schema_shape_unproven", schema_check)
    return {"compatible": all(checks.values()), "reasonCodes": reasons, "checks": checks}
