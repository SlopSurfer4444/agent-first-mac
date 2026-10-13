"""Pure, narrow current-runtime integration matching; no execution authority.

The caller owns descriptor custody, signed-app/version-floor checks, plugin
distribution/update-owner admission and historical owner continuity. It must
independently admit the source facts below, including the signed renderer and
browser service, NOT construct them from candidate config/effective rows.
``generation`` is a caller-owned observation identifier, not proof by itself.
Both callbacks must return exactly True. ``recheck_generation`` binds ALL source,
config and effective observations to that generation before and after matching;
it promises an operation-local recheck, not continuous exclusion or OS CAS.

Supported source facts: generation, home, app_version, plugin_roots (the reviewed
local identities), source_hashes (REVIEWED_SOURCE_HASHES), rendered_cua (the
rendered mcpServers.cua_repl definition), and history_cwd_root. The last requires
independent runtime resolution evidence: a literal '.' is NOT that evidence.
The fact remains canonical; the current effective row emits that root + '/.'
and retains the signed template's exact relative launcher command.
The admitted callbacks must bind physical source bytes/identities to these facts.
That includes both signed and installed launcher copies, the signed renderer's
Gi/Wi relationship, the browser service, and the runtime CODEX_HOME forwarding
context (the history launcher uses that variable, falling back to HOME/.codex).
Remote installed plugins are a separate provider inventory, never config tables.
Future identities, renderer options or env fields need review, not normalization.

Only private, detached projections are returned. No TOML serialization, filesystem
access, process launch, credential access, enablement or trust change occurs here.
"""

from dataclasses import dataclass, field
import json
import math
import re


LOCAL_PLUGINS = frozenset(
    [name + "@openai-bundled" for name in (
        "browser", "chrome", "unified-computer-use", "codex-app-tools",
        "computer-history", "computer-use", "sites", "visualize")]
    + [name + "@openai-curated" for name in ("google-calendar", "google-drive", "slack")]
    + [name + "@openai-primary-runtime" for name in (
        "documents", "pdf", "presentations", "spreadsheets", "template-creator")])
APP_RESOURCES = "/Applications/ChatGPT.app/Contents/Resources"
DOCS_URL = "https://developers.openai.com/mcp"
REVIEWED_SOURCE_HASHES = {
    "computer-history/.mcp.json": "fd199f6efbbaf60b4bbc8309b52d8c71cc40554c6e457c2477cebd5e40a14848",
    "computer-use/.mcp.json": "3516e1755f57daa9cc705c4dc048a149d5561f6d3b18059dc72fff721d7e9a73",
    "unified-computer-use/.mcp.json": "9c073ab5891b49cbc86a750c01366a993e7240660f0904a7d9ff3ce6aed08153",
    "computer-use-client-launcher": "096edf245e994f4a9a00177da90969acd2abe7d8acd73dad23844a40aea007f2",
    "unified-computer-use/scripts/launch.mjs": "a50b66879f7b72e45ab6fbaad77eff14a87680a946135f410c121b9b166a2597",
}
INSTRUCTIONS = {
    "NODE_REPL_INSTRUCTIONS_USE_CASE_BROWSER":
        "Control the in-app browser in conjunction with the Browser Plugin.",
    "NODE_REPL_INSTRUCTIONS_USE_CASE_CHROME":
        "Control the Chrome browser in conjunction with the Chrome Plugin. Prefer this method of controlling Chrome over alternatives (such as Computer Use) unless the user explicitly mentions an alternative.",
    "NODE_REPL_INSTRUCTIONS_USE_CASE_COMPUTER_USE":
        "Control desktop apps on macOS through Computer Use.",
}


@dataclass(frozen=True)
class IntegrationMatch:
    """Private values never appear in repr or public evidence."""

    plugins: object = field(default=None, repr=False)
    mcp: object = field(default=None, repr=False)
    reason: str = "integrations_need_review"

    def public(self):
        return {"verdict": "matched" if not self.reason else "needs-review",
                "reasonCodes": [self.reason] if self.reason else [],
                "executionAdmission": False, "configMutationAuthorized": False,
                "trustMutationAuthorized": False}


class _Mismatch(Exception):
    pass


def _require(condition):
    if not condition:
        raise _Mismatch()


def _snapshot(value):
    """Bounded exact builtin tree copy: no user object equality/copy hooks."""
    budget = [10000, 1024 * 1024]

    def copy(item, depth):
        budget[0] -= 1
        _require(depth <= 16 and budget[0] >= 0)
        kind = type(item)
        if kind is str:
            budget[1] -= len(item.encode("utf-8"))
            _require(budget[1] >= 0)
            return item
        if kind in (bool, int, type(None)):
            return item
        if kind is float:
            _require(math.isfinite(item))
            return item
        if kind is list:
            return [copy(child, depth + 1) for child in item]
        _require(kind is dict and all(type(key) is str for key in item))
        return {copy(key, depth + 1): copy(child, depth + 1)
                for key, child in item.items()}

    return copy(value, 0)


def _equal(a, b, *, mapping_order=False):
    """Semantic mapping equality, with exact scalar/list types and order."""
    if type(a) is not type(b):
        return False
    if type(a) is dict:
        return (set(a) == set(b) and (not mapping_order or list(a) == list(b))
                and all(_equal(a[key], b[key], mapping_order=mapping_order) for key in a))
    if type(a) is list:
        return len(a) == len(b) and all(_equal(x, y, mapping_order=mapping_order) for x, y in zip(a, b))
    return a == b


def _ordered(actual, expected):
    """Use candidate mapping order only AFTER independent value validation."""
    _require(_equal(actual, expected))
    if type(actual) is dict:
        return {key: _ordered(actual[key], expected[key]) for key in actual}
    if type(actual) is list:
        return [_ordered(a, b) for a, b in zip(actual, expected)]
    return expected


def _path(value):
    return (type(value) is str and value.startswith("/") and ":" not in value
            and "\\" not in value and not any(ord(c) < 32 or ord(c) == 127 for c in value)
            and all(part not in ("", ".", "..") for part in value[1:].split("/")))


def _callback(callback, facts):
    _require(callable(callback))
    argument = _snapshot(facts)
    _require(callback(argument) is True)
    _require(_equal(_snapshot(argument), facts))


def _sources(facts):
    _require(type(facts) is dict and set(facts) == {
        "generation", "home", "app_version", "plugin_roots", "source_hashes",
        "rendered_cua", "history_cwd_root"})
    _require(type(facts["generation"]) is str and 0 < len(facts["generation"]) <= 256)
    home, version, roots = facts["home"], facts["app_version"], facts["plugin_roots"]
    _require(_path(home) and type(version) is str
             and re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", version) is not None)
    _require(type(roots) is dict and set(roots) == LOCAL_PLUGINS)
    for identity, root in roots.items():
        name, marketplace = identity.split("@")
        prefix = home + "/.codex/plugins/cache/" + marketplace + "/" + name + "/"
        _require(_path(root) and root.startswith(prefix)
                 and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", root[len(prefix):]) is not None)
        if name in ("browser", "chrome", "unified-computer-use"):
            _require(root == prefix + version)
    _require(_equal(facts["source_hashes"], REVIEWED_SOURCE_HASHES))
    _require(facts["history_cwd_root"] == roots["computer-history@openai-bundled"])
    return home + "/.codex", version, roots


def _env(codex_home, version, roots):
    modules = APP_RESOURCES + "/cua_node/lib/node_modules"
    return {
        "NODE_REPL_NATIVE_PIPE_CONNECT_TIMEOUT_MS": "1000",
        "NODE_REPL_NODE_MODULE_DIRS": modules,
        "NODE_REPL_NODE_PATH": APP_RESOURCES + "/cua_node/bin/node",
        "NODE_REPL_TRUSTED_CODE_PATHS": codex_home + ":" + modules,
        "CODEX_HOME": codex_home,
        "BROWSER_USE_AVAILABLE_BACKENDS": "chrome,iab",
        "BROWSER_USE_TINYSKY_ENABLED": "1",
        **INSTRUCTIONS,
        "BROWSER_USE_CODEX_APP_BUILD_FLAVOR": "prod",
        "BROWSER_USE_CODEX_APP_VERSION": version,
        "NODE_REPL_TRUSTED_SERVICES": json.dumps({
            "browser": roots["browser@openai-bundled"] + "/scripts/browser-service.mjs",
            "sky": "@oai/sky/service"}, separators=(",", ":")),
        "SKY_CUA_SERVICE_PATH": codex_home + "/computer-use/Codex Computer Use.app",
        "CODEX_CLI_PATH": APP_RESOURCES + "/codex",
    }


def _services(env, expected):
    """JSON object formatting/order is not a service capability. Duplicates fail."""
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result)
            result[key] = value
        return result

    _require(type(env) is dict and type(env.get("NODE_REPL_TRUSTED_SERVICES")) is str)
    raw = env["NODE_REPL_TRUSTED_SERVICES"]
    _require(_equal(json.loads(raw, object_pairs_hook=pairs),
                    json.loads(expected["NODE_REPL_TRUSTED_SERVICES"])))
    # Independently validated raw JSON is retained, not rewritten in config.
    expected["NODE_REPL_TRUSTED_SERVICES"] = raw


def _row(name, transport, enabled=True, timeout=None):
    return {"name": name, "enabled": enabled, "disabled_reason": None,
            "auth_status": "unsupported", "startup_timeout_sec": timeout,
            "tool_timeout_sec": None, "transport": transport}


def _stdio(command, args, *, cwd=None, env=None, env_vars=None):
    return {"type": "stdio", "command": command, "args": args, "cwd": cwd,
            "env": env, "env_vars": [] if env_vars is None else env_vars}


def match_integrations(config_plugins, config_mcp, effective_mcp, *, sources,
                       admit_sources=None, recheck_generation=None):
    """Match one supported generation, or return no projections on any failure.

Effective MCP is the exact CLI JSON list, not config tables. Callback ordinary
exceptions are redacted into needs-review; interrupts propagate. A successful
match is only input for the existing classifier, never Phase 5/live admission.
    """
    try:
        inputs = [config_plugins, config_mcp, effective_mcp, sources]
        captured = _snapshot(inputs)
        plugins, mcp, effective, facts = captured
        codex_home, version, roots = _sources(facts)
        _callback(admit_sources, facts)
        _callback(recheck_generation, facts)
        expected_plugins = {identity: {"enabled": True} for identity in LOCAL_PLUGINS}
        plugin_projection = _ordered(plugins, expected_plugins)
        original_env = _env(codex_home, version, roots)
        cua = {
            "command": APP_RESOURCES + "/cua_node/bin/node",
            "args": [roots["unified-computer-use@openai-bundled"] + "/scripts/launch.mjs"],
            "enabled": True, "enabled_tools": ["js", "js_reset"],
            "omit_tools_from": ["code_mode", "deferred"], "startup_timeout_sec": 120,
            "tools": {"js": {"output_token_limit": 25000}}, "env_vars": [],
            "env": {**original_env,
                    "CUA_REPL_NODE_REPL_PATH": APP_RESOURCES + "/cua_node/bin/node_repl",
                    "CUA_REPL_ENABLED_SURFACES": "browser,computer"},
        }
        _services(facts["rendered_cua"]["env"], cua["env"])
        _require(_equal(facts["rendered_cua"], cua))
        node_env = {**original_env, **{key: "" for key in INSTRUCTIONS}}
        _services(mcp["node_repl"]["env"], node_env)
        computer = {
            "command": "./Codex Computer Use.app/Contents/SharedSupport/SkyComputerUseClient.app/Contents/MacOS/SkyComputerUseClient",
            "args": ["mcp"], "cwd": ".", "enabled": False,
        }
        node = {"command": APP_RESOURCES + "/cua_node/bin/node_repl", "args": [],
                "env": node_env, "startup_timeout_sec": 120}
        mcp_projection = _ordered(mcp, {"computer-use": computer, "node_repl": node,
                                       "openaiDeveloperDocs": {"url": DOCS_URL}})
        expected_rows = [
            _row("computer-use", _stdio(computer["command"], ["mcp"], cwd="."), False),
            _row("node_repl", _stdio(node["command"], [], env=node_env), timeout=120.0),
            _row("openaiDeveloperDocs", {
                "type": "streamable_http", "url": DOCS_URL, "bearer_token_env_var": None,
                "env_http_headers": None, "http_headers": None, "http_headers_helper": None}),
            _row("computer-history", _stdio(
                "./bin/computer-use-client-launcher",
                ["computer-history", "mcp"], cwd=facts["history_cwd_root"] + "/.", env_vars=["CODEX_HOME"])),
            _row("cua_repl", _stdio(cua["command"], cua["args"], env=cua["env"]), timeout=120.0),
        ]
        _require(type(effective) is list and all(type(row) is dict for row in effective))
        names = [row["name"] for row in effective]
        _require(all(type(name) is str for name in names) and len(names) == len(set(names)))
        _require(_equal({row["name"]: row for row in effective},
                        {row["name"]: row for row in expected_rows}))
        _callback(recheck_generation, facts)
        _require(_equal(_snapshot(inputs), captured, mapping_order=True))
        return IntegrationMatch(plugin_projection, mcp_projection, "")
    except Exception:
        # No exception message, trace, private path, env value or input repr escapes.
        return IntegrationMatch()
