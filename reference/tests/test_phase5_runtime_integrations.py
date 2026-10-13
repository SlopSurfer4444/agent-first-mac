"""Pure fake-data tests. No subprocess, native fixtures or owner file reads."""

import copy
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import phase5_runtime_integrations as I


IDENTITIES = (
    "browser@openai-bundled", "chrome@openai-bundled",
    "unified-computer-use@openai-bundled", "codex-app-tools@openai-bundled",
    "computer-history@openai-bundled", "computer-use@openai-bundled",
    "sites@openai-bundled", "visualize@openai-bundled",
    "google-calendar@openai-curated", "google-drive@openai-curated", "slack@openai-curated",
    "documents@openai-primary-runtime", "pdf@openai-primary-runtime",
    "presentations@openai-primary-runtime", "spreadsheets@openai-primary-runtime",
    "template-creator@openai-primary-runtime",
)


def fixture():
    home = "/Users/synthetic-owner"
    codex = home + "/.codex"
    app = "/Applications/ChatGPT.app/Contents/Resources"
    version = "26.901.51231"
    roots = {}
    for identity in IDENTITIES:
        name, marketplace = identity.split("@")
        generation = {
            "browser": version, "chrome": version, "unified-computer-use": version,
            "codex-app-tools": "0.1.3", "computer-history": "1.0.1000926",
            "computer-use": "1.0.1000926", "sites": "0.1.57", "visualize": "1.0.29",
        }.get(name, "1e285826" if marketplace == "openai-curated" else "26.905.11957")
        roots[identity] = codex + "/plugins/cache/" + marketplace + "/" + name + "/" + generation
    env = {
        "NODE_REPL_NATIVE_PIPE_CONNECT_TIMEOUT_MS": "1000",
        "NODE_REPL_NODE_MODULE_DIRS": app + "/cua_node/lib/node_modules",
        "NODE_REPL_NODE_PATH": app + "/cua_node/bin/node",
        "NODE_REPL_TRUSTED_CODE_PATHS": codex + ":" + app + "/cua_node/lib/node_modules",
        "CODEX_HOME": codex,
        "BROWSER_USE_AVAILABLE_BACKENDS": "chrome,iab",
        "BROWSER_USE_TINYSKY_ENABLED": "1",
        "NODE_REPL_INSTRUCTIONS_USE_CASE_BROWSER": "Control the in-app browser in conjunction with the Browser Plugin.",
        "NODE_REPL_INSTRUCTIONS_USE_CASE_CHROME": "Control the Chrome browser in conjunction with the Chrome Plugin. Prefer this method of controlling Chrome over alternatives (such as Computer Use) unless the user explicitly mentions an alternative.",
        "NODE_REPL_INSTRUCTIONS_USE_CASE_COMPUTER_USE": "Control desktop apps on macOS through Computer Use.",
        "BROWSER_USE_CODEX_APP_BUILD_FLAVOR": "prod",
        "BROWSER_USE_CODEX_APP_VERSION": version,
        "NODE_REPL_TRUSTED_SERVICES": json.dumps({
            "browser": roots["browser@openai-bundled"] + "/scripts/browser-service.mjs",
            "sky": "@oai/sky/service"}, separators=(",", ":")),
        "SKY_CUA_SERVICE_PATH": codex + "/computer-use/Codex Computer Use.app",
        "CODEX_CLI_PATH": app + "/codex",
    }
    cua = {
        "command": app + "/cua_node/bin/node",
        "args": [roots["unified-computer-use@openai-bundled"] + "/scripts/launch.mjs"],
        "enabled": True, "enabled_tools": ["js", "js_reset"],
        "omit_tools_from": ["code_mode", "deferred"], "startup_timeout_sec": 120,
        "tools": {"js": {"output_token_limit": 25000}}, "env_vars": [],
        "env": {**env, "CUA_REPL_NODE_REPL_PATH": app + "/cua_node/bin/node_repl",
                "CUA_REPL_ENABLED_SURFACES": "browser,computer"},
    }
    node_env = copy.deepcopy(env)
    for key in (
        "NODE_REPL_INSTRUCTIONS_USE_CASE_BROWSER", "NODE_REPL_INSTRUCTIONS_USE_CASE_CHROME",
        "NODE_REPL_INSTRUCTIONS_USE_CASE_COMPUTER_USE",
    ):
        node_env[key] = ""
    plugins = {identity: {"enabled": True} for identity in IDENTITIES}
    mcp = {
        "computer-use": {
            "command": "./Codex Computer Use.app/Contents/SharedSupport/SkyComputerUseClient.app/Contents/MacOS/SkyComputerUseClient",
            "args": ["mcp"], "cwd": ".", "enabled": False,
        },
        "node_repl": {"command": app + "/cua_node/bin/node_repl", "args": [],
                      "env": node_env, "startup_timeout_sec": 120},
        "openaiDeveloperDocs": {"url": "https://developers.openai.com/mcp"},
    }

    def stdio(command, args, cwd=None, env=None, env_vars=None):
        return dict(type="stdio", command=command, args=args, cwd=cwd, env=env,
                    env_vars=[] if env_vars is None else env_vars)

    def row(name, transport, enabled=True, timeout=None):
        return dict(name=name, enabled=enabled, disabled_reason=None, auth_status="unsupported",
                    startup_timeout_sec=timeout, tool_timeout_sec=None, transport=transport)

    effective = [
        row("computer-use", stdio(mcp["computer-use"]["command"], ["mcp"], cwd="."), False),
        row("node_repl", stdio(mcp["node_repl"]["command"], [], env=copy.deepcopy(node_env)), timeout=120.0),
        row("openaiDeveloperDocs", dict(type="streamable_http", url="https://developers.openai.com/mcp",
            bearer_token_env_var=None, env_http_headers=None, http_headers=None, http_headers_helper=None)),
        row("computer-history", stdio("./bin/computer-use-client-launcher",
            ["computer-history", "mcp"], cwd=roots["computer-history@openai-bundled"] + "/.", env_vars=["CODEX_HOME"])),
        row("cua_repl", stdio(cua["command"], copy.deepcopy(cua["args"]), env=copy.deepcopy(cua["env"])), timeout=120.0),
    ]
    sources = dict(generation="synthetic-operation-generation", home=home, app_version=version,
        plugin_roots=roots, source_hashes=dict(I.REVIEWED_SOURCE_HASHES), rendered_cua=cua,
        history_cwd_root=roots["computer-history@openai-bundled"])
    return [plugins, mcp, effective, sources]


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture()

    def run_match(self, *, admit=lambda _: True, recheck=lambda _: True):
        plugins, mcp, rows, facts = self.data
        return I.match_integrations(plugins, mcp, rows, sources=facts,
                                    admit_sources=admit, recheck_generation=recheck)

    def rejected(self, **kwargs):
        result = self.run_match(**kwargs)
        self.assertIsNone(result.plugins)
        self.assertIsNone(result.mcp)
        self.assertEqual(result.public(), {
            "verdict": "needs-review", "reasonCodes": ["integrations_need_review"],
            "executionAdmission": False, "configMutationAuthorized": False,
            "trustMutationAuthorized": False})
        self.assertNotIn("synthetic-owner", repr(result))
        return result

    def test_current15_and_unified17_wifi_blanking(self):
        result = self.run_match()
        self.assertEqual(result.public()["verdict"], "matched")
        self.assertEqual(result.plugins, self.data[0])
        self.assertEqual(result.mcp, self.data[1])
        self.assertEqual(len(result.mcp["node_repl"]["env"]), 15)
        self.assertEqual(len(self.data[3]["rendered_cua"]["env"]), 17)
        for key in I.INSTRUCTIONS:
            self.assertEqual(result.mcp["node_repl"]["env"][key], "")
            self.assertTrue(self.data[3]["rendered_cua"]["env"][key])
        self.assertNotIn("synthetic-owner", repr(result))
        self.assertFalse(result.public()["executionAdmission"])

    def test_projections_compose_with_existing_classifier_without_rewriting(self):
        from lib.phase5_current_runtime import classify

        def toml(value):
            if type(value) is dict:
                return "{" + ", ".join(json.dumps(key) + " = " + toml(item)
                                        for key, item in value.items()) + "}"
            if type(value) is list:
                return "[" + ", ".join(toml(item) for item in value) + "]"
            return json.dumps(value)

        hook = "/Users/synthetic-owner/AIDev/control/hooks/current.py"
        slots = {key: "sha256:" + "a" * 64 for key in (
            "session_start:0:0", "pre_tool_use:0:0", "stop:0:0")}
        hooks = {"state": {hook + ":" + key: {"trusted_hash": value} for key, value in slots.items()}}
        document = ("# preserve this formatting\napproval_policy = 'never'\n"
                    "sandbox_mode = 'danger-full-access'\n"
                    "hooks = " + toml(hooks) + "\nplugins = " + toml(self.data[0])
                    + "\nmcp_servers = " + toml(self.data[1]) + "\n").encode()
        before = bytes(document)
        matched = self.run_match()
        result = classify(document, control_root="/Users/synthetic-owner/AIDev/control",
                          hook_source=hook, hook_records=slots,
                          admitted_plugins=matched.plugins, admitted_mcp=matched.mcp)
        self.assertEqual(result["verdict"], "ready")
        self.assertFalse(result["executionAdmission"])
        self.assertEqual(document, before)

    def test_identity_set_not_counts(self):
        self.assertEqual(I.LOCAL_PLUGINS, frozenset(IDENTITIES))
        self.data[0]["unreviewed@openai-bundled"] = self.data[0].pop(IDENTITIES[0])
        self.rejected()

    def test_local_plugins_only_config_and_five_effective_mcp(self):
        result = self.run_match()
        self.assertEqual(set(result.mcp), {"computer-use", "node_repl", "openaiDeveloperDocs"})
        self.assertNotIn("cua_repl", result.mcp)
        self.assertNotIn("computer-history", result.mcp)
        self.data[0]["plugin-management@openai-curated-remote"] = {"enabled": True}
        self.rejected()

    def test_injected_server_must_not_become_config_table(self):
        self.data[1]["computer-history"] = {"enabled": True}
        self.rejected()

    def test_missing_or_added_or_duplicate_effective_server(self):
        for operation in (lambda rows: rows.pop(), lambda rows: rows.append(copy.deepcopy(rows[0])),
                          lambda rows: rows[4].update(name="unexpected")):
            with self.subTest(operation=operation):
                self.data = fixture()
                operation(self.data[2])
                self.rejected()

    def test_map_order_preserved_and_detached(self):
        self.data[0] = dict(reversed(list(self.data[0].items())))
        self.data[1] = dict(reversed(list(self.data[1].items())))
        self.data[1]["node_repl"]["env"] = dict(reversed(list(self.data[1]["node_repl"]["env"].items())))
        self.data[2].reverse()
        result = self.run_match()
        self.assertEqual(list(result.plugins), list(self.data[0]))
        self.assertEqual(list(result.mcp), list(self.data[1]))
        self.assertEqual(list(result.mcp["node_repl"]["env"]), list(self.data[1]["node_repl"]["env"]))
        result.mcp["node_repl"]["env"]["CODEX_HOME"] = "changed-result"
        self.assertNotEqual(result.mcp, self.data[1])

    def test_source_admission_required(self):
        for value in (None, False, 1, "yes"):
            with self.subTest(value=value):
                self.rejected(admit=None if value is None else lambda _, v=value: v)

    def test_both_generation_rechecks_required(self):
        for failure_index in (0, 1):
            seen = []
            def recheck(facts):
                seen.append(facts["generation"])
                return len(seen) - 1 != failure_index
            self.rejected(recheck=recheck)
            self.assertEqual(len(seen), failure_index + 1)
        self.rejected(recheck=None)
        self.rejected(recheck=lambda _: 1)

    def test_callback_order(self):
        calls = []
        def callback(name):
            def invoke(facts):
                calls.append((name, facts["generation"]))
                return True
            return invoke
        self.assertFalse(self.run_match(admit=callback("admit"), recheck=callback("recheck")).reason)
        self.assertEqual([item[0] for item in calls], ["admit", "recheck", "recheck"])

    def test_callback_mutating_argument_fails(self):
        def mutate(facts):
            facts["home"] = "/private-secret"
            return True
        self.rejected(admit=mutate)
        self.rejected(recheck=mutate)

    def test_original_input_drift_during_callbacks_fails(self):
        for index in range(4):
            self.data = fixture()
            def mutate_original(_):
                if index == 2:
                    self.data[index].reverse()
                else:
                    self.data[index]["unknown"] = "private-secret"
                return True
            self.rejected(admit=mutate_original)
        self.data = fixture()
        def reorder_config(_):
            entry = self.data[0].pop(IDENTITIES[0])
            self.data[0][IDENTITIES[0]] = entry
            return True
        self.rejected(admit=reorder_config)

    def test_callback_exceptions_redacted(self):
        def fail(_):
            raise RuntimeError("private-secret-value")
        result = self.rejected(admit=fail)
        self.assertNotIn("private-secret-value", repr(result.public()))
        self.rejected(recheck=fail)

    def test_interruptions_propagate(self):
        for exception in (KeyboardInterrupt(), SystemExit(5)):
            def interrupt(_):
                raise exception
            with self.assertRaises(type(exception)) as raised:
                self.run_match(admit=interrupt)
            self.assertIs(raised.exception, exception)

    def test_every_reviewed_plugin_enabled_true_and_no_extras(self):
        for identity in IDENTITIES:
            for bad in (False, 1, "true"):
                with self.subTest(identity=identity, bad=bad):
                    self.data = fixture()
                    self.data[0][identity]["enabled"] = bad
                    self.rejected()
        self.data = fixture()
        self.data[0][IDENTITIES[0]]["permissions"] = {}
        self.rejected()

    def test_missing_plugin_fails(self):
        self.data[0].pop(IDENTITIES[0])
        self.rejected()

    def test_disabled_legacy_computer_use_is_not_reenabled(self):
        self.data[1]["computer-use"]["enabled"] = True
        self.data[2][0]["enabled"] = True
        self.rejected()

    def test_config_unknown_keys_fail_even_if_null(self):
        for identity in self.data[1]:
            for key in ("auth", "oauth_resource", "env_vars", "permissions"):
                self.data = fixture()
                self.data[1][identity][key] = None
                self.rejected()

    def test_config_timeout_exact_int_effective_exact_float(self):
        for value in (True, False, 120.0, "120", 119, 0):
            self.data = fixture()
            self.data[1]["node_repl"]["startup_timeout_sec"] = value
            self.rejected()
        for value in (120, True, None, float("nan"), float("inf")):
            self.data = fixture()
            self.data[2][1]["startup_timeout_sec"] = value
            self.rejected()

    def test_old14_environment_fails(self):
        env = self.data[1]["node_repl"]["env"]
        env.pop("BROWSER_USE_TINYSKY_ENABLED")
        env.pop("NODE_REPL_TRUSTED_SERVICES")
        env["NODE_REPL_TRUSTED_BROWSER_CLIENT_SHA256S"] = "a" * 64
        self.assertEqual(len(env), 14)
        self.rejected()

    def test_conditional_env_extras_fail_even_if_source_and_effective_agree(self):
        for key in ("NODE_REPL_ENFORCE_MODEL_CHECK", "OPENAI_API_KEY", "DEBUG", "NODE_OPTIONS"):
            self.data = fixture()
            self.data[1]["node_repl"]["env"][key] = "unreviewed"
            self.data[2][1]["transport"]["env"][key] = "unreviewed"
            self.data[2][4]["transport"]["env"][key] = "unreviewed"
            self.data[3]["rendered_cua"]["env"][key] = "unreviewed"
            self.rejected()

    def test_each_node_environment_value_is_independently_checked(self):
        for key in self.data[1]["node_repl"]["env"]:
            with self.subTest(key=key):
                self.data = fixture()
                self.data[1]["node_repl"]["env"][key] = "private-secret"
                self.data[2][1]["transport"]["env"][key] = "private-secret"
                self.rejected()

    def test_node_instructions_require_all_three_blanks(self):
        for key in I.INSTRUCTIONS:
            self.data = fixture()
            self.data[1]["node_repl"]["env"][key] = I.INSTRUCTIONS[key]
            self.rejected()

    def test_cua_instructions_require_source_strings_not_blanks(self):
        for key in I.INSTRUCTIONS:
            self.data = fixture()
            self.data[3]["rendered_cua"]["env"][key] = ""
            self.data[2][4]["transport"]["env"][key] = ""
            self.rejected()

    def test_services_allow_only_exact_semantic_mapping_and_preserve_raw(self):
        env = self.data[1]["node_repl"]["env"]
        parsed = json.loads(env["NODE_REPL_TRUSTED_SERVICES"])
        raw = json.dumps(dict(reversed(list(parsed.items()))), indent=2)
        env["NODE_REPL_TRUSTED_SERVICES"] = raw
        self.data[2][1]["transport"]["env"]["NODE_REPL_TRUSTED_SERVICES"] = raw
        self.assertEqual(self.run_match().mcp["node_repl"]["env"]["NODE_REPL_TRUSTED_SERVICES"], raw)

    def test_service_extra_wrong_package_outside_or_prefix_decoy_fail(self):
        for key, value in (("extra", "@other/service"), ("sky", "@oai/sky/service/extra"),
                           ("browser", "/private/service.mjs"),
                           ("browser", fixture()[3]["plugin_roots"]["browser@openai-bundled"] + "-evil/scripts/browser-service.mjs")):
            self.data = fixture()
            env = self.data[1]["node_repl"]["env"]
            parsed = json.loads(env["NODE_REPL_TRUSTED_SERVICES"])
            parsed[key] = value
            raw = json.dumps(parsed)
            env["NODE_REPL_TRUSTED_SERVICES"] = raw
            self.data[2][1]["transport"]["env"]["NODE_REPL_TRUSTED_SERVICES"] = raw
            self.rejected()

    def test_services_duplicate_keys_and_malformed_json_fail(self):
        raw = self.data[1]["node_repl"]["env"]["NODE_REPL_TRUSTED_SERVICES"]
        for bad in (raw[:-1] + ',"sky":"@oai/sky/service"}', "[]", "null", "{", "NaN"):
            self.data = fixture()
            self.data[1]["node_repl"]["env"]["NODE_REPL_TRUSTED_SERVICES"] = bad
            self.rejected()

    def test_app_version_and_generation_paths_must_agree(self):
        self.data[3]["app_version"] = "26.902.1"
        self.rejected()
        self.data = fixture()
        self.data[1]["node_repl"]["env"]["BROWSER_USE_CODEX_APP_VERSION"] = "26.902.1"
        self.rejected()

    def test_new_admitted_numeric_app_version_not_historical_build_pin(self):
        before, after = "26.901.51231", "26.999.12345"
        def replace(value):
            if type(value) is str:
                return value.replace(before, after)
            if type(value) is dict:
                return {key: replace(item) for key, item in value.items()}
            if type(value) is list:
                return [replace(item) for item in value]
            return value
        self.data = replace(self.data)
        self.assertFalse(self.run_match().reason)

    def test_home_and_plugin_root_path_decoys(self):
        for home in ("/Users/../owner", "/Users//owner", "/Users/owner/", "/Users/owner:extra", "relative"):
            self.data = fixture()
            self.data[3]["home"] = home
            self.rejected()
        for suffix in ("/../other", "/nested", "-other/", ":other"):
            self.data = fixture()
            self.data[3]["plugin_roots"][IDENTITIES[0]] += suffix
            self.rejected()
        self.data = fixture()
        self.data[3]["plugin_roots"][IDENTITIES[0]] = "/Users/synthetic-owner/.codex/plugins/cache/openai-bundled-evil/browser/26.901.51231"
        self.rejected()

    def test_history_cwd_requires_independently_admitted_exact_root(self):
        canonical = self.data[3]["plugin_roots"]["computer-history@openai-bundled"]
        for bad in (None, ".", "./", "/private/outside", True, canonical + "/."):
            self.data = fixture()
            self.data[3]["history_cwd_root"] = bad
            self.data[2][3]["transport"]["cwd"] = bad
            self.rejected()
        self.data = fixture()
        self.data[2][3]["transport"]["cwd"] = "."
        self.rejected()

    def test_history_current_emission_exact_without_normalizing_paths(self):
        root = self.data[3]["history_cwd_root"]
        self.assertTrue(I._path(root))
        self.assertEqual(self.data[2][3]["transport"]["cwd"], root + "/.")
        self.assertFalse(self.run_match().reason)
        for key, value in (
            ("command", "bin/computer-use-client-launcher"),
            ("command", "./bin/other-launcher"),
            ("command", "./bin/../bin/computer-use-client-launcher"),
            ("command", "../bin/computer-use-client-launcher"),
            ("command", root + "/bin/computer-use-client-launcher"),
            ("cwd", root), ("cwd", root + "/"), ("cwd", root + "/./"),
            ("cwd", root + "/../."), ("cwd", root + "-other/."),
            ("cwd", self.data[3]["plugin_roots"]["computer-use@openai-bundled"] + "/."),
        ):
            self.data = fixture()
            self.data[2][3]["transport"][key] = value
            self.rejected()

    def test_command_args_cwd_and_forwarding_are_exact(self):
        changes = ((0, "cwd", "./"), (1, "command", "/private/node_repl"),
                   (3, "args", ["mcp"]), (3, "env_vars", ["CODEX_HOME", "API_KEY"]),
                   (4, "args", ["scripts/launch.mjs"]), (4, "cwd", "."),
                   (4, "env_vars", ["CODEX_HOME"]))
        for index, key, value in changes:
            self.data = fixture()
            self.data[2][index]["transport"][key] = value
            self.rejected()

    def test_reviewed_source_hashes_are_required_not_cache_presence(self):
        for key in I.REVIEWED_SOURCE_HASHES:
            self.data = fixture()
            self.data[3]["source_hashes"][key] = "0" * 64
            self.rejected()
        self.data = fixture()
        self.data[3].pop("source_hashes")
        self.rejected()

    def test_cua_policy_surfaces_tools_and_launcher_exact(self):
        cases = (("enabled", False), ("enabled", 1), ("startup_timeout_sec", 120.0),
                 ("enabled_tools", ["js", "js_reset", "execute"]),
                 ("omit_tools_from", ["deferred"]), ("env_vars", ["PRIVATE_KEY"]),
                 ("tools", {"js": {"output_token_limit": True}}),
                 ("args", ["/private/launch.mjs"]), ("permission", None))
        for key, value in cases:
            self.data = fixture()
            self.data[3]["rendered_cua"][key] = value
            self.rejected()
        self.data = fixture()
        self.data[3]["rendered_cua"]["env"]["CUA_REPL_ENABLED_SURFACES"] = "browser,computer,other"
        self.rejected()

    def test_http_helper_null_is_only_supported_default(self):
        for key in ("http_headers_helper", "bearer_token_env_var", "env_http_headers", "http_headers"):
            for value in ("secret", {}, [], False):
                self.data = fixture()
                self.data[2][2]["transport"][key] = value
                self.rejected()
        self.data = fixture()
        self.data[2][2]["transport"].pop("http_headers_helper")
        self.rejected()

    def test_http_auth_or_extra_field_even_null_fails(self):
        for key in ("auth", "oauth_resource", "permissions"):
            self.data = fixture()
            self.data[2][2]["transport"][key] = None
            self.rejected()
        self.data = fixture()
        self.data[1]["openaiDeveloperDocs"]["url"] += "/extra"
        self.rejected()

    def test_effective_policy_types_and_metadata_fail_closed(self):
        for key, value in (("enabled", 1), ("enabled", False), ("auth_status", "logged_in"),
                           ("disabled_reason", "policy"), ("tool_timeout_sec", 120.0),
                           ("unknown", None)):
            self.data = fixture()
            self.data[2][1][key] = value
            self.rejected()

    def test_malformed_or_oversized_inputs_fail_redacted(self):
        class Hostile(dict):
            def __eq__(self, other):
                raise AssertionError("must not invoke")
        for bad in (None, [], Hostile(), {"secret": object()}, {"secret": "x" * (1024 * 1024)}):
            self.data = fixture()
            self.data[0] = bad
            self.rejected()
        cycle = {}
        cycle["self"] = cycle
        self.data = fixture()
        self.data[0] = cycle
        self.rejected()


if __name__ == "__main__":
    unittest.main()
