"""Pure schema/bytes fixtures only; no Codex, subprocess, sockets or owner state."""

import ast
import copy
import json
from pathlib import Path
import re
import sys
import traceback
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import vendor_compatibility_policy as P


def scalar(kind):
    return {"type": kind.split("|") if "|" in kind else kind}


def obj(fields, required=()):
    return {"type": "object", "properties": fields, "required": list(required)}


def array(items):
    return {"type": "array", "items": items}


def enum(*values):
    return {"type": "string", "enum": list(values)}


def ref(name):
    return {"$ref": "#/definitions/v2/" + name}


def nullable(node):
    return {"anyOf": [node, {"type": "null"}]}


def fixture_envelopes():
    names = ("JSONRPCRequest", "JSONRPCNotification", "JSONRPCResponse", "JSONRPCError")
    identity = {"$ref": "#/definitions/RequestId"}
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "anyOf": [{"$ref": "#/definitions/" + name} for name in names],
        "definitions": {
            "RequestId": {"anyOf": [scalar("string"), {"type": "integer", "format": "int64"}]},
            "JSONRPCRequest": obj({"id": identity, "method": scalar("string"), "params": True}, ("id", "method")),
            "JSONRPCNotification": obj({"method": scalar("string"), "params": True}, ("method",)),
            "JSONRPCResponse": obj({"id": identity, "result": True}, ("id", "result")),
            "JSONRPCError": obj({"id": identity, "error": {"$ref": "#/definitions/JSONRPCErrorError"}}, ("id", "error")),
            "JSONRPCErrorError": obj({"code": {"type": "integer", "format": "int64"}, "message": scalar("string"), "data": True}, ("code", "message")),
        },
    }


def fixture_schema():
    # A deliberately small aggregate in the observed generated draft-07 format.
    # It is not copied from the policy's expected-field maps.
    v2 = {"RequestId": {"anyOf": [scalar("integer"), scalar("string")]}}
    root = {"$schema": "http://json-schema.org/draft-07/schema#", "definitions": {"v2": v2}}
    defs = root["definitions"]
    defs["InitializeResponse"] = obj({"userAgent": scalar("string")}, ("userAgent",))
    params = {
        "initialize": obj({"clientInfo": obj({"name": scalar("string"), "title": scalar("string|null"),
                                               "version": scalar("string")}, ("name", "version")),
                           "capabilities": nullable(obj({"experimentalApi": scalar("boolean")}))}, ("clientInfo",)),
        "hooks/list": obj({"cwds": array(scalar("string"))}),
        "skills/list": obj({"cwds": array(scalar("string")), "forceReload": scalar("boolean")}),
        "plugin/installed": obj({"cwds": array(scalar("string")), "installSuggestionPluginNames": array(scalar("string"))}),
        "plugin/list": obj({"cwds": array(scalar("string")), "forceRefetch": scalar("boolean"),
                            "marketplaceKinds": array(enum("vertical", "local"))}),
    }
    defs["ClientRequest"] = {"oneOf": [obj({"id": ref("RequestId"), "method": enum(method),
                                            "params": value}, ("id", "method", "params"))
                                      for method, value in params.items()]}
    defs["ClientNotification"] = {"oneOf": [obj({"method": enum("initialized")}, ("method",))]}
    fields = {key: scalar("string") for key in ("currentHash", "key", "sourcePath")}
    fields.update({"eventName": enum("sessionStart", "preToolUse", "stop"), "source": enum("user", "system"),
                   "trustStatus": enum("trusted", "untrusted"), "displayOrder": scalar("integer"),
                   "timeoutSec": scalar("integer"), "enabled": scalar("boolean"), "isManaged": scalar("boolean")})
    v2["HookMetadata"] = obj(fields, tuple(fields))
    fields.update({key: scalar("string|null") for key in ("matcher", "pluginId", "statusMessage")})
    fields["additionalContextLimit"] = {"type": ["integer", "null"], "minimum": 0.0, "format": "uint"}
    v2["HookMetadata"]["oneOf"] = [obj({"handlerType": enum("command"), "command": scalar("string"),
                                        "async": scalar("boolean")}, ("handlerType", "command"))]
    v2["SkillInterface"] = obj({key: scalar("string|null") for key in (
        "brandColor", "defaultPrompt", "displayName", "iconLarge", "iconLargeUrl", "iconSmall", "iconSmallUrl", "shortDescription")})
    tool = obj({"type": scalar("string"), "value": scalar("string"),
                **{key: scalar("string|null") for key in ("command", "description", "transport", "url")}}, ("type", "value"))
    v2["SkillDependencies"] = obj({"tools": array(tool)}, ("tools",))
    v2["SkillMetadata"] = obj({"name": scalar("string"), "description": scalar("string"), "enabled": scalar("boolean"),
                                "path": scalar("string"), "scope": enum("user", "repo", "system", "admin"),
                                "pluginId": scalar("string|null"), "shortDescription": scalar("string|null"),
                                "interface": nullable(ref("SkillInterface")), "dependencies": nullable(ref("SkillDependencies"))},
                               ("name", "description", "enabled", "path", "scope"))
    for kind, metadata in (("Hooks", "HookMetadata"), ("Skills", "SkillMetadata")):
        collection = kind.lower()
        row = obj({"cwd": scalar("string"), "errors": array(obj({})), collection: array(ref(metadata))},
                  ("cwd", "errors", collection))
        if kind == "Hooks":
            row["properties"]["warnings"] = array(scalar("string"))
            row["required"].append("warnings")
        v2[kind + "ListEntry"] = row
        v2[kind + "ListResponse"] = obj({"data": array(ref(kind + "ListEntry"))}, ("data",))
    v2["PluginSource"] = {"oneOf": [
        obj({"type": enum("local"), "path": scalar("string")}, ("type", "path")),
        obj({"type": enum("git"), "url": scalar("string"), **{key: scalar("string|null") for key in ("path", "refName", "sha")}}, ("type", "url")),
        obj({"type": enum("npm"), "package": scalar("string"), "registry": scalar("string|null"), "version": scalar("string|null")}, ("type", "package")),
        obj({"type": enum("remote")}, ("type",)),
    ]}
    v2["PluginSummary"] = obj({"authPolicy": enum("ON_USE"), "enabled": scalar("boolean"), "id": scalar("string"),
                               "installPolicy": enum("AVAILABLE"), "installed": scalar("boolean"), "name": scalar("string"),
                               "source": ref("PluginSource"), **{key: scalar("string|null") for key in ("remotePluginId", "version", "localVersion")}},
                              ("authPolicy", "enabled", "id", "installPolicy", "installed", "name", "source"))
    v2["PluginMarketplaceEntry"] = obj({"name": scalar("string"), "path": scalar("string|null"), "plugins": array(ref("PluginSummary"))}, ("name", "plugins"))
    for kind in ("PluginInstalled", "PluginList"):
        v2[kind + "Response"] = obj({"marketplaces": array(ref("PluginMarketplaceEntry")), "marketplaceLoadErrors": array(obj({}))}, ("marketplaces",))
    return root


def inputs():
    return {"version": b"codex-cli 0.145.0-alpha.18\n",
            "exec_help": ("Options:\n" + "\n".join("      " + key for key in sorted(P.EXEC_FLAGS))).encode(),
            "mcp_list_help": b"Options:\n      --json\n", "app_server_help": b"Options:\n      --listen <URL>\n      --strict-config\n  -c, --config <key=value>\n",
            "features": "\n".join(key + " under development false" for key in P.FEATURE_KEYS).encode(),
            "schema": fixture_schema(), "envelopes": fixture_envelopes()}


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.data = inputs()
        self.schema = self.data["schema"]
        self.defs = self.schema["definitions"]
        self.v2 = self.defs["v2"]

    def result(self):
        return P.assess_capabilities(**self.data)

    def fails(self, check="schema"):
        result = self.result()
        self.assertFalse(result["compatible"])
        self.assertFalse(result["checks"][check])
        self.assertLessEqual(set(result["reasonCodes"]), P.REASON_CODES)
        return result

    def test_positive_full_aggregate(self):
        result = self.result()
        self.assertTrue(result["compatible"])
        self.assertEqual(result["reasonCodes"], [])
        self.assertEqual(set(result), {"compatible", "reasonCodes", "checks"})

    def test_missing_envelope_cannot_borrow_aggregate_definitions(self):
        self.defs.update(fixture_envelopes()["definitions"])
        self.data.pop("envelopes")
        self.assertIn("schema_shape_unproven", self.fails()["reasonCodes"])

    def test_wire_schema_explicit_association_required(self):
        for change in ("duplicate", "unresolved", "flat"):
            with self.subTest(change=change):
                self.setUp()
                wire = self.data["envelopes"]
                if change == "duplicate":
                    wire["anyOf"][3] = wire["anyOf"][2]
                elif change == "unresolved":
                    wire["anyOf"][3] = {"$ref": "#/definitions/Other"}
                else:
                    self.data["envelopes"] = wire["definitions"]
                self.fails()

    def test_wire_reserved_jsonrpc_or_cross_kind_metadata_fails(self):
        for name in ("JSONRPCNotification", "JSONRPCResponse", "JSONRPCError"):
            for required in (False, True):
                with self.subTest(name=name, required=required):
                    self.setUp()
                    node = self.data["envelopes"]["definitions"][name]
                    node["properties"]["jsonrpc"] = enum("2.0")
                    if required:
                        node["required"].append("jsonrpc")
                    self.fails()
        self.setUp()
        self.data["envelopes"]["definitions"]["JSONRPCResponse"]["properties"]["method"] = scalar("string")
        self.fails()

    def test_wire_required_core_cannot_disappear(self):
        for name, key in (("JSONRPCResponse", "result"), ("JSONRPCError", "id"), ("JSONRPCNotification", "method")):
            with self.subTest(name=name, key=key):
                self.setUp()
                self.data["envelopes"]["definitions"][name]["required"].remove(key)
                self.fails()

    def test_wire_id_domain_and_format_are_independent(self):
        for change in (scalar("string"), scalar("boolean"), {"type": "integer", "maximum": 0},
                       {"type": ["integer", "boolean"]}, {"type": "integer", "format": "uuid"}):
            with self.subTest(change=change):
                self.setUp()
                self.data["envelopes"]["definitions"]["RequestId"] = change
                self.fails()

    def test_wire_request_shape_must_allow_later_rpcs(self):
        request = self.data["envelopes"]["definitions"]["JSONRPCRequest"]
        request["properties"]["params"] = obj({"clientInfo": obj({})}, ("clientInfo",))
        self.fails()
        self.setUp()
        self.data["envelopes"]["definitions"]["JSONRPCRequest"]["properties"]["method"] = enum("initialize")
        self.fails()

    def test_wire_nonreserved_response_metadata_is_inert(self):
        for name in ("JSONRPCResponse", "JSONRPCError"):
            node = self.data["envelopes"]["definitions"][name]
            node["properties"]["futureTrace"] = {"type": "string", "format": "uuid"}
            node["required"].append("futureTrace")
        self.assertTrue(self.result()["compatible"])

    def test_connected_actual_catalog_parser_agrees_with_reserved_boundary(self):
        from lib import phase5_plugin_catalog as catalog
        value = {"id": 1, "result": {}, "inert": "extra"}
        session = catalog._Session(0)
        session.expected = 1
        session._line(json.dumps(value).encode())
        self.assertTrue(session.responded)
        value["jsonrpc"] = "2.0"
        session = catalog._Session(0)
        session.expected = 1
        with self.assertRaises(catalog.CatalogClientError):
            session._line(json.dumps(value).encode())
        wire = self.data["envelopes"]["definitions"]["JSONRPCResponse"]
        wire["properties"]["jsonrpc"] = enum("2.0")
        self.fails()

    def test_input_not_mutated(self):
        before = copy.deepcopy(self.data)
        self.result()
        self.assertEqual(self.data, before)

    def test_version_equivalent_to_source_comparator_and_source_floor(self):
        tree = ast.parse((ROOT / "bin/phase5-trusted-probe").read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "version_at_or_above")
        namespace = {"re": re, "MINIMUM_VERSION": P.MINIMUM_VERSION}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "accepted-pure-comparator", "exec"), namespace)
        # Public export omits host observations; compare the two source constants.
        floor = next(node for node in tree.body if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == "MINIMUM_VERSION" for target in node.targets))
        self.assertEqual(P.MINIMUM_VERSION, ast.literal_eval(floor.value))
        feature_assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                                  and any(isinstance(target, ast.Name) and target.id == "FEATURES" for target in node.targets))
        self.assertEqual(tuple(ast.literal_eval(feature_assignment.value)), P.FEATURE_KEYS)
        for version in (P.MINIMUM_VERSION, "codex-cli 0.145", "codex-cli 0.145.0-alpha.17", "codex-cli 0.145.0-alpha.19",
                        "codex-cli 0.145.0", "codex-cli 0.144.99", "codex-cli 1.0.0", "codex-cli 0.145.0-alpha..18", "nonsense"):
            with self.subTest(version=version):
                self.assertEqual(P._version_at_or_above(version), namespace["version_at_or_above"](version))

    def test_each_required_exec_flag(self):
        for flag in P.EXEC_FLAGS:
            with self.subTest(flag=flag):
                self.data = inputs()
                self.data["exec_help"] = self.data["exec_help"].replace(flag.encode(), (flag + "-other").encode())
                self.fails("execFlags")

    def test_flag_in_prose_does_not_count(self):
        self.data["exec_help"] = b"These words mention " + b" ".join(x.encode() for x in P.EXEC_FLAGS)
        self.fails("execFlags")

    def test_additional_flag_and_feature_are_inert(self):
        self.data["exec_help"] += b"\n      --new-inert-option <VALUE>"
        self.data["features"] += b"\nother_feature stable true"
        self.assertTrue(self.result()["compatible"])

    def test_additional_dotted_features_are_inert(self):
        for row in (b"guardianv2.thread_context under development false",
                    b"vendor.guardian_v2.thread_context stable true"):
            with self.subTest(row=row):
                self.data = inputs()
                self.data["features"] += b"\n" + row
                self.assertTrue(self.result()["compatible"])

    def test_each_feature_missing_or_enabled(self):
        for key in P.FEATURE_KEYS:
            for replacement in ("", key + " stable true"):
                with self.subTest(key=key, replacement=replacement):
                    self.data = inputs()
                    self.data["features"] = self.data["features"].replace((key + " under development false").encode(), replacement.encode())
                    self.fails("features")

    def test_namespaced_lookalike_cannot_replace_or_mask_required_feature(self):
        required = b"apps under development false"
        for replacement in (b"vendor.apps stable false",
                            b"apps stable true\nvendor.apps stable false"):
            with self.subTest(replacement=replacement):
                self.data = inputs()
                self.data["features"] = self.data["features"].replace(required, replacement)
                self.fails("features")

    def test_duplicate_feature_and_unknown_format(self):
        for tail in (b"\napps stable false", b"\nerror: no configuration", b"\nstrange stable 0"):
            with self.subTest(tail=tail):
                self.data = inputs()
                self.data["features"] += tail
                self.fails("features")

    def test_dotted_feature_duplicate_and_malformed_segments_fail(self):
        valid = b"guardianv2.thread_context under development false"
        for tail in (b"\n" + valid + b"\n" + valid,
                     b"\n.guardian stable false", b"\nguardian. stable false",
                     b"\nguardian..thread stable false", b"\nguardian.2thread stable false",
                     b"\nguardian.Thread stable false", b"\nguardian.thread stable 0"):
            with self.subTest(tail=tail):
                self.data = inputs()
                self.data["features"] += tail
                self.fails("features")

    def test_feature_text_safety_and_budget_stay_fail_closed(self):
        for tail in (b"\ninvalid.utf8 stable false\xff",
                     b"\nguardian.\xc3\xa9 stable false",
                     b"\nguardian.thread stable false\x1b",
                     b"\n" + b"x" * P.MAX_TEXT_BYTES + b" stable false"):
            with self.subTest(tail=tail[:32]):
                self.data = inputs()
                self.data["features"] += tail
                self.fails("features")

    def test_text_limits_and_exact_bytes(self):
        for bad in (True, bytearray(b"x"), b"\xff", b"\x1b[31msecret", b"x" * (P.MAX_TEXT_BYTES + 1)):
            with self.subTest(kind=type(bad)):
                self.data["version"] = bad
                self.assertIn("version_input_invalid", self.fails("version")["reasonCodes"])

    def test_duplicate_json_and_private_traceback_redacted(self):
        for raw in (b'{"secret":"raw-private","secret":2}', b'{"raw-private": NaN}', b'{"raw-private":', b'[]'):
            with self.subTest(raw=raw):
                try:
                    P.parse_schema(raw)
                except P.PolicyError as error:
                    rendered = "".join(traceback.format_exception(type(error), error, error.__traceback__))
                    self.assertEqual(str(error), "schema_input_invalid")
                    self.assertNotIn("raw-private", rendered)
                    self.assertIsNone(error.__context__)
                else:
                    self.fail("accepted malformed input")

    def test_parse_roundtrip_and_bounds(self):
        self.assertEqual(P.parse_schema(json.dumps(self.schema).encode()), self.schema)
        for bad in (b" " * (P.MAX_SCHEMA_BYTES + 1), b'{"x":' * 66 + b'0' + b'}' * 66,
                    b'{"x":' + b'9' * 10000 + b'}'):
            with self.assertRaises(P.PolicyError):
                P.parse_schema(bad)

    def test_bad_schema_containers_and_cycles(self):
        class Custom(dict):
            pass
        cycle = {}; cycle["loop"] = cycle
        for bad in (True, [], Custom(self.schema), cycle, {"x": object()}):
            with self.subTest(kind=type(bad)):
                self.data["schema"] = bad
                self.fails()

    def test_unknown_schema_format_is_explicit(self):
        self.schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        self.assertIn("schema_shape_unproven", self.fails()["reasonCodes"])

    def test_incomplete_v2_document_does_not_pass_by_names(self):
        self.data["schema"] = {"$schema": self.schema["$schema"], "definitions": self.v2}
        self.fails()

    def test_new_required_request_parameter_fails(self):
        node = self.defs["ClientRequest"]["oneOf"][2]["properties"]["params"]
        node["properties"]["newRequired"] = scalar("boolean")
        node["required"].append("newRequired")
        self.fails()

    def test_new_required_envelope_field_fails(self):
        node = self.defs["ClientRequest"]["oneOf"][0]
        node["properties"]["jsonrpc"] = enum("2.0")
        node["required"].append("jsonrpc")
        self.fails()

    def test_new_optional_request_and_response_properties_pass(self):
        node = self.defs["ClientRequest"]["oneOf"][2]["properties"]["params"]
        node["properties"]["unused"] = {"type": "string", "pattern": "anything"}
        self.v2["SkillMetadata"]["properties"]["newLabel"] = scalar("string")
        self.v2["SkillMetadata"]["required"].append("newLabel")
        self.v2["HookMetadata"]["description"] = "An inert new description"
        self.assertTrue(self.result()["compatible"])

    def test_nullable_request_array_and_object_types(self):
        params = self.defs["ClientRequest"]["oneOf"][4]["properties"]["params"]
        params["properties"]["cwds"]["type"] = ["array", "null"]
        params["type"] = ["object", "null"]
        self.assertTrue(self.result()["compatible"])
        params["properties"]["cwds"]["minItems"] = 1
        self.fails()

    def test_removed_required_response_field(self):
        for name, key in (("HookMetadata", "currentHash"), ("SkillMetadata", "enabled"),
                          ("HooksListEntry", "warnings"), ("PluginSummary", "id"),
                          ("PluginMarketplaceEntry", "plugins"), ("SkillsListResponse", "data")):
            with self.subTest(name=name, key=key):
                self.setUp()
                self.v2[name]["required"].remove(key)
                self.fails()

    def test_wrong_consumed_property_type(self):
        for name, key in (("HookMetadata", "enabled"), ("SkillMetadata", "path"), ("PluginSummary", "installed")):
            with self.subTest(name=name, key=key):
                self.setUp()
                self.v2[name]["properties"][key] = scalar("number")
                self.fails()

    def test_bool_is_not_integer_in_schema_constraints_or_enum(self):
        for node in ({"type": "integer", "minimum": True}, {"type": "integer", "enum": [True]},
                     {"type": "integer", "const": True}, {"type": "integer", "maxLength": False}):
            with self.subTest(node=node):
                self.v2["HookMetadata"]["properties"]["displayOrder"] = node
                self.fails()

    def test_unknown_format_on_inspected_client_info_is_unproven(self):
        client = self.defs["ClientRequest"]["oneOf"][0]["properties"]["params"]["properties"]["clientInfo"]
        client["properties"]["name"]["format"] = "uuid"
        self.assertIn("schema_shape_unproven", self.fails()["reasonCodes"])

    def test_supported_integer_formats_enforce_ranges(self):
        schema = P._Schema(self.schema)
        for name, good, bad in (("int64", (-2**63, 2**63-1), (-2**63-1, 2**63)),
                                ("uint64", (0, 2**64-1), (-1, 2**64)),
                                ("uint", (0, 1), (-1,))):
            node = {"type": "integer", "format": name}
            for value in good:
                self.assertTrue(schema.accepts(node, value))
            for value in bad + (True, False):
                self.assertFalse(schema.accepts(node, value))
        self.v2["HookMetadata"]["properties"]["displayOrder"] = {"type": "integer", "format": "int64", "const": 2**63}
        self.fails()

    def test_selected_skill_and_hook_metadata_reject_forced_wrong_values(self):
        for name, key, change in (("SkillMetadata", "enabled", {"const": False}),
                                  ("SkillMetadata", "pluginId", {"enum": ["forced-plugin"]}),
                                  ("SkillMetadata", "name", {"const": "wrong-skill"}),
                                  ("HookMetadata", "pluginId", {"const": "forced-plugin"})):
            with self.subTest(name=name, key=key):
                self.setUp()
                self.v2[name]["properties"][key].update(change)
                self.fails()

    def test_skill_scope_cannot_widen_beyond_consumer_closed_domain(self):
        self.v2["SkillMetadata"]["properties"]["scope"]["enum"].append("workspace")
        self.fails()

    def test_nullable_threshold_change_is_semantic(self):
        for change in ({"default": 0}, {"const": 2500}, {"type": "integer"}):
            with self.subTest(change=change):
                self.setUp()
                self.v2["HookMetadata"]["properties"]["additionalContextLimit"].update(change)
                self.fails()

    def test_hook_state_constraint_cannot_disable_current_contract(self):
        for key, value in (("enabled", False), ("isManaged", True), ("source", "system")):
            with self.subTest(key=key):
                self.setUp()
                self.v2["HookMetadata"]["properties"][key]["const"] = value
                self.fails()

    def test_unknown_primitive_intersection_is_unproven(self):
        self.v2["HookMetadata"]["properties"]["displayOrder"]["anyOf"] = [scalar("boolean")]
        self.assertIn("schema_shape_unproven", self.fails()["reasonCodes"])

    def test_missing_notification_or_closed_added_params_fails(self):
        self.defs["ClientNotification"]["oneOf"][0]["additionalProperties"] = False
        self.fails()
        self.setUp()
        self.defs.pop("ClientNotification")
        self.fails()

    def test_cli_option_contracts_and_duplicate_required(self):
        self.data["app_server_help"] = b"Options:\n --listen <URL>\n"
        self.fails("appServerFlags")
        self.setUp()
        self.data["mcp_list_help"] = b"Options:\n --json-other\n"
        self.fails("mcpFlags")
        self.setUp()
        self.v2["HookMetadata"]["required"].append("enabled")
        self.fails()

    def test_bool_rpc_id_does_not_stand_in_for_integer(self):
        self.v2["RequestId"] = {"type": "boolean", "enum": [True, False]}
        self.fails()

    def test_id_zero_only_does_not_accept_later_requests(self):
        self.v2["RequestId"] = {"type": "integer", "maximum": 0}
        self.fails()

    def test_removed_event_or_trust_value_fails(self):
        for key, remove in (("eventName", "preToolUse"), ("source", "user"), ("trustStatus", "trusted")):
            with self.subTest(key=key):
                self.setUp()
                self.v2["HookMetadata"]["properties"][key]["enum"].remove(remove)
                self.fails()

    def test_duplicate_method_and_changed_method_fail(self):
        self.defs["ClientRequest"]["oneOf"].append(copy.deepcopy(self.defs["ClientRequest"]["oneOf"][2]))
        self.fails()
        self.setUp()
        self.defs["ClientRequest"]["oneOf"][2]["properties"]["method"]["enum"] = ["hooks/list-extra"]
        self.fails()

    def test_external_or_cyclic_ref_is_unproven(self):
        for target in ("https://example.test/private", "#/definitions/v2/RequestId"):
            with self.subTest(target=target):
                self.v2["RequestId"] = {"$ref": target}
                self.assertIn("schema_shape_unproven", self.fails()["reasonCodes"])

    def test_ref_semantic_sibling_and_unknown_keyword_are_unproven(self):
        self.v2["HookMetadata"]["properties"]["displayOrder"] = {"$ref": "#/definitions/v2/RequestId", "type": "integer"}
        self.fails()
        self.setUp()
        self.defs["ClientRequest"]["oneOf"][2]["properties"]["params"]["not"] = {"type": "object"}
        self.assertIn("schema_shape_unproven", self.fails()["reasonCodes"])

    def test_skill_dependency_and_plugin_source_semantics(self):
        self.v2["SkillDependencies"]["required"].remove("tools")
        self.fails()
        self.setUp()
        self.v2["PluginSource"]["oneOf"][0]["required"].remove("path")
        self.fails()

    def test_remote_source_extra_semantic_field_is_not_inert(self):
        self.v2["PluginSource"]["oneOf"][3]["properties"]["url"] = scalar("string")
        self.fails()

    def test_all_failures_are_bounded_and_redacted(self):
        self.data.update(version=b"raw-private", exec_help=b"raw-private", mcp_list_help=b"raw-private",
                         app_server_help=b"raw-private", features=b"raw-private", schema={"raw-private": "raw-private"})
        result = self.result()
        self.assertEqual(len(result["checks"]), 6)
        self.assertLessEqual(len(result["reasonCodes"]), 6)
        self.assertNotIn("raw-private", json.dumps(result))

    def test_interruptions_propagate_unchanged(self):
        for error in (KeyboardInterrupt("private"), SystemExit("private")):
            with self.subTest(kind=type(error)):
                with patch.object(P, "_schema_contract", side_effect=error):
                    with self.assertRaises(type(error)) as caught:
                        self.result()
                self.assertIs(caught.exception, error)


if __name__ == "__main__":
    unittest.main()
