"""Pure hostile contracts with explicitly loaded real legacy definitions."""

import copy
from contextlib import ExitStack
from dataclasses import replace
import importlib.machinery
import json
from pathlib import Path
import sys
import traceback
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import phase5_current_trusted as current

# Test-only admitted definitions; the production helper never imports the runner.
D = importlib.machinery.SourceFileLoader("current_trusted_legacy_fakes", str(ROOT / "bin/phase5-trusted-probe")).load_module()
HOME, CONTROL = "/Users/synthetic-owner", "/Users/synthetic-owner/AIDev/control"
SCHEMA, RESULT = "/private/tmp/owned-test/schema.json", "/private/tmp/owned-test/result.json"
SOURCE_PATHS = {"hooks-definition": "codex/hooks.json", "hook-router": "codex/hooks/phase5-contract.py",
                "skill-definition": "skills/manage-workstation/SKILL.md",
                "skill-metadata": "skills/manage-workstation/agents/openai.yaml"}


def fixture():
    sources = {key: (ROOT / relative).read_bytes() for key, relative in SOURCE_PATHS.items()}
    hashes = {key: D.sha256_bytes(raw) for key, raw in sources.items()}
    source = json.loads(sources["hooks-definition"])
    hooks = []
    for index, (slot, event) in enumerate(current.SOURCE_EVENTS.items()):
        group = source["hooks"][event][0]
        handler = group["hooks"][0]
        hooks.append({"key": HOME + "/.codex/hooks.json:" + slot, "sourcePath": HOME + "/.codex/hooks.json",
            "currentHash": D.HASHES[slot], "eventName": D.EVENTS[slot], "enabled": True, "isManaged": False,
            "handlerType": "command", "source": "user", "trustStatus": "trusted", "displayOrder": index,
            "command": handler["command"], "matcher": group.get("matcher"), "timeoutSec": handler["timeout"],
            "statusMessage": handler.get("statusMessage"), "pluginId": None, "async": False})
    description = next(line[13:] for line in sources["skill-definition"].decode().splitlines() if line.startswith("description: "))
    skill = {"name": "manage-workstation", "path": HOME + "/.codex/skills/manage-workstation/SKILL.md",
             "description": description, "enabled": True, "scope": "user", "pluginId": None,
             "interface": {"displayName": "Manage Workstation"}, "dependencies": None}
    return ({"data": [{"cwd": CONTROL, "errors": [], "warnings": [], "hooks": hooks}]},
            {"data": [{"cwd": CONTROL, "errors": [], "skills": [skill]}]}, sources, hashes)


class CurrentTrustedTests(unittest.TestCase):
    def setUp(self):
        self.hooks, self.skills, self.sources, self.installed = fixture()
        self.parameters = dict(home=HOME, control=CONTROL, hook_hashes=dict(D.HASHES))
        stack = ExitStack()
        self.addCleanup(stack.close)
        for name in ("live_snapshot", "real_run", "manifest_contract", "checked_cli", "owner_layout",
                     "app_server_probe", "isolated_validation", "write_private", "no_symlink_components"):
            stack.enter_context(patch.object(D, name, side_effect=AssertionError("forbidden historical/native helper")))
        stack.enter_context(patch.object(D.subprocess, "Popen", side_effect=AssertionError("no native child")))
        stack.enter_context(patch.object(D.subprocess, "run", side_effect=AssertionError("no native command")))

    def check(self):
        return current.validate_discovery(D, self.hooks, self.skills, **self.parameters,
            expected_sources=self.sources, installed_hashes=self.installed)

    def rejects(self, function):
        with self.assertRaises(current.TrustedError) as raised:
            function()
        self.assertEqual(str(raised.exception), "current_trusted_contract_required")
        return raised.exception

    def test_exact_discovery_launch_and_legacy_overrides(self):
        launch = current.discovery_launch(D, **self.parameters)
        self.assertEqual(launch.argv, tuple(D.app_server_command(Path(HOME), Path(CONTROL))))
        self.assertEqual(launch.environment, D.clean_environment(Path(HOME), Path(HOME) / ".codex"))
        self.assertEqual(launch.cwd, CONTROL)
        self.assertTrue(current.discovery_command_contract(D, launch, **self.parameters))
        for override in D.STATIC_OVERRIDES + D.dynamic_overrides(Path(HOME), Path(CONTROL)):
            self.assertIn(override, launch.argv)
        self.assertNotIn("--ignore-user-config", launch.argv)  # No invented app-server capability.
        self.assertNotIn(HOME, repr(launch))

    def test_discovery_recheck_rejects_changed_flags_environment_or_cwd(self):
        original = current.discovery_launch(D, **self.parameters)
        variants = [replace(original, argv=original.argv + (flag,)) for flag in ("--yolo", "--profile", "--search")]
        variants += [replace(original, argv=tuple(arg for arg in original.argv if arg != "--strict-config")),
                     replace(original, environment={**original.environment, "PRIVATE_TOKEN": "private"}),
                     replace(original, environment={**original.environment, "CODEX_HOME": HOME + "/elsewhere"}),
                     replace(original, cwd=HOME), replace(original, argv=list(original.argv))]
        for launch in variants:
            self.rejects(lambda: current.discovery_command_contract(D, launch, **self.parameters))

    def test_canonical_layout_and_exact_three_trust_hashes_required(self):
        for key, value in (("home", HOME + "/"), ("home", HOME + "/../owner"), ("home", HOME + '"'),
                           ("control", CONTROL + "/."), ("control", "/elsewhere/control"), ("home", True)):
            parameters = {**self.parameters, key: value}
            self.rejects(lambda: current.discovery_launch(D, **parameters))
        for kind in ("changed", "missing", "extra", "type"):
            hashes = dict(D.HASHES)
            if kind == "changed": hashes["stop:0:0"] = "sha256:" + "0" * 64
            elif kind == "missing": del hashes["stop:0:0"]
            elif kind == "extra": hashes["stop:0:1"] = hashes["stop:0:0"]
            else: hashes["stop:0:0"] = True
            self.rejects(lambda: current.discovery_launch(D, **{**self.parameters, "hook_hashes": hashes}))

    def test_valid_discovery_returns_only_redacted_observation_not_authority(self):
        before = copy.deepcopy((self.hooks, self.skills, self.sources, self.installed))
        result = self.check()
        self.assertEqual(result["verdict"], "matched")
        self.assertEqual((result["hookCount"], result["selectedSkillCount"]), (3, 1))
        for key in ("hookExecutionProven", "skillUseProven", "modelRequestAuthorized", "executionAdmission", "phase5Accepted", "phase6Allowed"):
            self.assertIs(result[key], False)
        self.assertNotIn(HOME, json.dumps(result))
        self.assertNotIn(D.HASHES["stop:0:0"], json.dumps(result))
        self.assertEqual((self.hooks, self.skills, self.sources, self.installed), before)

    def test_response_order_and_inert_metadata_are_not_authority(self):
        self.hooks["data"][0]["hooks"].reverse()
        self.hooks["serverLabel"] = "private diagnostic"
        self.skills["data"][0]["skills"].append({"name": "unrelated", "description": "ignored",
            "path": HOME + "/.codex/skills/unrelated/SKILL.md", "scope": "user", "enabled": False})
        self.assertEqual(self.check()["verdict"], "matched")

    def test_source_hash_mismatch_for_each_installed_component(self):
        original = dict(self.installed)
        for identity in current.SOURCE_IDS:
            self.installed = {**original, identity: "0" * 64}
            self.rejects(self.check)
        self.installed = original
        self.sources["unadmitted"] = b"private"
        self.rejects(self.check)

    def test_changed_event_slot_full_key_hash_trust_or_handler_rejected(self):
        original = copy.deepcopy(self.hooks)
        variants = {"key": HOME + "/decoy/hooks.json:session_start:0:0", "sourcePath": HOME + "/decoy/hooks.json",
            "eventName": "preToolUse", "currentHash": "sha256:" + "0" * 64, "enabled": 1,
            "isManaged": True, "handlerType": "mcpTool", "trustStatus": "untrusted", "source": "project",
            "command": "/usr/bin/true", "matcher": ".*", "timeoutSec": True,
            "statusMessage": "different", "async": True, "pluginId": "unadmitted", "displayOrder": True,
            "server": "unadmitted", "tool": "unadmitted"}
        for key, value in variants.items():
            self.hooks = copy.deepcopy(original)
            self.hooks["data"][0]["hooks"][0][key] = value
            self.rejects(self.check)
        self.hooks = copy.deepcopy(original)
        self.hooks["data"][0]["hooks"][1] = copy.deepcopy(self.hooks["data"][0]["hooks"][0])
        self.rejects(self.check)

    def test_missing_required_hook_metadata_or_extra_hook_rejected(self):
        original = copy.deepcopy(self.hooks)
        for key in ("key", "currentHash", "command", "displayOrder", "timeoutSec", "enabled", "source"):
            self.hooks = copy.deepcopy(original)
            del self.hooks["data"][0]["hooks"][0][key]
            self.rejects(self.check)
        self.hooks = copy.deepcopy(original)
        self.hooks["data"][0]["hooks"].append(copy.deepcopy(self.hooks["data"][0]["hooks"][0]))
        self.rejects(self.check)

    def test_absent_source_context_limit_accepts_only_omitted_or_null_default(self):
        source = json.loads(self.sources["hooks-definition"])
        for event in current.SOURCE_EVENTS.values():
            self.assertNotIn("additionalContextLimit", source["hooks"][event][0])
            self.assertNotIn("additionalContextLimit", source["hooks"][event][0]["hooks"][0])
        self.assertEqual(self.check()["verdict"], "matched")
        for hook in self.hooks["data"][0]["hooks"]:
            hook["additionalContextLimit"] = None
            hook["descriptiveMetadata"] = {"label": "still inert"}
            self.assertEqual(self.check()["verdict"], "matched")

    def test_context_limit_rejects_changed_thresholds_and_malformed_nullable_uint(self):
        original = copy.deepcopy(self.hooks)
        # The current-source contract is narrower than nullable uint: no number,
        # including effective-default 2500 or either uint boundary, is admitted.
        values = (False, True, "2500", "private threshold", -1, 0, 1, 2499, 2500,
                  2501, 2 ** 32 - 1, 2 ** 32, 2 ** 64 - 1, 2 ** 64,
                  0.0, 2500.0, [], {})
        for index in range(3):
            for value in values:
                with self.subTest(slot=index, value=value):
                    self.hooks = copy.deepcopy(original)
                    self.hooks["data"][0]["hooks"][index]["additionalContextLimit"] = value
                    self.rejects(self.check)

    def test_changed_context_limit_source_is_not_admitted_by_matching_hash_or_response(self):
        original = self.sources["hooks-definition"]
        for event in current.SOURCE_EVENTS.values():
            for location in ("group", "handler"):
                for value in (None, 0, 2500):
                    with self.subTest(event=event, location=location, value=value):
                        document = json.loads(original)
                        group = document["hooks"][event][0]
                        target = group if location == "group" else group["hooks"][0]
                        target["additionalContextLimit"] = value
                        raw = json.dumps(document).encode()
                        self.sources["hooks-definition"] = raw
                        self.installed["hooks-definition"] = D.sha256_bytes(raw)
                        for hook in self.hooks["data"][0]["hooks"]:
                            hook["additionalContextLimit"] = value
                        self.rejects(self.check)

    def test_cwd_errors_warnings_and_collection_shapes(self):
        original = copy.deepcopy((self.hooks, self.skills))
        for target in ("hooks", "skills"):
            for key, value in (("cwd", HOME), ("errors", ["private failure"]), ("warnings", ["private warning"]), (target, None)):
                self.hooks, self.skills = copy.deepcopy(original)
                getattr(self, target)["data"][0][key] = value
                self.rejects(self.check)
            self.hooks, self.skills = copy.deepcopy(original)
            getattr(self, target)["data"].append(copy.deepcopy(getattr(self, target)["data"][0]))
            self.rejects(self.check)

    def test_skill_identity_scope_source_and_optional_schema_failures(self):
        original = copy.deepcopy(self.skills)
        variants = {"name": "wrong", "path": HOME + "/.codex/skills/decoy/SKILL.md", "scope": "repo",
            "enabled": False, "description": "not the admitted source", "pluginId": "unadmitted",
            "interface": True, "shortDescription": 1, "dependencies": {"tools": [{"type": "mcp", "value": "unadmitted"}]}}
        for key, value in variants.items():
            self.skills = copy.deepcopy(original)
            self.skills["data"][0]["skills"][0][key] = value
            self.rejects(self.check)
        self.skills = copy.deepcopy(original)
        self.skills["data"][0]["skills"][0]["interface"] = {"displayName": False}
        self.rejects(self.check)

    def test_duplicate_or_disabled_shadow_skill_never_resolves_ambiguity(self):
        original = copy.deepcopy(self.skills)
        for changed in ({}, {"path": HOME + "/other/SKILL.md", "scope": "system", "enabled": False}):
            self.skills = copy.deepcopy(original)
            duplicate = {**self.skills["data"][0]["skills"][0], **changed}
            self.skills["data"][0]["skills"].append(duplicate)
            self.rejects(self.check)

    def test_malformed_duplicate_nonfinite_or_unbounded_input_is_redacted(self):
        for raw in (b'{"data":[],"data":[]}', b'not json private', b'\xff', b'{"data":NaN}',
                    b' ' * (current.MAX_BYTES + 1)):
            self.hooks = raw
            error = self.rejects(self.check)
            text = "".join(traceback.format_exception(type(error), error, error.__traceback__))
            self.assertNotIn("not json private", text)
        value = {}
        for _ in range(18): value = {"nested": value}
        self.hooks = value
        self.rejects(self.check)

    def test_task_material_is_unchanged_and_contains_exact_sentinel(self):
        material = current.task_material(D)
        self.assertEqual(material["prompt"], D.FIXED_TASK)
        self.assertEqual(material["schema"], D.canonical_schema())
        self.assertEqual((material["model"], material["reasoningEffort"], material["maximumRequests"]), ("gpt-5.6-sol", "max", 1))
        self.assertIn("/usr/bin/false && brew install phase5-never-run; /usr/bin/true", material["prompt"])
        self.assertFalse(material["modelRequestAuthorized"])
        material["schema"]["properties"]["route"]["const"] = "mutated"
        self.assertEqual(current.task_material(D)["schema"], D.canonical_schema())

    def test_exec_launch_exact_builder_validator_and_clean_environment(self):
        parameters = {**self.parameters, "schema_path": SCHEMA, "result_path": RESULT}
        launch = current.exec_launch(D, **parameters)
        expected = D.build_exec_command(Path(HOME), Path(HOME) / ".codex", Path(CONTROL), Path(SCHEMA), Path(RESULT))
        self.assertEqual(launch.argv, tuple(expected))
        self.assertTrue(current.exec_command_contract(D, launch, **parameters))
        for flag in ("--ignore-user-config", "--ignore-rules", "--ephemeral", "--json", "--model"):
            self.assertEqual(launch.argv.count(flag), 1)
            changed = replace(launch, argv=tuple(item for item in launch.argv if item != flag))
            self.rejects(lambda: current.exec_command_contract(D, changed, **parameters))
        for flag in ("--dangerously-bypass-hook-trust", "--yolo", "--search", "--profile"):
            changed = replace(launch, argv=launch.argv[:-2] + (flag,) + launch.argv[-2:])
            self.rejects(lambda: current.exec_command_contract(D, changed, **parameters))
        changed = replace(launch, argv=tuple("gpt-other" if arg == "gpt-5.6-sol" else arg for arg in launch.argv))
        self.rejects(lambda: current.exec_command_contract(D, changed, **parameters))
        self.rejects(lambda: current.exec_launch(D, **{**parameters, "result_path": SCHEMA}))

    def test_output_object_order_is_semantic_but_constants_types_and_keys_are_exact(self):
        def output(node):
            return {key: output(child) for key, child in reversed(list(node["properties"].items()))} if node["type"] == "object" else node["const"]
        valid = output(D.canonical_schema())
        self.assertEqual(current.validate_task_output(D, valid)["verdict"], "schema-valid")
        self.assertEqual(current.validate_task_output(D, json.dumps(valid).encode())["verdict"], "schema-valid")
        for key, value in (("route", "elsewhere"), ("manageWorkstationUsed", 1), ("extra", True)):
            invalid = {**valid, key: value}
            self.rejects(lambda: current.validate_task_output(D, invalid))
        for value in (False, 0.0, 1, "0"):
            invalid = copy.deepcopy(valid)
            invalid["observations"]["mutationCount"] = value
            self.rejects(lambda: current.validate_task_output(D, invalid))
        self.rejects(lambda: current.validate_task_output(D, b'{"route":"control","route":"control"}'))

    def test_interruptions_from_admitted_definition_are_not_suppressed(self):
        for error in (KeyboardInterrupt(), SystemExit(17)):
            with patch.object(D, "app_server_command", side_effect=error), self.assertRaises(type(error)) as raised:
                current.discovery_launch(D, **self.parameters)
            self.assertIs(raised.exception, error)


if __name__ == "__main__":
    unittest.main()
