"""PURE fake filesystem/collectors only. Never run the native entry point."""

import copy
import gc
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import stat
import sys
from types import SimpleNamespace
import unittest
import weakref
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
R = importlib.machinery.SourceFileLoader("readiness_test_module", str(ROOT / "bin/phase5-current-readiness")).load_module()


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


T = load("readiness_target_fakes", "tests/test_phase5_runtime_targets.py")
L = T.fakes
M = load("readiness_integration_fakes", "tests/test_phase5_runtime_integrations.py")
HOME = "/Users/owner"
MARKER = b"388d466a-c374-4294-b8f3-8614113e33ae\n"  # public signed distribution marker, not app ID


def raw(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def replace_home(value):
    if type(value) is str:
        return value.replace("/Users/synthetic-owner", HOME)
    if type(value) is dict:
        return {key: replace_home(item) for key, item in value.items()}
    if type(value) is list:
        return [replace_home(item) for item in value]
    return value


def toml(value):
    if type(value) is dict:
        return "{" + ", ".join(json.dumps(key) + " = " + toml(item) for key, item in value.items()) + "}"
    if type(value) is list:
        return "[" + ", ".join(toml(item) for item in value) + "]"
    return json.dumps(value)


class Pin:
    """Fake observations; source-file hashing itself is tested with fake syscalls."""
    def __init__(self, data, *, digest=None, absent=False):
        self.absent = absent
        self.data, self.digest = data, "absent" if absent else sha(data) if digest is None else digest
        self.initial = data, self.digest, self.absent
        self.closed = False
        self.stamp = (1, 2, 501, 20, stat.S_IFREG | 0o755, 1, len(data), 1, 1, 0)
        self.effect = None

    def verify(self):
        if self.effect is not None:
            effect, self.effect = self.effect, None
            effect()
        R.require((self.data, self.digest, self.absent) == self.initial and not self.closed)
        return True

    def close(self):
        self.closed = True


def runtime_fixture(target_fs):
    plugins, mcp, effective, facts = replace_home(M.fixture())
    runtime = R.NativeRuntime(HOME, 501, R.Budget(clock=lambda: 0))
    runtime.version = facts["app_version"]
    runtime.environment = {"HOME": HOME, "CODEX_HOME": HOME + "/.codex", "LANG": "C", "LC_ALL": "C",
                           "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SHELL": "/bin/zsh"}
    runtime.roots = facts["plugin_roots"]
    runtime.effective_bytes = raw(effective)
    runtime.contract = {"runtime": {"bundleId": "com.openai.codex"}, "generatedFiles": []}
    runtime.hook_records = {key: "sha256:" + "a" * 64 for key in ("session_start:0:0", "pre_tool_use:0:0", "stop:0:0")}
    hooks = {"state": {HOME + "/.codex/hooks.json:" + key: {"trusted_hash": value}
                       for key, value in runtime.hook_records.items()}}
    config = ("# synthetic owner comment\napproval_policy = 'never'\nsandbox_mode = 'danger-full-access'\n"
              + "hooks = " + toml(hooks) + "\nplugins = " + toml(plugins)
              + "\nmcp_servers = " + toml(mcp) + "\n").encode()
    target_fs.nodes[T.path(0)]["data"] = config
    for index, (identity, relative) in enumerate(R.MANAGED.items(), 1):
        data = target_fs.nodes[T.path(index)]["data"]
        runtime.pins[str(ROOT / relative)] = Pin(data, digest=R.GUIDANCE_HASH if identity == "global-agents" else None)
        runtime.contract["generatedFiles"].append({"source": relative, "sha256": sha(data)})

    def add(path, value, digest=None):
        runtime.pins[path] = Pin(value if type(value) is bytes else raw(value), digest=digest)

    source_roots = {
        "openai-bundled": HOME + "/.codex/.tmp/bundled-marketplaces/openai-bundled",
        "openai-curated": HOME + "/.codex/.tmp/plugins",
        "openai-primary-runtime": HOME + "/.cache/codex-runtimes/codex-primary-runtime/plugins/openai-primary-runtime",
    }
    signed = R.APP + "/plugins/openai-bundled"
    add(signed + "/.bundle-id", MARKER)
    marketplaces, material_rows = [], []
    for marketplace, source_root in source_roots.items():
        catalog_plugins, source_rows = [], []
        for identity, root in runtime.roots.items():
            name, kind = identity.split("@")
            if kind != marketplace:
                continue
            ref = root.rsplit("/", 1)[1]
            version = R.CURATED[name][0] if marketplace == "openai-curated" else ref
            manifest = {"name": name, "version": version, "description": "public fixture"}
            expected = dict(manifest)
            if marketplace == "openai-bundled":
                add(signed + "/plugins/" + name + "/.codex-plugin/plugin.json", manifest)
                if name in ("computer-use", "visualize"):
                    expected["bundledContentVariant"] = "node-repl" if name == "computer-use" else "live-disabled"
                material_rows.append({"name": name, "version": ref})
            digest = R.CURATED[name][1] if marketplace == "openai-curated" else None
            add(source_root + "/plugins/" + name + "/.codex-plugin/plugin.json", expected, digest=digest)
            add(root + "/.codex-plugin/plugin.json", expected)
            source_rows.append({"name": name, "source": {"source": "local", "path": "./plugins/" + name},
                                "description": "inert public field"})
            catalog_plugins.append({"id": identity, "name": name, "enabled": True, "installed": True,
                "authPolicy": "ON_USE" if marketplace == "openai-primary-runtime" else "ON_INSTALL",
                "installPolicy": "AVAILABLE", "source": {"type": "local", "path": source_root + "/plugins/" + name},
                "localVersion": version, "remotePluginId": None, "version": None})
        marketplaces.append({"name": marketplace, "path": source_root, "plugins": catalog_plugins})
        source_catalog = {"name": marketplace, "plugins": source_rows, "description": "inert top metadata"}
        add(source_root + "/.agents/plugins/marketplace.json", source_catalog)
        if marketplace == "openai-bundled":
            add(signed + "/.agents/plugins/marketplace.json", source_catalog)
    remote = [{"id": name + "@openai-curated-remote", "name": name, "source": {"type": "remote"},
               "enabled": True, "installed": True, "authPolicy": policies[0], "installPolicy": policies[1],
               "version": "opaque-provider-version", "remotePluginId": "private-synthetic-backend", "localVersion": None}
              for name, policies in R.REMOTE_POLICIES.items()]
    marketplaces.append({"name": "openai-curated-remote", "path": None, "plugins": remote})
    runtime.catalog_bytes = raw({"installed": {"marketplaces": marketplaces, "marketplaceLoadErrors": []},
        "vertical": {"marketplaces": [], "marketplaceLoadErrors": []},
        "transport": {"childReaped": True, "stderrEmpty": True, "notificationCount": 0}})
    add(source_roots["openai-bundled"] + "/.materialization-key", {
        "version": 1, "appVersion": runtime.version, "bundleId": MARKER.decode().strip(), "marketplaceName": "openai-bundled",
        "computerUseSkillVariant": "node-repl", "computerUseAudioEnabled": False,
        "liveVisualizationSkillVariant": "live-disabled", "visualizeSkillContentHash": R.VISUALIZE_HASH,
        "plugins": sorted(material_rows, key=lambda row: row["name"])})
    add(HOME + "/.codex/.tmp/plugins.sha", (R.CURATED_REF + "\n").encode())
    for name in ("computer-history", "computer-use"):
        definition = {"mcpServers": {name: {"command": "./bin/computer-use-client-launcher",
            "args": ["computer-history", "mcp"] if name == "computer-history" else ["mcp"], "cwd": ".", "env_vars": ["CODEX_HOME"]}}}
        add(signed + "/plugins/" + name + "/.mcp.json", definition)
        add(source_roots["openai-bundled"] + "/plugins/" + name + "/.mcp.json", definition)
        add(runtime.roots[name + "@openai-bundled"] + "/.mcp.json", definition)
    add(signed + "/plugins/unified-computer-use/.mcp.json", {"mcpServers": {"cua_repl": {"enabled": False}}})
    add(source_roots["openai-bundled"] + "/plugins/unified-computer-use/.mcp.json", {"mcpServers": {"cua_repl": {"enabled": False}}})
    add(runtime.roots["unified-computer-use@openai-bundled"] + "/.mcp.json", {"mcpServers": {"cua_repl": facts["rendered_cua"]}})
    computer_root = runtime.roots["computer-use@openai-bundled"]
    runtime.pins[computer_root + "/skills/computer-use"] = Pin(b"", absent=True)
    for path in (signed + "/plugins/computer-use/.codex-plugin/computer-use-node-repl.md",
                 source_roots["openai-bundled"] + "/plugins/computer-use/skills/computer-use/SKILL.md",
                 computer_root + "/.codex-plugin/computer-use-node-repl.md"):
        add(path, b"public synthetic computer skill", digest=R.COMPUTER_SKILL_HASH)
    for resource in R.CUA_RESOURCES:
        for plugin_root in (signed + "/plugins/unified-computer-use", source_roots["openai-bundled"] + "/plugins/unified-computer-use",
                            runtime.roots["unified-computer-use@openai-bundled"]):
            add(plugin_root + "/resources/" + resource, b"public signed resource")
    runtime.collect = lambda: runtime.facts()
    runtime.final_attest = runtime.verify  # explicitly fake attestation; no native path
    return runtime


class ConnectedTests(unittest.TestCase):
    def fixture(self):
        fs, metadata, _ = T.fixture()
        historical, pins = L.fixture()
        runtime = runtime_fixture(fs)
        return fs, metadata, historical, pins, runtime

    def run_connected(self, args, *, pending_owner=None):
        fs, metadata, historical, pins, runtime = args
        with patch.multiple(R.legacy, **pins), patch.object(R.capture.session, "capture", side_effect=AssertionError("no capture")), \
                patch.object(R.catalog.subprocess, "Popen", side_effect=AssertionError("no native process")):
            def invoke():
                return R.connected(HOME, 501, budget=runtime.budget,
                    target_observer=lambda home, uid: R.targets.observe(home, uid, syscalls=fs, platform=metadata),
                    legacy_observer=lambda home, uid: R.legacy.observe(home, uid, syscalls=historical),
                    runtime_factory=lambda *_: runtime)
            failure = None
            if pending_owner is None:
                result = invoke()
            else:
                with self.assertRaises(R.ReadinessError) as raised:
                    invoke()
                failure = raised.exception
                self.assertIs(failure.private_owner, pending_owner)
                self.assertIs(failure.settlement_failed, True)
                result = R.public("needs-review", settled=False, stage=failure.stage)
        self.assertEqual(fs.handles, {})
        self.assertEqual(historical.handles, {})
        self.assertTrue(all(pin.closed for pin in runtime.pins.values()))
        self.assertNotIn("private-synthetic-backend", str(result))
        self.assertNotIn(HOME, str(result))
        for key in ("executionAdmission", "liveAdmission", "configMutationAuthorized", "trustMutationAuthorized", "phase5Accepted", "phase6Allowed", "cleanupPerformed"):
            self.assertIs(result[key], False)
        return result if failure is None else failure

    def test_actual_targets_legacy_capture_matcher_classifier_connected_without_writes(self):
        args = self.fixture()
        originals = copy.deepcopy(args[0].nodes), copy.deepcopy(args[2].nodes)
        result = self.run_connected(args)
        self.assertEqual(result["verdict"], "ready")
        self.assertEqual(result["observedTargets"], 8)
        self.assertEqual(args[0].nodes, originals[0])
        self.assertEqual(args[2].nodes, originals[1])

    def test_nonempty_parent_xattrs_are_preserved_not_rejected(self):
        args = self.fixture()
        args[1].set(HOME + "/.codex", 0, ("com.private.parent",))
        self.assertEqual(self.run_connected(args)["verdict"], "ready")

    def test_file_metadata_not_silently_admitted_for_later_byte_only_capture(self):
        args = self.fixture()
        args[1].set(T.path(0), 0, ("com.private.file",))
        self.assertEqual(self.run_connected(args)["verdict"], "needs-review")

    def test_unknown_history_cwd_does_not_become_root_by_assumption(self):
        args = self.fixture()
        rows = args[4].effective
        rows[3]["transport"]["cwd"] = "."
        args[4].effective_bytes = raw(rows)
        self.assertEqual(self.run_connected(args)["verdict"], "needs-review")

    def test_connected_history_requires_exact_emission_and_canonical_fact(self):
        args = self.fixture()
        root = args[4].roots["computer-history@openai-bundled"]
        self.assertEqual(args[4].facts()["history_cwd_root"], root)
        self.assertTrue(R.integrations._path(root))
        history = next(row for row in args[4].effective if row["name"] == "computer-history")
        self.assertEqual(history["transport"]["command"], "./bin/computer-use-client-launcher")
        self.assertEqual(history["transport"]["cwd"], root + "/.")
        self.assertEqual(self.run_connected(args)["verdict"], "ready")
        for key, value in (
            ("cwd", root), ("cwd", root + "/"), ("cwd", root + "/./"),
            ("cwd", root + "/../."), ("cwd", root + "-other/."),
            ("command", "./bin/other-launcher"),
            ("command", "bin/computer-use-client-launcher"),
            ("command", "../bin/computer-use-client-launcher"),
            ("command", "./bin/../bin/computer-use-client-launcher"),
            ("command", root + "/bin/computer-use-client-launcher"),
        ):
            args = self.fixture()
            rows = args[4].effective
            next(row for row in rows if row["name"] == "computer-history")["transport"][key] = value
            args[4].effective_bytes = raw(rows)
            self.assertEqual(self.run_connected(args)["verdict"], "needs-review")

    def test_suppressed_legacy_skill_requires_actual_cua_rendering_and_effective_match(self):
        for source_change, effective_change in (("disabled", None), ("browser", None),
                                               (None, "disabled"), (None, "browser")):
            args = self.fixture()
            runtime = args[4]
            path = runtime.roots["unified-computer-use@openai-bundled"] + "/.mcp.json"
            if source_change is not None:
                rendered = runtime.json(path)
                cua = rendered["mcpServers"]["cua_repl"]
                if source_change == "disabled":
                    cua["enabled"] = False
                else:
                    cua["env"]["CUA_REPL_ENABLED_SURFACES"] = "browser"
                runtime.pins[path] = Pin(raw(rendered))
            if effective_change is not None:
                rows = runtime.effective
                cua = next(row for row in rows if row["name"] == "cua_repl")
                if effective_change == "disabled":
                    cua["enabled"] = False
                else:
                    cua["transport"]["env"]["CUA_REPL_ENABLED_SURFACES"] = "browser"
                runtime.effective_bytes = raw(rows)
            self.assertEqual(self.run_connected(args)["verdict"], "needs-review")

    def test_unexpected_installed_legacy_reappearance_and_retained_support_drift_fail(self):
        for kind in ("reappearance", "support"):
            args = self.fixture()
            runtime = args[4]
            root = runtime.roots["computer-use@openai-bundled"]
            if kind == "reappearance":
                runtime.pins[root + "/skills/computer-use"].absent = False
            else:
                runtime.pins[root + "/.codex-plugin/computer-use-node-repl.md"].data += b"changed"
            self.assertEqual(self.run_connected(args)["verdict"], "needs-review")

    def test_suppressed_skill_does_not_bypass_config_or_catalog_enablement(self):
        for evidence in ("config", "catalog"):
            args = self.fixture()
            runtime = args[4]
            if evidence == "config":
                value = args[0].nodes[T.path(0)]["data"]
                old = b'"unified-computer-use@openai-bundled" = {"enabled" = true}'
                self.assertIn(old, value)
                args[0].nodes[T.path(0)]["data"] = value.replace(old, old.replace(b"true", b"false"))
            else:
                value = R.strict_json(runtime.catalog_bytes)
                row = next(row for market in value["installed"]["marketplaces"] for row in market["plugins"]
                           if row["id"] == "computer-use@openai-bundled")
                row["enabled"] = False
                runtime.catalog_bytes = raw(value)
            self.assertEqual(self.run_connected(args)["verdict"], "needs-review")

    def test_config_plugin_disabled_is_checked_not_copied_as_expected(self):
        args = self.fixture()
        args[0].nodes[T.path(0)]["data"] = args[0].nodes[T.path(0)]["data"].replace(b'"enabled" = true', b'"enabled" = false', 1)
        self.assertEqual(self.run_connected(args)["verdict"], "needs-review")

    def test_classifier_rejects_managed_scalar_drift(self):
        args = self.fixture()
        args[0].nodes[T.path(0)]["data"] = args[0].nodes[T.path(0)]["data"].replace(b"'never'", b"'on-request'")
        self.assertEqual(self.run_connected(args)["verdict"], "needs-review")

    def test_source_admission_mismatch_and_source_drift(self):
        args = self.fixture()
        pin = args[4].pins[str(ROOT / R.MANAGED["global-agents"])]
        pin.data += b"changed private source"
        self.assertEqual(self.run_connected(args)["verdict"], "needs-review")

    def test_current_target_drift_during_collection_is_retained(self):
        args = self.fixture()
        def drift():
            args[0].nodes[T.path(0)]["data"] += b"# changed\n"
        args[4].collect = drift
        self.assertEqual(self.run_connected(args)["verdict"], "needs-review")
        self.assertTrue(args[0].nodes[T.path(0)]["data"].endswith(b"# changed\n"))

    def test_historical_drift_during_collection_is_retained(self):
        args = self.fixture()
        def drift():
            args[2].nodes[L.RUN + "/staged/config"]["data"] += b"# changed\n"
        args[4].collect = drift
        self.assertEqual(self.run_connected(args)["verdict"], "needs-review")

    def test_collection_failure_and_unsettled_owner_report_are_truthful(self):
        args = self.fixture()
        owner = unresolved_session()
        def fail():
            args[4].pending_owner = owner
            args[4].stage = "catalog"
            raise R.ReadinessError(private_owner=owner)
        args[4].collect = fail
        failure = self.run_connected(args, pending_owner=owner)
        self.assertEqual(failure.stage, "catalog")
        self.assertIsNone(failure.private_owner.process.poll())
        self.assertNotIn("private", str(failure))

    def test_owner_and_first_failure_stage_survive_later_cleanup_failure(self):
        args = self.fixture()
        owner = unresolved_session()
        def fail():
            args[4].stage = "catalog"
            raise R.ReadinessError(private_owner=owner)
        original_close = args[4].close
        def failed_close():
            original_close()
            raise OSError("private cleanup path")
        args[4].collect, args[4].close = fail, failed_close
        failure = self.run_connected(args, pending_owner=owner)
        self.assertEqual(failure.stage, "catalog")
        self.assertIs(failure.private_owner, owner)

    def test_final_budget_preserves_earliest_interrupt_and_original_owner(self):
        for primary, late in ((KeyboardInterrupt(), SystemExit(19)), (SystemExit(7), KeyboardInterrupt())):
            args = self.fixture()
            owner = unresolved_session()
            class FinalBudget:
                closing = False
                def check(self):
                    if self.closing:
                        raise late
            budget = FinalBudget()
            def interrupted():
                args[4].stage = "catalog"
                args[4].pending_owner = owner
                raise primary
            original_close = args[4].close
            def closed():
                original_close()
                budget.closing = True
            args[4].collect, args[4].close = interrupted, closed
            with patch.multiple(R.legacy, **args[3]), self.assertRaises(type(primary)) as raised:
                R.connected(HOME, 501, runtime_factory=lambda *_: args[4], budget=budget,
                    target_observer=lambda h, u: R.targets.observe(h, u, syscalls=args[0], platform=args[1]),
                    legacy_observer=lambda h, u: R.legacy.observe(h, u, syscalls=args[2]))
            self.assertIs(raised.exception, primary)
            self.assertIs(primary.private_owner, owner)
            self.assertIs(primary.settlement_failed, True)
            self.assertEqual(primary.readiness_stage, "catalog")
            self.assertEqual(args[0].handles, {})
            self.assertEqual(args[2].handles, {})
            self.assertTrue(all(pin.closed for pin in args[4].pins.values()))

    def test_actual_session_command_run_connected_retains_unsettled_owner(self):
        C = load("readiness_catalog_fakes", "tests/test_phase5_plugin_catalog.py")
        world = C.World()
        world.process.normal_exit = False
        world.process.ignore_term = world.process.ignore_kill = True
        fs, metadata, _ = T.fixture()
        historical, pins = L.fixture()
        owners, runtimes, source_pins = [], [], []
        def factory(home, uid, budget):
            runtime = runtime_fixture(fs)
            runtime.budget = budget
            runtimes.append(weakref.ref(runtime))
            source_pins.extend(runtime.pins.values())
            def collect():
                runtime.stage = "version"
                try:
                    runtime._run([R.CLI, "--version"])
                except BaseException as error:
                    owners.append(weakref.ref(error.private_owner))
                    raise
            runtime.collect = collect
            return runtime
        with world.installed(), patch.object(R.catalog.subprocess, "Popen", world.popen), \
                patch.multiple(R.legacy, **pins), self.assertRaises(R.ReadinessError) as raised:
            R.connected(HOME, 501, budget=R.Budget(clock=lambda: world.now), runtime_factory=factory,
                target_observer=lambda h, u: R.targets.observe(h, u, syscalls=fs, platform=metadata),
                legacy_observer=lambda h, u: R.legacy.observe(h, u, syscalls=historical))
        failure = raised.exception
        gc.collect()
        self.assertIsInstance(failure.private_owner, R.catalog._Session)
        self.assertIs(failure.private_owner, owners[0]())
        self.assertIs(failure.private_owner.process, world.process)
        self.assertIsNone(world.process.returncode)
        self.assertEqual(world.process.signals, ["term", "kill"])
        self.assertEqual(len(world.launches), 1)
        self.assertLessEqual(world.now, R.COMMAND_SECONDS + 0.001)
        self.assertEqual(failure.stage, "version")
        self.assertEqual(str(failure), "current_readiness_required")
        self.assertIsNone(runtimes[0]())
        self.assertEqual(fs.handles, {})
        self.assertEqual(historical.handles, {})
        self.assertTrue(all(pin.closed for pin in source_pins))

    def test_first_interruption_at_final_budget_is_preserved_after_cleanup(self):
        args = self.fixture()
        original = SystemExit(9)
        class FinalBudget:
            closing = False
            def check(self):
                if self.closing:
                    raise original
        budget = FinalBudget()
        close = args[4].close
        def closed():
            close()
            budget.closing = True
        args[4].close = closed
        with patch.multiple(R.legacy, **args[3]), self.assertRaises(SystemExit) as raised:
            R.connected(HOME, 501, runtime_factory=lambda *_: args[4], budget=budget,
                target_observer=lambda h, u: R.targets.observe(h, u, syscalls=args[0], platform=args[1]),
                legacy_observer=lambda h, u: R.legacy.observe(h, u, syscalls=args[2]))
        self.assertIs(raised.exception, original)
        self.assertEqual(original.readiness_stage, "cleanup")
        self.assertEqual(args[0].handles, {})
        self.assertEqual(args[2].handles, {})

    def test_interruptions_preserved_after_all_resources_closed(self):
        for error in (KeyboardInterrupt(), SystemExit(7)):
            args = self.fixture()
            def interrupt():
                raise error
            args[4].collect = interrupt
            with patch.multiple(R.legacy, **args[3]), self.assertRaises(type(error)) as raised:
                R.connected(HOME, 501, runtime_factory=lambda *_: args[4], budget=args[4].budget,
                    target_observer=lambda h, u: R.targets.observe(h, u, syscalls=args[0], platform=args[1]),
                    legacy_observer=lambda h, u: R.legacy.observe(h, u, syscalls=args[2]))
            self.assertIs(raised.exception, error)
            self.assertEqual(args[0].handles, {})
            self.assertEqual(args[2].handles, {})
            self.assertTrue(all(pin.closed for pin in args[4].pins.values()))


class SourceAssociationTests(unittest.TestCase):
    def setUp(self):
        fs, _, _ = T.fixture()
        self.runtime = runtime_fixture(fs)

    def changed_catalog(self, action):
        value = R.strict_json(self.runtime.catalog_bytes)
        action(value["installed"]["marketplaces"])
        self.runtime.catalog_bytes = raw(value)

    def test_curated_semantic_version_distinct_from_cache_ref(self):
        self.assertEqual(self.runtime.facts()["plugin_roots"]["google-drive@openai-curated"].rsplit("/", 1)[1], "1e285826")
        self.changed_catalog(lambda markets: markets[1]["plugins"][0].update(localVersion="1e285826"))
        with self.assertRaises(R.ReadinessError):
            self.runtime.facts()

    def test_distribution_marker_not_app_identifier_and_invalid_marker_fails(self):
        path = R.APP + "/plugins/openai-bundled/.bundle-id"
        self.assertEqual(sha(MARKER), R.BUNDLE_MARKER_HASH)
        self.assertNotEqual(MARKER.decode().strip(), self.runtime.contract["runtime"]["bundleId"])
        self.assertTrue(self.runtime.facts())
        for value in (b"", b" \n", b"com.openai.codex\n", b"invalid", b"\xff", MARKER + b" "):
            self.setUp()
            self.runtime.pins[path] = Pin(value)
            with self.assertRaises(R.ReadinessError):
                self.runtime.facts()
        self.setUp()
        del self.runtime.pins[path]
        with self.assertRaises((KeyError, R.ReadinessError)):
            self.runtime.facts()
        self.setUp()
        self.runtime.pins[path].data = b"changed marker"
        with self.assertRaises(R.ReadinessError):
            self.runtime.verify()

    def test_primary_inherited_source_route_not_cache_presence(self):
        self.changed_catalog(lambda markets: markets[2]["plugins"][0]["source"].update(path="/private/unreviewed"))
        with self.assertRaises(R.ReadinessError):
            self.runtime.facts()

    def test_remote4_preserved_separate_without_full_provenance_claim(self):
        facts = self.runtime.facts()
        self.assertEqual(set(facts["plugin_roots"]), R.integrations.LOCAL_PLUGINS)
        self.assertNotIn("private-synthetic-backend", repr(facts))
        self.changed_catalog(lambda markets: markets[3]["plugins"][0].update(localVersion="unexpected-local"))
        with self.assertRaises(R.ReadinessError):
            self.runtime.facts()

    def test_local_source_prefix_decoy_or_policy_change_fail(self):
        for modify in (
            lambda row: row["source"].update(path=row["source"]["path"] + "-evil"),
            lambda row: row.update(authPolicy="ON_USE"),
            lambda row: row.update(installed=False),
            lambda row: row.update(enabled=1),
        ):
            self.setUp()
            self.changed_catalog(lambda markets: modify(markets[0]["plugins"][0]))
            with self.assertRaises((R.ReadinessError, R.catalog.CatalogClientError)):
                self.runtime.facts()

    def test_descriptive_metadata_inert_and_identity_duplicates_rejected(self):
        self.changed_catalog(lambda markets: markets[0].update(extra="inert", path="descriptive-not-consumed"))
        self.assertTrue(self.runtime.facts())
        self.changed_catalog(lambda markets: markets[0]["plugins"].append(copy.deepcopy(markets[0]["plugins"][0])))
        with self.assertRaises(R.ReadinessError):
            self.runtime.facts()

    def test_materialization_variants_fail_closed(self):
        path = HOME + "/.codex/.tmp/bundled-marketplaces/openai-bundled/.materialization-key"
        for key, value in (("computerUseAudioEnabled", True), ("computerUseSkillVariant", "legacy-mcp"),
                           ("liveVisualizationSkillVariant", "live"), ("version", True),
                           ("visualizeSkillContentHash", "unproved")):
            self.setUp()
            material = self.runtime.json(path)
            material[key] = value
            self.runtime.pins[path] = Pin(raw(material))
            with self.assertRaises(R.ReadinessError):
                self.runtime.facts()

    def test_cua_banner_and_tool_instructions_bind_signed_resource_bytes(self):
        path = self.runtime.roots["unified-computer-use@openai-bundled"] + "/resources/banner.js"
        self.runtime.pins[path] = Pin(b"altered private instructions")
        with self.assertRaises(R.ReadinessError):
            self.runtime.facts()

    def test_manifest_unreviewed_permission_change_not_accepted_from_copy(self):
        identity = "computer-history@openai-bundled"
        cache = self.runtime.roots[identity] + "/.codex-plugin/plugin.json"
        source = HOME + "/.codex/.tmp/bundled-marketplaces/openai-bundled/plugins/computer-history/.codex-plugin/plugin.json"
        for path in (cache, source):
            value = self.runtime.json(path)
            value["permissions"] = {"new": True}
            self.runtime.pins[path] = Pin(raw(value))
        with self.assertRaises(R.ReadinessError):
            self.runtime.facts()


class SourceFileTests(unittest.TestCase):
    def fixture(self, data=b"public fixture"):
        fake = L.FakeOS()
        for path in ("/", "/Users", HOME, HOME + "/source"):
            fake.add(path, directory=True, mode=0o755)
        fake.add(HOME + "/source/file", data)
        def lseek(descriptor, offset, whence):
            self.assertEqual((offset, whence), (0, os.SEEK_SET))
            fake.handles[descriptor][2] = 0
        fake.lseek = lseek
        return fake, HOME + "/source/file"

    def test_actual_owned_chain_hash_and_held_fd_over_fake_syscalls(self):
        fake, path = self.fixture(b"x" * (R.MAX_OUTPUT + 1))
        pin = R.SourceFile(path, HOME, 501, R.Budget(clock=lambda: 0), keep=False, syscalls=fake)
        self.assertEqual(len(fake.handles), 1)
        self.assertEqual(pin.digest, sha(fake.nodes[path]["data"]))
        self.assertIsNone(pin.data)
        self.assertTrue(pin.verify())
        pin.close()
        self.assertEqual(fake.handles, {})

    def test_fifo_and_links_fail_before_any_read_and_never_write(self):
        for field, value in (("st_mode", stat.S_IFIFO | 0o600), ("st_mode", stat.S_IFLNK | 0o600), ("st_nlink", 2)):
            fake, path = self.fixture()
            fake.nodes[path][field] = value
            original = fake.open
            def opened(leaf, flags, **kwargs):
                self.assertTrue(flags & os.O_NONBLOCK)
                return original(leaf, flags, **kwargs)
            fake.open = opened
            with self.assertRaises(Exception):
                R.SourceFile(path, HOME, 501, R.Budget(clock=lambda: 0), syscalls=fake)
            self.assertEqual(fake.handles, {})
            self.assertNotIn(("read", path), fake.calls)

    def test_bytes_named_identity_chain_and_metadata_drift(self):
        for change in (
            lambda fs, path: fs.nodes[path].update(data=b"changed"),
            lambda fs, path: fs.nodes[path].update(st_ctime_ns=88),
            lambda fs, path: fs.nodes[HOME].update(st_ino=999),
            lambda fs, path: fs.nodes.__setitem__(path, {**fs.nodes[path], "st_ino": 12345}),
        ):
            fake, path = self.fixture()
            pin = R.SourceFile(path, HOME, 501, R.Budget(clock=lambda: 0), syscalls=fake)
            change(fake, path)
            with self.assertRaises(Exception):
                pin.verify()
            pin.close()
            self.assertEqual(fake.handles, {})

    def test_source_constructor_interruption_releases_fd_and_chain(self):
        fake, path = self.fixture()
        error = KeyboardInterrupt()
        fake.effects[("read", path)] = error
        with self.assertRaises(KeyboardInterrupt) as raised:
            R.SourceFile(path, HOME, 501, R.Budget(clock=lambda: 0), syscalls=fake)
        self.assertIs(raised.exception, error)
        self.assertEqual(fake.handles, {})

    def test_privileged_modes_rejected_initially_and_on_generation_recheck(self):
        for mode in (0o4755, 0o2755, 0o6755, 0o1755):
            fake, path = self.fixture()
            fake.nodes[path]["st_mode"] = stat.S_IFREG | mode
            with self.assertRaises(R.ReadinessError):
                R.SourceFile(path, HOME, 501, R.Budget(clock=lambda: 0), syscalls=fake)
            self.assertEqual(fake.handles, {})
            self.assertNotIn(("read", path), fake.calls)
            fake, path = self.fixture()
            pin = R.SourceFile(path, HOME, 501, R.Budget(clock=lambda: 0), syscalls=fake)
            fake.nodes[path]["st_mode"] = stat.S_IFREG | mode
            with self.assertRaises(R.ReadinessError):
                pin.verify()
            pin.close()
            self.assertEqual(fake.handles, {})

    def test_exact_absence_recheck_no_scan_and_reappearance_fails(self):
        fake, path = self.fixture()
        del fake.nodes[path]
        original = fake.stat
        def stat_missing(leaf, **kwargs):
            try:
                return original(leaf, **kwargs)
            except KeyError:
                raise FileNotFoundError() from None
        fake.stat = stat_missing
        pin = R.SourceFile(path, HOME, 501, R.Budget(clock=lambda: 0), absent=True, syscalls=fake)
        self.assertEqual(fake.handles, {})
        self.assertTrue(pin.verify())
        fake.add(path, directory=True)
        with self.assertRaises(R.ReadinessError):
            pin.verify()
        pin.close()
        self.assertEqual(fake.handles, {})
        self.assertFalse(any(name == "scandir" for name, _ in fake.calls))


class Stream:
    def __init__(self, descriptor):
        self.descriptor, self.closed = descriptor, False

    def fileno(self):
        return self.descriptor

    def close(self):
        self.closed = True


def unresolved_session():
    """Actual catalog owner/settlement logic, entirely synthetic process/pipes."""
    owner = R.catalog._Session(0)
    streams = {name: Stream(index) for index, name in enumerate(("stdin", "stdout", "stderr"))}
    owner.process = SimpleNamespace(**streams, poll=lambda: None)
    owner.streams = streams
    with patch.object(R.catalog.time, "monotonic", return_value=10):
        settled, _ = owner.close(0, True)  # expired budget: no signal or native call
    assert not settled and all(stream.closed for stream in streams.values())
    return owner


class ProcessOwner:
    def __init__(self, output=b"ok", stderr=b"", *, settled=True, launch_error=None):
        self.content = {1: output, 2: stderr}
        self.streams = {"stdin": Stream(0), "stdout": Stream(1), "stderr": Stream(2)}
        self.process = SimpleNamespace(poll=lambda: 0, returncode=0)
        self.eof, self.interruption, self.closed = set(), None, False
        self.settled, self.launch_error, self.started = settled, launch_error, []
        self.selector = SimpleNamespace(select=lambda _: [(SimpleNamespace(data=name), None)
            for name in ("stdout", "stderr") if name not in self.eof], unregister=lambda _: None)

    def start(self, argv, environment, factory):
        self.started.append((tuple(argv), environment))
        if self.launch_error:
            raise self.launch_error

    def read(self, descriptor, maximum):
        value = self.content[descriptor][:maximum]
        self.content[descriptor] = self.content[descriptor][maximum:]
        return value

    def close(self, deadline, failed):
        self.closed = True
        for stream in self.streams.values():
            stream.close()
        return self.settled, None


class ProcessTests(unittest.TestCase):
    def call(self, owner, argv=None, budget=None):
        environment = {"HOME": HOME, "CODEX_HOME": HOME + "/.codex", "LANG": "C", "LC_ALL": "C",
                       "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "SHELL": "/bin/zsh"}
        with patch.object(R.os, "read", owner.read), patch.object(R.catalog.subprocess, "Popen", side_effect=AssertionError("no native spawn")):
            return R.command_read(argv or [R.CLI, "mcp", "list", "--json"], environment,
                                  budget or R.Budget(), session_factory=lambda _: owner)

    def test_fixed_read_command_and_settled_bounded_pipe_capture(self):
        owner = ProcessOwner(b"[]")
        self.assertEqual(self.call(owner).stdout, "[]")
        self.assertTrue(owner.closed)
        self.assertTrue(all(stream.closed for stream in owner.streams.values()))
        self.assertEqual(owner.started[0][0], (R.CLI, "mcp", "list", "--json"))

    def test_unknown_argv_refused_before_spawn(self):
        owner = ProcessOwner()
        with self.assertRaises(R.ReadinessError):
            self.call(owner, [R.CLI, "exec", "private prompt"])
        self.assertEqual(owner.started, [])

    def test_combined_stdout_stderr_limit_and_decode_failure_cleanup(self):
        for owner in (ProcessOwner(b"a" * (R.MAX_OUTPUT // 2), b"b" * (R.MAX_OUTPUT // 2 + 1)), ProcessOwner(b"\xff")):
            with self.assertRaises(R.ReadinessError) as error:
                self.call(owner)
            self.assertIsNone(error.exception.private_owner)
            self.assertTrue(owner.closed)
            self.assertEqual(str(error.exception), "current_readiness_required")

    def test_launch_failure_or_interrupt_preserves_cleanup_ownership(self):
        for error in (RuntimeError("private launch text"), KeyboardInterrupt(), SystemExit(3)):
            owner = ProcessOwner(launch_error=error)
            with self.assertRaises(type(error) if not isinstance(error, Exception) else R.ReadinessError) as raised:
                self.call(owner)
            self.assertTrue(owner.closed)
            if not isinstance(error, Exception):
                self.assertIs(raised.exception, error)

    def test_unsettled_child_retains_private_owner(self):
        owner = ProcessOwner(settled=False)
        with self.assertRaises(R.ReadinessError) as error:
            self.call(owner)
        self.assertIs(error.exception.private_owner, owner)

    def test_aggregate_deadline_prevents_launch(self):
        ticks = iter([0, 100])
        budget = R.Budget(clock=lambda: next(ticks))
        owner = ProcessOwner()
        with self.assertRaises(R.ReadinessError):
            self.call(owner, budget=budget)
        self.assertEqual(owner.started, [])

    def test_command_deadline_stops_nonclosing_pipe_and_settles(self):
        owner = ProcessOwner()
        owner.process.poll = lambda: None
        ticks = iter(range(100))
        budget = R.Budget(clock=lambda: 0)
        with patch.object(R.time, "monotonic", side_effect=lambda: next(ticks)), self.assertRaises(R.ReadinessError):
            self.call(owner, budget=budget)
        self.assertTrue(owner.closed)

    def test_native_run_recheck_cannot_replace_original_interrupt(self):
        runtime = R.NativeRuntime(HOME, 501, R.Budget())
        runtime.environment = {}
        calls = []
        def verify():
            calls.append(1)
            if len(calls) == 2:
                raise R.ReadinessError()
            return True
        runtime.verify = verify
        error = KeyboardInterrupt()
        with patch.object(R, "command_read", side_effect=error), self.assertRaises(KeyboardInterrupt) as raised:
            runtime._run([R.CLI, "--version"])
        self.assertIs(raised.exception, error)


class NativeCollectionWiringTests(unittest.TestCase):
    def test_actual_collect_and_final_attestation_with_only_fake_sources_and_commands(self, privileged_mode=None):
        """Exercise the real native collector branch, without any native syscall."""
        fs, _, _ = T.fixture()
        sample = runtime_fixture(fs)
        loader = importlib.machinery.SourceFileLoader
        preflight = loader("readiness_fake_preflight", str(ROOT / "bin/phase5-preflight")).load_module()
        contract = {**sample.contract, "runtime": {
            "appMinimumVersion": "26.721.41059", "appVersionPolicy": "signed-vendor-floor",
            "cliVersionPolicy": "signed-vendor-floor", "observedAppBuild": "5848",
            "observedAppVersion": "26.721.41059", "bundleId": "com.openai.codex", "teamId": "2DC432GLL2",
            "designatedRequirement": 'designated => identifier "com.openai.codex"'},
            "cli": {"observedVersion": "codex-cli 0.145.0-alpha.18"}}

        class App:
            def __init__(self, bundle):
                self.descriptors = []
                self.bound_metadata = ((1, 2, 501),)
                self.plist_bytes = plistlib.dumps({"CFBundleIdentifier": "com.openai.codex",
                    "CFBundleShortVersionString": sample.version, "CFBundleVersion": "1234"})
            def recheck(self):
                return None
        preflight._AppBundleObservation = App
        reader = SimpleNamespace(clean_environment=lambda *_: dict(sample.environment),
            HOOK_TRUST_RECORDS=[("fake-event", slot, digest) for slot, digest in sample.hook_records.items()])
        def module_loader(name, path):
            self.assertIn(name, ("current_readiness_preflight", "current_readiness_reader"))
            return SimpleNamespace(load_module=lambda: preflight if name.endswith("preflight") else reader)

        paths = []
        def file_factory(path, root, uid, budget, *, keep=True, absent=False):
            paths.append((path, keep, absent))
            template = sample.pins.get(path)
            data = template.data if template else b"public synthetic source"
            digest = template.digest if template else sha(data)
            if path == str(ROOT / "manifests/codex-contract.json"):
                data, digest = raw(contract), R.CONTRACT_HASH
            named_hashes = {
                R.APP + "/app.asar": R.ASAR_HASH, R.CLI: R.CLI_HASH,
                HOME + "/.codex/.tmp/plugins.sha": R.CURATED_POINTER_HASH,
                HOME + "/.codex/.tmp/plugins/.agents/plugins/marketplace.json": R.CURATED_CATALOG_HASH,
            }
            digest = named_hashes.get(path, digest)
            for key, expected in R.integrations.REVIEWED_SOURCE_HASHES.items():
                if path.endswith(key) or key == "computer-use-client-launcher" and path.endswith("/bin/" + key):
                    digest = expected
            if path.endswith("/scripts/launch.mjs"):
                digest = R.integrations.REVIEWED_SOURCE_HASHES["unified-computer-use/scripts/launch.mjs"]
            if path.endswith("/scripts/browser-service.mjs"):
                digest = R.BROWSER_HASH
            if path.endswith("/skills/visualize/SKILL.md"):
                digest = R.VISUALIZE_HASH
            if path.endswith("/.codex-plugin/computer-use-node-repl.md") or path.endswith("/skills/computer-use/SKILL.md"):
                digest = R.COMPUTER_SKILL_HASH
            pin = Pin(data, digest=digest, absent=absent)
            if privileged_mode is not None and path == R.CLI:
                pin.stamp = (*pin.stamp[:4], stat.S_IFREG | privileged_mode, *pin.stamp[5:])
            return pin

        commands, catalogs = [], []
        def command(arguments, environment, budget):
            argv = tuple(str(value) for value in arguments)
            commands.append(argv)
            self.assertEqual(environment, sample.environment)
            if argv == (R.CLI, "mcp", "list", "--json"):
                stdout, stderr = sample.effective_bytes.decode(), ""
            elif argv == (R.CLI, "--version"):
                stdout, stderr = "codex-cli 0.153.4\n", ""
            elif "-dvv" in argv:
                stdout, stderr = "", "TeamIdentifier=2DC432GLL2\n"
            elif "-dr" in argv:
                stdout, stderr = "", contract["runtime"]["designatedRequirement"] + "\n"
            else:
                self.assertIn(argv[0], ("/usr/bin/codesign", "/usr/sbin/spctl"))
                stdout, stderr = "", ""
            return SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr)
        def collect(argv, environment, timeout_seconds):
            self.assertEqual(argv, [R.CLI, "app-server", "--listen", "stdio://"])
            self.assertEqual(environment, sample.environment)
            self.assertLessEqual(timeout_seconds, 20)
            catalogs.append(True)
            return R.strict_json(sample.catalog_bytes)
        runtime = R.NativeRuntime(HOME, 501, R.Budget(clock=lambda: 0), file_factory=file_factory)
        with patch.object(R.importlib.machinery, "SourceFileLoader", side_effect=module_loader), \
                patch.object(R, "command_read", side_effect=command), \
                patch.object(R.catalog, "collect_private_catalog", side_effect=collect), \
                patch.object(R.catalog.subprocess, "Popen", side_effect=AssertionError("no native process")):
            if privileged_mode is not None:
                with self.assertRaises(R.ReadinessError):
                    runtime.collect()
                self.assertEqual(commands, [])
                self.assertEqual(catalogs, [])
                runtime.close()
                self.assertTrue(all(pin.closed for pin in runtime.pins.values()))
                return
            runtime.collect()
            self.assertEqual(runtime.version, sample.version)
            self.assertTrue(runtime.admit_sources(runtime.facts()))
            self.assertTrue(runtime.final_attest())
        self.assertEqual(catalogs, [True])
        self.assertEqual(commands.count((R.CLI, "mcp", "list", "--json")), 1)
        self.assertEqual(commands.count((R.CLI, "--version")), 1)
        self.assertEqual(sum(argv[0] == "/usr/bin/codesign" for argv in commands), 6)
        self.assertEqual(sum(argv[0] == "/usr/sbin/spctl" for argv in commands), 2)
        self.assertEqual(len(paths), len(set(path for path, _, _ in paths)))
        self.assertEqual(len(paths), 128)
        self.assertEqual(sum(absent for _, _, absent in paths), 3)
        computer_root = runtime.roots["computer-use@openai-bundled"]
        self.assertIn((computer_root + "/skills/computer-use", True, True), paths)
        self.assertIn((computer_root + "/.codex-plugin/computer-use-node-repl.md", True, False), paths)
        self.assertNotIn(computer_root + "/skills/computer-use/SKILL.md", [path for path, _, _ in paths])
        self.assertIn((R.APP + "/app.asar", False, False), paths)
        self.assertIn((R.APP + "/plugins/openai-bundled/.bundle-id", True, False), paths)
        runtime.close()
        self.assertTrue(all(pin.closed for pin in runtime.pins.values()))

    def test_privileged_executable_rejected_before_any_native_command(self):
        for mode in (0o4755, 0o2755, 0o6755, 0o1755):
            self.test_actual_collect_and_final_attestation_with_only_fake_sources_and_commands(mode)


class TerminalTests(unittest.TestCase):
    def test_terminal_only_interrupt_redacted_with_nonzero_exit(self):
        error = KeyboardInterrupt("private interrupt text")
        error.private_owner = object()
        def interrupted():
            raise error
        output = io.StringIO()
        with patch("sys.stdout", output), self.assertRaises(SystemExit) as raised:
            R.entry(interrupted)
        self.assertEqual(raised.exception.code, 130)
        self.assertIs(raised.exception.private_owner, error.private_owner)
        self.assertIs(raised.exception.settlement_failed, True)
        result = json.loads(output.getvalue())
        self.assertEqual(result["verdict"], "needs-review")
        self.assertIs(result["childSettled"], False)
        self.assertNotIn("private interrupt text", output.getvalue())

    def test_private_failure_survives_main_and_terminal_without_false_settlement(self):
        owner = unresolved_session()
        error = R.ReadinessError(private_owner=owner, stage="catalog")
        output = io.StringIO()
        with patch.object(R.sys, "argv", ["readiness"]), patch.object(R.os, "getuid", return_value=501), \
                patch.object(R.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=HOME)), \
                patch.object(R.os, "getcwd", return_value=str(ROOT)), \
                patch.object(R, "connected", side_effect=error), patch("sys.stdout", output), \
                self.assertRaises(SystemExit) as raised:
            R.entry(R.main)
        self.assertEqual(raised.exception.code, 1)
        self.assertIs(raised.exception.private_owner, owner)
        self.assertIs(raised.exception.settlement_failed, True)
        result = json.loads(output.getvalue())
        self.assertIs(result["childSettled"], False)
        self.assertEqual(result["failureStage"], "catalog")
        self.assertNotIn(HOME, output.getvalue())
        self.assertNotIn(repr(owner), output.getvalue())

    def test_original_numeric_system_exit_keeps_owner_and_identity(self):
        error = SystemExit(7)
        error.private_owner = unresolved_session()
        error.settlement_failed = True
        def stopped():
            raise error
        with patch("sys.stdout", io.StringIO()) as output, self.assertRaises(SystemExit) as raised:
            R.entry(stopped)
        self.assertIs(raised.exception, error)
        self.assertEqual(output.getvalue(), "")

    def test_stage_is_allowlisted_and_ready_has_no_failure_stage(self):
        for stage in ("private/source/path", {"private": True}, False, None):
            self.assertIsNone(R.ReadinessError(stage=stage).stage)
            result = R.public("needs-review", stage=stage)
            self.assertEqual(result["failureStage"], "admission")
            self.assertNotIn("private", json.dumps(result))
        self.assertIsNone(R.public("ready")["failureStage"])

    def test_system_exit_preserves_integer_without_private_repr(self):
        for value, expected in ((7, 7), (0, 0), (None, 0), ("private exit text", 1)):
            def stopped():
                raise SystemExit(value)
            output = io.StringIO()
            with patch("sys.stdout", output):
                self.assertEqual(R.entry(stopped), expected)
            self.assertEqual(output.getvalue(), "")


class AdmissionRoundTests(unittest.TestCase):
    """Physical brackets remain connected; their body uses only held memory."""
    def fixture(self):
        from lib.phase5_runtime_transition import Image
        fs, _, source = T.fixture()
        runtime = runtime_fixture(fs)
        images = {}
        for i, identity in enumerate(R.capture.TARGET_IDS):
            original = source[0][identity][0].files[identity]
            images[identity] = Image(fs.nodes[T.path(i)]["data"], original.identity,
                                     original.mode, original.seal)
        calls = {"physical": 0, "facts": 0, "pins": 0}
        facts = runtime.facts
        def derive():
            calls["facts"] += 1
            return facts()
        runtime.facts = derive
        for pin in runtime.pins.values():
            original_verify = pin.verify
            def verify(original_verify=original_verify):
                calls["pins"] += 1
                return original_verify()
            pin.verify = verify
        def dependencies():
            calls["physical"] += 1
            return runtime.verify()
        def invoke(check=dependencies):
            return R.admit_current_round(images, home=HOME, runtime=runtime,
                metadata_empty=dict.fromkeys(R.capture.TARGET_IDS, True), recheck_dependencies=check)
        return runtime, images, calls, dependencies, invoke

    def test_exact_two_source_rounds_and_two_pure_derivations(self):
        runtime, _, calls, _, invoke = self.fixture()
        with patch.object(runtime, "admit_sources", side_effect=AssertionError("no repeated physical callback")), \
                patch.object(runtime, "same_generation", side_effect=AssertionError("no repeated physical callback")):
            self.assertIs(invoke(), True)
        self.assertEqual(calls, {"physical": 2, "facts": 2, "pins": 2 * len(runtime.pins)})
        self.assertEqual(R.AGGREGATE_SECONDS, 90.0)
        # Reference the replaced callback expression using only fake pins;
        # no native collector, command, historical gate or entry point runs.
        old, images, old_calls, dependencies, _ = self.fixture()
        document = R.toml_loads(images["config"].data.decode())
        matched = R.integrations.match_integrations(document["plugins"], document["mcp_servers"],
            old.effective, sources=old.facts(), admit_sources=old.admit_sources,
            recheck_generation=lambda facts: old.same_generation(facts) and dependencies())
        self.assertFalse(matched.reason)
        self.assertEqual(old_calls["pins"], 5 * len(old.pins))
        self.assertEqual(old_calls["facts"], 4)

    def test_pre_and_post_physical_source_drift_never_admit(self):
        for when in ("before", "during"):
            runtime, _, calls, _, invoke = self.fixture()
            pin = next(iter(runtime.pins.values()))
            actual = R.integrations.match_integrations
            def matching(*args, **kwargs):
                result = actual(*args, **kwargs)
                pin.data += b"private physical drift"
                return result
            if when == "before":
                pin.data += b"private physical drift"
            with patch.object(R.integrations, "match_integrations", side_effect=matching) as matcher:
                with self.assertRaises(Exception):
                    invoke()
            self.assertEqual(matcher.call_count, 0 if when == "before" else 1)
            self.assertEqual(calls["physical"], 2)

    def test_both_physical_checks_run_on_pre_failure_and_late_false(self):
        for which in (1, 2):
            _, _, calls, dependencies, invoke = self.fixture()
            def checked():
                value = dependencies()
                return False if calls["physical"] == which else value
            with self.assertRaises(R.ReadinessError):
                invoke(checked)
            self.assertEqual(calls["physical"], 2)

    def test_cached_catalog_effective_and_source_facts_drift_rejected(self):
        for field in ("catalog_bytes", "effective_bytes", "hook_records", "roots"):
            runtime, _, calls, _, invoke = self.fixture()
            actual = R.classify
            def classified(*args, **kwargs):
                result = actual(*args, **kwargs)
                if field == "catalog_bytes": runtime.catalog_bytes += b" "
                elif field == "effective_bytes": runtime.effective_bytes += b" "
                elif field == "hook_records": runtime.hook_records["stop:0:0"] = "changed"
                else: runtime.roots["computer-history@openai-bundled"] += "changed"
                return result
            with patch.object(R, "classify", side_effect=classified):
                with self.assertRaises(Exception):
                    invoke()
            self.assertEqual(calls["physical"], 2)

    def test_generic_matcher_still_rejects_callback_argument_mutation(self):
        for key in ("admit_sources", "recheck_generation"):
            _, _, calls, _, invoke = self.fixture()
            actual = R.integrations.match_integrations
            def matching(*args, **kwargs):
                callback = kwargs[key]
                def mutated(facts):
                    result = callback(facts)
                    facts["generation"] = "forged"
                    return result
                kwargs[key] = mutated
                return actual(*args, **kwargs)
            with patch.object(R.integrations, "match_integrations", side_effect=matching):
                with self.assertRaises(R.ReadinessError):
                    invoke()
            self.assertEqual(calls["physical"], 2)

    def test_detached_candidate_facts_and_projection_mutation_rejected(self):
        for what in ("candidate", "facts", "projection"):
            _, _, _, _, invoke = self.fixture()
            actual = R.integrations.match_integrations
            def matching(*args, **kwargs):
                result = actual(*args, **kwargs)
                if what == "candidate": args[0]["unadmitted"] = {"enabled": True}
                elif what == "facts": kwargs["sources"]["generation"] = "forged"
                return result
            classify = R.classify
            def classified(*args, **kwargs):
                result = classify(*args, **kwargs)
                if what == "projection": kwargs["admitted_plugins"]["unadmitted"] = {"enabled": True}
                return result
            with patch.object(R.integrations, "match_integrations", side_effect=matching), \
                    patch.object(R, "classify", side_effect=classified):
                with self.assertRaises(R.ReadinessError):
                    invoke()

    def test_earliest_exception_and_interrupt_preserved_with_postcheck(self):
        for first, second in ((RuntimeError("private first"), OSError("private last")),
                              (KeyboardInterrupt(), OSError("private last")),
                              (RuntimeError("private first"), SystemExit(13))):
            _, _, calls, dependencies, invoke = self.fixture()
            def checked():
                dependencies()
                if calls["physical"] == 2: raise second
                return True
            with patch.object(R, "classify", side_effect=first):
                expected = R.earliest(first, second)
                with self.assertRaises(type(expected)) as raised:
                    invoke(checked)
                self.assertIs(raised.exception, expected)
            self.assertEqual(calls["physical"], 2)

    def test_no_cross_round_verification_cache(self):
        runtime, _, calls, _, invoke = self.fixture()
        self.assertTrue(invoke())
        next(iter(runtime.pins.values())).data += b"changed after round"
        with self.assertRaises(Exception):
            invoke()
        self.assertEqual(calls["physical"], 4)


if __name__ == "__main__":
    unittest.main()
