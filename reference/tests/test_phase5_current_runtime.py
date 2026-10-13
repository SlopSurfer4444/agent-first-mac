"""Fake-only tests: no production state, Codex, hooks or provider execution."""

import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.phase5_current_runtime import (  # noqa: E402
    ContractError, MAX_CONFIG_BYTES, assert_preserved, classify,
)


CONTROL = "/fixture/control"
HOOK_SOURCE = "/fixture/home/.codex/hooks.json"
RECORDS = {slot: "sha256:" + char * 64 for slot, char in (
    ("session_start:0:0", "a"), ("pre_tool_use:0:0", "b"), ("stop:0:0", "c"))}
PLUGINS = {"fixture@reviewed": {"enabled": True}}
MCP = {"fixture": {"command": "/fixture/inert", "args": [], "enabled": False,
                   "env": {"PRIVATE_FIXTURE": "not-a-real-secret"}}}


def fixture(count=1):
    text = 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
    text += '# preserved owner comment\nmodel = "fixture"\n'
    for i in range(count):
        text += '[projects."/fixture/project-%d"]\ntrust_level = "%s"\n' % (
            i, "trusted" if i % 2 else "untrusted")
    text += '[plugins."fixture@reviewed"]\nenabled = true\n'
    text += ('[mcp_servers.fixture]\ncommand = "/fixture/inert"\nargs = []\n'
             'enabled = false\n[mcp_servers.fixture.env]\n'
             'PRIVATE_FIXTURE = "not-a-real-secret"\n[hooks.state]\n')
    for slot, digest in RECORDS.items():
        text += '[hooks.state.%s]\ntrusted_hash = "%s"\n' % (
            json.dumps(HOOK_SOURCE + ":" + slot), digest)
    return text.encode()


def check(raw, **overrides):
    args = dict(control_root=CONTROL, hook_source=HOOK_SOURCE,
                hook_records=RECORDS, admitted_plugins=PLUGINS, admitted_mcp=MCP)
    args.update(overrides)
    return classify(raw, **args)


class CurrentRuntimeTests(unittest.TestCase):
    def assert_verdict(self, result, verdict, reasons):
        self.assertEqual(result["verdict"], verdict)
        self.assertEqual(result["reasonCodes"], reasons)
        self.assertIs(result["executionAdmission"], False)
        self.assertIs(result["configMutationAuthorized"], False)
        self.assertIs(result["trustMutationAuthorized"], False)
        return result

    def test_dynamic_cardinality_not_historical_pins(self):
        for count in (0, 1, 19, 25, 43, 44, 100):
            with self.subTest(count=count):
                result = self.assert_verdict(check(fixture(count)), "ready", [])
                self.assertEqual(result["projectCount"], count)

    def test_zero_projects_and_integrations_need_explicit_admission(self):
        raw = fixture(0)
        start, end = raw.index(b"[plugins."), raw.index(b"[hooks.state]")
        raw = raw[:start] + raw[end:]
        self.assert_verdict(check(raw, admitted_plugins={}, admitted_mcp={}), "ready", [])
        self.assert_verdict(check(raw, admitted_plugins=None, admitted_mcp=None),
                            "needs-review", ["plugins_need_review", "mcp_need_review"])

    def test_complete_projects_only(self):
        raw = fixture()
        for candidate in (
            raw.replace(b'trust_level = "untrusted"\n', b"", 1),
            raw.replace(b'trust_level = "untrusted"', b'trust_level = true', 1),
            raw.replace(b'trust_level = "untrusted"', b'trust_level = "unknown"', 1),
            raw.replace(b'trust_level = "untrusted"', b'trust_level = "untrusted"\nextra = 1', 1),
            raw + b'\n[[projects."/fixture/array"]]\ntrust_level = "trusted"\n',
        ):
            with self.subTest(candidate=candidate[:50]):
                self.assertEqual(check(candidate)["verdict"], "invalid")

    def test_duplicate_decoded_project_is_invalid(self):
        for suffix in (
            b'\n[projects."/fixture/project-0"]\ntrust_level = "trusted"\n',
            b"\n[projects.'/fixture/project-0']\ntrust_level = 'trusted'\n",
            b'\n[projects."/fixture/project-\\u0030"]\ntrust_level = "trusted"\n',
        ):
            self.assert_verdict(check(fixture() + suffix), "invalid", ["config_toml_invalid"])

    def test_lexical_project_paths_and_control_reject(self):
        for identity in (CONTROL, "relative", "/", "/fixture//project", "/fixture/./project",
                         "/fixture/../project", "/fixture/project/", "/fixture/\nproject",
                         "/fixture/\\project"):
            raw = fixture().replace(b'"/fixture/project-0"', json.dumps(identity).encode(), 1)
            self.assert_verdict(check(raw), "invalid", ["project_records_invalid"])

    def test_lexical_only_no_claim_of_symlink_identity(self):
        raw = fixture().replace(b"/fixture/project-0", b"/fixture/possible-alias")
        result = self.assert_verdict(check(raw), "ready", [])
        self.assertNotIn("filesystemIdentity", result)

    def test_managed_scalars_exact(self):
        for old, new in ((b'"never"', b'"on-request"'), (b'"never"', b"true"),
                         (b'"danger-full-access"', b'"workspace-write"')):
            self.assert_verdict(check(fixture().replace(old, new, 1)),
                                "invalid", ["managed_scalars_invalid"])

    def test_hook_definition_and_trust_exact(self):
        raw = fixture()
        for candidate in (
            raw.replace(b"sha256:" + b"a" * 64, b"sha256:" + b"d" * 64, 1),
            raw.replace(b"session_start:0:0", b"session_start:1:0", 1),
            raw.replace(HOOK_SOURCE.encode(), b"/fixture/other-hooks.json", 1),
            raw + b'\n[hooks.state.extra]\ntrusted_hash = "extra"\n',
            raw + b'\n[hooks.SessionStart]\ncommand = "never execute"\n',
            raw.replace(b"[hooks.state]", b"[hooks]\ndisable_all_hooks = true\n[hooks.state]", 1),
            raw.replace(b'trusted_hash = "sha256:', b'enabled = true\ntrusted_hash = "sha256:', 1),
        ):
            self.assert_verdict(check(candidate), "invalid", ["hook_contract_invalid"])

    def test_unknown_plugin_is_review_not_count_acceptance(self):
        raw = fixture() + b'\n[plugins."new@unknown"]\nenabled = true\n'
        self.assert_verdict(check(raw), "needs-review", ["plugins_need_review"])
        raw = fixture().replace(b'fixture@reviewed', b'other@reviewed', 1)
        self.assert_verdict(check(raw), "needs-review", ["plugins_need_review"])

    def test_plugin_disabled_missing_or_extra_fields_need_review(self):
        for candidate in (
            fixture().replace(b"enabled = true", b"enabled = false", 1),
            fixture().replace(b"enabled = true", b"enabled = true\nnew_capability = true", 1),
            fixture().replace(b'[plugins."fixture@reviewed"]\nenabled = true\n', b"", 1),
        ):
            self.assert_verdict(check(candidate), "needs-review", ["plugins_need_review"])

    def test_changed_mcp_private_fields_need_review(self):
        for old, new in ((b"/fixture/inert", b"/fixture/other"),
                         (b"not-a-real-secret", b"different-fixture-value"),
                         (b"args = []", b'args = ["other"]'),
                         (b"enabled = false", b"enabled = true")):
            self.assert_verdict(check(fixture().replace(old, new, 1)),
                                "needs-review", ["mcp_need_review"])

    def test_exact_types_no_bool_as_integer(self):
        admitted = {"fixture@reviewed": {"enabled": 1}}
        self.assert_verdict(check(fixture(), admitted_plugins=admitted),
                            "needs-review", ["plugins_need_review"])
        raw = fixture().replace(b"args = []", b"args = [true]", 1)
        admitted = copy.deepcopy(MCP)
        admitted["fixture"]["args"] = [1]
        self.assert_verdict(check(raw, admitted_mcp=admitted), "needs-review", ["mcp_need_review"])

    def test_integration_order_is_not_silently_relaxed(self):
        admitted = {"fixture": dict(reversed(list(MCP["fixture"].items())))}
        self.assert_verdict(check(fixture(), admitted_mcp=admitted), "needs-review", ["mcp_need_review"])

    def test_invalid_integration_record(self):
        raw = fixture().replace(b'[plugins."fixture@reviewed"]\nenabled = true',
                                b'[plugins]\n"fixture@reviewed" = true', 1)
        self.assert_verdict(check(raw), "invalid", ["integration_records_invalid"])

    def test_toml_semantics_and_unmanaged_bytes_preserved(self):
        raw = fixture().replace(b'# preserved owner comment',
            b'# preserved owner comment\nopaque = { nested = [1, "# not comment"] }\n'
            b'description = """a multiline\nowner value"""\nwhen = 2026-09-07')
        self.assert_verdict(check(raw), "ready", [])
        self.assert_verdict(check(raw.replace(b"\n", b"\r\n")), "ready", [])
        self.assert_verdict(check(raw.rstrip(b"\n")), "ready", [])
        assert_preserved(raw, raw)
        for changed in (raw + b"\n", raw.replace(b"owner comment", b"changed comment"),
                        raw.replace(b"\n", b"\r\n")):
            with self.assertRaisesRegex(ContractError, "^config_bytes_changed$"):
                assert_preserved(raw, changed)

    def test_malformed_bounded_input_and_redaction(self):
        secret = "PRIVATE-CANARY-DO-NOT-EMIT"
        for raw in (b"", b"x" * (MAX_CONFIG_BYTES + 1), bytearray(fixture()), None,
                    b"\xff", b"\xef\xbb\xbf" + fixture(), fixture() + b"\x00",
                    ("[" + secret).encode(), b"x = " + b"[" * 1200):
            result = check(raw)
            self.assertEqual(result["verdict"], "invalid")
            rendered = json.dumps(result)
            self.assertNotIn(secret, rendered)
            self.assertNotIn("/fixture", rendered)
            self.assertNotIn("sha256", rendered)
            self.assertIsNone(result["projectCount"])

    def test_invalid_admission_redacted(self):
        for args in ({"control_root": "relative"}, {"hook_source": None},
                     {"hook_records": {}}, {"admitted_plugins": []}):
            self.assert_verdict(check(fixture(), **args), "invalid", ["admission_contract_invalid"])

    def test_preservation_rejects_non_bytes(self):
        for before, after in ((b"x", bytearray(b"x")), ("x", "x"), (None, None)):
            with self.assertRaisesRegex(ContractError, "^preservation_bytes_invalid$"):
                assert_preserved(before, after)

    def test_policy_has_no_io_and_does_not_mutate_arguments(self):
        raw, plugins, mcp, records = fixture(), copy.deepcopy(PLUGINS), copy.deepcopy(MCP), dict(RECORDS)
        original = copy.deepcopy((plugins, mcp, records))
        with patch("builtins.open", side_effect=AssertionError("IO forbidden")), \
             patch("os.open", side_effect=AssertionError("IO forbidden")), \
             patch("subprocess.run", side_effect=AssertionError("process forbidden")), \
             patch("socket.socket", side_effect=AssertionError("network forbidden")):
            self.assert_verdict(check(raw, admitted_plugins=plugins, admitted_mcp=mcp,
                                      hook_records=records), "ready", [])
            assert_preserved(raw, raw)
        self.assertEqual((plugins, mcp, records), original)


if __name__ == "__main__":
    unittest.main()
