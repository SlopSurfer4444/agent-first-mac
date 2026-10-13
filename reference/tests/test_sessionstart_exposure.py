"""Pure source-fixture tests: no shell, installed target or trust-state I/O."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import shlex
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_loader("sessionstart_planner",
    __import__("importlib.machinery", fromlist=["SourceFileLoader"]).SourceFileLoader(
        "sessionstart_planner", str(ROOT / "bin/aid-sessionstart")))
S = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = S
spec.loader.exec_module(S)
ORIGINAL = (ROOT / "codex/hooks.json").read_bytes()
MANIFEST = S.parse_json((ROOT / "manifests/sessionstart-exposure.json").read_bytes())


def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def command(output):
    return " ".join(shlex.quote(arg) for arg in ("/usr/bin/printf", "%s\\n", encode(output).decode("utf-8")))


class SessionStartTests(unittest.TestCase):
    def setUp(self):
        self.manifest = copy.deepcopy(MANIFEST)

    @property
    def handler(self):
        return self.manifest["definition"]["hooks"][0]

    def expect_refusal(self, raw=ORIGINAL):
        with self.assertRaises(S.PlanError) as caught:
            S.build_plan(raw, self.manifest)
        self.assertEqual(str(caught.exception), "sessionstart_plan_refused")

    def test_actual_original_single_insertion_preserves_every_byte(self):
        plan = S.build_plan(ORIGINAL, self.manifest)
        self.assertTrue(plan.changed)
        self.assertEqual(plan.after[:plan.offset], ORIGINAL[:plan.offset])
        self.assertEqual(plan.after[plan.offset + len(plan.insertion):], ORIGINAL[plan.offset:])
        old, new = S.parse_json(ORIGINAL), S.parse_json(plan.after)
        self.assertEqual(new["hooks"]["SessionStart"][:-1], old["hooks"]["SessionStart"])
        self.assertEqual(new["hooks"]["SessionStart"][-1], self.manifest["definition"])
        self.assertEqual(new["hooks"]["PreToolUse"], old["hooks"]["PreToolUse"])
        self.assertEqual(new["hooks"]["Stop"], old["hooks"]["Stop"])
        self.assertTrue(S.verify(plan.after, self.manifest, ORIGINAL))
        self.assertEqual(S.undo(plan.after, plan), ORIGINAL)

    def test_existing_exact_definition_is_byte_exact_noop(self):
        after = S.build_plan(ORIGINAL, self.manifest).after
        plan = S.build_plan(after, self.manifest)
        self.assertFalse(plan.changed)
        self.assertEqual(plan.insertion, b"")
        self.assertEqual(plan.before, plan.after)
        self.assertEqual(S.undo(after, plan), after)
        self.assertTrue(S.verify(after, self.manifest))

    def test_future_unrelated_sessionstart_after_managed_is_noop(self):
        installed = S.parse_json(S.build_plan(ORIGINAL, self.manifest).after)
        installed["hooks"]["SessionStart"].append({"matcher": "resume", "hooks": [], "future": True})
        raw = b" \r\n" + encode(installed) + b"\n\t"
        plan = S.build_plan(raw, self.manifest)
        self.assertFalse(plan.changed)
        self.assertEqual(plan.after, raw)
        self.assertTrue(S.verify(raw, self.manifest))
        self.assertFalse(S.verify(raw, self.manifest, ORIGINAL))

    def test_changed_unrelated_bytes_need_original_for_preservation_claim(self):
        after = S.build_plan(ORIGINAL, self.manifest).after
        changed = after.replace(b"Checking control handoff", b"Unrelated future message")
        self.assertTrue(S.verify(changed, self.manifest))
        self.assertFalse(S.verify(changed, self.manifest, ORIGINAL))

    def test_lexical_scan_escaped_keys_brackets_strings_and_unicode(self):
        raw = (b' \r\n{ "first": ["]", {"hooks":{"SessionStart":[]}}], '
               b'"ho\\u006fks" : {"Se\\u0073sionStart" : [ '
               b'{"metadata":"quote \\\" slash \\\\ ] } [","hooks":[]}, '
               + '{"note":"Юникод ] ","hooks":[]}'.encode("utf-8")
               + b' \n\t],"FutureEvent":[{"x":["]",{},true,null,1.25]}]},'
               b'"suffix":"[ ]"} \t\n')
        plan = S.build_plan(raw, self.manifest)
        self.assertEqual(plan.groups_before, 2)
        self.assertEqual(plan.after[:plan.offset] + plan.after[plan.offset + len(plan.insertion):], raw)
        self.assertTrue(S.verify(plan.after, self.manifest, raw))
        self.assertEqual(S.undo(plan.after, plan), raw)

    def test_all_original_groups_and_extra_top_metadata_unchanged(self):
        original = S.parse_json(ORIGINAL)
        original["description"] = "future owner metadata"
        original["hooks"]["SessionStart"].append({"hooks": [], "matcher": "future", "metadata": [False]})
        original["hooks"]["FutureEvent"] = [{"unknown": "preserve"}]
        raw = b"\n" + json.dumps(original, indent=4).encode() + b"\r\n"
        plan = S.build_plan(raw, self.manifest)
        parsed = S.parse_json(plan.after)
        self.assertEqual(parsed["hooks"]["SessionStart"][:-1], original["hooks"]["SessionStart"])
        self.assertEqual(parsed["hooks"]["FutureEvent"], original["hooks"]["FutureEvent"])
        self.assertEqual(parsed["description"], original["description"])
        self.assertEqual(S.undo(plan.after, plan), raw)

    def test_duplicate_managed_group_refused(self):
        value = S.parse_json(S.build_plan(ORIGINAL, self.manifest).after)
        value["hooks"]["SessionStart"].append(copy.deepcopy(self.manifest["definition"]))
        self.expect_refusal(encode(value))

    def test_same_status_changed_group_or_other_event_refused(self):
        for event in ("SessionStart", "OtherEvent"):
            with self.subTest(event=event):
                value = S.parse_json(ORIGINAL)
                conflict = copy.deepcopy(self.manifest["definition"])
                conflict["hooks"][0]["timeout"] = 3
                value["hooks"].setdefault(event, []).append(conflict)
                self.expect_refusal(encode(value))

    def test_item_marker_collision_refused(self):
        for key in ("item_id", "itemId", "id"):
            value = S.parse_json(ORIGINAL)
            value["hooks"]["SessionStart"].append({key: MANIFEST["item_id"], "hooks": []})
            self.expect_refusal(encode(value))

    def test_duplicate_json_keys_rejected_at_every_level(self):
        for raw in (b'{"hooks":{},"hooks":{"SessionStart":[{}]}}',
                    b'{"hooks":{"SessionStart":[{}],"SessionStart":[{}]}}',
                    b'{"hooks":{"SessionStart":[{"x":1,"x":2}]}}'):
            self.expect_refusal(raw)

    def test_bad_json_utf8_scalar_arrays_empty_and_wrong_shapes(self):
        for raw in (b"", b"[]", b"null", b"{}", b'{"hooks":[]}',
                    b'{"hooks":{"SessionStart":[]}}', b'{"hooks":{"SessionStart":[1]}}',
                    b'{"hooks":{"SessionStart":[{}]}} trailing', b"\xff", b"\xef\xbb\xbf{}",
                    b'{"hooks":{"SessionStart":[{},]}}'):
            with self.subTest(raw=raw):
                self.expect_refusal(raw)

    def test_nonfinite_and_excess_integer_rejected(self):
        for number in (b"NaN", b"Infinity", b"-Infinity", b"1e9999", b"9" * 129):
            self.expect_refusal(b'{"n":' + number + b',"hooks":{"SessionStart":[{}]}}')

    def test_size_and_depth_bounded_before_and_after(self):
        self.expect_refusal(ORIGINAL + b" " * S.LIMIT)
        near_limit = ORIGINAL + b" " * (S.LIMIT - len(ORIGINAL))
        self.expect_refusal(near_limit)  # insertion must also fit
        nested = b'{"hooks":{"SessionStart":[{}]},"other":' + b"[" * 65 + b"0" + b"]" * 65 + b"}"
        self.expect_refusal(nested)

    def test_manifest_cycles_and_nonjson_types_refused(self):
        self.manifest["lifecycle"]["cycle"] = self.manifest
        self.expect_refusal()
        self.manifest = copy.deepcopy(MANIFEST)
        self.manifest["policy"]["private"] = object()
        self.expect_refusal()

    def test_exact_metadata_and_nonblocking_policy_types(self):
        changes = (("schema", True), ("owner", "elsewhere"), ("target", "/tmp/hooks"),
                   ("item_id", "another"), ("versionPolicy", "floating"))
        for key, value in changes:
            self.manifest = copy.deepcopy(MANIFEST)
            self.manifest[key] = value
            self.expect_refusal()
        for key, value in MANIFEST["policy"].items():
            self.manifest = copy.deepcopy(MANIFEST)
            self.manifest["policy"][key] = 1 if value is True else True
            self.expect_refusal()

    def test_event_handler_fields_flags_types_are_closed(self):
        for key, value in (("timeout", True), ("timeout", 3), ("additionalContextLimit", True),
                           ("additionalContextLimit", 0), ("async", True), ("type", "mcp_tool"),
                           ("statusMessage", "other"), ("continue", False)):
            self.manifest = copy.deepcopy(MANIFEST)
            self.handler[key] = value
            self.expect_refusal()
        self.manifest = copy.deepcopy(MANIFEST)
        self.manifest["definition"]["matcher"] = "Stop"
        self.expect_refusal()
        self.manifest = copy.deepcopy(MANIFEST)
        self.manifest["definition"]["PreToolUse"] = []
        self.expect_refusal()

    def test_actual_printf_argv_and_nonblocking_output(self):
        argv = shlex.split(self.handler["command"])
        self.assertEqual(argv[:2], ["/usr/bin/printf", "%s\\n"])
        self.assertEqual(len(argv), 3)
        output = S.parse_json(argv[2].encode())
        self.assertEqual(set(output), {"hookSpecificOutput"})
        self.assertEqual(output["hookSpecificOutput"], {
            "hookEventName": "SessionStart", "additionalContext": MANIFEST["expectedContext"]})
        self.assertIn("never ordinary editing", MANIFEST["expectedContext"])
        self.assertIn("Git commits", MANIFEST["expectedContext"])

    def test_shell_extra_commands_flags_substitutions_rejected(self):
        original = self.handler["command"]
        for altered in (original + "; /usr/bin/false", original + " | /usr/bin/true",
                        original + "\n/usr/bin/false", original + " extra",
                        original.replace("/usr/bin/printf", "printf", 1),
                        "$(/usr/bin/printf x) " + original,
                        original.replace("'%s\\n'", '"%s\\n"', 1),
                        original.replace("'%s\\n'", "'%b\\n'", 1),
                        "/usr/bin/env " + original):
            self.manifest = copy.deepcopy(MANIFEST)
            self.handler["command"] = altered
            self.expect_refusal()

    def test_printf_data_is_not_a_shell_or_format_program(self):
        text = "Literal $(ignored); `ignored` %s 'quote' only."
        self.manifest["expectedContext"] = text
        self.handler["command"] = command({"hookSpecificOutput": {
            "hookEventName": "SessionStart", "additionalContext": text}})
        self.assertTrue(S.build_plan(ORIGINAL, self.manifest).changed)
        # Canonical shell quoting holds all metacharacters inside one data argument.
        self.assertEqual(shlex.split(self.handler["command"])[2], encode({"hookSpecificOutput": {
            "hookEventName": "SessionStart", "additionalContext": text}}).decode())

    def test_output_deny_fields_wrong_event_extra_properties_refused(self):
        base = {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": MANIFEST["expectedContext"]}}
        for key, value in (("continue", False), ("deny", True), ("stopReason", "stop"), ("systemMessage", "extra")):
            self.manifest = copy.deepcopy(MANIFEST)
            output = copy.deepcopy(base)
            output[key] = value
            self.handler["command"] = command(output)
            self.expect_refusal()
        for key, value in (("hookEventName", "Stop"), ("additionalContext", "different"), ("deny", False)):
            self.manifest = copy.deepcopy(MANIFEST)
            output = copy.deepcopy(base)
            output["hookSpecificOutput"][key] = value
            self.handler["command"] = command(output)
            self.expect_refusal()

    def test_context_empty_long_and_changed_manifest_mismatch_refused(self):
        for text in ("", " ", "x" * 1601):
            self.manifest = copy.deepcopy(MANIFEST)
            self.manifest["expectedContext"] = text
            self.handler["command"] = command({"hookSpecificOutput": {
                "hookEventName": "SessionStart", "additionalContext": text}})
            self.expect_refusal()
        self.manifest = copy.deepcopy(MANIFEST)
        self.manifest["expectedContext"] = "new unbound text"
        self.expect_refusal()

    def test_duplicate_key_in_command_output_refused(self):
        raw = '{"hookSpecificOutput":{},"hookSpecificOutput":{}}'
        self.handler["command"] = " ".join(map(shlex.quote, ("/usr/bin/printf", "%s\\n", raw)))
        self.expect_refusal()

    def test_undo_rejects_any_concurrent_drift(self):
        plan = S.build_plan(ORIGINAL, self.manifest)
        for changed in (plan.after + b"\n", plan.after.replace(b"SessionStart", b"SessionOther", 1), ORIGINAL):
            with self.assertRaises(S.PlanError):
                S.undo(changed, plan)

    def test_plan_repr_and_reports_do_not_disclose_images(self):
        plan = S.build_plan(ORIGINAL, self.manifest)
        self.assertEqual(repr(plan), "<private SessionStart plan>")
        self.assertEqual(set(plan.public_report()), {"status", "changed", "groupsBefore", "groupsAfter"})
        self.assertNotIn("Routing workstation", json.dumps(plan.public_report()))

    def test_cli_plan_and_check_use_only_explicit_mock_fixture_reads(self):
        for action, raw, expected in (("plan", ORIGINAL, 0), ("check", ORIGINAL, 1),
                ("check", S.build_plan(ORIGINAL, self.manifest).after, 0)):
            seen, emitted = [], []
            def opened(path, mode):
                seen.append((str(path), mode))
                return io.BytesIO({"fixture-input": raw, "fixture-manifest": encode(self.manifest)}[str(path)])
            with patch.object(Path, "open", opened):
                code = S.main([action, "--source-fixture", "fixture-input", "--manifest", "fixture-manifest"], emit=emitted.append)
            self.assertEqual(code, expected)
            self.assertEqual(seen, [("fixture-input", "rb"), ("fixture-manifest", "rb")])
            self.assertEqual(len(emitted), 1)
            self.assertNotIn(MANIFEST["expectedContext"], emitted[0])
            self.assertEqual(set(json.loads(emitted[0])),
                             {"status", "changed", "groupsBefore", "groupsAfter"} if expected == 0 else {"status"})

    def test_cli_invalid_args_and_io_errors_are_redacted(self):
        for arguments in ([], ["apply", "private"], ["--private-path"],
                          ["plan", "--source-fixture", "private", "--manifest", "private"]):
            emitted = []
            with patch.object(Path, "open", side_effect=OSError("secret path")):
                self.assertEqual(S.main(arguments, emit=emitted.append), 1)
            self.assertEqual(emitted, ['{"status":"REFUSED"}'])


if __name__ == "__main__":
    unittest.main()
