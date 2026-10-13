"""Pure plans/bytes only: never execute a launcher, sandbox, listener or model."""

import ast
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import phase5_current_quarantine as q

PROFILE = (ROOT / "codex/quarantine.config.toml").read_bytes()
LAUNCHER = (ROOT / "bin/codex-quarantine").read_bytes()
HOME = "/fixture/owner"
WORKSPACE = HOME + "/AIDev/quarantine/test with spaces"


def paths():
    result = {leaf: WORKSPACE + "/" + leaf for leaf in q.SECRET_LEAVES}
    result.update(visible=WORKSPACE + "/visible.txt", outside="/fixture/outside.txt")
    return result


def plan(**overrides):
    values = dict(home=HOME, workspace=WORKSPACE, fixture_paths=paths(), port=43210,
                  installed_profile=PROFILE, profile_home=WORKSPACE + "/profile-home")
    values.update(overrides)
    return q.build_plan(**values)


def network_diagnostic(port=43210, errno=b"Operation not permitted"):
    return (b"* Immediate connect fail for 127.0.0.1: " + errno + b"\n" +
            b"curl: (7) Failed to connect to 127.0.0.1 port " + str(port).encode() +
            b" after 0 ms: Couldn't connect to server\n")


def success(p):
    results = {}
    for case in p.cases:
        if case.name == "workspace-read":
            row = (0, b"visible\n", b"")
        elif case.name == "outside-read" or case.name.startswith("secret-"):
            row = (1, b"", ("cat: " + case.argv[-1] +
                            ": Operation not permitted\n").encode())
        elif case.name == "environment":
            row = (0, b"PATH=" + q.SAFE_PATH.encode() + b"\n", b"")
        elif case.name == "aid-admin":
            row = (1, b"", b"")
        elif case.name == "loopback-direct":
            row = (0, b"phase5-loopback\n", b"")
        else:
            row = (7, b"", network_diagnostic(p.port))
        results[case.name] = row
    return results


class QuarantineTests(unittest.TestCase):
    def assert_closed(self, result):
        for key in ("executionAdmission", "phase5PassClaimed", "phase6Authorized",
                    "integrationAbsenceProven"):
            self.assertIs(result[key], False)
        self.assertNotIn(HOME, repr(result))
        self.assertNotIn("fixture", repr(result))

    def test_source_bindings_and_fixed_command_contract(self):
        self.assertEqual(hashlib.sha256(PROFILE).hexdigest(), q.PROFILE_SHA256)
        self.assertEqual(hashlib.sha256(LAUNCHER).hexdigest(), q.LAUNCHER_SHA256)
        p = plan()
        self.assertEqual(tuple(c.name for c in p.cases), q.CASE_NAMES)
        self.assertEqual(len(p.cases), 12)
        for c in p.cases:
            self.assertEqual(c.cwd, WORKSPACE)
            if c.name != "loopback-direct":
                self.assertEqual(c.argv[:8], (q.CODEX, "sandbox", "--profile",
                    "quarantine", "--permission-profile", "quarantine", "--cd", WORKSPACE))
            env = dict(c.environment)
            self.assertEqual(env["CODEX_HOME"], WORKSPACE + "/profile-home")
            self.assertEqual(env["HOME"], HOME)
            self.assertEqual(env["PATH"], q.SAFE_PATH)
            self.assertEqual(len(env), 6 if c.name == "loopback-direct" else 7)
        self.assertNotIn(HOME, repr(p))
        self.assertNotIn(HOME, repr(p.cases[0]))

    def test_legacy_vectors_are_read_not_dispatched(self):
        # Read literal AST only, never import/execute the production validator.
        source = (ROOT / "bin/check-phase5-prep").read_text()
        tree = ast.parse(source)
        functions = {node.name: node for node in tree.body
                     if isinstance(node, ast.FunctionDef)}
        body = functions["capability_probe"]
        constants = {n.value for n in ast.walk(body)
                     if isinstance(n, ast.Constant) and type(n.value) is str}
        for value in ("sandbox", "--profile", "--permission-profile", "quarantine",
                      "--cd", "visible.txt", ".env", "command -v aid-admin",
                      q.SENTINEL, q.SENTINEL_VALUE):
            self.assertIn(value, constants)
        network = {n.value for n in ast.walk(functions["loopback_network_probe"])
                   if isinstance(n, ast.Constant) and type(n.value) is str}
        for value in ("/usr/bin/curl", "--noproxy", "*", "-fsS", "--max-time", "2"):
            self.assertIn(value, network)

    def test_complete_positive_never_grants_authority(self):
        p = plan()
        result = q.validate_complete(p, success(p))
        self.assertIs(result["casePassed"], True)
        self.assertEqual(result["evidenceClass"], "profile-bytes-capability")
        self.assert_closed(result)

    def test_profile_drift_rejected_no_direct_installed_stack_admission(self):
        for raw in (PROFILE + b"\n", b"", bytearray(PROFILE), None):
            with self.assertRaisesRegex(q.ContractError, "^quarantine_contract_invalid$"):
                plan(installed_profile=raw)

    def test_profile_home_fixed_isolated_child_and_actual_home_retained(self):
        for path in (HOME + "/.codex", WORKSPACE, WORKSPACE + "/other",
                     WORKSPACE + "/profile-home/", WORKSPACE + "/x/../profile-home",
                     None, 1):
            with self.assertRaises(q.ContractError):
                plan(profile_home=path)
        p = plan()
        for case in p.cases:
            env = dict(case.environment)
            self.assertEqual(env["HOME"], HOME)
            self.assertEqual(env["CODEX_HOME"], p.profile_home)
        self.assertIsNone(q.recheck_plan(p))
        self.assert_plan_rejected(replace(p, profile_home=HOME + "/.codex"), p)
        cases = list(p.cases)
        cases[0] = replace(cases[0], environment=tuple(
            (key, HOME + "/.codex" if key == "CODEX_HOME" else value)
            for key, value in cases[0].environment))
        self.assert_plan_rejected(replace(p, cases=tuple(cases)), p)

    def test_paths_are_lexical_canonical_not_filesystem_admission(self):
        for root in ("/", WORKSPACE + "/", WORKSPACE + "/../x", WORKSPACE + '//x',
                     WORKSPACE + '\\x', WORKSPACE + '"x', WORKSPACE + '\nx',
                     HOME + "/AIDev/quarantine", "/elsewhere/repo", 1):
            with self.subTest(root=root), self.assertRaises(q.ContractError):
                plan(workspace=root)

    def test_fixture_mapping_closed(self):
        for edit in (lambda p: p.update(extra="/fixture/extra"),
                     lambda p: p.pop(".env"),
                     lambda p: p.update(outside=WORKSPACE + "/outside.txt"),
                     lambda p: p.update(visible=WORKSPACE + "/secret.txt"),
                     lambda p: p.update({".env": "/fixture/elsewhere"})):
            value = paths()
            edit(value)
            with self.assertRaises(q.ContractError):
                plan(fixture_paths=value)

    def test_port_exact_type_and_bounds(self):
        for port in (True, False, 0, -1, 65536, 1.0, "123", None):
            with self.assertRaises(q.ContractError):
                plan(port=port)

    def test_no_generic_exit_or_signals_are_denial(self):
        p = plan()
        for rc in (2, 7, 126, 127, 255):
            result = q.validate_case(p, "outside-read", rc, b"", b"failed\n")
            self.assertIs(result["casePassed"], False)
        for rc in (-9, -15, True, 0.0, "1", None, 256):
            with self.assertRaises(q.ContractError):
                q.validate_case(p, "outside-read", rc, b"", b"")

    def test_cat_missing_file_or_partial_content_not_denial(self):
        p = plan()
        rc, out, err = success(p)["outside-read"]
        for row in ((1, b"", err.replace(b"Operation not permitted", b"No such file or directory")),
                    (1, b"outside\n", err), (0, b"", err),
                    (1, b"", err.replace(b"outside.txt", b"other.txt"))):
            self.assertFalse(q.validate_case(p, "outside-read", *row)["casePassed"])

    def test_workspace_requires_exact_visible_bytes(self):
        for row in ((0, b"", b""), (0, b"visible\n", b"warning"),
                    (1, b"visible\n", b""), (0, b"visible\nextra", b"")):
            self.assertFalse(q.validate_case(plan(), "workspace-read", *row)["casePassed"])

    def test_environment_sentinel_key_value_and_duplicate_negatives(self):
        base = b"PATH=" + q.SAFE_PATH.encode() + b"\n"
        for suffix in (q.SENTINEL.encode() + b"=x\n", b"OTHER=must-not-inherit\n",
                       base, b"no-equals\n", b"BAD\x00=one\n", b"=empty\n"):
            self.assertFalse(q.validate_case(plan(), "environment", 0, base + suffix,
                                            b"")["casePassed"])
        self.assertFalse(q.validate_case(plan(), "environment", 0,
                                        b"PATH=/fixture/bin\n", b"")["casePassed"])

    def test_aid_admin_must_be_unavailable_without_diagnostic_failure(self):
        for row in ((0, b"/fixture/aid-admin\n", b""), (127, b"", b""),
                    (1, b"", b"shell failed"), (1, b"unexpected", b"")):
            self.assertFalse(q.validate_case(plan(), "aid-admin", *row)["casePassed"])

    def test_loopback_positive_and_negative_are_both_required(self):
        p = plan()
        for name in ("loopback-direct", "loopback-sandbox"):
            result = success(p)
            result[name] = (7, b"", b"curl: (7) Connection refused\n")
            self.assertFalse(q.validate_complete(p, result)["casePassed"])
        for rc in (6, 28, 35, 52, 56):
            self.assertFalse(q.validate_case(p, "loopback-sandbox", rc, b"",
                b"curl: (7) Operation not permitted\n")["casePassed"])

    def test_loopback_command_and_environment_pair(self):
        p = plan()
        direct, sandbox = p.cases[-2:]
        self.assertEqual(sandbox.argv[8:], direct.argv[:2] + ("--verbose",) + direct.argv[2:])
        self.assertEqual(direct.argv, ("/usr/bin/curl", "-q", "--noproxy", "*", "-fsS",
                                     "--max-time", "2", "http://127.0.0.1:43210/phase5"))
        self.assertEqual(sandbox.argv.count("--verbose"), 1)
        for case in p.cases[:-1]:
            self.assertNotIn("--verbose", case.argv)
        self.assertEqual(direct.argv[:2], ("/usr/bin/curl", "-q"))
        self.assertEqual(sandbox.argv[8:10], ("/usr/bin/curl", "-q"))
        self.assertNotIn(q.SENTINEL, dict(direct.environment))
        self.assertEqual(dict(sandbox.environment)[q.SENTINEL], q.SENTINEL_VALUE)
        self.assertEqual(direct.argv[-1], "http://127.0.0.1:43210/phase5")

    def test_verbose_network_permission_with_optional_private_progress(self):
        for port in (1, 43210, 65535):
            for errno in (b"Operation not permitted", b"Permission denied"):
                p = plan(port=port)
                minimal = network_diagnostic(port, errno)
                marker, final = minimal.splitlines(keepends=True)
                progress = (b"*   Trying 127.0.0.1:" + str(port).encode() + b"...\n" + marker +
                            b"* " + final[len(b"curl: (7) "):] + b"* Closing connection 0\n" + final)
                for stderr in (minimal, progress, marker + b"* closing connection #0\n" + final):
                    result = q.validate_case(p, "loopback-sandbox", 7, b"", stderr)
                    self.assertTrue(result["casePassed"])
                    self.assert_closed(result)
                    self.assertNotIn(str(port), repr(result))

    def test_generic_refused_timeout_missing_or_cli_failure_is_not_network_denial(self):
        p = plan()
        good = network_diagnostic()
        for stderr in (good.splitlines(keepends=True)[-1],
                       b"curl: (7) Failed to connect: Operation not permitted\n",
                       good.replace(b"Operation not permitted", b"Connection refused"),
                       good.replace(b"Operation not permitted", b"Operation timed out"),
                       good.replace(b"Operation not permitted", b"No such file or directory"),
                       good.replace(b"* Immediate connect fail", b"* other error"),
                       b"error: unknown argument --verbose\n" + good,
                       good + b"curl: option --bad: unknown\n"):
            self.assertFalse(q.validate_case(p, "loopback-sandbox", 7, b"", stderr)["casePassed"])
        for rc, stdout in ((0, b""), (6, b""), (28, b""), (127, b""), (7, b"unexpected")):
            self.assertFalse(q.validate_case(p, "loopback-sandbox", rc, stdout, good)["casePassed"])

    def test_network_errno_and_final_error_are_bound_to_exact_loopback_target(self):
        good = network_diagnostic()
        for bad in (good.replace(b"127.0.0.1", b"127.0.0.2", 1),
                    good.replace(b"127.0.0.1", b"example.com"),
                    good.replace(b"port 43210", b"port 43211"),
                    good.replace(b"after 0 ms", b"after 0 ms: Connection refused"),
                    b"*   Trying 192.0.2.1:43210...\n" + good,
                    b"*   Trying 127.0.0.1:43211...\n" + good,
                    b"* Immediate connect fail for 127.0.0.2: Permission denied\n" + good,
                    b"* Immediate connect fail for 127.0.0.1: Connection refused\n" + good):
            self.assertFalse(q.validate_case(plan(), "loopback-sandbox", 7, b"", bad)["casePassed"])

    def test_network_diagnostic_is_bounded_complete_unambiguous_and_not_arbitrary_logs(self):
        good = network_diagnostic()
        marker, final = good.splitlines(keepends=True)
        for bad in (good[:-1], good + b"\n", marker + marker + final, final + marker,
                    good.replace(b"* Immediate", b"\x1b[31m* Immediate"),
                    good.replace(b"* Immediate", b"\x00* Immediate"), good.replace(b"\n", b"\r\n"),
                    b"* arbitrary permission-looking log\n" + good,
                    b"* Closing connection 0\n" * 15 + good,
                    b"* " + b"x" * 513 + b"\n" + good):
            self.assertFalse(q.validate_case(plan(), "loopback-sandbox", 7, b"", bad)["casePassed"])
        rows = success(plan())
        rows["loopback-sandbox"] = (7, b"", final)
        self.assertFalse(q.validate_complete(plan(), rows)["casePassed"])

    def test_verbose_is_mandatory_only_in_exact_sandbox_vector(self):
        p = plan()
        for index, argv in ((-1, tuple(arg for arg in p.cases[-1].argv if arg != "--verbose")),
                            (-2, p.cases[-2].argv[:2] + ("--verbose",) + p.cases[-2].argv[2:]),
                            (-1, p.cases[-1].argv + ("--trace-ascii", "-"))):
            cases = list(p.cases)
            cases[index] = replace(cases[index], argv=argv)
            self.assert_plan_rejected(replace(p, cases=tuple(cases)), p)

    def assert_plan_rejected(self, bad, original):
        # The same otherwise-passing captures cannot certify an altered plan.
        for consume in (lambda: q.recheck_plan(bad),
                        lambda: q.validate_case(bad, "workspace-read", 0, b"visible\n", b""),
                        lambda: q.validate_complete(bad, success(original))):
            with self.assertRaisesRegex(q.ContractError, "^quarantine_contract_invalid$"):
                consume()

    def test_recheck_plan_positive_no_authority_or_mutation(self):
        p = plan()
        before = p.cases
        self.assertIsNone(q.recheck_plan(p))
        self.assertIs(p.cases, before)
        self.assertIsNone(q.recheck_plan(p))

    def test_connected_fixed_command_cwd_environment_changes(self):
        p = plan()
        for index in range(len(p.cases)):
            case = p.cases[index]
            for change in (dict(argv=("/bin/echo", "visible")),
                           dict(argv=case.argv + ("--extra",)),
                           dict(cwd="/fixture/other"),
                           dict(environment=case.environment + (("EVIL", "value"),)),
                           dict(environment=tuple((k, "changed" if k == "HOME" else v)
                                                  for k, v in case.environment))):
                cases = list(p.cases)
                cases[index] = replace(case, **change)
                self.assert_plan_rejected(replace(p, cases=tuple(cases)), p)
        for index in (-1, -2):
            cases = list(p.cases)
            cases[index] = replace(cases[index], argv=tuple(
                arg for arg in cases[index].argv if arg != "-q"))
            self.assert_plan_rejected(replace(p, cases=tuple(cases)), p)

    def test_malformed_case_fields_never_leak_native_exceptions(self):
        p = plan()
        for field, values in (("name", (None, 1)), ("cwd", (None, [])),
                              ("argv", ((), [], None, (None,))),
                              ("environment", (None, [], (("A",),), (([], "v"),)))):
            for value in values:
                cases = list(p.cases)
                cases[1] = replace(cases[1], **{field: value})
                self.assert_plan_rejected(replace(p, cases=tuple(cases)), p)
        cases = list(p.cases)
        cases[1] = q.Case.__new__(q.Case)
        self.assert_plan_rejected(replace(p, cases=tuple(cases)), p)

    def test_malformed_or_changed_original_inputs_are_rechecked(self):
        p = plan()
        for change in (dict(home=None), dict(workspace=1), dict(port=True),
                       dict(port=43211), dict(installed_profile=PROFILE + b"\n"),
                       dict(fixture_paths=None), dict(fixture_paths=(([], []),) * 8),
                       dict(fixture_paths=p.fixture_paths[:1] * 8),
                       dict(cases=None), dict(cases=p.cases[:-1])):
            self.assert_plan_rejected(replace(p, **change), p)
        self.assert_plan_rejected(q.Plan.__new__(q.Plan), p)
        self.assert_plan_rejected(None, p)

    def test_no_exec_only_flags_added_to_sandbox(self):
        for case in plan().cases:
            self.assertNotIn("--ignore-user-config", case.argv)
            self.assertNotIn("--ignore-rules", case.argv)

    def test_stream_bounds_and_exact_bytes(self):
        for stdout, stderr in (("visible\n", b""), (b"", bytearray()),
                               (b"a" * 16385, b""), (b"", b"a" * 16385)):
            with self.assertRaises(q.ContractError):
                q.validate_case(plan(), "workspace-read", 0, stdout, stderr)

    def test_missing_extra_wrong_result_row_and_unknown_case(self):
        p = plan()
        for edit in (lambda rows: rows.pop("environment"),
                     lambda rows: rows.update(extra=(0, b"", b"")),
                     lambda rows: rows.update(environment=[0, b"", b""])):
            rows = success(p)
            edit(rows)
            with self.assertRaises(q.ContractError):
                q.validate_complete(p, rows)
        with self.assertRaises(q.ContractError):
            q.validate_case(p, "model-visibility", 0, b"", b"")

    def test_model_exact_launcher_surface_no_invented_flags(self):
        c = q.model_plan(HOME, WORKSPACE, PROFILE, LAUNCHER)
        self.assertEqual(c.argv, (HOME + "/AIDev/bin/codex-quarantine", "--root",
                                 WORKSPACE, "--", q.MODEL_PROMPT))
        self.assertEqual(c.environment, ())
        self.assertNotIn(WORKSPACE + "/profile-home", c.argv)
        self.assertNotIn("--json", c.argv)
        self.assertNotIn("--output-schema", c.argv)
        with self.assertRaises(q.ContractError):
            q.model_plan(HOME, WORKSPACE, PROFILE, LAUNCHER + b"\n")

    def test_model_success_is_supporting_only(self):
        value = {k: v["const"] for k, v in q.model_schema()["properties"].items()}
        result = q.validate_model_output(0, json.dumps(value).encode())
        self.assertTrue(result["casePassed"])
        self.assertTrue(result["supportingEvidenceOnly"])
        self.assertEqual(result["evidenceClass"], "installed-launcher-model-support")
        self.assert_closed(result)
        value["userMcpToolsVisible"] = True
        self.assertFalse(q.validate_model_output(0, json.dumps(value).encode())["casePassed"])

    def test_model_schema_all_consts_typed_closed_and_fresh(self):
        schema = q.model_schema()
        self.assertEqual(set(schema["required"]), set(schema["properties"]))
        self.assertIs(schema["additionalProperties"], False)
        schema["properties"]["schema"]["const"] = 9
        self.assertEqual(q.model_schema()["properties"]["schema"]["const"], 1)

    def test_model_wrong_types_extras_missing_fields(self):
        good = {k: v["const"] for k, v in q.model_schema()["properties"].items()}
        for key, value in (("schema", True), ("schema", 1.0),
                           ("userAppToolsVisible", 0), ("extra", "private")):
            bad = dict(good, **{key: value})
            self.assertFalse(q.validate_model_output(0, json.dumps(bad).encode())["casePassed"])
        self.assertFalse(q.validate_model_output(0, b"{}")["casePassed"])

    def test_model_duplicate_malformed_truncated_oversize_redacted(self):
        for raw in (b'{"schema":1,"schema":1}', b'{"schema":', b"\xff", b"x" * 1025,
                    b"```json\n{}\n```", b"{}\nprivate text"):
            with self.assertRaisesRegex(q.ContractError, "^quarantine_contract_invalid$"):
                q.validate_model_output(0, raw)


if __name__ == "__main__":
    unittest.main()
