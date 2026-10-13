"""Pure fake-byte coverage, never real state or native configuration calls."""

import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.phase5_runtime_compositions import (  # noqa: E402
    CompositionError, MAX_CONFIG_BYTES, compose,
)
from vendor.tomli import loads  # noqa: E402


BEFORE = (b'# old history stays historical\napproval_policy = "on-request"\n'
          b'sandbox_mode = "workspace-write"\nowner_setting = "old"\n')
AFTER = BEFORE.replace(b'"on-request"', b'"never"').replace(
    b'"workspace-write"', b'"danger-full-access"')
CURRENT = (b'# fresh owner comments\n  approval_policy\t= "never" # approval note\n'
           b"sandbox_mode = 'danger-full-access'  # sandbox note\n"
           b'owner_setting = "new"\nnotify = ["do-not-execute"]\n'
           b'[projects."/fixture/new-project"]\ntrust_level = "untrusted"\n'
           b'[plugins."new@fixture"]\nenabled = false\n'
           b'[mcp_servers.fixture]\ncommand = "/fixture/inert"\n'
           b'[hooks.state."/fixture/hooks.json:stop:0:0"]\n'
           b'trusted_hash = "private-fixture-only"\n')


def result(current=CURRENT, before=BEFORE, after=AFTER):
    return compose(before, after, current)


class RuntimeCompositionsTests(unittest.TestCase):
    def test_real_differing_rollback_exact_return(self):
        actual = result()
        expected = CURRENT.replace(b'"never"', b'"on-request"', 1).replace(
            b"'danger-full-access'", b'"workspace-write"', 1)
        self.assertEqual(actual, {"current": CURRENT, "rollback": expected, "return": CURRENT})
        self.assertNotEqual(actual["rollback"], actual["current"])
        self.assertNotIn(b'owner_setting = "old"', actual["rollback"])

    def test_noop_historical_scalars_keep_original_spelling(self):
        self.assertEqual(result(before=AFTER),
                         {"current": CURRENT, "rollback": CURRENT, "return": CURRENT})

    def test_all_known_scalar_enums(self):
        for approval in ("never", "on-request", "untrusted"):
            for sandbox in ("danger-full-access", "workspace-write", "read-only"):
                before = ('approval_policy = %s\nsandbox_mode = %s\n' % (
                    json.dumps(approval), json.dumps(sandbox))).encode()
                after = b'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
                actual = result(before=before, after=after)
                parsed = loads(actual["rollback"].decode())
                self.assertEqual((parsed["approval_policy"], parsed["sandbox_mode"]),
                                 (approval, sandbox))

    def test_absent_keys_preserve_current_comments_and_spacing(self):
        after = b'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
        actual = result(before=b"", after=after)
        expected = CURRENT.replace(b'approval_policy\t= "never"', b"", 1).replace(
            b"sandbox_mode = 'danger-full-access'", b"", 1)
        self.assertEqual(actual["rollback"], expected)
        self.assertIn(b"   # approval note\n", expected)
        self.assertIn(b"  # sandbox note\n", expected)
        parsed = loads(expected.decode())
        self.assertNotIn("approval_policy", parsed)
        self.assertNotIn("sandbox_mode", parsed)
        self.assertEqual(actual["return"], CURRENT)

    def test_one_absent_one_changed(self):
        before = b'sandbox_mode = "read-only"\n'
        after = b'sandbox_mode = "danger-full-access"\napproval_policy = "never"\n'
        actual = result(before=before, after=after)
        expected = CURRENT.replace(b'approval_policy\t= "never"', b"", 1).replace(
            b"'danger-full-access'", b'"read-only"', 1)
        self.assertEqual(actual["rollback"], expected)

    def test_crlf_and_no_final_newline_preserved(self):
        for raw in (CURRENT.replace(b"\n", b"\r\n"), CURRENT.rstrip(b"\n")):
            actual = result(raw)
            self.assertEqual(actual["return"], raw)
            expected = raw.replace(b'"never"', b'"on-request"', 1).replace(
                b"'danger-full-access'", b'"workspace-write"', 1)
            self.assertEqual(actual["rollback"], expected)

    def test_absent_assignment_at_eof_keeps_inline_comment(self):
        raw = b'sandbox_mode = "danger-full-access"\napproval_policy = "never" # keep EOF'
        before = b'sandbox_mode = "workspace-write"\n'
        after = b'sandbox_mode = "danger-full-access"\napproval_policy = "never"\n'
        actual = result(raw, before, after)
        self.assertEqual(actual["rollback"], b'sandbox_mode = "workspace-write"\n # keep EOF')

    def test_both_absent_minimal_current(self):
        raw = b'approval_policy = "never"\nsandbox_mode = "danger-full-access"'
        actual = result(raw, b"", raw)
        self.assertEqual(actual["rollback"], b"\n")
        self.assertEqual(actual["return"], raw)

    def test_multiline_string_assignment_and_table_decoys_never_edited(self):
        decoy = (b'poem = """owner text\napproval_policy = "never"\n'
                 b'[fake.table]\nsandbox_mode = "danger-full-access"\n"""\n')
        raw = decoy + CURRENT
        actual = result(raw)
        self.assertTrue(actual["rollback"].startswith(decoy))
        self.assertEqual(loads(actual["rollback"].decode())["poem"],
                         loads(raw.decode())["poem"])

    def test_literal_multiline_decoy_never_edited(self):
        decoy = (b"poem = '''\napproval_policy = 'never' # decoy\n"
                 b"sandbox_mode = 'danger-full-access'\n'''\n")
        actual = result(decoy + CURRENT)
        self.assertTrue(actual["rollback"].startswith(decoy))

    def test_nested_dotted_and_comment_decoys_preserved(self):
        prefix = (b'# approval_policy = "never"\n'
                  b'nested.approval_policy = "never"\n'
                  b'nested.sandbox_mode = "danger-full-access"\n')
        suffix = (b'[other]\napproval_policy = "never"\n'
                  b'sandbox_mode = "danger-full-access"\n')
        raw = prefix + CURRENT + suffix
        actual = result(raw)
        self.assertTrue(actual["rollback"].startswith(prefix))
        self.assertTrue(actual["rollback"].endswith(suffix))

    def test_preserves_nan_datetime_nested_types(self):
        prefix = (b'nan_values = [nan, +nan, -nan, inf, -inf]\n'
                  b'calendar = 2026-09-07\nclock = 11:12:13\n'
                  b'instant = 2026-09-07T11:12:13+03:00\n'
                  b'mixed = [{a = true, b = 1, c = 1.0}, ["owner"]]\n')
        actual = result(prefix + CURRENT, prefix + BEFORE, prefix + AFTER)
        self.assertTrue(actual["rollback"].startswith(prefix))
        self.assertEqual(actual["return"], prefix + CURRENT)

    def test_unmanaged_historical_type_drift_rejected(self):
        for before, after in ((b"value = true\n", b"value = 1\n"),
                              (b"value = 1\n", b"value = 1.0\n"),
                              (b"value = [1]\n", b"value = [true]\n")):
            with self.assertRaisesRegex(CompositionError, "^composition_historical_pair_invalid$"):
                result(before=before + BEFORE, after=after + AFTER)

    def test_unsupported_root_spelling_cannot_redirect_to_decoy(self):
        for actual_root in (b'"approval_policy" = "never"',
                            b"'approval_policy' = 'never'",
                            b'approval_policy = """never"""'):
            raw = CURRENT.replace(b'approval_policy\t= "never"', actual_root, 1)
            raw += b'[decoy]\napproval_policy = "never"\n'
            with self.assertRaisesRegex(CompositionError, "^composition_scalar_span_unproved$"):
                result(raw)

    def test_escaped_simple_string_is_provable(self):
        raw = CURRENT.replace(b'"never"', b'"ne\\u0076er"', 1)
        self.assertEqual(result(raw)["rollback"], CURRENT.replace(
            b'"never"', b'"on-request"', 1).replace(
            b"'danger-full-access'", b'"workspace-write"', 1))
        self.assertEqual(result(raw, before=AFTER)["rollback"], raw)

    def test_after_and_current_must_have_managed_state(self):
        for kwargs in ({"current": BEFORE}, {"after": BEFORE},
                       {"current": CURRENT.replace(b'"never"', b"true", 1)},
                       {"after": b""}, {"current": b""}):
            with self.assertRaisesRegex(CompositionError, "^composition_managed_state_invalid$"):
                result(**kwargs)

    def test_historical_values_not_arbitrary_insertion_material(self):
        for value in (b'"arbitrary-private-text"', b"true", b"7", b"[]", b'"on-failure"'):
            before = BEFORE.replace(b'"on-request"', value, 1)
            with self.assertRaisesRegex(CompositionError, "^composition_historical_scalar_invalid$"):
                result(before=before)

    def test_historical_unmanaged_drift_rejected(self):
        with self.assertRaisesRegex(CompositionError, "^composition_historical_pair_invalid$"):
            result(after=AFTER.replace(b'"old"', b'"other"'))

    def test_duplicate_malformed_and_non_bytes_redacted(self):
        for candidate in (CURRENT + b'[unterminated-private-canary',
                          CURRENT + b'\n[projects."unterminated', b"\xff", b"\x00",
                          None, bytearray(CURRENT), b"x" * (MAX_CONFIG_BYTES + 1),
                          b'approval_policy = "never"\napproval_policy = "never"\n',
                          b"x = " + b"[" * 1200):
            with self.assertRaises(CompositionError) as caught:
                result(candidate)
            message = str(caught.exception)
            self.assertRegex(message, r"^composition_[a-z_]+$")
            self.assertNotIn("private-canary", message)
            self.assertNotIn("/fixture", message)
            self.assertNotIn("sha256", message)

    def test_candidate_work_is_bounded(self):
        raw = b'poem = """\n' + b'approval_policy = "never"\n' * 17 + b'"""\n' + CURRENT
        with self.assertRaisesRegex(CompositionError, "^composition_candidate_limit$"):
            result(raw)

    def test_only_bytes_no_io_process_network_or_import_dispatch(self):
        with patch("builtins.open", side_effect=AssertionError("no IO")), \
             patch("os.open", side_effect=AssertionError("no IO")), \
             patch("subprocess.run", side_effect=AssertionError("no process")), \
             patch("socket.socket", side_effect=AssertionError("no network")):
            actual = result()
        self.assertTrue(all(type(value) is bytes for value in actual.values()))
        self.assertEqual(set(actual), {"current", "rollback", "return"})


if __name__ == "__main__":
    unittest.main()
