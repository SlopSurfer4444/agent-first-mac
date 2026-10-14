"""Offline P7 protocol and observation negatives; no native command is invoked."""

import base64
import hashlib
import importlib.machinery
import json
from pathlib import Path
import struct
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
module = importlib.machinery.SourceFileLoader(
    "wave_ssh_holder_protocol",
    str(ROOT / "bin/codex-windows-host-ssh-app-server-holder"),
).load_module()

KEY = "dGhlIHNhbXBsZSBub25jZQ=="
OTHER_KEY = base64.b64encode(b"a-different-key!").decode("ascii")
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def accept_for(key):
    return base64.b64encode(
        hashlib.sha1((key + GUID).encode("ascii")).digest()
    )


def upgrade(key=KEY, *, connection=b"Upgrade", upgrade_value=b"websocket"):
    return (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: " + upgrade_value + b"\r\n"
        b"Connection: " + connection + b"\r\n"
        b"Sec-WebSocket-Accept: " + accept_for(key) + b"\r\n\r\n"
    )


def server_frame(payload, *, first=0x81):
    length = len(payload)
    if length < 126:
        header = bytes((first, length))
    elif length < 65536:
        header = bytes((first, 126)) + struct.pack("!H", length)
    else:
        header = bytes((first, 127)) + struct.pack("!Q", length)
    return header + payload


def initialize_payload(**changes):
    value = {
        "id": 7,
        "result": {
            "platformFamily": "windows",
            "platformOs": "windows",
            "userAgent": "fixture-client/1",
        },
    }
    value.update(changes)
    return json.dumps(value, separators=(",", ":")).encode()


class WebSocketUpgradeTests(unittest.TestCase):
    def test_valid_challenge_and_token_case_variants(self):
        self.assertTrue(module.validate_websocket_upgrade(upgrade(), KEY))
        self.assertTrue(module.validate_websocket_upgrade(
            upgrade(connection=b"keep-alive, UpGrAdE", upgrade_value=b"WebSocket"),
            KEY,
        ))
        mixed = upgrade().replace(b"Sec-WebSocket-Accept:", b"sEc-WeBsOcKeT-aCcEpT:")
        self.assertTrue(module.validate_websocket_upgrade(mixed, KEY))

    def test_missing_wrong_and_replayed_challenge(self):
        missing = upgrade().replace(
            b"Sec-WebSocket-Accept: " + accept_for(KEY) + b"\r\n", b""
        )
        wrong = upgrade().replace(accept_for(KEY), b"not-the-request-challenge")
        for response in (missing, wrong, upgrade(OTHER_KEY)):
            with self.subTest(response=response):
                self.assertFalse(module.validate_websocket_upgrade(response, KEY))

    def test_complete_header_required(self):
        for removed in (1, 2, 3, 4):
            with self.subTest(removed=removed):
                self.assertFalse(module.validate_websocket_upgrade(
                    upgrade()[:-removed], KEY
                ))

    def test_duplicate_reserved_headers_rejected_even_when_equal(self):
        for line in (
            b"Sec-WebSocket-Accept: " + accept_for(KEY),
            b"Upgrade: websocket",
            b"Connection: Upgrade",
        ):
            response = upgrade()[:-2] + line + b"\r\n\r\n"
            with self.subTest(line=line):
                self.assertFalse(module.validate_websocket_upgrade(response, KEY))

    def test_status_lookalikes_and_missing_tokens_rejected(self):
        responses = (
            upgrade().replace(b"101 Switching", b"200 Switching"),
            upgrade().replace(b"101 Switching", b"1010 Switching"),
            upgrade().replace(b"HTTP/1.1", b"HTTP/1.0"),
            upgrade(connection=b"keep-alive"),
            upgrade(upgrade_value=b"notwebsocket"),
            upgrade().replace(b"\r\n", b"\n"),
        )
        for response in responses:
            with self.subTest(response=response):
                self.assertFalse(module.validate_websocket_upgrade(response, KEY))

    def test_oversized_header_rejected(self):
        response = upgrade()[:-2] + b"X-Fixture: " + b"x" * 16385 + b"\r\n\r\n"
        self.assertFalse(module.validate_websocket_upgrade(response, KEY))

    def test_header_may_be_coalesced_with_first_frame(self):
        response = upgrade() + server_frame(initialize_payload())
        self.assertTrue(module.validate_websocket_upgrade(response, KEY))


class WebSocketFrameTests(unittest.TestCase):
    def test_client_text_frame_is_masked_and_recovers_exact_json(self):
        payload = {"id": 7, "method": "initialize", "params": {"fixture": "value"}}
        frame = module.encode_websocket_text(payload)
        self.assertEqual(frame[0], 0x81)
        self.assertEqual(frame[1] & 0x80, 0x80)
        size = frame[1] & 0x7f
        offset = 2
        if size == 126:
            size = struct.unpack("!H", frame[2:4])[0]
            offset = 4
        elif size == 127:
            size = struct.unpack("!Q", frame[2:10])[0]
            offset = 10
        mask = frame[offset:offset + 4]
        body = frame[offset + 4:]
        self.assertEqual(len(mask), 4)
        self.assertEqual(len(body), size)
        decoded = bytes(value ^ mask[index % 4] for index, value in enumerate(body))
        self.assertEqual(json.loads(decoded), payload)

    def test_client_mask_is_fresh_for_each_frame(self):
        payload = {"fixture": "small"}
        with patch.object(module.os, "urandom", side_effect=[b"abcd", b"efgh"]):
            one = module.encode_websocket_text(payload)
            two = module.encode_websocket_text(payload)
        self.assertNotEqual(one, two)

    def test_server_frame_preserves_coalesced_next_frame(self):
        first = initialize_payload()
        second = server_frame(b"next")
        self.assertEqual(
            module.decode_websocket_frame(server_frame(first) + second),
            (first, second),
        )

    def test_all_prefixes_of_incomplete_frame_remain_incomplete(self):
        for payload in (b"short", b"x" * 126, b"x" * 65536):
            frame = server_frame(payload)
            positions = range(len(frame)) if len(frame) < 200 else (0, 1, 2, 5, 9, 10, len(frame) - 1)
            for end in positions:
                with self.subTest(length=len(payload), end=end):
                    self.assertIsNone(module.decode_websocket_frame(frame[:end]))
            self.assertEqual(module.decode_websocket_frame(frame), (payload, b""))

    def test_invalid_server_frame_flags_rejected(self):
        for first in (0x01, 0xC1, 0xA1, 0x91, 0x82, 0x80, 0x8F):
            with self.subTest(first=first):
                with self.assertRaises(module.ContractError):
                    module.decode_websocket_frame(server_frame(b"fixture", first=first))
        with self.assertRaises(module.ContractError):
            module.decode_websocket_frame(b"\x81\x81abcdx")

    def test_length_encoding_and_size_limit_fail_before_body_read(self):
        invalid_headers = (
            b"\x81\x7e" + struct.pack("!H", 1),
            b"\x81\x7f" + struct.pack("!Q", 126),
            b"\x81\x7f" + struct.pack("!Q", 65537),
            b"\x81\x7f" + struct.pack("!Q", 1 << 63),
        )
        for frame in invalid_headers:
            with self.subTest(frame=frame):
                with self.assertRaises(module.ContractError):
                    module.decode_websocket_frame(frame)


class InitializeResponseTests(unittest.TestCase):
    def test_windows_result_with_optional_jsonrpc(self):
        self.assertTrue(module.validate_initialize_response(initialize_payload(), 7))
        self.assertTrue(module.validate_initialize_response(
            initialize_payload(jsonrpc="2.0"), 7
        ))

    def test_nonobject_invalid_json_and_wrong_scalar_types_rejected(self):
        for body in (b"", b"not-json", b"\xff", b"[]", b"null", b"true", b"7", b'"text"',
                     b'{"id":7,"id":7,"result":{}}',
                     b'{"id":7,"result":{"userAgent":NaN}}'):
            with self.subTest(body=body):
                self.assertFalse(module.validate_initialize_response(body, 7))
        for identifier in (True, False, 7.0, "7", None, 8):
            with self.subTest(identifier=identifier):
                self.assertFalse(module.validate_initialize_response(
                    initialize_payload(id=identifier), 7
                ))
        self.assertFalse(module.validate_initialize_response(
            initialize_payload(id=True), 1
        ))

    def test_error_or_incompatible_jsonrpc_rejected(self):
        for change in (
            {"jsonrpc": "1.0"}, {"jsonrpc": None}, {"jsonrpc": 2},
            {"error": {"code": -32600, "message": "fixture"}},
            {"result": None}, {"result": []},
        ):
            with self.subTest(change=change):
                self.assertFalse(module.validate_initialize_response(
                    initialize_payload(**change), 7
                ))

    def test_required_windows_identity_and_nonempty_user_agent(self):
        base = json.loads(initialize_payload())["result"]
        for field, values in (
            ("platformFamily", ("unix", "Windows", True, None)),
            ("platformOs", ("macos", "Windows", True, None)),
            ("userAgent", ("", True, 7, None, [])),
        ):
            for value in values:
                with self.subTest(field=field, value=value):
                    self.assertFalse(module.validate_initialize_response(
                        initialize_payload(result={**base, field: value}), 7
                    ))
            result = {name: value for name, value in base.items() if name != field}
            self.assertFalse(module.validate_initialize_response(
                initialize_payload(result=result), 7
            ))


class LaunchdObservationTests(unittest.TestCase):
    def observe(self, returncode, stderr=b"", stdout=b""):
        result = SimpleNamespace(returncode=returncode, stderr=stderr, stdout=stdout)
        with patch.object(module.os, "getuid", return_value=501), patch.object(
            module, "run", return_value=result
        ) as mocked:
            observed = module.observe_launchd()
        argv = mocked.call_args.args[0]
        self.assertEqual(argv, ["/bin/launchctl", "print", f"gui/501/{module.LABEL}"])
        return observed

    def test_success_is_present(self):
        self.assertEqual(self.observe(0, stdout=b"fixture label is loaded"), "PRESENT")

    def test_exact_requested_service_not_found_is_absent(self):
        stderr = (
            f'Bad request.\nCould not find service "{module.LABEL}" '
            'in domain for user gui: 501\n'
        ).encode()
        self.assertEqual(self.observe(113, stderr), "ABSENT")

    def test_other_errors_and_wrong_target_are_unknown(self):
        errors = (
            b"", b"Operation not permitted", b"Permission denied",
            b"Could not find domain", b"connection lost",
            b'Could not find service "unrelated.label" in domain for user gui: 501\n',
            f'Could not find service "{module.LABEL}" in domain for user gui: 502\n'.encode(),
            f'Could not find service "{module.LABEL}" in domain for user system: 501\n'.encode(),
        )
        for error in errors:
            with self.subTest(error=error):
                self.assertEqual(self.observe(5, error), "UNKNOWN")

    def test_timeout_and_execution_error_are_unknown(self):
        for error in (subprocess.TimeoutExpired("fixture", 1), OSError("fixture")):
            with self.subTest(error=type(error).__name__):
                with patch.object(module, "run", side_effect=error):
                    self.assertEqual(module.observe_launchd(), "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
