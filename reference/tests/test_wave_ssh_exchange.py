"""Exercise the wired proxy exchange with synthetic streams, never sockets."""
import base64
import hashlib
import importlib.machinery
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
holder = importlib.machinery.SourceFileLoader("wave_ssh_exchange",
    str(ROOT / "bin/codex-windows-host-ssh-app-server-holder")).load_module()
compat = importlib.machinery.SourceFileLoader("wave_ssh_native_exchange",
    str(ROOT / "bin/codex-windows-host-ssh-stdio-compat")).load_module()


class Stream:
    def __init__(self):
        self.writes = []
        self.closed = False
    def write(self, data):
        self.writes.append(data)
        return len(data)
    def flush(self):
        pass
    def close(self):
        self.closed = True
    def fileno(self):
        return 987


class Child:
    def __init__(self):
        self.stdin, self.stdout = Stream(), Stream()
        self.returncode = None
        self.waited = False
    def poll(self):
        return self.returncode
    def terminate(self):
        self.returncode = -15
    def wait(self, timeout):
        self.waited = True
        return self.returncode


class Selector:
    def register(self, *args):
        pass
    def select(self, **kwargs):
        return [True]
    def close(self):
        pass


def client_payload(frame):
    length = frame[1] & 127
    assert length < 126 or length == 126
    offset = 2 if length < 126 else 4
    if offset == 4:
        length = int.from_bytes(frame[2:4], "big")
    mask = frame[offset:offset+4]
    data = frame[offset+4:offset+4+length]
    return json.loads(bytes(v ^ mask[i % 4] for i, v in enumerate(data)))


class ProxyExchangeFixtures(unittest.TestCase):
    def probe(self, mode="valid", chunks=None, native=False):
        target = compat if native else holder
        child = Child()
        seen = []
        def read(fd, count):
            if chunks is not None:
                return chunks.pop(0) if chunks else b""
            if not seen:
                seen.append("header")
                key = child.stdin.writes[0].split(b"Sec-WebSocket-Key: ")[1].split(b"\r\n")[0]
                accept = base64.b64encode(hashlib.sha1(key +
                    b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
                if mode == "wrong-accept":
                    accept = b"wrong"
                return (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                        b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
            if len(seen) == 1 and mode not in {"header-only", "wrong-accept"}:
                seen.append("result")
                request = client_payload(child.stdin.writes[1])
                body = json.dumps({"id": request["id"] if mode != "wrong-id" else "foreign",
                    "result": {"platformFamily": "windows", "platformOs": "windows",
                               "userAgent": "fixture"}}, separators=(",", ":")).encode()
                header = (b"\x81" + bytes([len(body)]) if len(body) < 126 else
                          b"\x81\x7e" + len(body).to_bytes(2, "big"))
                return header + body
            return b""
        with patch.object(target.subprocess, "Popen", return_value=child) as launch, \
             patch.object(target.selectors, "DefaultSelector", return_value=Selector()), \
             patch.object(target.os, "read", side_effect=read):
            result = (target.remote_native_websocket_handshake_passes() if native
                      else target.remote_proxy_observation())
        self.assertTrue(child.waited)
        self.assertTrue(child.stdin.closed)
        self.assertTrue(child.stdout.closed)
        argv = launch.call_args.args[0]
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("ForwardAgent=no", argv)
        return result, child

    def test_complete_challenge_initialize_initialized_and_child_closure(self):
        facts, child = self.probe()
        self.assertEqual(facts, {"state": "PRESENT", "transport": True, "application": True})
        self.assertEqual(client_payload(child.stdin.writes[1])["method"], "initialize")
        self.assertEqual(client_payload(child.stdin.writes[2])["method"], "initialized")

    def test_wrong_challenge_sends_no_application_request(self):
        facts, child = self.probe("wrong-accept")
        self.assertEqual(facts["state"], "UNKNOWN")
        self.assertFalse(facts["transport"])
        self.assertEqual(len(child.stdin.writes), 1)

    def test_header_only_is_transport_not_application_readiness(self):
        facts, child = self.probe("header-only")
        self.assertEqual(facts, {"state": "UNKNOWN", "transport": True, "application": False})
        self.assertEqual(len(child.stdin.writes), 2)

    def test_wrong_initialize_id_never_sends_initialized(self):
        facts, child = self.probe("wrong-id")
        self.assertEqual(facts["state"], "UNKNOWN")
        self.assertFalse(facts["application"])
        self.assertEqual(len(child.stdin.writes), 2)

    def test_eof_partial_header_is_unknown_not_absence(self):
        facts, child = self.probe(chunks=[b"HTTP/1.1 101 Switching Protocols\r\n"])
        self.assertEqual(facts["state"], "UNKNOWN")
        self.assertFalse(facts["transport"])

    def test_new_request_key_and_request_id_each_time(self):
        _, first = self.probe()
        _, second = self.probe()
        self.assertNotEqual(first.stdin.writes[0], second.stdin.writes[0])
        self.assertNotEqual(client_payload(first.stdin.writes[1])["id"],
                            client_payload(second.stdin.writes[1])["id"])

    def test_launch_failure_returns_unknown(self):
        with patch.object(holder.subprocess, "Popen", side_effect=OSError("fixture")):
            self.assertEqual(holder.remote_proxy_observation()["state"], "UNKNOWN")

    def test_child_failure_during_initialized_flush_is_unknown_and_reaped(self):
        original = Stream.flush
        def flush(stream):
            if len(stream.writes) == 3:
                # The child exits after initialize but before final observation.
                # Its incarnation is the exact process object owned by the probe.
                child.returncode = 1
            original(stream)
        child = Child()
        with patch("test_wave_ssh_exchange.Child", return_value=child), \
             patch.object(Stream, "flush", flush):
            facts, result = self.probe()
        self.assertEqual(facts["state"], "UNKNOWN")
        self.assertFalse(facts["application"])
        self.assertTrue(result.waited)

    def test_selector_construction_failure_still_closes_and_reaps_child(self):
        child = Child()
        with patch.object(holder.subprocess, "Popen", return_value=child), \
             patch.object(holder.selectors, "DefaultSelector", side_effect=OSError("fixture")):
            self.assertEqual(holder.remote_proxy_observation()["state"], "UNKNOWN")
        self.assertTrue(child.waited)
        self.assertTrue(child.stdin.closed)
        self.assertTrue(child.stdout.closed)

    def test_disposable_native_helper_requires_the_complete_shared_exchange(self):
        self.assertTrue(self.probe(native=True)[0])
        for mode in ("wrong-accept", "header-only", "wrong-id"):
            with self.subTest(mode=mode):
                self.assertFalse(self.probe(mode, native=True)[0])

    def test_disposable_native_helper_uses_fresh_challenge_each_time(self):
        _, first = self.probe(native=True)
        _, second = self.probe(native=True)
        self.assertNotEqual(first.stdin.writes[0], second.stdin.writes[0])


if __name__ == "__main__":
    unittest.main()
