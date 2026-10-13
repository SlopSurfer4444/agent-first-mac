#!/usr/bin/python3
import importlib.util
import contextlib
import copy
import json
from pathlib import Path
import subprocess
import sys
import traceback
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "lib/phase5_plugin_catalog.py"
SPEC = importlib.util.spec_from_file_location("phase5_plugin_catalog", MODULE_PATH)
catalog = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(catalog)


FAKE_SERVER = r'''
import json, os, sys, time

scenario = sys.argv[1]
def read():
    line = sys.stdin.buffer.readline()
    return json.loads(line)
def send(value):
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()

if scenario == "hang":
    time.sleep(60)
    raise SystemExit
first = read()
expected = {
    "id": 0, "method": "initialize",
    "params": {"clientInfo": {
        "name": "phase5_plugin_catalog_observer",
        "title": "Phase 5 Plugin Catalog Observer", "version": "1.0.0"}},
}
if first != expected or "jsonrpc" in first:
    send({"id": 0, "error": {"code": -1, "message": "bad init secret"}})
    raise SystemExit
if scenario == "malformed":
    sys.stdout.write("not-json\n"); sys.stdout.flush(); raise SystemExit
if scenario == "wrong_id":
    send({"id": 99, "result": {}}); raise SystemExit
send({"id": 0, "result": {"userAgent": "fake"}})
initialized = read()
if initialized != {"method": "initialized", "params": {}}:
    raise SystemExit(3)
installed_request = read()
if installed_request != {
    "id": 1, "method": "plugin/installed",
    "params": {"cwds": [], "installSuggestionPluginNames": []},
}:
    raise SystemExit(4)
if scenario == "server_error":
    send({"id": 1, "error": {"code": 7, "message": "private path /secret"}})
    raise SystemExit
if scenario == "eof":
    raise SystemExit
if scenario == "overflow":
    sys.stdout.write("x" * 8192 + "\n"); sys.stdout.flush(); raise SystemExit
plugin = {
    "authPolicy": "ON_INSTALL", "enabled": True,
    "id": "opaque-private-id", "installPolicy": "AVAILABLE",
    "installed": True, "name": "private-name",
    "source": {"type": "remote"},
    "remotePluginId": "private-backend-id", "version": "9.8.7",
    "localVersion": "9.8.7",
    "interface": {"developerName": "Private Publisher"},
    "shareContext": {"creatorAccountUserId": "private-account-id"},
}
response = {
    "marketplaces": [{"name": "private-marketplace", "path": None,
                       "plugins": [plugin]}],
    "marketplaceLoadErrors": [],
}
send({"id": 1, "result": response})
vertical_request = read()
if vertical_request != {
    "id": 2, "method": "plugin/list",
    "params": {"cwds": [], "forceRefetch": False,
               "marketplaceKinds": ["vertical"]},
}:
    raise SystemExit(5)
send({"method": "account/updated", "params": {"private": "ignored"}})
send({"id": 2, "result": response})
if scenario == "stderr":
    sys.stderr.write("private diagnostic /secret\n"); sys.stderr.flush()
if scenario == "nonzero":
    raise SystemExit(6)
'''


def command(scenario):
    # argv[1] remains app-server for the production launch guard.  The fake
    # factory removes only that marker before starting the Python fixture.
    return [sys.executable, "app-server", "--listen", "stdio://",
            "-I", "-S", "-B", "-c", FAKE_SERVER, scenario]


ENVIRONMENT = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}


def fake_popen(arguments, **kwargs):
    return subprocess.Popen([arguments[0]] + arguments[4:], **kwargs)


NATIVE_FIXTURES = "--native-fixtures" in sys.argv
if NATIVE_FIXTURES:
    sys.argv.remove("--native-fixtures")


@unittest.skipUnless(NATIVE_FIXTURES, "separate root admission: --native-fixtures")
class NativeCatalogTests(unittest.TestCase):
    """REAL Python child servers. Never run in default source validation."""
    def test_exact_fixed_handshake_and_private_capture(self):
        value = catalog.collect_private_catalog(
            command("ok"), ENVIRONMENT, 3, _popen_factory=fake_popen)
        self.assertEqual(value["installed"], value["vertical"])
        self.assertTrue(value["transport"]["childReaped"])
        self.assertEqual(value["transport"]["notificationCount"], 1)
        self.assertTrue(value["transport"]["stderrEmpty"])

    def test_public_projection_has_only_counts_booleans_and_classes(self):
        private = catalog.collect_private_catalog(
            command("ok"), ENVIRONMENT, 3, _popen_factory=fake_popen)
        public = catalog.public_projection(private)
        encoded = json.dumps(public, sort_keys=True)
        for secret in (
            "opaque-private-id", "private-name", "private-marketplace",
            "private-backend-id", "Private Publisher", "private-account-id",
        ):
            self.assertNotIn(secret, encoded)
        self.assertTrue(public["observationSucceeded"])
        self.assertEqual(public["catalogIdentityIntersectionCount"], 1)
        self.assertEqual(public["vertical"]["sourceClassCounts"]["remote"], 1)
        self.assertTrue(all(value is False for value in public["admission"].values()))

    def test_stderr_is_boolean_only(self):
        private = catalog.collect_private_catalog(
            command("stderr"), ENVIRONMENT, 3, _popen_factory=fake_popen)
        public = catalog.public_projection(private)
        self.assertFalse(public["transport"]["stderrEmpty"])
        self.assertNotIn("secret", json.dumps(public))

    def test_server_error_is_closed(self):
        with self.assertRaises(catalog.CatalogClientError) as caught:
            catalog.collect_private_catalog(
                command("server_error"), ENVIRONMENT, 3, _popen_factory=fake_popen)
        self.assertEqual(caught.exception.reason_class, "server_error")
        self.assertEqual(str(caught.exception), "server_error")

    def test_protocol_malformed(self):
        for scenario in ("malformed", "wrong_id"):
            with self.subTest(scenario=scenario):
                with self.assertRaises(catalog.CatalogClientError) as caught:
                    catalog.collect_private_catalog(
                        command(scenario), ENVIRONMENT, 3, _popen_factory=fake_popen)
                self.assertEqual(caught.exception.reason_class, "protocol_malformed")

    def test_eof_is_closed(self):
        with self.assertRaises(catalog.CatalogClientError) as caught:
            catalog.collect_private_catalog(
                command("eof"), ENVIRONMENT, 3, _popen_factory=fake_popen)
        self.assertEqual(caught.exception.reason_class, "unexpected_eof")

    def test_total_output_limit(self):
        with mock.patch.object(catalog, "MAX_CAPTURE_BYTES", 1024):
            with self.assertRaises(catalog.CatalogClientError) as caught:
                catalog.collect_private_catalog(
                    command("overflow"), ENVIRONMENT, 3, _popen_factory=fake_popen)
        self.assertEqual(caught.exception.reason_class, "output_limit")

    def test_deadline_reaps_owned_child(self):
        processes = []
        original = subprocess.Popen
        def recording(*args, **kwargs):
            arguments = args[0]
            process = original([arguments[0]] + arguments[4:], **kwargs)
            processes.append(process)
            return process
        with self.assertRaises(catalog.CatalogClientError) as caught:
            catalog.collect_private_catalog(
                command("hang"), ENVIRONMENT, 2.2, _popen_factory=recording)
        self.assertEqual(caught.exception.reason_class, "deadline_exceeded")
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())

    def test_interruption_reaps_and_propagates(self):
        processes = []
        original = subprocess.Popen
        def recording(*args, **kwargs):
            arguments = args[0]
            process = original([arguments[0]] + arguments[4:], **kwargs)
            processes.append(process)
            return process
        with mock.patch.object(catalog._Session, "request", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                catalog.collect_private_catalog(
                    command("hang"), ENVIRONMENT, 3, _popen_factory=recording)
        self.assertEqual(len(processes), 1)
        self.assertIsNotNone(processes[0].poll())

    def test_nonzero_settlement_fails(self):
        with self.assertRaises(catalog.CatalogClientError) as caught:
            catalog.collect_private_catalog(
                command("nonzero"), ENVIRONMENT, 3, _popen_factory=fake_popen)
        self.assertEqual(caught.exception.reason_class, "process_settlement_failed")

    def test_invalid_arguments_never_launch(self):
        for bad in (
            ("not-a-sequence", ENVIRONMENT, 3),
            ([sys.executable, "exec"], ENVIRONMENT, 3),
            (command("ok"), {"BAD": object()}, 3),
            (command("ok"), ENVIRONMENT, 2),
            (command("ok"), ENVIRONMENT, 21),
        ):
            with self.subTest(bad=type(bad[0]).__name__):
                with self.assertRaises(catalog.CatalogClientError) as caught:
                    catalog.collect_private_catalog(*bad)
                self.assertEqual(caught.exception.reason_class, "invalid_arguments")

    def test_malformed_private_projection_fails_closed(self):
        value = catalog.public_projection({"installed": {}, "vertical": {}})
        self.assertFalse(value["observationSucceeded"])
        self.assertEqual(value["reasonClass"], "catalog_shape")
        self.assertTrue(all(flag is False for flag in value["admission"].values()))


def rows(name="private-name", identifier="private-id", marketplace="private-market"):
    return {"marketplaces": [{"name": marketplace, "plugins": [{
        "authPolicy": "ON_INSTALL", "enabled": True, "id": identifier,
        "installPolicy": "AVAILABLE", "installed": True, "name": name,
        "source": {"type": "remote"}, "remotePluginId": "private-backend",
        "version": "2.3", "localVersion": "2.3",
    }]}], "marketplaceLoadErrors": []}


def capture(installed=None, vertical=None):
    return {"installed": rows() if installed is None else installed,
            "vertical": rows() if vertical is None else vertical,
            "transport": {"childReaped": True, "notificationCount": 0,
                          "stderrEmpty": True}}


class Pipe:
    def __init__(self, owner, name, fd):
        self.owner, self.name, self.fd = owner, name, fd
        self.closed = False

    def fileno(self):
        return self.fd

    def close(self):
        self.owner.world.trip("close_" + self.name)
        if self.name == self.owner.close_failure:
            raise OSError("private-close-path")
        self.closed = True
        if self.name == "stdin" and self.owner.normal_exit:
            self.owner.returncode = self.owner.exit_code


class Process:
    def __init__(self, world):
        self.world = world
        self.stdin = Pipe(self, "stdin", 10)
        self.stdout = Pipe(self, "stdout", 11)
        self.stderr = Pipe(self, "stderr", 12)
        self.returncode = None
        self.normal_exit = True
        self.exit_code = 0
        self.close_failure = None
        self.ignore_term = self.ignore_kill = False
        self.signals = []

    @property
    def pid(self):
        raise AssertionError("never use a raw PID")

    def poll(self):
        self.world.trip("poll")
        if all(stream is None or stream.closed
               for stream in (self.stdin, self.stdout, self.stderr)):
            self.world.trip("reap_poll")
        return self.returncode

    def wait(self, *args, **kwargs):
        raise AssertionError("no process.wait, especially no unbounded wait")

    def terminate(self):
        self.world.trip("terminate")
        if self.returncode is not None:
            raise AssertionError("signal after reaping")
        self.signals.append("term")
        if not self.ignore_term:
            self.returncode = -15

    def kill(self):
        self.world.trip("kill")
        if self.returncode is not None:
            raise AssertionError("signal after reaping")
        self.signals.append("kill")
        if not self.ignore_kill:
            self.returncode = -9


class Selector:
    def __init__(self, world):
        self.world, self.keys, self.closed = world, {}, False

    def register(self, stream, events, data):
        self.world.trip("register")
        self.keys[stream.fd] = types.SimpleNamespace(fd=stream.fd, data=data)

    def unregister(self, stream):
        del self.keys[stream.fd]

    def select(self, timeout):
        if timeout <= 0 or timeout > 20:
            raise AssertionError("unbounded selector timeout")
        if self.world.process.stdin.closed:
            self.world.trip("drain")
        self.world.trip("select")
        self.world.timeouts.append(timeout)
        ready = []
        for fd, key in self.keys.items():
            if key.data == "stdin":
                active = not self.world.write_blocked
            else:
                active = bool(self.world.buffers[fd]) or self.world.eof(fd)
            if active:
                ready.append((key, 1))
        self.world.now += min(timeout, 0.001) if ready else timeout
        return ready

    def close(self):
        self.world.trip("selector_close")
        self.keys.clear()
        self.closed = True


class World:
    """Pure in-memory fake process, file descriptors, clock and readiness."""

    def __init__(self):
        self.now = 0.0
        self.process = Process(self)
        self.selector = None
        self.buffers = {11: bytearray(), 12: bytearray()}
        self.written = bytearray()
        self.messages, self.launches, self.timeouts = [], [], []
        self.write_blocked = self.no_response = self.inherited_pipes = False
        self.partial_write = 65536
        self.stderr = self.tail = b""
        self.exit_on_request = None
        self.responses = {0: {}, 1: rows(), 2: rows()}
        self.raw = {}
        self.failures = {}
        self.calls = {}
        self.set_blocking_calls = []

    def trip(self, operation):
        self.calls[operation] = self.calls.get(operation, 0) + 1
        failure = self.failures.get((operation, self.calls[operation]))
        if failure is not None:
            raise failure

    def popen(self, arguments, **kwargs):
        self.trip("spawn")
        self.launches.append((arguments, kwargs))
        return self.process

    def selector_factory(self):
        self.trip("selector")
        self.selector = Selector(self)
        return self.selector

    def blocking(self, fd, blocking):
        self.trip("blocking")
        self.set_blocking_calls.append((fd, blocking))

    def eof(self, fd):
        return self.process.returncode is not None and not self.inherited_pipes

    def read(self, fd, count):
        self.trip("read")
        if count <= 0 or count > 65536:
            raise AssertionError("unbounded read")
        if not self.buffers[fd]:
            if self.eof(fd):
                return b""
            raise BlockingIOError()
        data = bytes(self.buffers[fd][:count])
        del self.buffers[fd][:count]
        return data

    def write(self, fd, data):
        self.trip("write")
        self.assert_fd = fd
        written = min(len(data), self.partial_write)
        self.written.extend(data[:written])
        while b"\n" in self.written:
            line, _, tail = self.written.partition(b"\n")
            self.written = bytearray(tail)
            message = json.loads(line)
            self.messages.append(message)
            if "id" in message and not self.no_response:
                identifier = message["id"]
                response = self.raw.get(identifier, catalog._encode(
                    {"id": identifier, "result": self.responses[identifier]}))
                self.buffers[11].extend(response)
                if identifier == 2:
                    self.buffers[11].extend(self.tail)
                    self.buffers[12].extend(self.stderr)
                if identifier == self.exit_on_request:
                    self.process.returncode = self.process.exit_code
        return written

    def sleep(self, seconds):
        self.trip("sleep")
        if not 0 < seconds <= 0.01:
            raise AssertionError("unbounded settlement sleep")
        self.now += seconds

    @contextlib.contextmanager
    def installed(self):
        with contextlib.ExitStack() as stack:
            for target, name, value in (
                (catalog.selectors, "DefaultSelector", self.selector_factory),
                (catalog.os, "set_blocking", self.blocking),
                (catalog.os, "read", self.read), (catalog.os, "write", self.write),
                (catalog.time, "monotonic", lambda: self.now),
                (catalog.time, "sleep", self.sleep),
                (catalog.os, "killpg", mock.Mock(side_effect=AssertionError("killpg forbidden"))),
                (catalog.subprocess, "Popen", mock.Mock(side_effect=AssertionError("native spawn forbidden"))),
            ):
                stack.enter_context(mock.patch.object(target, name, value))
            yield

    def run(self, seconds=3):
        with self.installed():
            return catalog.collect_private_catalog(command("ok"), ENVIRONMENT,
                                                   seconds, _popen_factory=self.popen)


class PureCatalogTests(unittest.TestCase):
    def assert_failure(self, world, reason, seconds=3):
        with self.assertRaises(catalog.CatalogClientError) as caught:
            world.run(seconds)
        self.assertEqual(caught.exception.reason_class, reason)
        self.assertLessEqual(world.now, seconds + 0.000001)
        return caught.exception

    def closed(self, world):
        self.assertIsNotNone(world.process.returncode)
        for stream in (world.process.stdin, world.process.stdout, world.process.stderr):
            self.assertTrue(stream.closed)
        if world.selector is not None:
            self.assertTrue(world.selector.closed)

    def test_exact_handshake_partial_writes_and_nonblocking_fds(self):
        world = World()
        world.partial_write = 7
        result = world.run()
        self.assertEqual(world.messages, [catalog._INITIALIZE, catalog._INITIALIZED,
                                         catalog._INSTALLED, catalog._VERTICAL])
        self.assertEqual(world.set_blocking_calls, [(10, False), (11, False), (12, False)])
        self.assertEqual(result["installed"], result["vertical"])
        self.assertEqual(world.process.signals, [])
        self.assertEqual(len(world.launches), 1)
        self.assertFalse(world.launches[0][1]["text"])
        self.assertEqual(world.launches[0][1]["bufsize"], 0)
        self.closed(world)

    def test_blocked_write_has_deadline_and_owned_settlement(self):
        world = World()
        world.write_blocked = True
        world.process.normal_exit = False
        self.assert_failure(world, "deadline_exceeded")
        self.assertEqual(world.process.signals, ["term"])
        self.closed(world)

    def test_read_timeout_term_then_kill_still_inside_total_budget(self):
        world = World()
        world.no_response = True
        world.process.normal_exit = False
        world.process.ignore_term = True
        self.assert_failure(world, "deadline_exceeded", 2.2)
        self.assertEqual(world.process.signals, ["term", "kill"])
        self.closed(world)

    def test_nonblocking_read_and_write_interruptions_retry_within_deadline(self):
        for operation, exception in (("read", BlockingIOError()),
                                     ("read", InterruptedError()),
                                     ("write", BlockingIOError()),
                                     ("write", InterruptedError())):
            world = World()
            world.failures[operation, 1] = exception
            self.assertTrue(world.run()["transport"]["childReaped"])
            self.assertLess(world.now, 3)
            self.closed(world)

    def test_eof_before_response_and_partial_line_are_distinct(self):
        for raw, reason in ((b"", "unexpected_eof"),
                            (b'{"id":0', "protocol_malformed")):
            world = World()
            world.raw[0] = raw
            world.exit_on_request = 0
            self.assert_failure(world, reason)
            self.assertEqual(world.process.signals, [])
            self.closed(world)

    def test_broken_pipe_is_write_failure_with_safe_settlement(self):
        world = World()
        world.failures["write", 1] = BrokenPipeError("private pipe")
        self.assert_failure(world, "write_failed")
        self.closed(world)

    def test_unknown_settlement_dominates_protocol_failure_retains_owner(self):
        world = World()
        world.raw[0] = b"private broken json\n"
        world.process.normal_exit = False
        world.process.ignore_term = world.process.ignore_kill = True
        error = self.assert_failure(world, "process_settlement_failed")
        self.assertEqual(error.primary_reason, "protocol_malformed")
        self.assertIs(error.private_owner.process, world.process)
        self.assertEqual(repr(error.private_owner), "<private catalog process owner>")
        self.assertIsNone(world.process.returncode)

    def test_reaped_child_never_signaled_with_inherited_pipe_writer(self):
        world = World()
        world.inherited_pipes = True
        self.assert_failure(world, "process_settlement_failed")
        self.assertEqual(world.process.signals, [])
        self.closed(world)

    def test_setup_failures_after_spawn_settle_all_resources(self):
        for operation, count in (("selector", 1), ("blocking", 1),
                                 ("blocking", 2), ("blocking", 3),
                                 ("register", 1), ("register", 2)):
            with self.subTest(operation=operation, count=count):
                world = World()
                world.failures[operation, count] = OSError("private-init-failure")
                self.assert_failure(world, "protocol_malformed")
                self.closed(world)

    def test_missing_pipe_is_launch_failure_and_other_handles_closed(self):
        world = World()
        world.process.stderr = None
        self.assert_failure(world, "launch_failed")
        self.assertTrue(world.process.stdin.closed)
        self.assertTrue(world.process.stdout.closed)
        self.assertIsNotNone(world.process.returncode)

    def test_keyboard_interrupt_setup_or_write_settles_then_propagates(self):
        for operation in ("selector", "blocking", "register", "write", "select"):
            with self.subTest(operation=operation):
                world = World()
                world.failures[operation, 1] = KeyboardInterrupt()
                with self.assertRaises(KeyboardInterrupt):
                    world.run()
                self.closed(world)

    def test_cleanup_drain_interruptions_propagate_after_successful_settlement(self):
        for interruption in (KeyboardInterrupt(), SystemExit(23)):
            world = World()
            world.failures["drain", 1] = interruption
            with self.assertRaises(type(interruption)) as caught:
                world.run()
            self.assertIs(caught.exception, interruption)
            self.assertFalse(interruption.settlement_failed)
            self.assertIsNone(interruption.private_owner)
            self.assertEqual(world.process.signals, [])
            self.closed(world)

    def test_cleanup_stream_interruptions_keep_other_cleanup_and_owner(self):
        for name in ("stdin", "stdout", "stderr"):
            for interruption in (KeyboardInterrupt(), SystemExit(23)):
                world = World()
                world.failures["close_" + name, 1] = interruption
                with self.assertRaises(type(interruption)) as caught:
                    world.run()
                self.assertIs(caught.exception, interruption)
                self.assertIsNotNone(world.process.returncode)
                self.assertTrue(world.selector.closed)
                if name == "stdin":
                    # Interrupted initial stdin closure is completed by the
                    # unconditional final descriptor cleanup.
                    self.assertFalse(interruption.settlement_failed)
                    self.assertIsNone(interruption.private_owner)
                    self.closed(world)
                else:
                    self.assertTrue(interruption.settlement_failed)
                    self.assertIs(interruption.private_owner.process, world.process)
                    self.assertFalse(getattr(world.process, name).closed)
                    other = "stderr" if name == "stdout" else "stdout"
                    self.assertTrue(getattr(world.process, other).closed)
                self.assertLessEqual(world.now, 3)

    def test_cleanup_selector_interruptions_propagate_with_retained_owner(self):
        for interruption in (KeyboardInterrupt(), SystemExit(23)):
            world = World()
            world.failures["selector_close", 1] = interruption
            with self.assertRaises(type(interruption)) as caught:
                world.run()
            self.assertIs(caught.exception, interruption)
            self.assertTrue(interruption.settlement_failed)
            self.assertIs(interruption.private_owner.selector, world.selector)
            self.assertFalse(world.selector.closed)
            self.assertIsNotNone(world.process.returncode)
            self.assertTrue(all(stream.closed for stream in (
                world.process.stdin, world.process.stdout, world.process.stderr)))

    def test_cleanup_reaping_interruptions_preserve_deadline_and_ownership(self):
        for operation in ("reap_poll", "terminate", "sleep", "kill"):
            for interruption in (KeyboardInterrupt(), SystemExit(23)):
                world = World()
                world.process.normal_exit = False
                world.process.ignore_term = operation in ("sleep", "kill")
                world.failures[operation, 1] = interruption
                with self.assertRaises(type(interruption)) as caught:
                    world.run()
                self.assertIs(caught.exception, interruption)
                if operation == "kill":
                    # The one kill attempt was interrupted before delivery;
                    # do not pretend that the still-running child was reaped.
                    self.assertTrue(interruption.settlement_failed)
                    self.assertIs(interruption.private_owner.process, world.process)
                    self.assertIsNone(world.process.returncode)
                else:
                    self.assertFalse(interruption.settlement_failed)
                    self.assertIsNone(interruption.private_owner)
                    self.closed(world)
                self.assertLessEqual(world.now, 3)

    def test_final_reap_observation_interrupt_is_explicitly_unresolved(self):
        for interruption in (KeyboardInterrupt(), SystemExit(23)):
            world = World()
            world.failures["reap_poll", 3] = interruption
            with self.assertRaises(type(interruption)) as caught:
                world.run()
            self.assertIs(caught.exception, interruption)
            self.assertTrue(interruption.settlement_failed)
            self.assertIs(interruption.private_owner.process, world.process)
            self.assertEqual(world.process.signals, [])

    def test_first_interruption_survives_later_cleanup_interruption(self):
        for operation in ("drain", "write"):
            world = World()
            first = KeyboardInterrupt()
            world.failures[operation, 1] = first
            world.failures["close_stdout", 1] = SystemExit(23)
            with self.assertRaises(KeyboardInterrupt) as caught:
                world.run()
            self.assertIs(caught.exception, first)
            self.assertTrue(first.settlement_failed)
            self.assertIs(first.private_owner.process, world.process)
            self.assertTrue(world.process.stderr.closed)

    def test_request_interrupt_with_unreapable_child_preserves_private_owner(self):
        world = World()
        first = KeyboardInterrupt()
        world.failures["write", 1] = first
        world.process.normal_exit = False
        world.process.ignore_term = world.process.ignore_kill = True
        with self.assertRaises(KeyboardInterrupt) as caught:
            world.run()
        self.assertIs(caught.exception, first)
        self.assertTrue(first.settlement_failed)
        self.assertIs(first.private_owner.process, world.process)
        self.assertIsNone(world.process.returncode)
        self.assertLessEqual(world.now, 3)

    def test_close_failure_is_not_hidden_and_retains_private_owner(self):
        world = World()
        world.process.close_failure = "stdout"
        error = self.assert_failure(world, "process_settlement_failed")
        self.assertIs(error.private_owner.process, world.process)
        self.assertFalse(world.process.stdout.closed)

    def test_shared_stdout_stderr_total_rejects_sum_not_individual_channels(self):
        world = World()
        world.stderr = b"x" * 500
        # stdout alone < 1000, stderr alone < 1000, together > 1000.
        with mock.patch.object(catalog, "MAX_CAPTURE_BYTES", 1000):
            self.assert_failure(world, "output_limit")
        self.closed(world)

    def test_stderr_overflow_is_prompt_and_only_remaining_plus_one_is_read(self):
        world = World()
        world.buffers[12].extend(b"x" * 10000)
        world.no_response = True
        with mock.patch.object(catalog, "MAX_CAPTURE_BYTES", 100):
            self.assert_failure(world, "output_limit")
        self.assertEqual(len(world.buffers[12]), 9899)
        self.assertLess(world.now, 0.1)
        self.closed(world)

    def test_output_exact_shared_limit_is_positive_control(self):
        world = World()
        world.stderr = b"x" * 13
        limit = sum(len(catalog._encode({"id": key, "result": result}))
                    for key, result in world.responses.items()) + len(world.stderr)
        with mock.patch.object(catalog, "MAX_CAPTURE_BYTES", limit):
            self.assertTrue(world.run()["transport"]["childReaped"])
        self.closed(world)

    def test_line_limit_applies_with_and_without_newline(self):
        for suffix in (b"", b"\n"):
            world = World()
            world.raw[0] = b"x" * 100 + suffix
            with mock.patch.object(catalog, "MAX_RPC_LINE_BYTES", 99):
                self.assert_failure(world, "output_limit")
            self.closed(world)

    def test_catalog_line_above_old_one_mib_floor_within_shared_cap_passes(self):
        world = World()
        plugin = world.responses[1]["marketplaces"][0]["plugins"][0]
        plugin["interface"] = {"description": "x" * (1024 * 1024 + 1)}
        self.assertEqual(catalog.MAX_RPC_LINE_BYTES, catalog.MAX_CAPTURE_BYTES)
        public = catalog.public_projection(world.run())
        self.assertTrue(public["observationSucceeded"])
        self.assertEqual(public["installed"]["pluginCount"], 1)
        self.closed(world)

    def test_notification_limit_without_queue_or_unbounded_capture(self):
        notification = catalog._encode({"method": "event", "params": {}})
        world = World()
        world.raw[0] = notification * 4 + catalog._encode({"id": 0, "result": {}})
        with mock.patch.object(catalog, "MAX_NOTIFICATIONS", 3):
            self.assert_failure(world, "output_limit")
        self.closed(world)

    def test_strict_response_ids_reject_bool_float_and_string(self):
        for identifier in (False, 0.0, "0", True, 99):
            with self.subTest(identifier=identifier):
                world = World()
                world.raw[0] = catalog._encode({"id": identifier, "result": {}})
                self.assert_failure(world, "protocol_malformed")
                self.closed(world)

    def test_duplicate_json_keys_rejected_at_every_depth(self):
        for raw in (b'{"id":99,"id":0,"result":{}}\n',
                    b'{"id":0,"result":{},"result":{}}\n',
                    b'{"id":0,"result":{"private":1,"private":2}}\n'):
            world = World()
            world.raw[0] = raw
            self.assert_failure(world, "protocol_malformed")
            self.closed(world)

    def test_boolean_and_float_aliases_for_later_request_ids(self):
        for request_id, response_id in ((1, True), (1, 1.0), (2, 2.0)):
            world = World()
            world.raw[request_id] = catalog._encode({"id": response_id, "result": rows()})
            self.assert_failure(world, "protocol_malformed")
            self.closed(world)

    def test_invalid_json_utf8_and_constants_redact_formatted_traceback(self):
        for raw in (b"private-json-payload\n", b"\xffprivate-secret\n",
                    b'{"id":0,"result":{"private":NaN}}\n'):
            world = World()
            world.raw[0] = raw
            try:
                world.run()
            except catalog.CatalogClientError:
                formatted = traceback.format_exc()
            else:
                self.fail("expected error")
            self.assertNotIn("private-json-payload", formatted)
            self.assertNotIn("private-secret", formatted)
            self.assertNotIn("JSONDecodeError", formatted)
            self.assertNotIn("UnicodeDecodeError", formatted)

    def test_oserror_filename_and_spawn_message_never_in_traceback(self):
        for operation in ("spawn", "write", "read", "selector"):
            world = World()
            world.failures[operation, 1] = OSError(5, "private-os-message", "/private/secret")
            try:
                world.run()
            except catalog.CatalogClientError:
                formatted = traceback.format_exc()
            else:
                self.fail("expected error")
            self.assertNotIn("private-os-message", formatted)
            self.assertNotIn("/private/secret", formatted)

    def test_server_error_message_is_never_returned(self):
        world = World()
        world.raw[0] = catalog._encode({"id": 0, "error": {"message": "secret"}})
        error = self.assert_failure(world, "server_error")
        self.assertEqual(str(error), "server_error")
        self.assertIsNone(error.__context__)
        self.closed(world)

    def test_extra_notification_metadata_is_inert_and_not_captured(self):
        for metadata in (None, False, 3, "private-envelope", [1, 2],
                         {"id": 99, "method": "turn/start", "params": {"private": True}}):
            world = World()
            notification = {"method": "account/updated", "params": {},
                            "futureEnvelopeMetadata": metadata, "anotherUnknownField": []}
            world.raw[0] = (catalog._encode(notification)
                            + catalog._encode({"id": 0, "result": {}}))
            private = world.run()
            public = catalog.public_projection(private)
            self.assertTrue(public["observationSucceeded"])
            self.assertEqual(public["transport"]["notificationCount"], 1)
            self.assertNotIn("futureEnvelopeMetadata", json.dumps(private))
            self.assertNotIn("private-envelope", json.dumps(public))
            self.assertEqual(world.messages, [catalog._INITIALIZE, catalog._INITIALIZED,
                                             catalog._INSTALLED, catalog._VERTICAL])
            self.closed(world)

    def test_extra_response_metadata_is_inert_at_each_fixed_rpc(self):
        world = World()
        for identifier in (0, 1, 2):
            world.raw[identifier] = catalog._encode({
                "id": identifier, "result": world.responses[identifier],
                "futureEnvelopeMetadata": {"private": "value", "result": "not-a-result"},
            })
        private = world.run()
        self.assertEqual(private["installed"], rows())
        self.assertEqual(private["vertical"], rows())
        self.assertNotIn("futureEnvelopeMetadata", json.dumps(private))
        public = catalog.public_projection(private)
        self.assertTrue(public["observationSucceeded"])
        self.assertTrue(all(flag is False for flag in public["admission"].values()))
        self.closed(world)

    def test_extra_error_metadata_preserves_closed_server_error(self):
        world = World()
        world.raw[0] = catalog._encode({
            "id": 0, "error": {"code": 7, "message": "private-error"},
            "futureEnvelopeMetadata": {"private": "value"},
        })
        error = self.assert_failure(world, "server_error")
        self.assertEqual(str(error), "server_error")
        self.assertIsNone(error.__context__)
        self.closed(world)

    def test_reserved_envelope_keys_cannot_mix_message_kinds(self):
        kinds = (
            ({"method": "event", "params": {}}, ("id", "result", "error", "jsonrpc")),
            ({"id": 0, "result": {}}, ("method", "params", "error", "jsonrpc")),
            ({"id": 0, "error": {}}, ("method", "params", "result", "jsonrpc")),
        )
        for base, conflicts in kinds:
            for field in conflicts:
                with self.subTest(kind=tuple(base), conflict=field):
                    message = dict(base, futureEnvelopeMetadata={"ignored": True})
                    message[field] = (0 if field == "id" else
                                      "2.0" if field == "jsonrpc" else None)
                    world = World()
                    world.raw[0] = catalog._encode(message)
                    self.assert_failure(world, "protocol_malformed")
                    self.closed(world)

    def test_server_requests_with_metadata_are_not_answered_or_executed(self):
        for method in ("attestation/generate", "account/chatgptAuthTokens/refresh",
                       "item/tool/call"):
            world = World()
            world.raw[0] = catalog._encode({"id": 0, "method": method, "params": {},
                                           "futureEnvelopeMetadata": True})
            self.assert_failure(world, "protocol_malformed")
            self.assertEqual(world.messages, [catalog._INITIALIZE])
            self.closed(world)

    def test_metadata_cannot_hide_missing_or_invalid_core_fields(self):
        for core in ({"method": "event"}, {"method": "event", "params": None},
                     {"method": "event", "params": []}, {"method": "", "params": {}},
                     {"method": False, "params": {}}, {"id": 0}, {"result": {}},
                     {"id": False, "result": {}}, {"id": "0", "result": {}},
                     {"id": 0.0, "result": {}}):
            world = World()
            world.raw[0] = catalog._encode(dict(core, futureEnvelopeMetadata="ignored"))
            self.assert_failure(world, "protocol_malformed")
            self.closed(world)

    def test_duplicate_keys_in_extra_metadata_still_fail_closed(self):
        for raw in (
            b'{"id":0,"result":{},"meta":1,"meta":2}\n',
            b'{"id":0,"result":{},"meta":{"private":1,"private":2}}\n',
            b'{"method":"event","params":{},"meta":1,"meta":2}\n',
        ):
            world = World()
            world.raw[0] = raw
            self.assert_failure(world, "protocol_malformed")
            self.closed(world)

    def test_extra_metadata_still_consumes_shared_capture_budget(self):
        world = World()
        world.raw[0] = catalog._encode({"id": 0, "result": {}, "meta": "x" * 201})
        with mock.patch.object(catalog, "MAX_CAPTURE_BYTES", 200):
            self.assert_failure(world, "output_limit")
        self.closed(world)

    def test_extra_metadata_does_not_admit_duplicate_or_late_responses(self):
        for phase, late_id in ((0, 0), (2, 2), (2, 0)):
            world = World()
            response = {"id": phase, "result": world.responses[phase], "meta": {}}
            late = {"id": late_id, "result": {}, "otherMetadata": []}
            world.raw[phase] = catalog._encode(response) + catalog._encode(late)
            self.assert_failure(world, "protocol_malformed")
            self.closed(world)

    def test_extra_metadata_preserves_json_parser_depth_and_constant_rejections(self):
        for metadata in (b"[" * 2000 + b"0" + b"]" * 2000, b"Infinity"):
            world = World()
            world.raw[0] = b'{"id":0,"result":{},"meta":' + metadata + b'}\n'
            self.assert_failure(world, "protocol_malformed")
            self.closed(world)

    def test_duplicate_response_and_response_after_final_are_rejected(self):
        for phase in (0, 2):
            world = World()
            world.raw[phase] = catalog._encode({"id": phase, "result": world.responses[phase]}) * 2
            self.assert_failure(world, "protocol_malformed")
            self.closed(world)

    def test_stderr_notification_success_and_safe_projection(self):
        world = World()
        world.stderr = b"private-stderr-value"
        world.tail = catalog._encode({"method": "account/updated", "params": {"secret": "value"}})
        public = catalog.public_projection(world.run())
        self.assertTrue(public["observationSucceeded"])
        self.assertFalse(public["transport"]["stderrEmpty"])
        self.assertEqual(public["transport"]["notificationCount"], 1)
        self.assertEqual(public["catalogIdentityIntersectionCount"], 1)
        self.assertTrue(all(flag is False for flag in public["admission"].values()))
        self.assertNotIn("private-", json.dumps(public))
        self.closed(world)

    def test_nonzero_exit_is_settlement_failure_without_signals(self):
        world = World()
        world.process.exit_code = 7
        self.assert_failure(world, "process_settlement_failed")
        self.assertEqual(world.process.signals, [])
        self.closed(world)

    def test_duplicate_identity_is_marketplace_and_id_not_name(self):
        value = rows()
        value["marketplaces"][0]["plugins"] *= 2
        public = catalog.public_projection(capture(value))
        self.assertFalse(public["installed"]["uniquePluginIdentities"])
        self.assertEqual(public["catalogIdentityIntersectionCount"], 1)
        self.assertTrue(catalog.public_projection(capture())["installed"]["uniquePluginIdentities"])

    def test_contradictory_identity_names_within_and_between_catalogs_fail(self):
        conflicting = rows()
        second = copy.deepcopy(conflicting["marketplaces"][0]["plugins"][0])
        second["name"] = "different-name"
        conflicting["marketplaces"][0]["plugins"].append(second)
        for private in (capture(conflicting), capture(vertical=rows(name="different-name"))):
            public = catalog.public_projection(private)
            self.assertFalse(public["observationSucceeded"])
            self.assertEqual(public["reasonClass"], "catalog_shape")

    def test_same_plugin_id_in_distinct_marketplaces_is_distinct(self):
        private = capture(vertical=rows(marketplace="different-market"))
        public = catalog.public_projection(private)
        self.assertTrue(public["observationSucceeded"])
        self.assertEqual(public["catalogIdentityIntersectionCount"], 0)

    def test_invalid_arguments_never_launch(self):
        for command_value, environment, timeout in (
            ("not-an-argv", {}, 3), (["codex", "exec"], {}, 3),
            (command("ok"), {"X": object()}, 3),
            (command("ok"), {"X": "value\0"}, 3),
            (command("ok"), {}, float("nan")),
            (command("ok"), {}, 2), (command("ok"), {}, 21),
        ):
            factory = mock.Mock(side_effect=AssertionError("must not spawn"))
            with self.assertRaises(catalog.CatalogClientError) as caught:
                catalog.collect_private_catalog(command_value, environment, timeout,
                                                _popen_factory=factory)
            self.assertEqual(caught.exception.reason_class, "invalid_arguments")
            factory.assert_not_called()

    def test_public_failure_and_invalid_private_capture_remain_closed(self):
        for malformed in ({}, {"private-path": "secret"}, None):
            public = catalog.public_projection(malformed)
            self.assertFalse(public["observationSucceeded"])
            self.assertEqual(public["reasonClass"], "catalog_shape")
        for reason in ([], {}, "secret", None, "ok"):
            public = catalog.public_failure(reason)
            self.assertEqual(public["reasonClass"], "protocol_malformed")
            self.assertTrue(all(flag is False for flag in public["admission"].values()))


if __name__ == "__main__":
    unittest.main()
