"""Owned-thread/socket lifecycle with pure cooperative fakes; no native IO."""

from contextlib import ExitStack
import dis
from pathlib import Path
import socket
import sys
import threading
import traceback
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib import phase5_loopback_probe as p


GET = b"GET /phase5 HTTP/1.1\r\nHost: 127.0.0.1:43210\r\nUser-Agent: curl/test\r\nAccept: */*\r\n\r\n"


class Timeout(Exception):
    pass


class Connection:
    def __init__(self, world, chunks=None):
        self.world, self.chunks = world, list(chunks if chunks is not None else [GET])
        self.timeouts, self.sent, self.sends, self.recv_sizes = [], b"", [], []
        self.close_count, self.close_error, self.timeout_error = 0, None, None

    def settimeout(self, value):
        self.timeouts.append(value)
        if self.timeout_error is not None:
            raise self.timeout_error

    def recv(self, size):
        self.recv_sizes.append(size)
        self.world.time += self.world.io_tick
        result = self.chunks.pop(0) if self.chunks else b""
        if isinstance(result, BaseException):
            raise result
        return result

    def send(self, data):
        self.world.time += self.world.io_tick
        result = self.sends.pop(0) if self.sends else len(data)
        if isinstance(result, BaseException):
            raise result
        if type(result) is int and 0 < result <= len(data):
            self.sent += data[:result]
        return result

    def close(self):
        self.close_count += 1
        if self.close_error is not None:
            raise self.close_error


class Listener:
    def __init__(self, world):
        self.world, self.address, self.fd = world, ("127.0.0.1", 43210), 17
        self.calls, self.pending, self.close_count, self.errors = [], [], 0, {}

    def operation(self, name, value=None):
        self.calls.append((name, value))
        if name in self.errors:
            raise self.errors[name]

    def settimeout(self, value): self.operation("timeout", value)
    def bind(self, address): self.operation("bind", address)
    def listen(self, backlog): self.operation("listen", backlog)
    def getsockname(self):
        self.operation("address")
        return self.address
    def fileno(self):
        self.operation("fileno")
        return self.fd

    def accept(self):
        self.operation("accept")
        if not self.pending:
            self.world.owner._stop_requested = True  # Cooperative external stop schedule.
            raise Timeout()
        item = self.pending.pop(0)
        if callable(item):
            item()
            raise Timeout()
        if isinstance(item, BaseException):
            raise item
        return item if type(item) is tuple else (item, ("127.0.0.1", 50000))

    def close(self):
        self.close_count += 1
        if self.world.thread is not None:
            assert not self.world.thread.alive, "listener closed under live worker"
        self.operation("close")


class Thread:
    def __init__(self, world, target, daemon):
        self.world, self.target, self.daemon = world, target, daemon
        self.alive, self.start_count, self.joins = False, 0, []
        self.start_error = self.join_error = self.alive_error = None
        self.launch_before_error, self.stuck = False, False

    def start(self):
        self.start_count += 1
        if self.start_error is not None:
            self.alive = self.launch_before_error
            raise self.start_error
        self.alive = True

    def is_alive(self):
        if self.alive_error is not None:
            raise self.alive_error
        return self.alive

    def run(self):
        try:
            self.target()
        finally:
            self.alive = False

    def join(self, timeout):
        self.joins.append(timeout)
        if self.alive and not self.stuck:
            self.run()
        if self.join_error is not None:
            raise self.join_error


class World:
    AF_INET, SOCK_STREAM, timeout = 2, 1, Timeout
    def __init__(self):
        self.time, self.io_tick, self.thread = 0.0, 0.001, None
        self.listener, self.socket_calls = Listener(self), []
        self.socket_error = self.factory_error = self.configure_thread = None
        self.owner = p.LoopbackProbe(socket_api=self, thread_factory=self.make_thread,
                                     clock=lambda: self.time)

    def socket(self, family, kind):
        self.socket_calls.append((family, kind))
        if self.socket_error is not None:
            raise self.socket_error
        return self.listener

    def make_thread(self, *, target, daemon):
        if self.factory_error is not None:
            raise self.factory_error
        self.thread = Thread(self, target, daemon)
        if self.configure_thread is not None:
            self.configure_thread(self.thread)
        return self.thread


class LoopbackTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(socket, "socket", side_effect=AssertionError("native socket forbidden")))
        stack.enter_context(patch.object(threading, "Thread", side_effect=AssertionError("native thread forbidden")))
        self.w = World()

    def rejects(self, function, error_type=p.ProbeError):
        with self.assertRaises(error_type) as caught:
            function()
        self.assertIs(caught.exception.private_owner, self.w.owner)
        return caught.exception

    def test_constructor_has_no_native_effects_and_fixed_loopback_start(self):
        self.assertEqual(self.w.socket_calls, [])
        self.assertEqual(self.w.listener.calls, [])
        self.assertIsNone(self.w.thread)
        self.assertEqual(self.w.owner.start(), 43210)
        self.assertEqual(self.w.socket_calls, [(2, 1)])
        self.assertIn(("bind", ("127.0.0.1", 0)), self.w.listener.calls)
        self.assertIn(("listen", 1), self.w.listener.calls)
        self.assertIn(("timeout", 0.1), self.w.listener.calls)
        self.assertIs(self.w.thread.daemon, False)
        self.assertEqual(self.w.owner.health(), 0)
        self.assertTrue(self.w.owner.stop())
        self.assertTrue(self.w.owner.stop())
        self.assertEqual(self.w.thread.joins, [2.0])
        self.assertEqual(self.w.listener.close_count, 1)
        self.assertTrue(self.w.owner.settled)

    def test_connected_worker_positive_denied_silence_positive_counter_sequence(self):
        first, second, counts = Connection(self.w), Connection(self.w), []
        first.chunks = [GET[:9], GET[9:]]
        first.sends = [5, 9]
        def observe(): counts.append(self.w.owner.health())
        self.w.listener.pending = [first, observe, Timeout(), observe, second, observe]
        self.w.owner.start()
        self.w.thread.run()
        self.assertEqual(counts, [1, 1, 2])
        self.assertEqual(first.sent, p.RESPONSE)
        self.assertEqual(second.sent, p.RESPONSE)
        self.assertEqual(len(p.BODY), 16)
        self.assertEqual(p.RESPONSE.split(b"\r\n\r\n")[1], b"phase5-loopback\n")
        self.assertTrue(self.w.owner.stop())
        self.assertEqual([first.close_count, second.close_count, self.w.listener.close_count], [1, 1, 1])
        self.assertTrue(all(0 < value <= 0.1 for value in first.timeouts + second.timeouts))

    def test_health_rejects_dead_thread_address_and_descriptor_drift(self):
        for change in (lambda w: setattr(w.thread, "alive", False),
                       lambda w: setattr(w.listener, "address", ("127.0.0.1", 43211)),
                       lambda w: setattr(w.listener, "address", ("0.0.0.0", 43210)),
                       lambda w: setattr(w.listener, "fd", 18)):
            self.w = World()
            self.w.owner.start()
            change(self.w)
            self.rejects(self.w.owner.health)

    def test_invalid_bind_identity_is_rejected_before_thread_creation(self):
        for address in (("0.0.0.0", 43210), ("::1", 43210), ("127.0.0.1", True),
                        ("127.0.0.1", 0), ("127.0.0.1", 65536)):
            self.w = World()
            self.w.listener.address = address
            self.rejects(self.w.owner.start)
            self.assertIsNone(self.w.thread)
            self.rejects(self.w.owner.stop)
            self.assertTrue(self.w.owner.settled)
            self.assertEqual(self.w.listener.close_count, 1)

    def test_partial_setup_failures_leave_owner_for_one_explicit_close(self):
        for stage in ("timeout", "bind", "address", "fileno", "listen", "thread"):
            self.w = World()
            original = OSError("private setup value")
            if stage == "thread": self.w.factory_error = original
            else: self.w.listener.errors[stage] = original
            self.rejects(self.w.owner.start)
            self.assertEqual(self.w.listener.close_count, 0)
            self.rejects(self.w.owner.stop)
            self.rejects(self.w.owner.stop)
            self.assertIs(self.w.owner.private_error, original)
            self.assertEqual(self.w.listener.close_count, 1)
            self.assertTrue(self.w.owner.settled)

    def test_socket_acquisition_interruption_without_handle_never_claims_closed(self):
        for error in (OSError("private acquisition"), KeyboardInterrupt(), SystemExit(19)):
            self.w = World()
            self.w.socket_error = error
            kind = type(error) if isinstance(error, (KeyboardInterrupt, SystemExit)) else p.ProbeError
            raised = self.rejects(self.w.owner.start, kind)
            if kind is not p.ProbeError: self.assertIs(raised, error)
            raised = self.rejects(self.w.owner.stop, kind)
            self.assertTrue(raised.settlement_failed)
            self.assertFalse(self.w.owner.settled)
            self.assertEqual(self.w.listener.close_count, 0)

    def test_unknown_thread_start_without_alive_or_finished_proof_retains_listener(self):
        for error in (OSError("private start"), KeyboardInterrupt(), SystemExit(20)):
            self.w = World()
            self.w.configure_thread = lambda thread: setattr(thread, "start_error", error)
            kind = type(error) if isinstance(error, (KeyboardInterrupt, SystemExit)) else p.ProbeError
            self.rejects(self.w.owner.start, kind)
            raised = self.rejects(self.w.owner.stop, kind)
            self.assertTrue(raised.settlement_failed)
            self.assertFalse(self.w.owner.settled)
            self.assertEqual(self.w.listener.close_count, 0)
            self.assertEqual(self.w.thread.joins, [])
            self.assertEqual(self.w.thread.start_count, 1)

    def test_interrupted_started_thread_is_joined_but_original_interrupt_survives(self):
        for error in (KeyboardInterrupt(), SystemExit(21)):
            self.w = World()
            def configure(thread):
                thread.start_error, thread.launch_before_error = error, True
            self.w.configure_thread = configure
            self.assertIs(self.rejects(self.w.owner.start, type(error)), error)
            self.assertIs(self.rejects(self.w.owner.stop, type(error)), error)
            self.assertEqual(self.w.thread.joins, [2.0])
            self.assertEqual(self.w.listener.close_count, 1)
            self.assertTrue(self.w.owner.settled)
            self.assertFalse(error.settlement_failed)

    def test_live_thread_after_bounded_join_does_not_close_listener(self):
        self.w.owner.start()
        self.w.thread.stuck = True
        raised = self.rejects(self.w.owner.stop)
        self.assertTrue(raised.settlement_failed)
        self.assertEqual(self.w.thread.joins, [2.0])
        self.assertEqual(self.w.listener.close_count, 0)
        self.w.thread.stuck = False  # Explicit root-directed later settlement, no restart.
        raised = self.rejects(self.w.owner.stop)
        self.assertFalse(raised.settlement_failed)
        self.assertEqual(self.w.listener.close_count, 1)

    def test_join_interrupt_keeps_owner_and_first_interrupt_after_later_close_failure(self):
        for first in (KeyboardInterrupt(), SystemExit(22)):
            self.w = World()
            self.w.owner.start()
            self.w.thread.join_error = first
            self.assertIs(self.rejects(self.w.owner.stop, type(first)), first)
            self.assertEqual(self.w.listener.close_count, 0)
            self.w.thread.join_error = None
            self.w.listener.errors["close"] = SystemExit(99)
            self.assertIs(self.rejects(self.w.owner.stop, type(first)), first)
            self.assertIs(self.rejects(self.w.owner.stop, type(first)), first)
            self.assertEqual(self.w.listener.close_count, 1)
            self.assertTrue(first.settlement_failed)

    def test_malformed_wrong_method_path_body_and_oversized_requests_fail_privately(self):
        for request in (b"", b"GET /elsewhere HTTP/1.1\r\n\r\n", b"POST /phase5 HTTP/1.1\r\n\r\n",
                        b"GET /phase5 HTTP/1.1\r\nBad\r\n\r\n", GET + b"body", GET.replace(b"Host:", b"\x00Host:"),
                        GET.replace(b"Accept: */*", b"Content-Length: 1"),
                        GET.replace(b"Accept: */*", b"Transfer-Encoding: chunked"),
                        b"x" * p.MAX_REQUEST_BYTES, b"x" * (p.MAX_REQUEST_BYTES + 1)):
            self.w = World()
            connection = Connection(self.w, [request])
            self.w.listener.pending = [connection]
            self.w.owner.start()
            self.w.thread.run()
            self.assertEqual(self.w.owner._accepted, 0)
            self.assertEqual(connection.sent, b"")
            self.rejects(self.w.owner.stop)
            self.assertEqual(connection.close_count, 1)
            self.assertTrue(self.w.owner.settled)

    def test_slow_partial_request_and_send_failure_cannot_claim_successful_response(self):
        for chunks, sends, count in (([Timeout()] * 10, [], 0), ([GET], [OSError("private send")], 1),
                                    ([GET], [0], 1), ([GET], [True], 1), ([GET], [Timeout()] * 10, 1)):
            self.w = World()
            self.w.io_tick = 0.2
            connection = Connection(self.w, chunks)
            connection.sends = sends
            self.w.listener.pending = [connection]
            self.w.owner.start()
            self.w.thread.run()
            self.assertEqual(self.w.owner._accepted, count)
            self.assertNotEqual(connection.sent, p.RESPONSE)
            self.rejects(self.w.owner.stop)
            self.assertEqual(connection.close_count, 1)

    def test_worker_interrupt_precedes_cleanup_interrupt_and_all_known_closes_once(self):
        for first in (KeyboardInterrupt(), SystemExit(23)):
            self.w = World()
            connection = Connection(self.w, [first])
            connection.close_error = SystemExit(90)
            self.w.listener.errors["close"] = KeyboardInterrupt()
            self.w.listener.pending = [connection]
            self.w.owner.start()
            self.w.thread.run()
            self.assertIs(self.w.owner.private_error, first)
            self.assertIs(self.rejects(self.w.owner.stop, type(first)), first)
            self.assertIs(self.rejects(self.w.owner.stop, type(first)), first)
            self.assertEqual((connection.close_count, self.w.listener.close_count), (1, 1))
            self.assertTrue(first.settlement_failed)

    def test_first_ordinary_worker_error_is_preserved_before_ordinary_close_error(self):
        first = OSError("first private")
        connection = Connection(self.w, [first])
        connection.close_error = OSError("later private")
        self.w.listener.pending = [connection]
        self.w.owner.start()
        self.w.thread.run()
        self.rejects(self.w.owner.stop)
        self.assertIs(self.w.owner.private_error, first)

    def test_cleanup_interrupt_supersedes_ordinary_failure_but_not_an_earlier_interrupt(self):
        for first in (OSError("private request"), KeyboardInterrupt(), SystemExit(24)):
            self.w = World()
            later = KeyboardInterrupt()
            connection = Connection(self.w, [first])
            connection.close_error = later
            self.w.listener.pending = [connection]
            self.w.owner.start()
            self.w.thread.run()
            expected = first if isinstance(first, (KeyboardInterrupt, SystemExit)) else later
            self.assertIs(self.rejects(self.w.owner.stop, type(expected)), expected)
            self.assertEqual((connection.close_count, self.w.listener.close_count), (1, 1))

    def check_ordinary_worker_interleavings(self, interruption_factory):
        # Simulate the main producer at EVERY visited worker _record bytecode
        # boundary. This exercises the real worker/cleanup/stop without threads.
        code = p.LoopbackProbe._record.__code__
        failures, exercised = [], 0
        for instruction in dis.get_instructions(code):
            self.w = World()
            ordinary, interruption = OSError("private worker"), interruption_factory()
            connection = Connection(self.w, [ordinary])
            self.w.listener.pending = [connection]
            self.w.owner.start()
            injected = [False]
            def trace(frame, event, argument):
                if frame.f_code is code:
                    if event == "call":
                        frame.f_trace_opcodes = True
                    elif (event == "opcode" and frame.f_lasti == instruction.offset
                          and frame.f_locals.get("error") is ordinary and not injected[0]):
                        injected[0] = True
                        self.w.owner._record(interruption)
                return trace
            previous = sys.gettrace()
            try:
                sys.settrace(trace)
                self.w.thread.run()
            finally:
                sys.settrace(previous)
            if not injected[0]:
                continue
            exercised += 1
            with self.assertRaises(BaseException) as caught:
                self.w.owner.stop()
            if (self.w.owner.private_error is not interruption or
                    caught.exception is not interruption):
                failures.append(instruction.offset)
            self.assertEqual((connection.close_count, self.w.listener.close_count), (1, 1))
            self.assertTrue(self.w.owner.settled)
        self.assertGreater(exercised, 15)
        self.assertEqual(failures, [], "worker publication lost main interruption at bytecode offsets")

    def test_keyboard_interrupt_survives_every_ordinary_worker_publication_interleaving(self):
        self.check_ordinary_worker_interleavings(KeyboardInterrupt)

    def test_system_exit_survives_every_ordinary_worker_publication_interleaving(self):
        self.check_ordinary_worker_interleavings(lambda: SystemExit(31))

    def test_first_published_interruption_survives_full_diagnostic_buffer_and_later_errors(self):
        self.w.owner.start()
        first_ordinary = OSError("first private")
        self.w.owner._record(first_ordinary)
        for _ in range(8):
            self.w.owner._record(OSError("later private"))
        self.assertIs(self.w.owner.private_error, first_ordinary)
        self.assertEqual(len(self.w.owner.private_errors), 8)
        first_interrupt = SystemExit(32)
        self.w.owner._record(first_interrupt)
        self.w.owner._record(KeyboardInterrupt())
        self.w.owner._record(OSError("last private"))
        self.assertIs(self.rejects(self.w.owner.stop, SystemExit), first_interrupt)
        self.assertEqual(len(self.w.owner.private_errors), 8)
        self.assertEqual(set(self.w.owner._first_errors), {"ordinary", "interrupt"})

    def test_stop_liveness_interrupt_retains_listener_until_explicit_recheck(self):
        self.w.owner.start()
        first = SystemExit(25)
        self.w.thread.alive_error = first
        self.assertIs(self.rejects(self.w.owner.stop, SystemExit), first)
        self.assertEqual(self.w.listener.close_count, 0)
        self.assertTrue(first.settlement_failed)
        self.w.thread.alive_error = None
        self.assertIs(self.rejects(self.w.owner.stop, SystemExit), first)
        self.assertEqual(self.w.listener.close_count, 1)
        self.assertFalse(first.settlement_failed)

    def test_stop_during_accepted_request_read_closes_connection_without_response(self):
        connection = Connection(self.w)
        def recv(size):
            self.w.owner._stop_requested = True  # Cooperative root stop while recv waits.
            raise Timeout()
        connection.recv = recv
        self.w.listener.pending = [connection]
        self.w.owner.start()
        self.w.thread.run()
        self.assertTrue(self.w.owner.stop())
        self.assertEqual(self.w.owner._accepted, 0)
        self.assertEqual(connection.sent, b"")
        self.assertEqual((connection.close_count, self.w.listener.close_count), (1, 1))

    def test_accept_interruption_without_connection_handle_is_unsettled_after_thread_exit(self):
        first = KeyboardInterrupt()
        self.w.listener.pending = [first]
        self.w.owner.start()
        self.w.thread.run()
        self.assertIs(self.rejects(self.w.owner.stop, KeyboardInterrupt), first)
        self.assertEqual(self.w.listener.close_count, 1)
        self.assertFalse(self.w.owner.settled)
        self.assertTrue(first.settlement_failed)

    def test_counter_bound_and_duplicate_socket_never_trigger_repeated_close(self):
        for duplicate in (False, True):
            self.w = World()
            connections = [Connection(self.w) for _ in range(4)]
            self.w.listener.pending = [connections[0], connections[0]] if duplicate else list(connections)
            self.w.owner.start()
            self.w.thread.run()
            self.rejects(self.w.owner.stop)
            self.assertEqual(self.w.owner._accepted, 1 if duplicate else 3)
            self.assertEqual(connections[0].close_count, 1)
            self.assertEqual(connections[3].close_count, 0)
            self.assertTrue(self.w.owner.settled)

    def test_start_cannot_retry_and_errors_do_not_format_private_context(self):
        self.w.owner.start()
        self.rejects(self.w.owner.start)
        self.assertEqual(self.w.thread.start_count, 1)
        self.assertEqual(len(self.w.socket_calls), 1)
        self.rejects(self.w.owner.stop)
        self.w = World()
        self.w.listener.errors["bind"] = OSError("PRIVATE-OWNER-TEXT")
        error = self.rejects(self.w.owner.start)
        text = "".join(traceback.format_exception(type(error), error, error.__traceback__))
        self.assertNotIn("PRIVATE-OWNER-TEXT", text)
        self.assertNotIn("43210", repr(self.w.owner))
        self.rejects(self.w.owner.stop)


if __name__ == "__main__":
    unittest.main()
