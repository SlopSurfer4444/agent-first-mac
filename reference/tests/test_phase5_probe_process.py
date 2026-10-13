"""Connected catalog._Session over pure fake processes/pipes; no native fixture."""

import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from lib import phase5_probe_process as probe

spec = importlib.util.spec_from_file_location("probe_catalog_fakes", ROOT / "tests/test_phase5_plugin_catalog.py")
fakes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fakes)
catalog = fakes.catalog


class Budget:
    def __init__(self, world, seconds=180):
        self.world, self.end = world, world.now + seconds

    def check(self):
        if self.world.now >= self.end:
            raise probe.ProbeProcessError("deadline_exceeded")

    def command(self, maximum):
        return min(maximum, self.end - self.world.now)


def launch(discovery=False):
    argv = ("/synthetic/codex", "app-server", "--listen", "stdio://") if discovery else (
        "/synthetic/codex", "sandbox", "--", "/bin/cat", "fixture")
    return SimpleNamespace(argv=argv, environment={"HOME": "/synthetic", "LANG": "C"},
                           cwd="/synthetic/fixture")


class ProbeTests(unittest.TestCase):
    def run_probe(self, world, *, discovery=False, value=None, admit=lambda _: True,
                  seconds=180, maximum=8, close=None, read=None):
        value = launch(discovery) if value is None else value
        calls = []
        original_close = catalog._Session.close
        def closing(owner, deadline, failed):
            calls.append((owner, deadline, failed))
            return (original_close if close is None else close)(owner, deadline, failed)
        with world.installed(), patch.object(catalog._Session, "close", closing):
            arguments = dict(admit_launch=admit, catalog=catalog, process_factory=world.popen,
                             clock=lambda: world.now)
            try:
                if discovery:
                    return probe.discovery(value, Budget(world, seconds), **arguments)
                return probe.command(value, Budget(world, seconds), maximum,
                                     read=world.read if read is None else read, **arguments)
            finally:
                self.assertLessEqual(len(calls), 1)
                if world.calls.get("spawn"):
                    self.assertEqual(len(calls), 1)

    def error(self, world, expected, **kwargs):
        with self.assertRaises(probe.ProbeProcessError) as caught:
            self.run_probe(world, **kwargs)
        self.assertEqual(caught.exception.reason_class, expected)
        self.assertNotIn("private", str(caught.exception))
        self.assertNotIn("synthetic", json.dumps(caught.exception.public()))
        return caught.exception

    def test_discovery_exact_order_cwd_and_privacy(self):
        world = fakes.World()
        world.responses = {0: {}, 1: {"data": ["private-hook"]}, 2: {"data": ["private-skill"]}}
        world.partial_write = 7
        result = self.run_probe(world, discovery=True)
        self.assertEqual([row["method"] for row in world.messages],
                         ["initialize", "initialized", "hooks/list", "skills/list"])
        self.assertEqual(world.messages[0]["params"]["capabilities"], {"experimentalApi": True})
        self.assertEqual(world.messages[2]["params"], {"cwds": ["/synthetic/fixture"]})
        self.assertEqual(world.messages[3]["params"], {"cwds": ["/synthetic/fixture"], "forceReload": False})
        argv, kwargs = world.launches[0]
        self.assertEqual(tuple(argv), launch(True).argv)
        self.assertEqual(kwargs["cwd"], launch(True).cwd)
        self.assertEqual(kwargs["env"], launch(True).environment)
        self.assertTrue(kwargs["close_fds"] and kwargs["start_new_session"])
        self.assertFalse(kwargs["text"])
        self.assertEqual(result.hooks, world.responses[1])
        self.assertEqual(result.skills, world.responses[2])
        self.assertTrue(result.public()["childSettled"])
        self.assertNotIn("private-hook", repr(result) + json.dumps(result.public()))
        self.assertNotIn("private-skill", repr(result) + json.dumps(result.public()))
        self.assertEqual(world.process.signals, [])

    def test_command_preserves_binary_channels_and_nonzero(self):
        world = fakes.World()
        world.buffers[11].extend(b"private\xff\x00")
        world.buffers[12].extend(b"denied\xfe")
        world.process.exit_code = 1
        result = self.run_probe(world)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b"private\xff\x00", b"denied\xfe"))
        self.assertFalse(result.public()["exitZero"])
        self.assertNotIn("private", repr(result) + json.dumps(result.public()))
        self.assertEqual(world.messages, [])
        self.assertEqual(world.process.signals, [])

    def test_tuple_environment_and_exact_admission_object(self):
        world, value, seen = fakes.World(), launch(), []
        value.environment = (("HOME", "/synthetic"), ("LANG", "C"))
        def admit(observed):
            seen.append(observed)
            return True
        self.run_probe(world, value=value, admit=admit)
        self.assertEqual(seen, [value])
        self.assertEqual(world.launches[0][1]["env"], dict(value.environment))

    def test_no_explicit_admission_never_spawns(self):
        for answer in (False, None, 1, "yes"):
            world = fakes.World()
            self.error(world, "launch_not_admitted", admit=lambda _: answer)
            self.assertEqual(world.launches, [])

    def test_mutating_admission_cannot_change_spawn(self):
        for field, changed in (("argv", ("/wrong",)), ("cwd", "/wrong"), ("environment", {"BAD": "yes"})):
            world, value = fakes.World(), launch()
            def admit(observed):
                setattr(observed, field, changed)
                return True
            self.error(world, "launch_changed", value=value, admit=admit)
            self.assertEqual(world.launches, [])

    def test_invalid_launch_or_deadline_never_spawns(self):
        for maximum in (True, 0, -1, 181, float("nan"), float("inf")):
            world = fakes.World()
            self.error(world, "invalid_arguments", maximum=maximum)
            self.assertEqual(world.launches, [])
        for maximum in (0.5, 2):
            world = fakes.World()
            self.error(world, "deadline_exceeded", maximum=maximum)
            self.assertEqual(world.launches, [])
        for field, changed in (("argv", ["/bad"]), ("cwd", "/x/../y"),
                               ("environment", (("HOME", "a"), ("HOME", "b")))):
            world, value = fakes.World(), launch()
            setattr(value, field, changed)
            self.error(world, "invalid_arguments", value=value)
            self.assertEqual(world.launches, [])

    def test_discovery_uses_twenty_second_total_budget(self):
        world = fakes.World()
        world.no_response = True
        world.process.normal_exit = False
        world.process.ignore_term = True
        self.error(world, "deadline_exceeded", discovery=True)
        self.assertLessEqual(world.now, 20)
        self.assertEqual(world.process.signals, ["term", "kill"])

    def test_command_timeout_and_inherited_eof_are_not_success(self):
        for inherited in (False, True):
            world = fakes.World()
            world.inherited_pipes = inherited
            world.process.normal_exit = inherited
            self.error(world, "deadline_exceeded", maximum=4)
            self.assertLessEqual(world.now, 4)
            if inherited:
                self.assertEqual(world.process.signals, [])

    def test_eof_without_direct_exit_is_not_success(self):
        world = fakes.World()
        world.process.normal_exit = False
        world.eof = lambda _: True
        self.error(world, "deadline_exceeded", maximum=4)
        self.assertEqual(world.process.signals, ["term"])

    def test_discovery_premature_eof_rejected(self):
        world = fakes.World()
        world.exit_on_request = 0
        world.raw[0] = b""
        self.error(world, "unexpected_eof", discovery=True)

    def test_discovery_nonzero_settlement_not_pass(self):
        world = fakes.World()
        world.process.exit_code = 3
        self.error(world, "process_settlement_failed", discovery=True)

    def test_shared_output_limit_for_both_functions(self):
        world = fakes.World()
        world.buffers[11].extend(b"a" * (probe.MAX_BYTES // 2))
        world.buffers[12].extend(b"b" * (probe.MAX_BYTES // 2 + 1))
        self.error(world, "output_limit")
        world = fakes.World()
        world.responses[1] = {"value": "a" * (probe.MAX_BYTES // 2)}
        world.stderr = b"b" * (probe.MAX_BYTES // 2)
        self.error(world, "output_limit", discovery=True)

    def test_spawn_exception_before_handle_return_is_unknown(self):
        for discovery in (False, True):
            world = fakes.World()
            world.failures["spawn", 1] = OSError("private launch error")
            error = self.error(world, "process_settlement_failed", discovery=discovery)
            self.assertIsNone(error.child_settled)
            self.assertTrue(error.settlement_failed)
            self.assertIsNotNone(error.private_owner)
            self.assertIsNone(error.private_owner.process)

    def test_spawn_interrupt_object_and_unknown_owner_preserved(self):
        for interrupted in (KeyboardInterrupt(), SystemExit(29)):
            world = fakes.World()
            world.failures["spawn", 1] = interrupted
            with self.assertRaises(type(interrupted)) as caught:
                self.run_probe(world)
            self.assertIs(caught.exception, interrupted)
            self.assertTrue(interrupted.settlement_failed)
            self.assertIsNotNone(interrupted.private_owner)

    def test_popen_adapter_return_interrupt_retains_or_settles_bound_child(self):
        for discovery in (False, True):
            for can_settle in (False, True):
                for interrupted in (KeyboardInterrupt(), SystemExit(47)):
                    with self.subTest(discovery=discovery, can_settle=can_settle,
                                      kind=type(interrupted)):
                        world = fakes.World()
                        world.process.normal_exit = can_settle
                        world.process.ignore_term = world.process.ignore_kill = not can_settle
                        hits, owners = [], []
                        def interrupt_return(frame, event, value):
                            if (event == "return" and frame.f_code.co_name == "popen"
                                    and frame.f_globals.get("__name__") == probe.__name__):
                                hits.append(value)
                                owners.append(frame.f_back.f_locals["self"])
                                raise interrupted
                            return interrupt_return
                        previous_trace = sys.gettrace()
                        try:
                            sys.settrace(interrupt_return)
                            with self.assertRaises(type(interrupted)) as caught:
                                self.run_probe(world, discovery=discovery, maximum=4)
                        finally:
                            sys.settrace(previous_trace)
                        self.assertIs(caught.exception, interrupted)
                        self.assertEqual(hits, [world.process])
                        self.assertIs(owners[0].process, world.process)
                        self.assertTrue(all(stream.closed for stream in (
                            world.process.stdin, world.process.stdout, world.process.stderr)))
                        if can_settle:
                            self.assertIsNotNone(world.process.returncode)
                            self.assertTrue(interrupted.child_settled)
                            self.assertFalse(interrupted.settlement_failed)
                            self.assertIsNone(interrupted.private_owner)
                        else:
                            self.assertIsNone(world.process.returncode)
                            self.assertIsNone(interrupted.child_settled)
                            self.assertTrue(interrupted.settlement_failed)
                            self.assertIs(interrupted.private_owner, owners[0])

    def test_postspawn_setup_error_closes_returned_child(self):
        for operation in ("selector", "blocking", "register"):
            world = fakes.World()
            world.failures[operation, 1] = OSError("private setup")
            error = self.error(world, "protocol_malformed")
            self.assertTrue(error.child_settled)
            self.assertIsNone(error.private_owner)
            self.assertIsNotNone(world.process.returncode)

    def test_close_errors_retain_uncertain_owner_and_attempt_other_handles(self):
        for operation in ("close_stdout", "close_stderr", "selector_close"):
            world = fakes.World()
            world.failures[operation, 1] = OSError("private close")
            error = self.error(world, "process_settlement_failed")
            self.assertIs(error.private_owner.process, world.process)
            self.assertGreaterEqual(world.calls.get("selector_close", 0), 1)
            self.assertGreaterEqual(world.calls.get("close_stdout", 0), 1)
            self.assertGreaterEqual(world.calls.get("close_stderr", 0), 1)

    def test_stdin_close_failures_follow_existing_idempotent_owner_contract(self):
        for discovery in (False, True):
            for occurrence in (1, 2):
                for failure in (OSError("private stdin"), KeyboardInterrupt(), SystemExit(39)):
                    with self.subTest(discovery=discovery, occurrence=occurrence, kind=type(failure)):
                        world = fakes.World()
                        world.failures["close_stdin", occurrence] = failure
                        expected = probe.ProbeProcessError if isinstance(failure, Exception) else type(failure)
                        with self.assertRaises(expected) as caught:
                            self.run_probe(world, discovery=discovery)
                        error = caught.exception
                        if not isinstance(failure, Exception):
                            self.assertIs(error, failure)
                        self.assertEqual(error.settlement_failed, occurrence == 2)
                        self.assertEqual(world.calls["close_stdin"], 2)
                        self.assertEqual(world.calls["close_stdout"], 1)
                        self.assertEqual(world.calls["close_stderr"], 1)
                        self.assertEqual(world.calls["selector_close"], 1)

    def test_missing_returned_handle_keeps_spawn_unknown(self):
        world = fakes.World()
        def no_handle(*_args, **_kwargs):
            world.trip("spawn")
            return None
        world.popen = no_handle
        error = self.error(world, "process_settlement_failed")
        self.assertIsNone(error.child_settled)
        self.assertIsNotNone(error.private_owner)

    def test_close_late_after_deadline_is_not_reported_as_success(self):
        world = fakes.World()
        original_close = catalog._Session.close
        def close(owner, deadline, failed):
            outcome = original_close(owner, deadline, failed)
            world.now = deadline + 1
            return outcome
        error = self.error(world, "deadline_exceeded", close=close)
        self.assertTrue(error.child_settled)
        self.assertIsNone(error.private_owner)

    def test_raised_close_is_not_retried_and_keeps_owner(self):
        for failure in (OSError("private close"), KeyboardInterrupt(), SystemExit(71)):
            world = fakes.World()
            def close(owner, deadline, failed):
                raise failure
            with self.assertRaises(probe.ProbeProcessError if isinstance(failure, Exception) else type(failure)) as caught:
                self.run_probe(world, close=close)
            self.assertIsNotNone(caught.exception.private_owner)
            self.assertTrue(caught.exception.settlement_failed)
            if not isinstance(failure, Exception):
                self.assertIs(caught.exception, failure)

    def test_operation_interrupt_wins_over_all_cleanup_errors(self):
        for close_error in (OSError("private close"), KeyboardInterrupt(), SystemExit(19)):
            world = fakes.World()
            original = KeyboardInterrupt()
            world.failures["read", 1] = original
            world.failures["close_stdout", 1] = close_error
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.run_probe(world)
            self.assertIs(caught.exception, original)
            self.assertIsNotNone(original.private_owner)
            self.assertGreaterEqual(world.calls.get("close_stderr", 0), 1)

    def test_first_cleanup_interrupt_wins_after_ordinary_operation_error(self):
        world = fakes.World()
        first = SystemExit(77)
        world.failures["read", 1] = OSError("private read")
        world.failures["close_stdout", 1] = first
        world.failures["close_stderr", 1] = KeyboardInterrupt()
        with self.assertRaises(SystemExit) as caught:
            self.run_probe(world)
        self.assertIs(caught.exception, first)
        self.assertIsNotNone(first.private_owner)
        self.assertEqual(world.calls["selector_close"], 1)

    def test_owner_remembered_interrupt_precedes_later_raised_close_interrupt(self):
        world = fakes.World()
        first, later = SystemExit(31), KeyboardInterrupt()
        def close(owner, deadline, failed):
            owner.interruption = first
            raise later
        with self.assertRaises(SystemExit) as caught:
            self.run_probe(world, close=close)
        self.assertIs(caught.exception, first)

    def test_unsettled_direct_child_retained_after_bounded_attempt(self):
        world = fakes.World()
        world.process.normal_exit = False
        world.process.ignore_term = world.process.ignore_kill = True
        error = self.error(world, "process_settlement_failed", maximum=4)
        self.assertIs(error.private_owner.process, world.process)
        self.assertIsNone(world.process.returncode)
        self.assertLessEqual(world.now, 4)

    def test_nonblocking_read_signals_do_not_lose_data(self):
        for error in (BlockingIOError(), InterruptedError()):
            world = fakes.World()
            world.buffers[11].extend(b"bytes")
            world.failures["read", 1] = error
            self.assertEqual(self.run_probe(world).stdout, b"bytes")

    def test_read_crossing_io_deadline_is_not_success(self):
        world = fakes.World()
        def read(fd, count):
            value = world.read(fd, count)
            world.now = 9
            return value
        self.error(world, "deadline_exceeded", maximum=8, read=read)


if __name__ == "__main__":
    unittest.main()
