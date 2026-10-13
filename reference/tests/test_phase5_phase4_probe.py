"""Root caller + actual helper/P4 over existing pure synthetic world, no native."""
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
from lib import phase5_phase4_probe as B
from lib import phase5_phase4_health as H
from lib import phase5_probe_process as O

spec = importlib.util.spec_from_file_location("component_world", ROOT / "tests/test_phase5_phase4_health.py")
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)


def earliest(first, later):
    return first if isinstance(first, (KeyboardInterrupt, SystemExit)) else later if first is None or isinstance(later, (KeyboardInterrupt, SystemExit)) else first


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.world, self.sources = F.World(), []
        self.io = self.world.io
        self.closes = self.verifications = self.launches = 0
        self.io.verify, self.io.close = self.verify, self.close
        self.command_error = self.close_error = self.source_error = None
        self.output_effect = self.helper_effect = None

    def verify(self):
        self.verifications += 1
        return True

    def close(self):
        self.closes += 1
        if self.close_error:
            raise self.close_error

    def source(self, path):
        if self.source_error:
            raise self.source_error
        value = SimpleNamespace(digest="a" * 64, closed=0, verify=lambda: True)
        def close():
            value.closed += 1
        value.close = close
        self.sources.append(value)
        return value

    def command(self, launch, budget, maximum, **kwargs):
        self.assertTrue(kwargs["admit_launch"](launch))
        self.assertIn(maximum, (8, 20))
        self.launches += 1
        if self.command_error:
            raise self.command_error
        value = self.world.run(list(launch.argv), cwd=launch.cwd, environment=launch.environment)
        result = O.CommandResult(value.returncode, value.stdout.encode(), b"")
        return self.output_effect(result) if self.output_effect else result

    def invoke(self):
        kwargs = dict(R=SimpleNamespace(earliest=earliest, catalog=object()), H=H,
            P4=self.world.P4, O=SimpleNamespace(command=self.command), Observer=lambda **k: self.io,
            home=F.HOME, uid=501, budget=self.world.budget, bindings={F.CONTROL + "/source": "a" * 64},
            source_factory=self.source, process_factory=lambda *a, **k: self.fail("native forbidden"),
            syscalls=object(), path_api=Path, clock=lambda: 0.0, read=lambda *a: self.fail("native forbidden"))
        with patch.object(self.world.P4.subprocess, "Popen", side_effect=AssertionError("native forbidden")):
            if self.helper_effect:
                with patch.object(H, "collect", self.helper_effect):
                    return B.run(**kwargs)
            return B.run(**kwargs)

    def rejected(self):
        with self.assertRaises(B.ProbeError) as caught:
            self.invoke()
        state = caught.exception.outcome
        self.assertEqual(state.public["verdict"], "NEEDS_REVIEW")
        self.assertNotIn(F.HOME, json.dumps(state.public))
        self.assertNotIn(F.TARGET, json.dumps(state.public))
        return state

    def test_actual_helper_and_unmodified_p4_composition(self):
        result = self.invoke()
        self.assertEqual(result["verdict"], "CURRENT_PHASE4_COMPONENT_HEALTH")
        self.assertTrue(result["sourceHandlesClosed"] and result["nativeChildrenSettled"])
        self.assertFalse(result["phase5Accepted"] or result["phase6Allowed"])
        self.assertGreater(self.launches, 15)
        self.assertLess(self.launches, 40)
        self.assertEqual(self.closes, 1)
        self.assertTrue(all(s.closed == 1 for s in self.sources))

    def test_actual_observer_sourcefile_helper_and_p4_connected(self):
        spec = importlib.util.spec_from_file_location(
            "probe_observer_fixture", ROOT / "tests/test_phase5_phase4_observer.py")
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        self.world, fake = fixture.world()
        self.io = self.world.io
        result = self.invoke()
        self.assertEqual(result["verdict"], "CURRENT_PHASE4_COMPONENT_HEALTH")
        self.assertEqual(result["commandCount"], 23)
        self.assertTrue(result["sourceHandlesClosed"] and result["nativeChildrenSettled"])
        self.assertEqual(fake.handles, {})
        self.assertTrue(all(s.closed == 1 for s in self.sources))

    def test_unknown_commands_and_stale_receipt_never_admitted(self):
        for command in (("/usr/bin/sudo", "-n", "/bin/sh"), ("/bin/rm", "x"),
                        (*self.world.P4.GIT, "push"),
                        (*self.world.P4.GIT, "cat-file", "-e", "f" * 40 + "^{commit}"),
                        ("/nix/var/nix/profiles/default/bin/nix-store", "--query", "--hash", "/nix/store/foreign")):
            with self.assertRaises(ValueError):
                B.plan(list(command), H=H, P4=self.world.P4, io=self.io)
        self.assertEqual(self.launches, 0)

    def test_settled_transport_failure_closes_sources(self):
        self.command_error = O.ProbeProcessError("deadline_exceeded")
        state = self.rejected()
        self.assertFalse(state.pending)
        self.assertEqual(self.closes, 1)
        self.assertTrue(all(s.closed == 1 for s in self.sources))

    def test_unknown_transport_failure_keeps_private_owners(self):
        owner = object()
        self.command_error = O.ProbeProcessError("process_settlement_failed", private_owner=owner, child_settled=None)
        state = self.rejected()
        self.assertTrue(state.pending)
        self.assertIs(state.private_owner, owner)
        self.assertIs(state.observer, self.io)
        self.assertEqual(self.launches, 1)
        self.assertEqual(self.closes, 0)
        self.assertTrue(all(s.closed == 0 for s in self.sources))

    def test_original_interrupt_and_owner_retained(self):
        for error in (KeyboardInterrupt(), SystemExit(0)):
            self.setUp()
            owner = object()
            error.private_owner, error.settlement_failed = owner, True
            self.command_error = error
            with self.assertRaises(type(error)) as caught:
                self.invoke()
            self.assertIs(caught.exception, error)
            self.assertIs(error.phase4_probe_outcome.private_owner, owner)
            self.assertEqual(self.closes, 0)

    def test_postcommand_drift_blocks_success_and_closes(self):
        def output(value):
            self.sources[0].verify = lambda: False
            return value
        self.output_effect = output
        state = self.rejected()
        self.assertFalse(state.public["sourceBindingsUnchanged"])
        self.assertEqual(self.closes, 1)

    def test_ambiguous_stream_order_rejected(self):
        self.output_effect = lambda value: O.CommandResult(value.returncode, b"out", b"err")
        self.assertTrue(self.rejected().public["nativeChildrenSettled"])

    def test_malformed_helper_report_not_serialized(self):
        self.helper_effect = lambda **kw: {"private": F.HOME}
        state = self.rejected()
        self.assertIsNone(state.public["componentReport"])

    def test_close_failure_no_success_and_all_sources_attempted(self):
        self.close_error = OSError("private")
        state = self.rejected()
        self.assertFalse(state.public["sourceHandlesClosed"])
        self.assertTrue(all(s.closed == 1 for s in self.sources))

    def test_constructor_failure_no_false_source_or_closure_claim(self):
        self.source_error = OSError("private constructor")
        state = self.rejected()
        self.assertFalse(state.public["sourceBindingsUnchanged"])
        self.assertFalse(state.public["sourceHandlesClosed"])
        self.assertEqual(self.launches, 0)


if __name__ == "__main__":
    unittest.main()
