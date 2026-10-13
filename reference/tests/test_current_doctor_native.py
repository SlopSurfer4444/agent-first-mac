"""Injected wiring checks; no native child or filesystem observation."""
from pathlib import Path
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

from lib import current_doctor_native as N


class WiringTests(unittest.TestCase):
    def doctor(self):
        budget = object()
        R = NS(Budget=Mock(return_value=budget), integrations=NS(_path=lambda value: True))
        def require(value):
            if value is not True:
                raise ValueError("required")
        return NS(ROOT=Path("/Users/fixture/AIDev/control"), require=require,
                  D=NS(R=R, process=object()), NativeGit=Mock(return_value=object()), run=Mock(return_value={}))

    def invoke(self, doctor, git_only, **kwargs):
        with patch.object(N.os, "getuid", return_value=501), \
                patch.object(N.pwd, "getpwuid", return_value=NS(pw_dir="/Users/fixture")), \
                patch.object(N.os, "getcwd", return_value=str(doctor.ROOT)):
            return N.native(doctor, git_only, **kwargs)

    def test_git_only_never_installs_a_sentinel_callback(self):
        doctor = self.doctor()
        with patch.object(N.probe, "observe") as observe:
            self.invoke(doctor, True)
        self.assertIsNone(doctor.run.call_args.kwargs["sentinel_check"])
        observe.assert_not_called()
        self.assertNotIn("runtime_check", doctor.run.call_args.kwargs)

    def test_sentinel_gets_same_budget_guard_and_capture(self):
        doctor = self.doctor()
        capture = Mock()
        self.invoke(doctor, False, capture=capture)
        args = doctor.run.call_args.kwargs
        guard = Mock(return_value=True)
        result = {"status": "PASS", "childSettled": True, "sourceHandlesClosed": True}
        with patch.object(N.probe, "observe", return_value=result) as observe:
            self.assertIs(args["sentinel_check"](args["budget"], source_guard=guard), result)
        self.assertIs(observe.call_args.kwargs["source_guard"], guard)
        self.assertIs(observe.call_args.kwargs["budget"], args["budget"])
        capture.assert_called_once_with(result)
        self.assertTrue(args["canonical_main"])

    def test_partial_source_is_retained_before_constructor_failure(self):
        doctor = self.doctor()
        original = KeyboardInterrupt()
        class Source:
            def __init__(self, *args, **kwargs):
                self.fds = []
                raise original
        doctor.D.R.SourceFile = Source
        self.invoke(doctor, True)
        with self.assertRaises(KeyboardInterrupt) as caught:
            doctor.run.call_args.kwargs["source_factory"]("some/source")
        self.assertIs(caught.exception, original)
        self.assertIsInstance(caught.exception.retained_sources[-1], Source)
        self.assertTrue(caught.exception.source_handles_closed)

    def test_own_close_does_not_prove_inherited_owner_closed(self):
        doctor = self.doctor()
        owner = object()
        original = ValueError("constructor")
        original.source_handles_closed = False
        original.retained_sources = (owner,)
        class Source:
            def __init__(self, *args, **kwargs):
                self.fds = []
                raise original
        doctor.D.R.SourceFile = Source
        self.invoke(doctor, True)
        with self.assertRaises(ValueError) as caught:
            doctor.run.call_args.kwargs["source_factory"]("some/source")
        self.assertFalse(caught.exception.source_handles_closed)
        self.assertIn(owner, caught.exception.retained_sources)
        self.assertIn(original, caught.exception.private_errors)


if __name__ == "__main__":
    unittest.main()
