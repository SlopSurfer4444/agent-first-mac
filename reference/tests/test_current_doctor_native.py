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

    def test_reviewed_target_uses_real_wave_admission_while_source_is_held(self):
        doctor = self.doctor()
        git = NS(_text=Mock(return_value='a'*40), _tree=Mock(return_value={'wave': ('100644', 'b'*40)}))
        doctor.NativeGit.return_value = git
        doctor.current_sources = NS(OWNER_FIRST_WAVE_PATH='wave', reviewed_target=Mock(return_value=True))
        self.invoke(doctor, True, reviewed_target=True)
        guard = Mock(return_value=True)
        self.assertTrue(doctor.run.call_args.kwargs['operation_check']('a'*40, source_guard=guard))
        guard.assert_called_once_with()
        doctor.current_sources.reviewed_target.assert_called_once_with(git, 'a'*40, git._tree.return_value)
        self.assertIsNone(doctor.run.call_args.kwargs['sentinel_check'])

    def test_legacy_reviewed_target_preserves_actual_history_audit(self):
        doctor = self.doctor()
        git = NS(_text=Mock(return_value='a'*40), _tree=Mock(return_value={}))
        doctor.NativeGit.return_value = git
        doctor.current_sources = NS(OWNER_FIRST_WAVE_PATH='wave')
        self.invoke(doctor, True, reviewed_target=True)
        self.assertIs(git.audit_history, True)
        self.assertNotIn('operation_check', doctor.run.call_args.kwargs)

    def test_unreviewed_wave_cannot_be_preparation_target(self):
        doctor = self.doctor()
        git = NS(_text=Mock(return_value='a'*40), _tree=Mock(return_value={'wave': ('100644', 'b'*40)}))
        doctor.NativeGit.return_value = git
        doctor.current_sources = NS(OWNER_FIRST_WAVE_PATH='wave',
            reviewed_target=Mock(side_effect=ValueError('root_target_requires_independent_review')))
        self.invoke(doctor, True, reviewed_target=True)
        with self.assertRaisesRegex(ValueError, 'root_target_requires_independent_review'):
            doctor.run.call_args.kwargs['operation_check']('a'*40, source_guard=lambda: True)

    def test_actual_native_consumer_retains_success_artifact_privately(self):
        doctor = self.doctor()
        captured = []
        self.invoke(doctor, False, capture=captured.append)
        args = doctor.run.call_args.kwargs
        fixture = object.__new__(N.probe.Fixture)
        fixture.handles = []
        fixture.path = '/private/fixture-do-not-publish'
        disposition = N.probe.FixtureDisposition(fixture, 'fixture_invalid',
            child_settled=True, handles_closed=True)
        def observe(**kwargs):
            kwargs['fixture_consumer'](disposition)
            return {'status':'PASS', 'childSettled':True, 'sourceHandlesClosed':True,
                    'fixtureRetired':False}
        with patch.object(N.probe, 'observe', side_effect=observe):
            result = args['sentinel_check'](args['budget'], source_guard=lambda: True)
        self.assertEqual(result['retainedFixtureCount'], 1)
        self.assertEqual(doctor._vendor_fixture_dispositions, [disposition])
        self.assertIs(captured[0]['privateFixtureDispositions'][0].owner, fixture)

    def test_actual_native_failure_preserves_private_disposition(self):
        doctor = self.doctor()
        self.invoke(doctor, False)
        fixture = object.__new__(N.probe.Fixture)
        fixture.handles = []
        error = N.probe.ProbeError('fixture_invalid')
        error.private_fixture_disposition = N.probe.FixtureDisposition(fixture,
            'fixture_invalid', child_settled=True, handles_closed=True)
        with patch.object(N.probe, 'observe', side_effect=error), self.assertRaises(N.probe.ProbeError) as caught:
            doctor.run.call_args.kwargs['sentinel_check'](object(), source_guard=lambda: True)
        self.assertIs(caught.exception, error)
        self.assertEqual(error.retained_fixture_count, 1)
        self.assertIs(doctor._vendor_fixture_dispositions[0].owner, fixture)

    def test_retirement_uses_held_accepted_git_only_callback_never_vendor_gate(self):
        doctor = self.doctor()
        custody = Mock()
        custody.retire.return_value = {'scope':'disposable-vendor-fixture-custody','retired':True,'slot':2}
        guard = Mock(return_value=True)
        def admitted(d, git_only, **kwargs):
            self.assertIs(d, doctor)
            self.assertIs(git_only, True)
            self.assertTrue(kwargs['operation_check']('a'*40, source_guard=guard))
            return {'verdict':'GIT_ONLY_VALID'}
        with patch.object(N.os, 'getuid', return_value=501), patch.object(N.pwd, 'getpwuid', return_value=NS(pw_dir='/Users/fixture')), \
                patch.object(N.custody_policy, 'Custody') as cls, patch.object(N, 'native', side_effect=admitted), \
                patch.object(N.probe, 'observe') as vendor:
            cls.return_value.__enter__.return_value = custody
            value = N.custody_cli(doctor, 2)
        self.assertTrue(value['retired'])
        custody.retire.assert_called_once_with(2)
        self.assertEqual(guard.call_count, 2)
        vendor.assert_not_called()

    def test_unaccepted_source_cannot_execute_retirement_callback(self):
        doctor = self.doctor()
        with patch.object(N.os, 'getuid', return_value=501), patch.object(N.pwd, 'getpwuid', return_value=NS(pw_dir='/Users/fixture')), \
                patch.object(N, 'native', side_effect=ValueError('source-not-accepted')), \
                patch.object(N.custody_policy, 'Custody') as cls:
            with self.assertRaises(ValueError):
                N.custody_cli(doctor, 2)
            cls.assert_not_called()

    def test_custody_status_is_read_only_and_launches_no_git_or_vendor_gate(self):
        doctor = self.doctor()
        with patch.object(N.os, 'getuid', return_value=501), patch.object(N.pwd, 'getpwuid', return_value=NS(pw_dir='/Users/fixture')), \
                patch.object(N.custody_policy, 'Custody') as cls, patch.object(N, 'native') as gate:
            cls.return_value.__enter__.return_value.status.return_value = {'outstanding':1}
            self.assertEqual(N.custody_cli(doctor), {'outstanding':1})
            self.assertIs(cls.call_args.kwargs['create'], False)
            gate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
