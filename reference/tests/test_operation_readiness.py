"""Connected source-custody and dependency tests; no native/vendor execution."""
import unittest
from unittest.mock import patch
from lib import operation_readiness as O
from test_current_doctor import C, Budget
from test_current_source_doctor import CurrentDoctorTests


class ReadinessTests(unittest.TestCase):
    def test_unused_vendor_is_not_a_dependency(self):
        for operation in ("shell-recovery", "wine-recovery"):
            calls = []
            checks = {key: lambda key=key: calls.append(key) or True
                      for key in O.DEPENDENCIES[operation]}
            with patch('lib.current_doctor_native.probe.observe',
                       side_effect=AssertionError('unrelated vendor launched')):
                value = O.evaluate(operation, 'a'*40, checks=checks,
                                   source_guard=lambda: True, target_guard=lambda: True)
            self.assertEqual(calls, list(O.DEPENDENCIES[operation]))
            self.assertTrue(value['scopedCandidateReady'])
            for field in ('machineMutationAuthorized', 'liveGateSatisfied',
                          'installedStateAccepted', 'nativeConsentGranted'):
                self.assertFalse(value[field])

    def test_unknown_missing_extra_and_wrong_type_dependencies_reject(self):
        for checks in ({}, {'payload-owner': lambda: True},
                       {'payload-owner': lambda: True, 'recovery': lambda: 1},
                       {'payload-owner': lambda: True, 'recovery': lambda: True,
                        'vendor': lambda: True}):
            with self.subTest(checks=tuple(checks)), self.assertRaises(RuntimeError):
                O.evaluate('wine-recovery', 'a'*40, checks=checks,
                           source_guard=lambda: True, target_guard=lambda: True)

    def test_changed_target_rejects_after_successful_observation(self):
        stable = [True]
        def mutate():
            stable[0] = False
            return True
        with self.assertRaisesRegex(RuntimeError, 'operation_target_drift'):
            O.evaluate('wine-recovery', 'a'*40,
                       checks={'payload-owner': mutate, 'recovery': lambda: True},
                       source_guard=lambda: True, target_guard=lambda: stable[0])

    def test_canonical_restriction_is_not_a_pathname_authority_grant(self):
        from pathlib import Path
        with self.assertRaisesRegex(RuntimeError, 'operation_canonical_source'):
            O.require_scoped_operation_ready(Path('/private/tmp'), 'wine-recovery', 'a'*40,
                checks={'payload-owner': lambda: True, 'recovery': lambda: True},
                target_guard=lambda: True)

    def test_native_scoped_and_full_routes_are_distinct_no_activation_flag(self):
        import tempfile
        from pathlib import Path
        from lib import current_doctor_native as N
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            root = home/'AIDev/control'
            root.mkdir(parents=True)
            calls = []
            def native(doctor, git_only, *, operation_check):
                calls.append(git_only)
                operation_check('a'*40, source_guard=lambda: True)
                return C.report(historical=True, source=True, accepted=True,
                    integrated=True, git_only=git_only, sentinel=not git_only,
                    sentinel_checked=not git_only)
            checks = {'payload-owner': lambda: True, 'recovery': lambda: True}
            with patch.object(Path, 'home', return_value=home), \
                 patch.object(O.importlib.machinery.SourceFileLoader, 'load_module', return_value=C), \
                 patch.object(N, 'native', side_effect=native):
                value = O.require_scoped_operation_ready(root, 'shell-recovery', 'a'*40,
                    checks=checks, target_guard=lambda: True)
                self.assertEqual(calls, [True])
                self.assertFalse(value['liveGateSatisfied'])
                calls.clear()
                value = O.require_operation_ready(root, 'shell-recovery', 'a'*40,
                    checks=checks, target_guard=lambda: True)
                self.assertEqual(calls, [True, False])
                self.assertTrue(value['liveGateSatisfied'])
                self.assertFalse(value['machineMutationAuthorized'])

    def test_reviewed_target_cli_is_explicit_git_only_and_cannot_mix_audit(self):
        calls = []
        def operation(git_only, **kwargs):
            calls.append((git_only, kwargs))
            return C.report(git_only=git_only)
        C.main(['--git-only', '--reviewed-target', '--json'], operation=operation, emit=lambda _: None)
        self.assertEqual(calls, [(True, {'reviewed_target': True})])
        for arguments in (['--reviewed-target'], ['--git-only','--reviewed-target','--audit-history']):
            calls.clear()
            self.assertEqual(C.main(arguments, operation=operation, emit=lambda _: None), 2)
            self.assertFalse(calls)


class HeldSourceTests(CurrentDoctorTests):
    def operation(self, head, *, source_guard):
        self.assertEqual(head, self.state['head'])
        O.evaluate('shell-recovery', head,
            checks={'payload-owner': lambda: True, 'recovery': lambda: True},
            source_guard=source_guard, target_guard=lambda: True)
        self.assertTrue(self.sources)
        self.assertTrue(all(s.closes == 0 for _,s in self.sources))
        return True

    def test_scoped_callback_keeps_actual_sources_held_without_vendor(self):
        value = self.run_doctor(git_only=True, operation_check=self.operation)
        self.assertEqual(value['verdict'], 'GIT_ONLY_VALID')
        self.assertEqual(self.sentinel_calls, 0)
        self.assertTrue(all(s.closes == 1 for _,s in self.sources))
        self.assertFalse(any(value[key] for key in C.AUTHORITY))

    def test_used_source_drift_blocks_scoped_callback(self):
        def mutate(head, *, source_guard):
            self.sources[0][1].data += b'drift'
            return self.operation(head, source_guard=source_guard)
        with self.assertRaises(C.DoctorError):
            self.run_doctor(git_only=True, operation_check=mutate)

    def test_live_full_gate_still_runs_and_rejects_unready_vendor(self):
        self.sentinel = lambda *args, **kwargs: dict(
            status='NEEDS_REVIEW', childSettled=True, sourceHandlesClosed=True)
        with self.assertRaises(C.DoctorError):
            self.run_doctor(operation_check=self.operation)


if __name__ == '__main__':
    unittest.main()
