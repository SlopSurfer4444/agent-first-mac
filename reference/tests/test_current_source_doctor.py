"""Current admission through the real held-source doctor, with fixture callbacks only."""
import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from test_current_doctor import C, Source, Budget
import test_current_source_admission as fixture


class CurrentDoctorTests(unittest.TestCase):
    def setUp(self):
        self.repo = fixture.CurrentSourceTests('test_checkpoint_and_two_payload_successors_need_no_receipt')
        self.repo.setUp()
        self.addCleanup(self.repo.doCleanups)
        self.sources = []
        observation, head, tree = self.repo.observe()
        self.state = dict(head=head, branch='main', clean=True, tree=tree, currentAdmission=observation)
        self.git = SimpleNamespace(state=lambda: copy.deepcopy(self.state))
        self.sentinel_calls = 0

    def source(self, path, absent=False):
        data = b'' if absent else (self.repo.root/path).read_bytes()
        mode = '100644' if absent else self.state['tree'][path][0]
        held = Source(data, mode, absent)
        self.sources.append((path, held))
        return held

    def sentinel(self, budget, *, source_guard):
        self.sentinel_calls += 1
        source_guard()
        return dict(status='PASS', childSettled=True, sourceHandlesClosed=True)

    def run_doctor(self, **kwargs):
        return C.run(git=self.git, source_factory=self.source, budget=Budget(), canonical_main=True,
                     sentinel_check=self.sentinel, **kwargs)

    def test_full_sentinel_and_current_mode_bind_all_current_sources(self):
        value = self.run_doctor()
        self.assertEqual(value['admissionMode'], 'current-state')
        self.assertEqual(value['verdict'], 'PASS')
        self.assertEqual(self.sentinel_calls, 1)
        self.assertEqual({p for p,s in self.sources if not s.absent}, set(self.state['tree']))
        self.assertTrue(all(s.closes == 1 for _,s in self.sources))
        self.assertFalse(any(value[key] for key in C.AUTHORITY))
        C.public_report(value)

    def test_git_only_does_not_probe_vendor(self):
        value = self.run_doctor(git_only=True)
        self.assertEqual(value['verdict'], 'GIT_ONLY_VALID')
        self.assertEqual(self.sentinel_calls, 0)

    def test_dirty_and_noncanonical_fail_before_sentinel(self):
        self.state['clean'] = False
        with self.assertRaises(C.DoctorError): self.run_doctor()
        self.assertEqual(self.sentinel_calls, 0)
        self.state['clean'] = True
        with self.assertRaises(C.DoctorError):
            C.run(git=self.git, source_factory=self.source, budget=Budget(), canonical_main=False,
                  sentinel_check=self.sentinel)

    def test_source_drift_blocks_callback_and_final_result(self):
        def mutate(budget, *, source_guard):
            self.sources[0][1].data += b'drift'
            source_guard()
        self.sentinel = mutate
        with self.assertRaises(C.DoctorError) as caught: self.run_doctor()
        self.assertFalse(caught.exception.outcome.public['currentSentinelReady'])
        self.assertFalse(caught.exception.outcome.public['repositoryChecksPassed'])

    def test_final_git_drift_blocks_even_successful_vendor_probe(self):
        def mutate(budget, *, source_guard):
            value = CurrentDoctorTests.sentinel(self, budget, source_guard=source_guard)
            self.state['head'] = 'f'*40
            return value
        self.sentinel = mutate
        with self.assertRaises(C.DoctorError) as caught: self.run_doctor()
        self.assertEqual(caught.exception.outcome.public['failureStage'], 'final-recheck')

    def test_explicit_history_audit_routes_old_native_mode(self):
        calls = []
        def operation(git_only, **kwargs):
            calls.append((git_only, kwargs))
            return C.report(git_only=git_only)
        self.assertEqual(C.main(['--git-only', '--audit-history', '--json'], operation=operation,
                                emit=lambda _: None), 1)
        self.assertEqual(calls, [(True, {'audit_history': True})])

    def test_native_present_malformed_migration_never_falls_back(self):
        instance = object.__new__(C.NativeGit)
        instance._tree = lambda _: self.state['tree']
        instance._text = lambda *args: self.state['head'] if args[0] == 'rev-parse' else 'main'
        instance._read = lambda *args, **kwargs: (0, b'')
        with patch.object(C.current_sources, 'observe', side_effect=ValueError('invalid migration')), \
             patch('lib.config_transition_git.observe', side_effect=AssertionError('fallback forbidden')):
            with self.assertRaisesRegex(ValueError, 'invalid migration'): instance.state()


if __name__ == '__main__': unittest.main()
